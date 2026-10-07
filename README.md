# multi-tenant-access-guard-java

面向多租户的多入口访问控制服务：统一的权限判定、双登录入口、限流与敏感操作临时锁定、
同编号资源租户隔离、续期凭据收紧与可解释审计。

## 鉴权模型

- **主体（Subject）**：`userId + tenantId + roles`，角色为 `ADMIN / USER / VIEWER`。
- **资源（GuardedResource）**：`resourceId + tenantId + ownerId`，归属某租户与某属主。
- **判定（AccessEvaluator）**：两种入口共用同一判定器，顺序固定，拒绝原因可区分：

  | 顺序 | 检查 | 拒绝原因 |
  |---|---|---|
  | 1 | 资源在本租户下是否存在 | `RESOURCE_NOT_FOUND`（404） |
  | 2 | 任一角色允许该动作 | `INSUFFICIENT_ROLE`（403） |
  | 3 | 写/删要求属主本人或本租户 ADMIN | `NOT_OWNER`（403） |

- **一致性语义**：权限配置保存在不可变快照（`PolicySnapshot`）中，变更以写时复制方式
  原子替换（`InMemoryPolicyStore`）。单次判定复用同一快照；变更对新请求立即整体生效——
  旧权限不会长期残留，也不存在权限被短暂放大的中间态。审计记录含 `policyVersion`，可溯源。
- **角色实时加载**：凭据只承载身份（userId/tenantId），角色在每次认证时从 `UserDirectory`
  实时读取，权限/角色变更无需重新登录即可生效。

## 同编号资源的租户隔离

- 资源以 **(tenantId, resourceId) 复合键**登记在快照中：同一资源编号可在不同租户下
  各自独立存在、各自管理归属，后写入的同名资源不会顶掉其他租户的记录，
  租户数量与资源量上涨、批量写入后依然稳定（`TenantResourceIsolationTest` 验证）。
- 判定只按**调用方租户**查找资源：跨租户访问他租户的同名资源，与访问不存在的资源
  返回**完全相同的** `RESOURCE_NOT_FOUND`（404）——调用方无法通过探测判断对方
  是否持有该编号，不泄露资源存在性。
- 移除资源同样按复合键进行：`removeResource(tenantId, resourceId)` 只影响本租户的记录。

## 两种登录入口与兼容规则

| 入口 | 端点 | 凭据携带方式 |
|---|---|---|
| 令牌入口 | `POST /api/auth/token` → `{token, refreshToken}` | `Authorization: Bearer <token>` |
| 会话入口 | `POST /api/auth/session` → `{sessionId}` | `X-Session-Id: <sessionId>` |

- 两个入口产出**同一类 `AuthContext`**，后续判定与入口无关，同一主体访问同一资源结论一致
  （`EntryConsistencyTest` 全覆盖验证）。
- 同时携带两种凭据时优先使用 Bearer 令牌。
- 令牌为 HMAC-SHA256 签名（`payload.signature`），校验失败原因可区分：
  `CREDENTIAL_TAMPERED`（篡改/格式非法）、`CREDENTIAL_EXPIRED`（过期）、
  `CREDENTIAL_REPLAYED`（续期后旧凭据再次使用）、
  `CREDENTIAL_TYPE_MISMATCH`（凭据类型与入口不匹配）。

## 续期凭据的兼容范围

- 令牌分两类，**互不通用**：
  - `ACCESS`：日常访问凭据（默认 30min，`guard.token.ttl-seconds`），**不能用于续期**；
  - `REFRESH`：续期专用凭据（默认 24h，`guard.token.refresh-ttl-seconds`），**不能用于访问**。
  - 混用一律拒绝：`CREDENTIAL_TYPE_MISMATCH`（401）。
- 登录（令牌入口）同时签发同一续期链（family）上的访问凭据 + 续期凭据；
  `POST /api/auth/refresh` 只接受续期凭据，成功后在**同一条链上**轮换出新的凭据对，
  身份始终绑定原主体与原租户，不会认到别的租户或主体上。
- **重放防护**：旧续期凭据的 `jti` 通过原子占位一次性作废，再次提交判定为
  `CREDENTIAL_REPLAYED`，并**作废整条续期链**——链上已签发的其他凭据（含新轮换出的）
  一并失效，重放视为泄露信号。并发续期只有一个成功，其余判定为重放（同样触发整链作废，
  需重新登录）。
- 已轮换/已作废状态随原过期时间惰性清理，无需人工干预。

## 限流与敏感操作锁定

- **登录限流与锁定**（`RateLimiter`）：固定窗口计数，窗口切换与自增在
  `ConcurrentHashMap.compute` 内原子完成。登录失败按 `login:<username>` 计数，
  达到阈值（默认 5 次）临时锁定（默认 60s）；锁定期间即使口令正确也拒绝（`LOCKED`，429）；
  锁定期满惰性自动恢复；登录成功清零计数。
- **敏感操作守卫**（`SensitiveOperationGuard`）：写/删操作在限流之外还有
  基于连续失败的临时锁定，计数键为 `租户 + 主体 + 动作`，互不影响：
  - 窗口内尝试超限 → `RATE_LIMITED`（429，单纯限流）；
  - 连续失败达到阈值（默认 5 次）→ `LOCKED`（429，明确锁定状态），与限流可区分；
  - 锁定期满（默认 60s）自动恢复，无需人工解锁；成功操作清零失败计数；
  - 并发下计数与锁定状态原子变更：已锁定主体的并发请求无一放行。
- 参数可通过 `guard.ratelimit.*`、`guard.sensitive.*`、`guard.token.*`、
  `guard.session.ttl-seconds` 配置。

## 审计与异常

- 每次判定写入审计日志并打印：主体、租户、资源、动作、结论、拒绝原因与判定依据
  （含策略版本与入口类型），例如：

  ```
  AUDIT subject=u-bob tenant=tenant-b resource=doc-1 action=READ decision=DENY reason=RESOURCE_NOT_FOUND basis=policyVersion=2, entry=TOKEN, basis=...
  ```

- `GlobalExceptionHandler` 统一兜底：内部异常只记录服务端日志，向调用方返回
  通用 `INTERNAL_ERROR`，不泄露内部细节。

## 本地验证

```bash
# 运行全部测试，日志中可见各业务场景的覆盖与通过情况：
#   TEST-DECISION   统一判定（角色/归属/快照一致性）
#   TEST-LOCK       登录锁定阈值与到期恢复
#   TEST-RATE       限流窗口边界与并发计数
#   TEST-SENSITIVE  敏感操作锁定（阈值边界/到期/与限流区分/并发不放行）
#   TEST-TENANT     同编号资源跨租户隔离与批量写入稳定性
#   TEST-CRED       凭据过期/篡改
#   TEST-REFRESH    续期轮换与并发占位
#   TEST-REFRESH2   续期收紧（类型隔离/重放整链作废/并发/身份绑定）
#   TEST-WEB        Web 全链路（双入口/跨租户不泄露/登录锁定）
mvn test

# 启动服务并手工验证
mvn spring-boot:run
curl -X POST localhost:8080/api/auth/token -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"alice-pw"}'
# 响应含 token（访问凭据）与 refreshToken（续期凭据）
curl localhost:8080/api/resources/doc-1 -H "Authorization: Bearer <token>"

# 续期：只能用 refreshToken；用访问凭据续期会被拒（CREDENTIAL_TYPE_MISMATCH）
curl -X POST localhost:8080/api/auth/refresh -H 'Content-Type: application/json' \
     -d '{"token":"<refreshToken>"}'

# 跨租户（bob 属 tenant-b，访问 tenant-a 的 doc-1 得到与不存在一致的 404）
curl -X POST localhost:8080/api/auth/token -H 'Content-Type: application/json' \
     -d '{"username":"bob","password":"bob-pw"}'
curl localhost:8080/api/resources/doc-1 -H "Authorization: Bearer <bob-token>"
```

演示账号：`alice/alice-pw`（tenant-a, USER）、`carol/carol-pw`（tenant-a, ADMIN）、
`dave/dave-pw`（tenant-a, VIEWER）、`bob/bob-pw`（tenant-b, USER）。
演示资源：`doc-1`（tenant-a, 属主 alice）、`doc-2`（tenant-b, 属主 bob）。
