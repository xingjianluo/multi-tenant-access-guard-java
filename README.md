# multi-tenant-access-guard-java

面向多租户的多入口访问控制服务：统一的权限判定、双登录入口、限流与临时锁定、可解释审计。

## 鉴权模型

- **主体（Subject）**：`userId + tenantId + roles`，角色为 `ADMIN / USER / VIEWER`。
- **资源（GuardedResource）**：`resourceId + tenantId + ownerId`，归属某租户与某属主。
- **判定（AccessEvaluator）**：两种入口共用同一判定器，顺序固定，拒绝原因可区分：

  | 顺序 | 检查 | 拒绝原因 |
  |---|---|---|
  | 1 | 资源是否存在 | `RESOURCE_NOT_FOUND`（404） |
  | 2 | 资源租户 == 主体租户 | `CROSS_TENANT`（403） |
  | 3 | 任一角色允许该动作 | `INSUFFICIENT_ROLE`（403） |
  | 4 | 写/删要求属主本人或本租户 ADMIN | `NOT_OWNER`（403） |

- **一致性语义**：权限配置保存在不可变快照（`PolicySnapshot`）中，变更以写时复制方式
  原子替换（`InMemoryPolicyStore`）。单次判定复用同一快照；变更对新请求立即整体生效——
  旧权限不会长期残留，也不存在权限被短暂放大的中间态。审计记录含 `policyVersion`，可溯源。
- **角色实时加载**：凭据只承载身份（userId/tenantId），角色在每次认证时从 `UserDirectory`
  实时读取，权限/角色变更无需重新登录即可生效。

## 两种登录入口与兼容规则

| 入口 | 端点 | 凭据携带方式 |
|---|---|---|
| 令牌入口 | `POST /api/auth/token` → `{token}` | `Authorization: Bearer <token>` |
| 会话入口 | `POST /api/auth/session` → `{sessionId}` | `X-Session-Id: <sessionId>` |

- 两个入口产出**同一类 `AuthContext`**，后续判定与入口无关，同一主体访问同一资源结论一致
  （`EntryConsistencyTest` 全覆盖验证）。
- 同时携带两种凭据时优先使用 Bearer 令牌。
- 令牌为 HMAC-SHA256 签名（`payload.signature`），校验失败原因可区分：
  `CREDENTIAL_TAMPERED`（篡改/格式非法）、`CREDENTIAL_EXPIRED`（过期）、
  `CREDENTIAL_REPLAYED`（续期后旧令牌再次使用）。
- **续期**：`POST /api/auth/refresh`。旧令牌的 `jti` 通过原子占位一次性作废，
  并发续期只有一个成功，其余判定为重放，不会重复放行或身份错认。

## 限流与锁定策略（RateLimiter）

- 固定窗口计数：窗口切换与自增在 `ConcurrentHashMap.compute` 内原子完成，并发下计数准确。
- 登录失败按 `login:<username>` 计数，达到阈值（默认 5 次）即临时锁定（默认 60s）；
  锁定期间即使口令正确也拒绝（`LOCKED`，429）；锁定期满惰性自动恢复；登录成功清零计数。
- 敏感操作（写/删）按 `sensitive:<userId>` 限流（默认每 60s 20 次），超限返回 `RATE_LIMITED`（429）。
- 参数可通过 `guard.ratelimit.*`、`guard.token.ttl-seconds`、`guard.session.ttl-seconds` 配置。

## 审计与异常

- 每次判定写入审计日志并打印：主体、租户、资源、动作、结论、拒绝原因与判定依据
  （含策略版本与入口类型），例如：

  ```
  AUDIT subject=u-bob tenant=tenant-b resource=doc-1 action=READ decision=DENY reason=CROSS_TENANT basis=policyVersion=2, entry=TOKEN, basis=...
  ```

- `GlobalExceptionHandler` 统一兜底：内部异常只记录服务端日志，向调用方返回
  通用 `INTERNAL_ERROR`，不泄露内部细节。

## 本地验证

```bash
# 运行全部测试（跨租户越权、过期/篡改/重放凭据、并发续期、限流锁定边界、双入口一致性）
mvn test

# 启动服务并手工验证
mvn spring-boot:run
curl -X POST localhost:8080/api/auth/token -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"alice-pw"}'
curl localhost:8080/api/resources/doc-1 -H "Authorization: Bearer <token>"
# 跨租户（bob 属 tenant-b，访问 tenant-a 的 doc-1 将被拒：CROSS_TENANT）
curl -X POST localhost:8080/api/auth/token -H 'Content-Type: application/json' \
     -d '{"username":"bob","password":"bob-pw"}'
curl localhost:8080/api/resources/doc-1 -H "Authorization: Bearer <bob-token>"
```

演示账号：`alice/alice-pw`（tenant-a, USER）、`carol/carol-pw`（tenant-a, ADMIN）、
`dave/dave-pw`（tenant-a, VIEWER）、`bob/bob-pw`（tenant-b, USER）。
演示资源：`doc-1`（tenant-a, 属主 alice）、`doc-2`（tenant-b, 属主 bob）。
