# multi-tenant-access-guard-java

面向多租户的多入口访问控制服务：统一的权限判定、双登录入口、限流、敏感操作临时锁定、
同编号资源的租户隔离、用途分离的凭据与续期链、可解释审计。

## 鉴权模型

- **主体（Subject）**：`userId + tenantId + roles`，角色为 `ADMIN / USER / VIEWER`。
- **资源（GuardedResource）**：`resourceId + tenantId + ownerId`，归属某租户与某属主。
- **判定（AccessEvaluator）**：两种入口共用同一判定器，顺序固定，拒绝原因可区分：

  | 顺序 | 检查 | 拒绝原因 |
  |---|---|---|
  | 1 | 资源在**本租户命名空间**是否存在 | `RESOURCE_NOT_FOUND`（404，含跨租户探测） |
  | 2 | 任一角色允许该动作 | `INSUFFICIENT_ROLE`（403） |
  | 3 | 写/删要求属主本人或本租户 ADMIN | `NOT_OWNER`（403） |

- **一致性语义**：权限配置保存在不可变快照（`PolicySnapshot`）中，变更以写时复制方式
  原子替换（`InMemoryPolicyStore`）。单次判定复用同一快照；变更对新请求立即整体生效。
- **角色实时加载**：凭据只承载身份（userId/tenantId），角色在每次认证时从 `UserDirectory`
  实时读取，权限/角色变更无需重新登录即可生效。

## 同编号资源的租户隔离

- 资源以 **（tenantId, resourceId）复合键** 唯一标识。同一个资源编号（如 `shared-doc`）
  可以在不同租户下各自独立存在、各自管理归属；A 租户写自己的 `shared-doc` 不影响 B 租户。
- 判定时只在**主体自己的租户命名空间**内查找资源。跨租户去碰别人的同名资源时，
  本租户查无此编号，统一返回 `404 RESOURCE_NOT_FOUND`，与“真的不存在”不可区分，
  调用方无法靠探测判断对方租户到底有没有这个资源。
  - 对内部审计不丢失信息：若该编号在别的租户确实存在，审计 `basis` 中带 `CROSS_TENANT`
    标记供溯源；对调用方返回的拒绝原因仍是 `RESOURCE_NOT_FOUND`。
- 批量注册（`PolicyStore.registerResources`）在**一次原子快照替换**内整体生效。
  租户数量与资源量上涨、大批量写入后，每个租户的每条同名记录都保留且归属正确，
  不会出现后写的把前面租户记录顶掉（`TenantIsolationTest` 以 200 租户 × 50 同名资源验证）。
- 删除同样按租户作用域：`removeResource(tenantId, resourceId)` 只删本租户那份。

## 两种登录入口与凭据用途

| 入口 | 端点 | 凭据携带方式 |
|---|---|---|
| 令牌入口 | `POST /api/auth/token` | `Authorization: Bearer <token>` |
| 会话入口 | `POST /api/auth/session` | `X-Session-Id: <sessionId>` |
| 续期入口 | `POST /api/auth/refresh` | body `{"token":"<refreshToken>"}` |

- 令牌登录成功后返回**一对凭据**：
  - `token`：访问凭据（claim `typ=access`），平时访问 `/api/resources/**` 用；
  - `refreshToken`：续期凭据（claim `typ=refresh`），**只能**用于 `/api/auth/refresh`。
- 两个访问入口产出同一类 `AuthContext`，后续判定与入口无关；同时携带两种凭据时优先 Bearer。
- 凭据为 HMAC-SHA256 签名，校验失败原因可区分：

  | 场景 | 拒绝原因 | HTTP |
  |---|---|---|
  | 篡改 / 格式非法 / 缺声明 | `CREDENTIAL_TAMPERED` | 401 |
  | 超过有效期 | `CREDENTIAL_EXPIRED` | 401 |
  | 续期后旧凭据再次使用 | `CREDENTIAL_REPLAYED` | 401 |
  | 用 access 凭据去续期 | `CREDENTIAL_NOT_REFRESHABLE` | **403** |
  | 用 refresh 凭据访问业务入口 | `CREDENTIAL_TYPE_MISMATCH` | 401 |
  | 所在续期链被作废 | `CREDENTIAL_REPLAYED` | 401 |

## 续期链、重放与并发

- 每次令牌登录生成一条续期链 `chainId`，access 与 refresh 都绑定该链；
  续期凭据寿命独立于访问凭据（默认 access TTL 的 2 倍）。
- `POST /api/auth/refresh` 原子轮换：链头 refresh 换成下一代，并签发新的一对凭据。
  并发续期在链状态上串行化，**恰好一个成功**，其余判定为 `CREDENTIAL_REPLAYED`，
  一份凭据不可能被多次成功续期，身份也不会错认到别的租户/主体。
- **紧邻上一代** refresh 的再次提交（含并发落败者）只拒绝、不作废链，避免把胜出者
  刚拿到的新凭据误杀。
- **隔代或更老** refresh 的重放视为凭据被盗：整条续期链立即作废，链上尚未过期的
  access 也一并拒绝。
- 普通访问不轮换 refresh，access 在自身有效期内持续可用；会话入口不参与续期。

## 限流与敏感操作临时锁定

系统中有两类彼此独立、拒绝原因可区分的“临时拦截”：

| 机制 | 触发对象 | 触发条件 | 拒绝原因（HTTP 429） |
|---|---|---|---|
| 登录失败锁定 | `login:<username>` | 连续登录失败达阈值（默认 5 次） | `LOCKED` |
| 敏感操作限流 | `sensitive:<tenant>:<user>` | 固定窗口内操作超上限（默认 60s 20 次） | `RATE_LIMITED` |
| **敏感操作临时锁定** | `sensitive:<tenant>:<user>` | 短时间内敏感动作**连续失败**达阈值（默认 3 次 / 300s） | `SENSITIVE_LOCKED` |

敏感操作锁定（`SensitiveActionLockout`）语义：

- 写/删（WRITE/DELETE）为敏感动作。被权限/归属判定拒绝的敏感请求计为一次失败；
  成功执行即清零连续失败计数。
- 连续失败达到阈值进入**明确的锁定状态**，与“只是被限流”区分开：调用方拿到的是
  `SENSITIVE_LOCKED`，而非 `RATE_LIMITED`。
- 锁定期满（默认 300s）后**惰性自动恢复**，无需人工解锁。
- **并发正确性**：每个主体映射一把分段锁（striped lock），控制器在同一把锁内完成
  “查锁定 → 限流计数 → 权限判定 → 记失败”整段流程，因此不会出现已经锁定还能被放行，
  也不会丢失失败计数；不同主体互不阻塞、互不牵连。
- 参数：`guard.sensitive-lock.failure-threshold`、`guard.sensitive-lock.lock-duration-seconds`、
  `guard.sensitive-lock.failure-window-seconds`；
  限流参数：`guard.ratelimit.*`；`guard.token.ttl-seconds`、`guard.session.ttl-seconds`。

## 审计与异常

- 每次判定写入审计日志并打印：主体、租户、资源、动作、结论、拒绝原因与判定依据
  （含策略版本、入口类型；跨租户探测含 `CROSS_TENANT` 溯源标记）。
- `GlobalExceptionHandler` 统一兜底：内部异常只记录服务端日志，向调用方返回
  通用 `INTERNAL_ERROR`，不泄露内部细节。

## 自动化测试

```bash
mvn test
```

- 日志按业务打印覆盖情况：每个用例输出 `business=<场景> ... result=PASS`，
  `BusinessCoverageReportTest` 启动时打印业务覆盖矩阵；审计日志同步可见拒绝原因。
- 覆盖范围：
  - `SensitiveActionLockoutTest`：锁定阈值下边界/阈值点、到期前一刻与到期自动恢复、
    成功清零、失败窗口滚动、主体隔离、并发下“已锁定绝不漏放”；
  - `TenantIsolationTest`：同名资源各租户独立通过、跨租户探测与不存在不可区分、
    200×50 批量写入互不顶掉、按租户删除互不影响；
  - `TokenServiceTest`：access/refresh 用途分离（两种新拒绝原因）、续期轮换、
    紧邻重放、隔代重放整链作废（含未过期 access）、并发续期唯一成功、跨租户身份不串；
  - `WebIntegrationTest`：上述场景的端到端 HTTP 行为；
  - 原有用例（跨租户越权、过期/篡改、双入口一致性、登录锁定、限流边界、审计溯源）
    全部保留且无回归。

## 本地手工验证

```bash
mvn spring-boot:run

# 1) 登录，拿到 token（access）与 refreshToken
curl -X POST localhost:8080/api/auth/token -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"alice-pw"}'

# 2) access 访问自己的同名资源
curl localhost:8080/api/resources/shared-doc -H "Authorization: Bearer <token>"

# 3) 用 access 去续期 → 403 CREDENTIAL_NOT_REFRESHABLE
curl -X POST localhost:8080/api/auth/refresh -H 'Content-Type: application/json' \
     -d '{"token":"<token>"}'

# 4) 用 refreshToken 正常续期 → 返回新的 token/refreshToken；旧 refreshToken 再提交 → 401 CREDENTIAL_REPLAYED
curl -X POST localhost:8080/api/auth/refresh -H 'Content-Type: application/json' \
     -d '{"token":"<refreshToken>"}'

# 5) bob（tenant-b）探测 tenant-a 独占的 doc-1 → 404 RESOURCE_NOT_FOUND（防探测）
curl -X POST localhost:8080/api/auth/token -H 'Content-Type: application/json' \
     -d '{"username":"bob","password":"bob-pw"}'
curl localhost:8080/api/resources/doc-1 -H "Authorization: Bearer <bob-token>"

# 6) erin（VIEWER）连续 3 次写 doc-1 → 第 3 次起 429 SENSITIVE_LOCKED，到期自动恢复
curl -X POST localhost:8080/api/auth/token -H 'Content-Type: application/json' \
     -d '{"username":"erin","password":"erin-pw"}'
curl -X PUT localhost:8080/api/resources/doc-1 -H "Authorization: Bearer <erin-token>"
```

演示账号：`alice/alice-pw`（tenant-a, USER）、`carol/carol-pw`（tenant-a, ADMIN）、
`dave/dave-pw`（tenant-a, VIEWER）、`erin/erin-pw`（tenant-a, VIEWER）、
`bob/bob-pw`（tenant-b, USER）。
演示资源：`doc-1`（tenant-a, 属主 alice）、`doc-2`（tenant-b, 属主 bob）、
`shared-doc`（两租户各一份，分别属 alice / bob）。
