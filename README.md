# Multi-Tenant Access Guard（多租户多入口访问控制服务）

基于 Spring Boot 3.4 / Java 21 的多租户访问控制参考实现。提供：

- 基于**角色 + 资源归属**的授权，跨租户访问、越权操作、不存在资源以**可区分原因**拒绝；
- **两种并存登录入口**（密码 / SSO），同一主体经任一入口对同一资源的判定结论一致；
- 凭据的**过期 / 篡改 / 重放 / 并发续期**防护，避免重复放行、身份错认与权限提升；
- 登录失败与敏感操作的**频率限制与临时锁定**，并发计数准确、锁定期满自动恢复；
- 全链路**可追溯审计**，对外错误不泄露内部细节。

---

## 1. 鉴权模型

### 1.1 核心概念

| 概念 | 说明 |
| --- | --- |
| 租户 `tenantId` | 资源与主体的硬隔离边界 |
| 主体 `Subject` | 身份**只由 `(tenantId, subjectId)` 构成**；`loginEntry` 仅用于审计，不影响判定 |
| 资源 `Resource` | 属于唯一租户，并记录 `ownerSubjectId` |
| 权限 `Permission` | `(tenantId, subjectId, role, scope, resourceId)`，`scope` 为 `RESOURCE` 或 `TENANT` |
| 权限快照 `PermissionSnapshot` | 不可变、带单调递增 `version` 的整份权限配置 |

角色权限（角色 → 可执行动作）：

| 角色 | READ | WRITE | DELETE |
| --- | --- | --- | --- |
| `viewer` | ✅ | – | – |
| `editor` | ✅ | ✅ | – |
| `admin` | ✅ | ✅ | ✅ |

资源所有者（`ownerSubjectId`）对自己的资源拥有全部动作权限；此外按
`RESOURCE` 级授权 → `TENANT` 级授权的顺序匹配。

### 1.2 判定顺序（每条分支对应一个可区分的拒绝原因）

1. **资源必须在请求租户内存在**，否则 `RESOURCE_NOT_FOUND`（HTTP 404）。
   资源查找按 `(tenantId, resourceId)` 进行，因此跨租户探测**无法确认外部资源是否存在**。
2. **主体租户必须等于资源租户**，否则 `CROSS_TENANT_ACCESS`（HTTP 403）。
3. 依次检查**资源归属 → RESOURCE 级角色 → TENANT 级角色**，均不满足则
   `FORBIDDEN`（HTTP 403）。

### 1.3 权限变更的一致性语义（关键设计）

- 每次权限变更都会构造**新的不可变快照**，并通过 `AtomicReference` 的**单次原子切换**发布，
  版本号来自 `AtomicLong` 单调递增。
- 一次授权判定从进入到结束只读取**同一个快照**，因此：
  - **不会出现新旧权限混合读取或权限被短暂放大**；
  - 切换完成后，**所有新判定立即看到新权限**，不存在“旧权限长期生效”的缓存窗口。
- 令牌**不携带角色**：访问令牌只承载身份，角色/权限在判定时从当前快照读取，
  所以权限回收无需等待旧令牌过期即生效。
- 每个 `Decision` 与审计行都记录所依据的 `snapshotVersion`，判定可解释、可复核。

---

## 2. 两种登录入口的兼容规则

| 入口 | `entry` | 凭据 | 说明 |
| --- | --- | --- | --- |
| 密码登录 | `PASSWORD` | `tenantId + username + password` | 盐值 + SHA-256 摘要校验（演示级） |
| 单点登录 | `SSO` | `tenantId + assertionId` | 一次性 SSO 断言（联邦登录的本地桩） |

兼容规则：

1. **身份归一**：两种入口最终都解析为仅以 `(tenantId, subjectId)` 为键的 `Subject`，
   因此同一主体经任一入口访问同一资源，授权结论必然一致（测试
   `passwordAndSsoConvergeToSameDecision` / `twoEntriesSameConclusionOverHttp` 覆盖）。
2. **统一签发**：登录成功后都签发同一形态的 `accessToken` + `refreshToken`，
   令牌中 `loginEntry` 仅作审计标记。
3. **SSO 断言一次性**：断言首次使用即被原子移除；再次出示判定为 `CREDENTIAL_REPLAYED`，
   不会产生第二个会话。
4. 未知入口返回 `UNSUPPORTED_ENTRY`（HTTP 400）。

### 2.1 令牌格式与失效原因

令牌为自实现的 HMAC-SHA256 紧凑令牌（无第三方 JWT 依赖）：
`base64url(payload).base64url(hmac(payload))`，签名比较采用常量时间比较。

两类失效**严格区分**：

- 签名/结构错误（被篡改、伪造、错误密钥）→ `INVALID_CREDENTIAL`（HTTP 401）；
- 签名完好但超过 `expiresAt` → `CREDENTIAL_EXPIRED`（HTTP 401）；
- 缺少 `Authorization: Bearer …` → `UNAUTHENTICATED`（HTTP 401）。

### 2.2 刷新令牌轮换与并发续期

- 刷新令牌按**家族（family）**管理，服务端保存“当前唯一有效 tokenId”。
- 续期采用**轮换（rotation）**：旧 refresh token 用一次即失效，签发新的 access/refresh 对。
- 兑换是**原子操作**（按家族记录加锁）：并发续期同一刷新令牌时，
  **恰有一次成功**，其余看到重放并**吊销整个家族**。
- 重放 → `CREDENTIAL_REPLAYED`；家族已吊销 → `CREDENTIAL_REVOKED`；未知令牌 →
  `INVALID_CREDENTIAL`。从而并发续期不会重复放行，更不会权限提升。

---

## 3. 限流与临时锁定策略

固定窗口失败计数 + 阈值触发的临时锁定，全部按 key 同步，保证并发准确；锁定到期**惰性自动恢复**。

| 策略家族 | key 形态 | 默认阈值 | 窗口 | 锁定时长 | 拒绝原因 / HTTP |
| --- | --- | --- | --- | --- | --- |
| 登录失败 `login` | `login:{tenant}:{username或sso-id}` | 5 次失败 | 5 分钟 | 10 分钟 | `ACCOUNT_LOCKED` / 429 |
| 敏感操作 `sensitive` | `sensitive:{tenant}:{subject}` | 3 次失败 | 1 分钟 | 2 分钟 | `RATE_LIMITED` / 429 |

规则：

- **登录**：先查锁，锁定中直接拒绝（即使密码正确也拒绝）；凭据校验失败则计数，
  达到阈值即上锁；登录成功清零。
- **敏感操作（DELETE）**：先查锁；被拒绝的敏感尝试计为一次失败，达到阈值上锁。
  接口提供 `?simulateFailure=true` 用于在不删除数据的情况下驱动锁定测试。
- **自动恢复**：锁定到期后下一次请求自动清锁、计数归零；窗口外的旧失败不计入。
- 锁定/限流事件写入审计（`RATE_LIMIT_LOCKED` / `SENSITIVE`）。
- 阈值均可通过 `application.properties` 覆盖（见下）。

---

## 4. 审计与错误处理

### 4.1 审计

所有关键事件（`LOGIN` / `AUTHN` / `REFRESH` / `AUTHZ` / `SENSITIVE` /
`RATE_LIMIT_LOCKED` / `DENIED` / `INTERNAL_ERROR`）都会：

- 打印一行结构化日志（logger 名 `AUDIT`），并在内存中保留最近事件供查询；
- 字段固定包含：**主体 subject、租户 tenant、资源 resource、动作 action、
  是否允许 allowed、原因 reason、判定依据 basis、快照版本 snapshotVersion、traceId**。

### 4.2 对外错误（不泄露内部信息）

统一由 `GlobalExceptionHandler` 转换，响应体只有：

```json
{ "traceId": "…", "reason": "CROSS_TENANT_ACCESS", "message": "cross-tenant access denied" }
```

内部异常类型、堆栈、账号是否存在等只写入服务端日志/审计，绝不返回给调用方；
未预期异常统一为 `INTERNAL_ERROR`（HTTP 500）并带 `traceId`。

---

## 5. HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/auth/login` | 登录；body 含 `entry` 及对应凭据 |
| POST | `/api/auth/refresh` | 刷新令牌轮换 |
| POST | `/api/tenants/{tenantId}/resources/{resourceId}/read` | 读 |
| POST | `/api/tenants/{tenantId}/resources/{resourceId}/write` | 写 |
| POST | `/api/tenants/{tenantId}/resources/{resourceId}/delete` | 删除（敏感，受限流） |

种子数据：租户 `tenant-a`（alice/bob）、`tenant-b`（carol）；资源
`tenant-a/doc-1`、`tenant-a/doc-2`（alice 所有）、`tenant-b/doc-1`（carol 所有）。

### 快速手动验证

```bash
mvn spring-boot:run

# 1) 密码登录
curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"entry":"PASSWORD","tenantId":"tenant-a","username":"alice","password":"alice-pw"}'

# 2) 带 access token 访问（把 <TOKEN> 换成上一步返回的 accessToken）
curl -s -X POST localhost:8080/api/tenants/tenant-a/resources/doc-1/read \
  -H 'Authorization: Bearer <TOKEN>'

# 3) 跨租户访问（carol 访问 tenant-a 的资源）-> 403 CROSS_TENANT_ACCESS
# 4) 连续 3 次 delete?simulateFailure=true -> 第 3 次起 429 RATE_LIMITED
```

---

## 6. 本地验证方法

### 6.1 运行全部测试

```bash
mvn test
```

共 30 个测试（7 个测试类），覆盖：

| 测试类 | 覆盖场景 |
| --- | --- |
| `TokenServiceTest` | 签发验签、**篡改**与**过期**原因区分、错误密钥 |
| `RefreshStoreTest` | 轮换后重放吊销家族、**32 线程并发续期恰好一次成功**、未知令牌 |
| `RateLimitServiceTest` | 阈值锁定、**到期自动恢复**、窗口滑动、**100 并发计数准确** |
| `AuthorizationServiceTest` | 归属放行、**跨租户**、**越权**、**资源不存在**、快照原子授予/撤销一致性、租户级角色不越界 |
| `AuthenticationServiceTest` | **双入口判定一致**、过期/篡改令牌、**SSO 一次性重放**、刷新重放吊销、过期刷新、**16 线程并发续期**、登录锁定与恢复 |
| `HttpAccessIntegrationTest` | 全链路 403/404/401/429、双入口 HTTP 一致、敏感锁定恢复、错误体不泄露内部细节、审计字段断言 |
| `ApplicationTests` | Spring 上下文可加载 |

测试日志会打印每个判定的**主体、租户、资源、动作与判定依据**，例如：

```
AUDIT|type=AUTHZ|tenant=tenant-b|subject=carol|entry=PASSWORD|resource=doc-1|action=READ|allowed=false|reason=CROSS_TENANT_ACCESS|basis=subject tenant 'tenant-b' != resource tenant 'tenant-a'|snapshot=1|trace=…
```

时间相关测试通过可手动推进的 `MutableClock` 实现确定性验证，无需真实等待锁定过期。

### 6.2 配置项（`src/main/resources/application.properties`）

```properties
server.port=0
guard.token.secret=local-dev-secret
guard.token.access-ttl-millis=900000      # 访问令牌 15 分钟
guard.token.refresh-ttl-millis=86400000   # 刷新令牌 24 小时
guard.login.max-failures=5
guard.login.window-millis=300000
guard.login.lock-millis=600000
guard.sensitive.max-failures=3
guard.sensitive.window-millis=60000
guard.sensitive.lock-millis=120000
```

### 6.3 代码结构

```
model/       领域类型与可区分拒绝原因 DenyReason
auth/        HMAC 令牌、刷新家族存储、双入口凭据目录、认证门面
authz/       版本化权限存储、角色+归属授权
ratelimit/   固定窗口计数与临时锁定
audit/       结构化审计
web/         认证/资源接口与全局异常处理
config/      限流策略装配与种子数据
```

> 说明：密码哈希（盐值 + SHA-256）与内存存储用于演示/测试，生产环境应替换为
> 自适应哈希（如 Argon2/bcrypt）与持久化存储；HMAC 密钥应来自密钥管理系统。
