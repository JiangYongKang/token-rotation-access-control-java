# 本地令牌轮换与访问控制服务（Java / Spring Boot）

一套**完全本地可运行**的身份与访问控制参考实现：用内存存储模拟用户、角色、会话与签名密钥，
覆盖登录签发、基于角色/权限的访问判定、刷新令牌一次性轮换与复用检测、凭证轮换、密钥切换、
强制登出，并为每一次判定输出带**凭证标识**与**判定依据**的审计记录。

无外部服务依赖：不需要数据库、Redis、第三方 IdP、真实凭据或付费组件；
令牌使用 JDK 自带的 HMAC-SHA256 自实现（不依赖 JWT 库），Web 层只用 Spring Boot Web。

## 1. 快速开始

```bash
# JDK 21+（本仓库在 JDK 25 上编译，release 目标为 21）
mvn spring-boot:run                     # 默认随机端口
# 或固定端口
mvn package -DskipTests
java -jar target/token-rotation-access-control-java-1.0-SNAPSHOT.jar --server.port=18091
```

启动后预置的本地演示账号（密码仅以 SHA-256 哈希存在内存中）：

| 用户 | 密码 | 角色 | 权限 | 备注 |
|------|------|------|------|------|
| admin | admin123 | admin | article:read, article:write, admin:manage | 可调用管理接口 |
| alice | alice123 | editor | article:read, article:write | |
| bob | bob123 | reader | article:read | |
| carol | carol123 | reader | article:read | 账号初始禁用 |

## 2. 令牌与权限模型

### 2.1 令牌结构

令牌为自签名字符串：`base64url(JSON 声明).base64url(HMAC-SHA256(声明, 密钥))`，声明包含：

| 字段 | 含义 |
|------|------|
| `iss` | 签发者（`app.security.issuer`） |
| `sub` | 用户 id |
| `sid` | 会话 id（每次刷新轮换产生新会话） |
| `fam` | 会话链路（family）id，一次登录内的所有轮换共享 |
| `jti` | 凭证唯一标识，登录/刷新响应中同时明文返回，便于日志追踪 |
| `typ` | `access` 或 `refresh` |
| `kid` | 签名密钥版本号 |
| `iat`/`exp` | 签发/过期时间（毫秒） |

**关键设计：声明中刻意不携带角色与权限。** 访问接口时，服务端只从令牌中取出 `sub`，
然后到内存用户/角色存储中读取**当前**角色与权限。因此管理员修改角色权限、调整用户角色
或禁用用户后，用户手中的旧令牌无需失效处理，下一次请求就按新状态判定
（测试 `permissionRevocationShouldTakeEffectImmediatelyForOldToken` 覆盖）。

### 2.2 访问判定流程（每次请求实时执行）

1. 无 `Authorization` 头 → `missing_credential`（401，**未认证**）；
2. 验签：格式/签名错误 → `invalid_credential`（401）；签名密钥版本已轮换退役
   → `signing_key_retired`（401）；过期 → `token_expired` / `refresh_token_expired`（401）；
3. 令牌类型必须匹配（刷新接口只收 refresh，资源接口只收 access）→ `wrong_token_type`；
4. 会话存在性与状态：不存在 → `session_not_found`；已吊销
   → `session_revoked`（401，**身份/会话已吊销**，响应附带吊销原因）；
5. 用户存在且启用，否则 → `user_disabled`（401）；
6. 实时聚合权限（用户直接权限 ∪ 各角色当前权限），缺少所需权限
   → `forbidden_permission`（403，**已认证但无权限**）。

“未认证 / 已认证无权限 / 被吊销”三类结论在 HTTP 状态码与响应体 `reason` 字段上都可区分。

## 3. 吊销与轮换语义

### 3.1 刷新令牌：一次性轮换 + 复用检测（RFC 6819 / OAuth 刷新令牌轮换模型）

- 每次登录或刷新成功都签发一对新令牌；刷新令牌的 `jti` 是**一次性凭证**，
  使用时在内存表 `consumedRefreshJtis` 中做原子 `putIfAbsent` 消费。
- 刷新成功后旧会话立即标记为 `rotated` 退役：**旧访问令牌、旧刷新令牌同时失效**，
  新令牌挂在同一 `fam` 链路的新会话上。
- 已消费的刷新令牌再次出现 ⇒ 判定为**凭证复用**（可能是攻击者在使用失窃令牌）：
  本次拒绝（`refresh_reuse_detected`），并**吊销整条 family 链路**，
  包括此前轮换出的、本属“合法”的新会话——这确保受害方与攻击方的令牌都不能再用。
- 复用检查优先于会话吊销检查：
  - 已消费令牌重放（哪怕发生在正常轮换之后）→ `refresh_reuse_detected`；
  - 强制登出后出示一张从未消费过的刷新令牌 → `session_revoked`，两者原因互不混淆。

### 3.2 并发安全

- 以 `familyId` 为粒度加锁（`ConcurrentHashMap` 中的每链路一把锁）：
  同一条登录链路上的刷新、登出串行；不同链路并行。
- 同一刷新令牌并发刷新（测试用 16 线程同时冲击）：锁内先查消费表，再原子消费，
  **恰好 1 个请求成功**，其余全部得到 `refresh_reuse_detected`，链路随即整体吊销，
  不可能出现“两个刷新结果都有效”。
- 强制登出与刷新交叉执行时二者在同一把锁上串行；
  `interleavedLogoutAndRefreshMustEndInConsistentRevokedState`
  以 30 个随机交错线程验证最终状态一致：链路一旦登出，期间任何一次轮换产生的
  最新 access/refresh 都不能再访问或再轮换。

### 3.3 强制登出与密钥切换

- `POST /api/auth/logout`：吊销当前刷新令牌所在的**整条链路**（全部后裔会话），
  旧访问令牌在下一次请求即得到 `session_revoked`。
- `POST /api/admin/users/{username}/logout`：管理员吊销某用户全部链路。
- `POST /api/admin/keys/rotate`：密钥切换。新登录/刷新使用新版本随机密钥；
  默认旧密钥立即从内存丢弃，所有旧 kid 令牌验签失败，原因 `signing_key_retired`
  （无需逐个会话处理，测试 `keyRotationMustInvalidateOldTokensImmediately` 覆盖）。

## 4. 接口一览

| 方法/路径 | 所需权限 | 说明 |
|-----------|----------|------|
| `GET  /api/resources/public` | 无 | 公开资源 |
| `GET  /api/resources/profile` | 已认证 | 返回用户信息与 jti |
| `GET  /api/resources/articles` | article:read | |
| `GET  /api/resources/articles/draft` | article:write | 403/401 区分演示 |
| `POST /api/auth/login` | 无 | `{username,password}` → 令牌对 |
| `POST /api/auth/refresh` | 有效 refresh | `{refreshToken}` → 新令牌对（旧的立即失效） |
| `POST /api/auth/logout` | 有效 refresh | `{refreshToken}` → 吊销整条链路 |
| `POST /api/admin/roles/{role}/permissions` | admin:manage | `{permission, action: add|remove}` |
| `POST /api/admin/users/{username}/enabled` | admin:manage | `{enabled:false}` 即时禁用 |
| `POST /api/admin/users/{username}/logout` | admin:manage | 吊销该用户全部会话 |
| `POST /api/admin/keys/rotate` | admin:manage | 签名密钥切换 |
| `GET  /api/admin/audit?limit=N` | admin:manage | 最近审计事件 |

错误响应体：`{status, reason, message, credentialId, timestamp}`。

### 拒绝原因（reason）速查

| reason | HTTP | 类别 |
|--------|------|------|
| `missing_credential` | 401 | 未认证 |
| `invalid_credential` | 401 | 未认证（伪造/篡改） |
| `token_expired` / `refresh_token_expired` | 401 | 未认证（过期） |
| `signing_key_retired` | 401 | 未认证（密钥已轮换） |
| `wrong_token_type` | 401 | 令牌类型不符 |
| `session_not_found` | 401 | 会话不存在 |
| `session_revoked` | 401 | **会话/链路已吊销**（含吊销原因） |
| `user_disabled` | 401 | **用户身份已禁用** |
| `refresh_token_already_used` / `refresh_reuse_detected` | 401 | 一次性凭证复用 |
| `bad_credentials` | 401 | 登录用户名/密码错误 |
| `forbidden_permission` | 403 | **已认证但无权限** |
| `bad_request` | 400 | 参数错误 |

## 5. 配置项（`src/main/resources/application.properties`）

| 键 | 默认值 | 说明 |
|----|--------|------|
| `server.port` | `0`（随机） | 本地端口 |
| `app.security.access-ttl-seconds` | `900` | 访问令牌有效期 |
| `app.security.refresh-ttl-seconds` | `1209600` | 刷新令牌有效期（14 天） |
| `app.security.key-seed` | `local-demo-master-key` | 初代密钥的派生种子（仅演示） |
| `app.security.issuer` | `local-token-service` | iss 声明 |
| `app.security.keep-retired-keys` | `false` | 轮换后是否保留旧密钥；false 时旧令牌验签失败（推荐） |

## 6. 本地验证

```bash
# 一键运行全部测试（含并发/复用/权限撤销/密钥轮换）
mvn test
```

测试类 `AuthFlowIntegrationTests` 启动真实 HTTP 容器，覆盖：

1. `shouldDistinguishUnauthenticatedForbiddenAndRevoked`
   ——未认证 401 / 无权限 403 / 用户禁用后旧令牌 401，原因码逐一断言；
2. `shouldRotateRefreshTokenOnceAndDetectReuse`
   ——刷新后旧 access 立即 `session_revoked`；旧 refresh 重放触发
   `refresh_reuse_detected` 且新令牌也随链路失效；
3. `concurrentRefreshOfSameTokenMustHaveSingleWinnerAndRevokeChain`
   ——16 线程并发刷新同一令牌，恰好 1 成功、15 个复用拒绝；
4. `permissionRevocationShouldTakeEffectImmediatelyForOldToken`
   ——移除/恢复角色权限，同一张旧令牌的判定即时变化；
5. `keyRotationMustInvalidateOldTokensImmediately`
   ——密钥切换后旧 access/refresh 均为 `signing_key_retired`，重新登录正常；
6. `interleavedLogoutAndRefreshMustEndInConsistentRevokedState`
   ——30 个刷新/登出线程随机交错，最终状态始终一致地为“链路已吊销”。

测试日志（`TEST` logger）与应用日志（`AUDIT` logger）会打印 `jti / sid / fam`
等凭证标识以及 ALLOW/DENY 判定依据。也可调用 `GET /api/admin/audit` 查看审计事件。

手动 curl 示例：

```bash
PORT=18091
curl -s -X POST localhost:$PORT/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"bob123"}'
# 取响应中的 accessToken / refreshToken 后：
curl -s localhost:$PORT/api/resources/articles -H "Authorization: Bearer <accessToken>"
curl -s -X POST localhost:$PORT/api/auth/refresh -H 'Content-Type: application/json' \
  -d '{"refreshToken":"<refreshToken>"}'
```

## 7. 代码结构

```
config/      SecurityProperties（app.security.* 配置）、WebConfig
domain/      User / Role / SessionInfo（会话含 family/parent 族谱）
store/       UserStore（实时权限聚合）、RoleStore、SessionStore（消费表 + family 锁）
security/    KeyManager（版本化 HMAC 密钥/轮换）、TokenService（签发/验签）、
             AccessGuard（认证+实时权限判定）、AccessDecision、AuditLogger
service/     AuthService（登录/轮换/复用检测/登出/密钥切换）、AccessControlService
web/         AuthController、ResourceController、AdminController、ApiExceptionHandler
bootstrap/   DataSeeder（本地演示账号）
```

## 8. 本地实现的边界（诚实声明）

- 所有状态在内存中，重启即重置；这是用于演示与可重复测试的有意设计，不是生产持久化方案。
- 密码用固定盐 SHA-256 演示；生产应使用 BCrypt/Argon2 等慢哈希。
- 自实现令牌格式仅用于本地教学与验证；生产建议采用成熟 JWT/JWE 库与密钥管理服务。
- 管理接口本身用 `admin:manage` 权限保护，但演示环境没有额外的网络层鉴权，请勿暴露到公网。
