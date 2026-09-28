# 本地身份与访问控制服务（令牌轮换演示）

一个**完全本地、零外部依赖**的 Spring Boot 3 / Java 21 服务，用内存存储模拟用户、角色、
会话与审计，演示以下能力在**并发**与**吊销**场景下如何给出**一致且可解释**的结论：

- 登录签发访问令牌（access token）与刷新令牌（refresh token），按角色/权限放行或拒绝；
- 刷新令牌**一次性轮换**、**复用检测**、**并发刷新只有一个赢家**；
- 签名密钥切换、密码/角色轮换、管理员强制登出，旧凭证立即失效；
- 每次判定都写审计日志，拒绝原因可区分、可解释。

> 本项目用于本地演示与测试，密码哈希使用带固定盐的 SHA-256、令牌存于内存，
> **不可直接用于生产**；真实系统应使用 bcrypt/argon2、持久化存储与标准 JWT/JWK 方案。

## 1. 运行与验证

要求：JDK 21+、Maven（依赖已在 Spring Boot 常规仓库内）。

```bash
# 启动服务（默认 8080）
mvn spring-boot:run

# 全部自动化测试（含并发刷新、复用、吊销、密钥轮换）
mvn test
```

种子账号（启动时写入内存）：

| 用户名 | 密码 | 角色 | 权限 |
|---|---|---|---|
| `viewer` | `viewer-pass` | VIEWER | `DOCS_READ` |
| `editor` | `editor-pass` | EDITOR | `DOCS_READ`, `DOCS_WRITE` |
| `admin`  | `admin-pass`  | ADMIN  | `DOCS_READ/WRITE`, `ADMIN_AUDIT/KEYS/USERS` |

手动验证：

```bash
# 1) 登录
curl -s -X POST localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"viewer","password":"viewer-pass"}'

# 2) 带访问令牌访问（把 <AT> 换成返回的 accessToken）
curl -s localhost:8080/api/docs -H 'Authorization: Bearer <AT>'

# 3) 刷新（把 <RT> 换成 refreshToken；原 RT 立即失效）
curl -s -X POST localhost:8080/api/auth/refresh \
  -H 'Content-Type: application/json' -d '{"refreshToken":"<RT>"}'

# 4) 用 viewer 的令牌访问写接口 -> 403 ACCESS_DENIED
curl -s localhost:8080/api/docs/write-demo -H 'Authorization: Bearer <VIEWER_AT>'

# 5) 管理员轮换签名密钥 -> 所有旧访问令牌立即 401 UNKNOWN_SIGNING_KEY
curl -s -X POST localhost:8080/api/admin/rotate-key -H 'Authorization: Bearer <ADMIN_AT>'

# 6) 查看审计流水
curl -s localhost:8080/api/admin/audit -H 'Authorization: Bearer <ADMIN_AT>'
```

## 2. 令牌与权限模型

### 访问令牌（access token）

自包含字符串：`base64url(payload).base64url(HMAC-SHA256(payload))`。
payload 为最小 JSON，字段：

| 字段 | 含义 |
|---|---|
| `kid` | 签名密钥 id；密钥轮换后旧 `kid` 不再被识别 |
| `jti` | 访问令牌唯一标识，用于日志/审计追踪 |
| `sub` | 用户名 |
| `sid` | 会话 id（用于会话级吊销） |
| `ver` | 签发时的**用户凭证版本号** |
| `roles` | 签发时角色快照（仅展示；判定以存储中最新角色为准） |
| `iat`/`exp` | 签发/过期时间戳 |

### 刷新令牌（refresh token）

不透明随机串（`rt.` + 256 位随机值的 base64url），服务端**只保存其 SHA-256 哈希**：

- 每个会话保存一个“当前刷新令牌哈希”和一个“已用刷新令牌哈希链”；
- 刷新成功：旧哈希进入已用链，生成新的刷新令牌与新的访问令牌；
- 刷新令牌与签名密钥无关，因此密钥轮换不影响刷新能力，但轮换后签发的访问令牌用新密钥签名。

### 角色与权限

- 角色（`Role`）：`VIEWER / EDITOR / ADMIN`，每个角色映射一组权限（`Permission`）。
- 访问判定（`AccessControlService`）在**每次请求**时执行，顺序如下，任一环节失败即返回
  对应拒绝原因：

  1. `Authorization` 头是否存在（`MISSING_TOKEN`）、是否 Bearer（`UNSUPPORTED_TOKEN_TYPE`）；
  2. 令牌能否解析：`MALFORMED_TOKEN` / `UNKNOWN_SIGNING_KEY` / `INVALID_SIGNATURE` / `EXPIRED_TOKEN`；
  3. 会话是否存在（`SESSION_NOT_FOUND`）、是否已吊销（`SESSION_REVOKED`）；
  4. 用户是否存在/启用（`USER_NOT_FOUND` / `USER_DISABLED`）；
  5. 用户当前版本号是否等于令牌 `ver`（`CREDENTIALS_CHANGED`）；
  6. 用户**当前角色**是否拥有所需权限（`ACCESS_DENIED`，HTTP 403）。

### 三类拒绝如何区分

| 场景 | HTTP | reason |
|---|---|---|
| 未认证（无令牌/坏令牌/过期/未知密钥/会话吊销） | 401 | 上述各具体原因 |
| 已认证但无权限 | **403** | `ACCESS_DENIED` |
| 身份或会话已吊销 | 401 | `SESSION_REVOKED`（或 `USER_DISABLED`） |
| 登录失败 | 401 | `LOGIN_FAILED` |

响应体形如：

```json
{"error":"Unauthorized","reason":"SESSION_REVOKED","detail":"session revoked: ...","credentialId":"at-xxxx"}
```

权限**始终按存储中的最新角色**判定，因此收回权限对仍在有效期内的令牌即时生效；
角色/密码变更还会抬高用户版本号，使旧令牌额外以 `CREDENTIALS_CHANGED` 失效。

## 3. 吊销与轮换语义

### 刷新令牌一次性轮换

- 一次刷新必然消费旧令牌并签发新令牌；旧令牌不能再成功使用。
- 刷新状态变更在**会话级锁**内原子完成（`InMemorySessionStore#mutateByRefreshHash`：
  先快照定位会话，再在锁内重读最新状态后判定）。

### 复用检测与令牌家族吊销

- 轮换宽限窗口过后再次提交已进入“已用链”的旧令牌 → 判定 `REFRESH_TOKEN_REUSE`，
  **整条会话链立即吊销**：该会话最新的刷新令牌、既有访问令牌全部失效
  （随后请求得到 `SESSION_REVOKED`）。
- 宽限窗口（默认 1 秒，`app.security.refresh-grace-millis`）用于把“同一瞬间的并发重复提交”
  与“事后重放攻击”区分开：

  | 情形 | 结论 | 是否吊销 |
  |---|---|---|
  | 与赢家并发提交同一令牌（窗口内） | `CONCURRENT_REFRESH_LOST` | 否 |
  | 窗口结束后再次提交旧令牌 | `REFRESH_TOKEN_REUSE` | 是，整条链 |
  | 提交从未见过的随机令牌 | `SESSION_NOT_FOUND` | 否 |

- 进程内“在途声明”注册表（`RefreshClaimRegistry`）保证同一哈希在任一时刻只有一个处理者，
  因此 20 个线程并发刷新同一令牌时**恰好 1 个成功、19 个失败，且不会出现两个都有效**。
  赢家签发的新令牌可继续正常使用；声明带 TTL，避免赢家异常退出后永久阻塞。

### 密钥切换

- HMAC 密钥由 `masterSecret + keyId` 经 SHA-256 派生（`DefaultKeyManager`），无需持久化密钥。
- `POST /api/admin/rotate-key` 生成新 `keyId` 并**立即丢弃旧密钥**：旧访问令牌无法验签，
  返回 `UNKNOWN_SIGNING_KEY`；之后登录/刷新签发的令牌使用新密钥。

### 密码轮换 / 角色变更 / 强制登出

| 操作 | 效果 |
|---|---|
| `POST /api/admin/change-password` | 更新密码哈希、抬高用户版本、吊销该用户全部会话；旧密码不可再登录 |
| `POST /api/admin/change-roles` | 更新角色并抬高版本；旧访问令牌 `CREDENTIALS_CHANGED` 失效，新登录反映新权限 |
| `POST /api/admin/force-logout` | 吊销该用户全部会话（会话内原子计数） |
| `POST /api/auth/logout` | 按刷新令牌哈希吊销对应会话 |

并发“登出 vs 刷新”交叉时，两者在同一会话锁上串行：
刷新赢家得到新链、登出赢家吊销会话；交叉后旧令牌绝不可能再产生第二个有效结果，
最终状态收敛为“已轮换一次”或“已吊销”（测试中以 10 轮交叉验证）。

## 4. 审计

所有登录、刷新（成功/各类拒绝）、登出、强制登出、密码/角色轮换、密钥轮换以及每次访问
判定都会写入内存审计流水（`InMemoryAuditService`），字段包括：

`sequence, timestamp, action, subject, credentialId, outcome, reason, detail`

- 被拒绝的访问与刷新都会给出明确 `reason` 与可读 `detail`；
- 日志中会打印凭证标识（`at-...` / `rt-...`），便于串联“哪张凭证因为什么被判定”。
- 通过 `GET /api/admin/audit`（需要 `ADMIN_AUDIT` 权限）查看。

## 5. 配置项（`src/main/resources/application.properties`）

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `server.port` | `8080` | 服务端口 |
| `app.security.access-token-ttl-seconds` | `300` | 访问令牌有效期 |
| `app.security.refresh-token-ttl-seconds` | `3600` | 刷新令牌有效期（随响应返回，本演示未强制过期） |
| `app.security.issuer` | `local-iac-service` | 发行方标识 |
| `app.security.master-secret` | 本地演示值 | 派生 HMAC 密钥的主秘密 |
| `app.security.initial-key-id` | `k1` | 初始签名密钥 id |
| `app.security.password-salt` | `local-static-salt` | 演示用密码哈希固定盐 |
| `app.security.refresh-grace-millis` | `1000` | 轮换后区分并发落败与重放攻击的宽限窗口 |

## 6. HTTP 接口

| 方法与路径 | 权限 | 说明 |
|---|---|---|
| `POST /api/auth/login` | 公开 | 登录，返回双令牌与凭证 id |
| `POST /api/auth/refresh` | 公开 | 一次性轮换；并发落败/复用/吊销原因可区分 |
| `POST /api/auth/logout` | 持有刷新令牌 | 吊销对应会话 |
| `GET  /api/docs` | `DOCS_READ` | 受保护读接口 |
| `GET  /api/docs/write-demo` | `DOCS_WRITE` | 受保护写接口 |
| `POST /api/admin/rotate-key` | `ADMIN_KEYS` | 切换签名密钥 |
| `POST /api/admin/force-logout` | `ADMIN_USERS` | 强制某用户全部会话登出 |
| `POST /api/admin/change-password` | `ADMIN_USERS` | 轮换密码并吊销会话 |
| `POST /api/admin/change-roles` | `ADMIN_USERS` | 变更角色、使旧令牌失效 |
| `GET  /api/admin/audit` | `ADMIN_AUDIT` | 查询审计流水 |

## 7. 测试

| 测试类 | 覆盖点 |
|---|---|
| `AuthorizationTest` | 未认证/登录失败/授权/越权 403/坏令牌，原因可区分 |
| `RefreshRotationTest` | 串行轮换、宽限后重放→复用吊销、链路全灭、未知令牌 |
| `ConcurrentRefreshTest` | 20 线程并发刷新同一令牌恰好 1 个成功、其余不吊销 |
| `RevocationAndRotationTest` | 角色/权限撤销即时生效、密钥轮换旧令牌失效、密码轮换、强制登出、10 轮登出×刷新交叉、审计可解释 |
| `ExpiredTokenTest` | 短 TTL 下 `EXPIRED_TOKEN` 与刷新续期 |

测试使用 `TestRestTemplate` 走完整 HTTP 链路，并在控制台打印凭证标识与判定依据，例如：

```
[CONCURRENT-REFRESH] threads=20 winners=1 losers=19
[CONCURRENT-REFRESH] LOSER reason=CONCURRENT_REFRESH_LOST count=19
[REUSE] replayed credential=rt-8db9c773b867 -> REFRESH_TOKEN_REUSE ... chain revoked
[KEY-ROTATE] old access token rejected ... reason=UNKNOWN_SIGNING_KEY
[ROLE-CHANGE] old access token rejected ... reason=CREDENTIALS_CHANGED
```

## 8. 代码结构

```
model/      枚举与记录：Permission/Role、DenyReason、AuthDecision、SessionInfo、AuditEvent...
token/      KeyManager（密钥派生/切换）、HmacTokenService（签发/验签/刷新令牌）
store/      内存用户/会话/审计存储（会话级原子变更）
auth/       PasswordHasher、AuthService（登录/刷新/登出/轮换）、
            AccessControlService（判定链）、RefreshClaimRegistry（并发声明+宽限）
web/        AuthorizationFilter（路径->权限、原因->HTTP 映射）、Controller、DTO
bootstrap/  DataSeeder（种子账号）
config/     SecurityProperties
```
