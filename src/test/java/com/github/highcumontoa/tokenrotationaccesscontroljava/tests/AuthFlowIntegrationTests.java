package com.github.highcumontoa.tokenrotationaccesscontroljava.tests;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 身份与访问控制端到端测试（真实 HTTP + 本地内存存储）。
 * 覆盖：未认证 / 无权限 / 吊销三态区分、刷新令牌复用与并发刷新、
 * 权限撤销即时生效、密钥轮换后旧令牌失效。
 * 每个关键步骤都打印凭证标识与判定依据。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthFlowIntegrationTests {

    private static final Logger log = LoggerFactory.getLogger("TEST");

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> login(String username, String password) {
        ResponseEntity<Map> resp = rest.postForEntity(url("/api/auth/login"),
                Map.of("username", username, "password", password), Map.class);
        assertEquals(200, resp.getStatusCode().value(), "登录应成功");
        Map<String, Object> body = resp.getBody();
        log.info("[登录] user={} accessJti={} refreshJti={} sid={} fam={}",
                username, body.get("accessJti"), body.get("refreshJti"),
                body.get("sessionId"), body.get("familyId"));
        return body;
    }

    private HttpHeaders bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return headers;
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Map> get(String path, String token) {
        return rest.exchange(url(path), HttpMethod.GET,
                new HttpEntity<>(bearer(token)), Map.class);
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Map> post(String path, Object body, String token) {
        HttpHeaders headers = bearer(token);
        headers.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
        return rest.postForEntity(url(path), new HttpEntity<>(body, headers), Map.class);
    }

    private void assertReason(ResponseEntity<Map> resp, int status, String reason) {
        assertEquals(status, resp.getStatusCode().value(),
                "HTTP 状态应为 " + status + "，实际 body=" + resp.getBody());
        Object actual = resp.getBody().get("reason");
        assertEquals(reason, actual, "拒绝原因应可区分；body=" + resp.getBody());
        log.info("[拒绝断言] status={} reason={} message={} credentialId={}",
                status, actual, resp.getBody().get("message"),
                resp.getBody().get("credentialId"));
    }

    @Test
    void shouldDistinguishUnauthenticatedForbiddenAndRevoked() {
        // 1) 未认证：无 Authorization 头
        ResponseEntity<Map> noToken = get("/api/resources/articles", null);
        assertReason(noToken, 401, "missing_credential");

        // 2) 已认证但权限不足：bob(reader) 访问草稿（需 article:write）
        Map<String, Object> bob = login("bob", "bob123");
        String bobAccess = (String) bob.get("accessToken");

        ResponseEntity<Map> allowed = get("/api/resources/articles", bobAccess);
        assertEquals(200, allowed.getStatusCode().value(), "reader 应可读取文章");
        log.info("[放行] jti={} 判定=ALLOW permissions={}",
                allowed.getBody().get("jti"), allowed.getBody().get("effectivePermissions"));

        ResponseEntity<Map> forbidden = get("/api/resources/articles/draft", bobAccess);
        assertReason(forbidden, 403, "forbidden_permission");

        // 3) 无效凭证：篡改签名
        ResponseEntity<Map> invalid = get("/api/resources/articles", bobAccess + "x");
        assertReason(invalid, 401, "invalid_credential");

        // 4) 身份吊销：禁用用户后，旧访问令牌立刻得到 user_disabled
        Map<String, Object> admin = login("admin", "admin123");
        ResponseEntity<Map> disable = post("/api/admin/users/bob/enabled",
                Map.of("enabled", false), (String) admin.get("accessToken"));
        assertEquals(200, disable.getStatusCode().value());

        ResponseEntity<Map> disabled = get("/api/resources/articles", bobAccess);
        assertReason(disabled, 401, "user_disabled");

        // 恢复现场，避免污染其他测试
        post("/api/admin/users/bob/enabled", Map.of("enabled", true),
                (String) admin.get("accessToken"));
    }
    @Test
    void shouldRotateRefreshTokenOnceAndDetectReuse() {
        Map<String, Object> alice = login("alice", "alice123");
        String firstRefresh = (String) alice.get("refreshToken");
        String firstAccess = (String) alice.get("accessToken");

        // 第一次轮换：成功
        ResponseEntity<Map> rotated = post("/api/auth/refresh",
                Map.of("refreshToken", firstRefresh), null);
        assertEquals(200, rotated.getStatusCode().value(), "首次刷新应成功");
        String secondAccess = (String) rotated.getBody().get("accessToken");
        String secondRefresh = (String) rotated.getBody().get("refreshToken");
        log.info("[轮换成功] 旧refreshJti={} 新refreshJti={} 新sid={}",
                alice.get("refreshJti"), rotated.getBody().get("refreshJti"),
                rotated.getBody().get("sessionId"));

        // 轮换后：旧访问令牌立即失效（旧会话已 rotated）
        ResponseEntity<Map> staleAccess = get("/api/resources/profile", firstAccess);
        assertReason(staleAccess, 401, "session_revoked");

        // 旧刷新令牌再次使用 => 凭证复用，整条链路吊销
        ResponseEntity<Map> reuse = post("/api/auth/refresh",
                Map.of("refreshToken", firstRefresh), null);
        assertReason(reuse, 401, "refresh_reuse_detected");

        // 复用攻击发生后，连攻击者本不该拿到的“合法新令牌”也必须失效：
        // 第二次轮换产生的新令牌同样随链路吊销
        ResponseEntity<Map> afterReuse = get("/api/resources/profile", secondAccess);
        assertReason(afterReuse, 401, "session_revoked");

        // 用第二次轮换返回的新刷新令牌再刷新，也应因链路吊销被拒绝
        ResponseEntity<Map> refreshOnRevoked = post("/api/auth/refresh",
                Map.of("refreshToken", secondRefresh), null);
        assertReason(refreshOnRevoked, 401, "session_revoked");
    }

    @Test
    void concurrentRefreshOfSameTokenMustHaveSingleWinnerAndRevokeChain() throws Exception {
        Map<String, Object> bob = login("bob", "bob123");
        String refreshToken = (String) bob.get("refreshToken");

        int threads = 16;
        java.util.concurrent.CyclicBarrier barrier = new java.util.concurrent.CyclicBarrier(threads);
        java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(threads);
        java.util.Collection<ResponseEntity<Map>> results =
                java.util.Collections.synchronizedList(new java.util.ArrayList<>());

        List<Thread> workers = new java.util.ArrayList<>();
        for (int i = 0; i < threads; i++) {
            Thread t = new Thread(() -> {
                try {
                    barrier.await();
                    results.add(post("/api/auth/refresh",
                            Map.of("refreshToken", refreshToken), null));
                } catch (Exception ignored) {
                } finally {
                    done.countDown();
                }
            }, "refresh-racer-" + i);
            workers.add(t);
            t.start();
        }
        assertTrue(done.await(20, java.util.concurrent.TimeUnit.SECONDS), "并发刷新应在超时前结束");

        int success = 0;
        int reuseDenied = 0;
        String winnerAccess = null;
        String winnerRefresh = null;
        for (ResponseEntity<Map> r : results) {
            if (r.getStatusCode().is2xxSuccessful()) {
                success++;
                winnerAccess = (String) r.getBody().get("accessToken");
                winnerRefresh = (String) r.getBody().get("refreshToken");
            } else if ("refresh_reuse_detected".equals(r.getBody().get("reason"))) {
                reuseDenied++;
            }
        }
        log.info("[并发刷新] 线程数={} 成功数={} 复用拒绝数={}",
                threads, success, reuseDenied);
        assertEquals(1, success, "同一刷新令牌并发刷新只能有一个成功");
        assertEquals(threads - 1, reuseDenied, "其余请求必须被识别为凭证复用");
        assertNotNull(winnerAccess);

        // 复用检测触发后链路已被整体吊销：赢家的新令牌也不能继续访问 / 再刷新
        ResponseEntity<Map> winnerCall = get("/api/resources/profile", winnerAccess);
        assertReason(winnerCall, 401, "session_revoked");

        ResponseEntity<Map> winnerRefreshAgain = post("/api/auth/refresh",
                Map.of("refreshToken", winnerRefresh), null);
        assertReason(winnerRefreshAgain, 401, "session_revoked");
    }

    @Test
    void permissionRevocationShouldTakeEffectImmediatelyForOldToken() {
        Map<String, Object> bob = login("bob", "bob123");
        String access = (String) bob.get("accessToken");
        Map<String, Object> admin = login("admin", "admin123");
        String adminAccess = (String) admin.get("accessToken");

        // 撤销 reader 的 article:read：bob 的旧访问令牌无需重新签发，立刻 403
        ResponseEntity<Map> revoke = post("/api/admin/roles/reader/permissions",
                Map.of("permission", "article:read", "action", "remove"), adminAccess);
        assertEquals(200, revoke.getStatusCode().value());
        log.info("[权限撤销] reader/article:read 已移除，继续使用旧 jti 访问");

        ResponseEntity<Map> denied = get("/api/resources/articles", access);
        assertReason(denied, 403, "forbidden_permission");

        // 恢复权限后，同一张旧令牌立刻又可访问（证明判定实时读取角色状态）
        post("/api/admin/roles/reader/permissions",
                Map.of("permission", "article:read", "action", "add"), adminAccess);
        ResponseEntity<Map> allowedAgain = get("/api/resources/articles", access);
        assertEquals(200, allowedAgain.getStatusCode().value(),
                "权限恢复后旧令牌应立即恢复访问，body=" + allowedAgain.getBody());
        log.info("[权限恢复] 同一旧令牌 jti={} 恢复放行", allowedAgain.getBody().get("jti"));
    }

    @Test
    void keyRotationMustInvalidateOldTokensImmediately() {
        Map<String, Object> alice = login("alice", "alice123");
        String oldAccess = (String) alice.get("accessToken");
        String oldRefresh = (String) alice.get("refreshToken");
        Map<String, Object> admin = login("admin", "admin123");
        String adminAccess = (String) admin.get("accessToken");

        // 轮换前旧访问令牌可用
        ResponseEntity<Map> before = get("/api/resources/profile", oldAccess);
        assertEquals(200, before.getStatusCode().value());

        // 管理员切换签名密钥
        ResponseEntity<Map> rotated = post("/api/admin/keys/rotate", Map.of(), adminAccess);
        assertEquals(200, rotated.getStatusCode().value());
        log.info("[密钥轮换] newKid={}，旧访问令牌 jti={} 与旧刷新令牌应立即失效",
                rotated.getBody().get("newKid"), alice.get("accessJti"));

        ResponseEntity<Map> oldAccessAfter = get("/api/resources/profile", oldAccess);
        assertReason(oldAccessAfter, 401, "signing_key_retired");

        ResponseEntity<Map> oldRefreshAfter = post("/api/auth/refresh",
                Map.of("refreshToken", oldRefresh), null);
        assertReason(oldRefreshAfter, 401, "signing_key_retired");

        // 轮换后重新登录获得新 kid 令牌，一切正常
        Map<String, Object> alice2 = login("alice", "alice123");
        ResponseEntity<Map> newAccess = get("/api/resources/profile",
                (String) alice2.get("accessToken"));
        assertEquals(200, newAccess.getStatusCode().value());
        log.info("[新密钥登录] 新 jti={} 正常放行", alice2.get("accessJti"));
    }

    @Test
    void interleavedLogoutAndRefreshMustEndInConsistentRevokedState() throws Exception {
        Map<String, Object> carol = login("alice", "alice123");
        String initialRefresh = (String) carol.get("refreshToken");
        Map<String, Object> admin = login("admin", "admin123");
        String adminAccess = (String) admin.get("accessToken");

        int rounds = 30;
        java.util.concurrent.atomic.AtomicInteger refreshOk = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicInteger refreshDenied = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicReference<String> latestAccess =
                new java.util.concurrent.atomic.AtomicReference<>((String) carol.get("accessToken"));
        java.util.concurrent.atomic.AtomicReference<String> latestRefresh =
                new java.util.concurrent.atomic.AtomicReference<>(initialRefresh);

        java.util.Random rng = new java.util.Random(42);
        List<Thread> threads = new java.util.ArrayList<>();
        for (int i = 0; i < rounds; i++) {
            final int n = i;
            threads.add(new Thread(() -> {
                try {
                    if (n % 2 == 0) {
                        // 刷新方：取当前最新刷新令牌轮换
                        String token = latestRefresh.get();
                        ResponseEntity<Map> r = post("/api/auth/refresh",
                                Map.of("refreshToken", token), null);
                        if (r.getStatusCode().is2xxSuccessful()) {
                            refreshOk.incrementAndGet();
                            latestAccess.set((String) r.getBody().get("accessToken"));
                            latestRefresh.set((String) r.getBody().get("refreshToken"));
                        } else {
                            refreshDenied.incrementAndGet();
                        }
                    } else {
                        // 登出方：用初始刷新令牌登出（链路级吊销，覆盖全部后裔）
                        post("/api/auth/logout",
                                Map.of("refreshToken", initialRefresh), null);
                    }
                    Thread.sleep(rng.nextInt(5));
                } catch (Exception ignored) {
                }
            }, "logout-refresh-" + n));
        }
        java.util.Collections.shuffle(threads, rng);
        for (Thread t : threads) {
            t.start();
        }
        for (Thread t : threads) {
            t.join(10000);
        }
        log.info("[登出/刷新交叉] 刷新成功={} 刷新被拒={}", refreshOk.get(), refreshDenied.get());

        // 最终一致性：登出至少执行过一次，链路必然已吊销；
        // 最新访问令牌无论来自哪一次刷新，都不得再访问；最新刷新令牌也不得再轮换
        ResponseEntity<Map> finalAccess = get("/api/resources/profile", latestAccess.get());
        assertReason(finalAccess, 401, "session_revoked");

        ResponseEntity<Map> finalRefresh = post("/api/auth/refresh",
                Map.of("refreshToken", latestRefresh.get()), null);
        Object reason = finalRefresh.getBody().get("reason");
        assertTrue("session_revoked".equals(reason) || "refresh_reuse_detected".equals(reason),
                "最终刷新必须被明确拒绝，实际=" + reason);

        // 管理员视角强制登出用户后，该用户所有会话吊销，重新登录获得全新链路
        ResponseEntity<Map> adminLogout = post("/api/admin/users/alice/logout",
                Map.of(), adminAccess);
        assertEquals(200, adminLogout.getStatusCode().value());
        log.info("[管理员强制登出] 吊销会话数={}", adminLogout.getBody().get("revokedSessions"));
    }

}
