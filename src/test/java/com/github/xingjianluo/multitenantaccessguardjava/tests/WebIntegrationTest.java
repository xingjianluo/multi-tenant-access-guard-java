package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.multitenantaccessguardjava.lockout.SensitiveActionLockout;
import com.github.xingjianluo.multitenantaccessguardjava.ratelimit.RateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class WebIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(WebIntegrationTest.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private MockMvc mvc;

    @Autowired
    private RateLimiter rateLimiter;

    @Autowired
    private SensitiveActionLockout sensitiveLockout;

    /** 敏感锁定与登录锁定在单例 Bean 内累积，测试间复位，避免共享状态相互影响。 */
    @BeforeEach
    void resetGuardState() {
        rateLimiter.reset("login:dave");
        rateLimiter.reset("login:erin");
        rateLimiter.reset("sensitive:tenant-a:u-erin");
        sensitiveLockout.reset("sensitive:tenant-a:u-erin");
    }

    private String loginToken(String username, String password) throws Exception {
        MvcResult result = mvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        return MAPPER.readTree(result.getResponse().getContentAsString()).get("token").asText();
    }

    @Test
    void tokenEntryFullChain() throws Exception {
        String token = loginToken("alice", "alice-pw");
        mvc.perform(get("/api/resources/doc-1").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value("OK"));
    }

    @Test
    void sessionEntryGivesSameConclusion() throws Exception {
        MvcResult login = mvc.perform(post("/api/auth/session")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"alice-pw\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String sessionId = MAPPER.readTree(login.getResponse().getContentAsString())
                .get("sessionId").asText();
        String token = loginToken("alice", "alice-pw");

        MvcResult viaSession = mvc.perform(get("/api/resources/doc-1").header("X-Session-Id", sessionId))
                .andExpect(status().isOk()).andReturn();
        MvcResult viaToken = mvc.perform(get("/api/resources/doc-1").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andReturn();
        assertEquals(viaToken.getResponse().getContentAsString(),
                viaSession.getResponse().getContentAsString(), "两入口结论必须一致");
    }

    @Test
    void crossTenantDeniedWithDistinctReason() throws Exception {
        // 防探测：跨租户访问统一 404/RESOURCE_NOT_FOUND，与本租户不存在的资源不可区分
        String bobToken = loginToken("bob", "bob-pw");
        MvcResult result = mvc.perform(get("/api/resources/doc-1")
                        .header("Authorization", "Bearer " + bobToken))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.reason").value("RESOURCE_NOT_FOUND"))
                .andReturn();
        log.info("TEST-WEB subject=u-bob tenant=tenant-b resource=doc-1 action=READ response={}",
                result.getResponse().getContentAsString());
    }

    @Test
    void missingResourceDeniedWithDistinctReason() throws Exception {
        String token = loginToken("alice", "alice-pw");
        mvc.perform(get("/api/resources/doc-x").header("Authorization", "Bearer " + token))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.reason").value("RESOURCE_NOT_FOUND"));
    }

    @Test
    void tamperedTokenRejected() throws Exception {
        String token = loginToken("alice", "alice-pw");
        int dot = token.lastIndexOf('.');
        String body = token.substring(0, dot);
        char c = body.charAt(5);
        String tampered = body.substring(0, 5) + (c == 'A' ? 'B' : 'A') + body.substring(6)
                + token.substring(dot);
        mvc.perform(get("/api/resources/doc-1").header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("CREDENTIAL_TAMPERED"));
    }

    @Test
    void noCredentialIsUnauthenticated() throws Exception {
        mvc.perform(get("/api/resources/doc-1"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("UNAUTHENTICATED"));
    }

    @Test
    void loginFailuresTriggerLockout() throws Exception {
        for (int i = 0; i < 4; i++) {
            mvc.perform(post("/api/auth/token")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"username\":\"dave\",\"password\":\"wrong\"}"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.reason").value("UNAUTHENTICATED"));
        }
        // 第 5 次失败触发锁定
        mvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"dave\",\"password\":\"wrong\"}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.reason").value("LOCKED"));
        // 锁定期间即使口令正确也拒绝
        MvcResult result = mvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"dave\",\"password\":\"dave-pw\"}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.reason").value("LOCKED"))
                .andReturn();
        log.info("TEST-WEB subject=dave action=LOGIN response={}",
                result.getResponse().getContentAsString());
    }

    @Test
    void malformedTokenDoesNotLeakInternals() throws Exception {
        MvcResult result = mvc.perform(get("/api/resources/doc-1")
                        .header("Authorization", "Bearer not-a-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("CREDENTIAL_TAMPERED"))
                .andReturn();
        String body = result.getResponse().getContentAsString();
        assertFalse(body.contains("Exception"), "不得暴露内部异常");
        assertFalse(body.contains("stack"), "不得暴露堆栈");
    }

    /** 敏感操作连续失败到阈值进入 SENSITIVE_LOCKED，与 RATE_LIMITED/登录 LOCKED 不同。 */
    @Test
    void sensitiveFailuresTriggerDistinctLockout() throws Exception {
        String token = loginToken("erin", "erin-pw");
        // erin 是 VIEWER，对 doc-1 写操作连续被 INSUFFICIENT_ROLE 拒绝，计为敏感失败。
        // 默认阈值 3：前两次仍是 403/INSUFFICIENT_ROLE，第 3 次触发锁定返回 429/SENSITIVE_LOCKED。
        for (int i = 0; i < 2; i++) {
            mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                            .put("/api/resources/doc-1")
                            .header("Authorization", "Bearer " + token))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.reason").value("INSUFFICIENT_ROLE"));
        }
        MvcResult locked = mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .put("/api/resources/doc-1")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.reason").value("SENSITIVE_LOCKED"))
                .andReturn();
        // 锁定后继续请求：一律 SENSITIVE_LOCKED，不会因任何原因被放行
        MvcResult stillLocked = mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .put("/api/resources/doc-1")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.reason").value("SENSITIVE_LOCKED"))
                .andReturn();
        log.info("TEST-WEB business=sensitive-lock subject=u-erin third={} subsequent={} result=PASS",
                locked.getResponse().getContentAsString(), stillLocked.getResponse().getContentAsString());
    }

    /** 同名资源：两个租户各自访问自己的 shared-doc 均通过；跨租户探测返回 404。 */
    @Test
    void sameNamedResourceIsIsolatedPerTenant() throws Exception {
        String alice = loginToken("alice", "alice-pw");
        String bob = loginToken("bob", "bob-pw");
        mvc.perform(get("/api/resources/shared-doc").header("Authorization", "Bearer " + alice))
                .andExpect(status().isOk());
        mvc.perform(get("/api/resources/shared-doc").header("Authorization", "Bearer " + bob))
                .andExpect(status().isOk());
        // tenant-a 独占的 doc-1：bob 视角与“不存在”不可区分
        MvcResult probe = mvc.perform(get("/api/resources/doc-1").header("Authorization", "Bearer " + bob))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.reason").value("RESOURCE_NOT_FOUND"))
                .andReturn();
        log.info("TEST-WEB business=tenant-isolation subject=u-bob probe=doc-1 response={} result=PASS",
                probe.getResponse().getContentAsString());
    }

    /** access 凭据不能续期（403/NOT_REFRESHABLE）；refresh 凭据不能进业务入口（401/TYPE_MISMATCH）。 */
    @Test
    void refreshEndpointRejectsAccessCredential() throws Exception {
        String token = loginToken("alice", "alice-pw");
        MvcResult notRefreshable = mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + token + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("CREDENTIAL_NOT_REFRESHABLE"))
                .andReturn();
        log.info("TEST-WEB business=access-at-refresh response={} result=PASS",
                notRefreshable.getResponse().getContentAsString());

        // 取 refreshToken，用它访问业务入口应被拒为 CREDENTIAL_TYPE_MISMATCH
        String refreshToken = credentialFromLogin("alice", "alice-pw", "refreshToken");
        mvc.perform(get("/api/resources/doc-1").header("Authorization", "Bearer " + refreshToken))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("CREDENTIAL_TYPE_MISMATCH"));
    }

    /** 合法续期链路：refresh 轮换成功；旧 refresh 重放被拒。 */
    @Test
    void refreshRotationAndReplayFlow() throws Exception {
        String refreshToken = credentialFromLogin("alice", "alice-pw", "refreshToken");
        MvcResult renewed = mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + refreshToken + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andReturn();
        // 旧 refresh 重放
        MvcResult replay = mvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"token\":\"" + refreshToken + "\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("CREDENTIAL_REPLAYED"))
                .andReturn();
        log.info("TEST-WEB business=refresh-replay response={} result=PASS",
                replay.getResponse().getContentAsString());
        // 新 access 可正常访问
        String newAccess = MAPPER.readTree(renewed.getResponse().getContentAsString()).get("token").asText();
        mvc.perform(get("/api/resources/doc-1").header("Authorization", "Bearer " + newAccess))
                .andExpect(status().isOk());
    }

    private String credentialFromLogin(String username, String password, String field) throws Exception {
        MvcResult result = mvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode json = MAPPER.readTree(result.getResponse().getContentAsString());
        return json.get(field).asText();
    }
}
