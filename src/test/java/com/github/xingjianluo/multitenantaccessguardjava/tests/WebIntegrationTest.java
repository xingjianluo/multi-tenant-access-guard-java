package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
        String bobToken = loginToken("bob", "bob-pw");
        MvcResult result = mvc.perform(get("/api/resources/doc-1")
                        .header("Authorization", "Bearer " + bobToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("CROSS_TENANT"))
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
}
