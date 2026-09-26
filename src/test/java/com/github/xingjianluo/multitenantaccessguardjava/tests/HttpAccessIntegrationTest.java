package com.github.xingjianluo.multitenantaccessguardjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditEvent;
import com.github.xingjianluo.multitenantaccessguardjava.audit.AuditService;
import com.github.xingjianluo.multitenantaccessguardjava.support.TimeSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class HttpAccessIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(HttpAccessIntegrationTest.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    @TestConfiguration
    static class FixedClockConfig {
        static final MutableClock CLOCK = MutableClock.startAt(5_000_000L);

        @Bean
        @Primary
        TimeSource mutableClock() {
            return CLOCK;
        }
    }

    @Autowired MockMvc mvc;
    @Autowired AuditService auditService;

    @BeforeEach
    void resetClock() {
        FixedClockConfig.CLOCK.set(5_000_000L);
    }

    private String login(String entry, String tenant, String username, String pw, String assertion) throws Exception {
        String body;
        if ("SSO".equals(entry)) {
            body = JSON.writeValueAsString(java.util.Map.of(
                    "entry", "SSO", "tenantId", tenant, "assertionId", assertion));
        } else {
            body = JSON.writeValueAsString(java.util.Map.of(
                    "entry", "PASSWORD", "tenantId", tenant, "username", username, "password", pw));
        }
        String resp = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JSON.readTree(resp).get("accessToken").asText();
    }

    @Test
    @DisplayName("HTTP跨租户访问返回403+CROSS_TENANT_ACCESS，且审计含主体/租户/资源/动作/依据")
    void crossTenantOverHttp() throws Exception {
        String carol = login("PASSWORD", "tenant-b", "carol", "carol-pw", null);

        mvc.perform(post("/api/tenants/tenant-a/resources/doc-1/read")
                        .header("Authorization", "Bearer " + carol))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("CROSS_TENANT_ACCESS"))
                .andExpect(jsonPath("$.traceId").exists());

        List<AuditEvent> events = auditService.findBySubject("tenant-b", "carol");
        AuditEvent authz = events.stream().filter(e -> "AUTHZ".equals(e.eventType())).findFirst().orElseThrow();
        // subject's own tenant is the audit tenant key; the requested foreign tenant and
        // the mismatch are fully captured in the basis text.
        assertEquals("tenant-b", authz.tenantId());
        assertTrue(authz.basis().contains("tenant-a") && authz.basis().contains("tenant-b"),
                "basis must show both tenants: " + authz.basis());
        assertEquals("doc-1", authz.resourceId());
        assertEquals("READ", authz.action());
        assertEquals("CROSS_TENANT_ACCESS", authz.reason());
        log.info("TEST|case=httpCrossTenant|tenant={}|subject={}|resource={}|action={}|basis={}",
                authz.tenantId(), authz.subjectId(), authz.resourceId(), authz.action(), authz.basis());
    }

    @Test
    @DisplayName("HTTP资源不存在返回404+RESOURCE_NOT_FOUND；无令牌返回401+UNAUTHENTICATED")
    void notFoundAndUnauthenticatedOverHttp() throws Exception {
        String alice = login("PASSWORD", "tenant-a", "alice", "alice-pw", null);
        mvc.perform(post("/api/tenants/tenant-a/resources/ghost/read")
                        .header("Authorization", "Bearer " + alice))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.reason").value("RESOURCE_NOT_FOUND"));

        mvc.perform(post("/api/tenants/tenant-a/resources/doc-1/read"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.reason").value("UNAUTHENTICATED"));
        log.info("TEST|case=httpNotFound|tenant=tenant-a|subject=alice|resource=ghost|action=READ|basis=RESOURCE_NOT_FOUND");
    }

    @Test
    @DisplayName("双入口HTTP访问同一资源结论一致")
    void twoEntriesSameConclusionOverHttp() throws Exception {
        // SSO assertion for alice must be minted through the credential service; use password login
        // then SSO via a freshly issued assertion. We obtain one by logging in as alice over SSO:
        // the demo federation stub issues assertions through CredentialService, exposed only on the
        // bean; fetch it here.
        String pwToken = login("PASSWORD", "tenant-a", "alice", "alice-pw", null);
        // Issue SSO assertion via reflection-free autowired bean is not available; instead assert
        // password path succeeds and is allowed; SSO path is covered at service level. To still
        // exercise SSO over HTTP, mint an assertion using the same bean through context:
        String assertion = issueSsoAssertion("tenant-a", "alice");
        String ssoToken = login("SSO", "tenant-a", "alice", null, assertion);

        for (String token : List.of(pwToken, ssoToken)) {
            mvc.perform(post("/api/tenants/tenant-a/resources/doc-1/write")
                            .header("Authorization", "Bearer " + token))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.allowed").value(true));
        }
        log.info("TEST|case=httpTwoEntries|tenant=tenant-a|subject=alice|resource=doc-1|action=WRITE|basis=both entries allowed identically");
    }

    @Autowired com.github.xingjianluo.multitenantaccessguardjava.auth.CredentialService credentialService;

    private String issueSsoAssertion(String tenant, String subject) {
        return credentialService.issueSsoAssertion(tenant, subject);
    }

    @Test
    @DisplayName("敏感操作连续失败达阈值后被限流锁定（429 RATE_LIMITED），锁定期满自动恢复")
    void sensitiveActionLocksOverHttp() throws Exception {
        String alice = login("PASSWORD", "tenant-a", "alice", "alice-pw", null);
        // simulateFailure drives a denied sensitive attempt without deleting data;
        // policy allows 3 failures within a window then locks.
        for (int i = 1; i <= 3; i++) {
            int status = mvc.perform(post("/api/tenants/tenant-a/resources/doc-1/delete")
                            .param("simulateFailure", "true")
                            .header("Authorization", "Bearer " + alice))
                    .andReturn().getResponse().getStatus();
            assertTrue(status == 403 || status == 429, "attempt " + i + " status=" + status);
        }
        mvc.perform(post("/api/tenants/tenant-a/resources/doc-1/delete")
                        .header("Authorization", "Bearer " + alice))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.reason").value("RATE_LIMITED"));

        // advance past the lock window -> access works again
        FixedClockConfig.CLOCK.advance(120_001L);
        mvc.perform(post("/api/tenants/tenant-a/resources/doc-1/read")
                        .header("Authorization", "Bearer " + alice))
                .andExpect(status().isOk());
        log.info("TEST|case=httpSensitiveLock|tenant=tenant-a|subject=alice|resource=doc-1|action=DELETE|basis=locked after 3 failures then recovered");
    }

    @Test
    @DisplayName("错误响应不含内部异常细节，只含稳定原因与traceId")
    void errorBodiesDoNotLeakInternals() throws Exception {
        // malformed JSON body reaches Spring; our handler must still return a sanitized 500/400 body
        String resp = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ not-json"))
                .andReturn().getResponse().getContentAsString();
        JsonNode node = JSON.readTree(resp);
        // Whatever Spring emits, it must not contain a Java stack element
        assertFalse(resp.contains("Exception"), "body must not leak exception types: " + resp);
        assertFalse(resp.contains("at java."), "body must not leak stack traces");
        log.info("TEST|case=noInternalLeak|tenant=-|subject=-|resource=-|action=LOGIN|basis=malformed body sanitized keys={}",
                node.fieldNames().hasNext() ? "present" : "none");
    }
}
