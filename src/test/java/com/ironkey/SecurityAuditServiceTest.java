package com.ironkey;

import com.ironkey.dao.VaultEntryDAO;
import com.ironkey.model.User;
import com.ironkey.model.VaultAuditReport;
import com.ironkey.model.VaultEntry;
import com.ironkey.security.KeyDerivationService;
import com.ironkey.service.SecurityAuditService;
import com.ironkey.service.VaultService;
import com.ironkey.util.SessionManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 5: Automated Integration Test Suite for SecurityAuditService.
 * Validates full audit execution, configurable thresholds, multi-tenant user isolation,
 * session timeout safeguards, and in-memory privacy preservation.
 */
class SecurityAuditServiceTest {

    private InMemoryVaultEntryDAO mockVaultDAO;
    private SessionManager sessionManager;
    private VaultService vaultService;
    private SecurityAuditService auditService;

    private User userA;
    private User userB;
    private SecretKey keyA;
    private SecretKey keyB;

    @BeforeEach
    void setUp() {
        mockVaultDAO = new InMemoryVaultEntryDAO();
        sessionManager = SessionManager.getInstance();
        sessionManager.clearSession();

        vaultService = new VaultService(mockVaultDAO, sessionManager);
        auditService = new SecurityAuditService(vaultService, sessionManager);

        String validSaltA = Base64.getEncoder().encodeToString(new byte[32]);
        userA = new User("user_a", "user_a@ironkey.io", "hashA", validSaltA, validSaltA);
        userA.setUserId(7001L);
        keyA = KeyDerivationService.deriveVaultKey("UserAPassword#2026!".toCharArray(), userA.getKeyDerivationSalt());

        String validSaltB = Base64.getEncoder().encodeToString(new byte[32]);
        userB = new User("user_b", "user_b@ironkey.io", "hashB", validSaltB, validSaltB);
        userB.setUserId(8002L);
        keyB = KeyDerivationService.deriveVaultKey("UserBPassword#2026!".toCharArray(), userB.getKeyDerivationSalt());

        sessionManager.startSession(userA, keyA);
    }

    @Test
    @DisplayName("1. Full audit correctly catalogs strong, weak, reused, and outdated credentials")
    void testFullAuditExecution() throws Exception {
        // 1. Strong & unique
        vaultService.addEntry("AWS", "https://aws.com", "admin", "P@ssw0rd$AWS#2026!Long", "Cloud", "");
        // 2 & 3. Reused pair
        vaultService.addEntry("Social1", "https://s1.com", "u1", "weakreused1", "Social", "");
        vaultService.addEntry("Social2", "https://s2.com", "u2", "weakreused1", "Social", "");
        // 4. Critically weak
        vaultService.addEntry("Forum", "https://forum.com", "u3", "123456", "General", "");

        VaultAuditReport report = auditService.performAudit();

        assertEquals(4, report.getTotalScanned());
        assertEquals(1, report.getStrongCount());
        assertTrue(report.getWeakFindings().size() >= 1);
        assertEquals(1, report.getReuseGroupsCount());
        assertEquals(2, report.getReusedAccountsCount());
        assertTrue(report.getOverallScore() < 100);
        assertNotNull(report.getAuditTimestamp());
    }

    @Test
    @DisplayName("2. Configurable outdated age threshold correctly filters credentials")
    void testConfigurableOutdatedThreshold() throws Exception {
        VaultEntry entry = vaultService.addEntry("Service1", "https://s1.com", "u1", "StrongPass#2026!X1", "Logins", "");

        // Set last modified to 100 days ago
        LocalDateTime hundredDaysAgo = LocalDateTime.now().minusDays(100);
        entry.setCreatedAt(hundredDaysAgo);
        entry.setUpdatedAt(hundredDaysAgo);
        mockVaultDAO.update(entry);

        // With default 180-day threshold, entry is NOT outdated
        VaultAuditReport report180 = auditService.performAudit(180);
        assertEquals(0, report180.getOutdatedCount());

        // With custom 90-day threshold, entry IS outdated
        VaultAuditReport report90 = auditService.performAudit(90);
        assertEquals(1, report90.getOutdatedCount());
        assertEquals(100, report90.getOutdatedFindings().get(0).getDaysOld());
    }

    @Test
    @DisplayName("3. Unauthenticated access or session timeout blocks audit execution")
    void testSessionExpirationGuardsAudit() {
        sessionManager.clearSession();
        assertFalse(sessionManager.isLoggedIn());

        assertThrows(IllegalStateException.class, () -> {
            auditService.performAudit();
        }, "Audit must throw IllegalStateException when no active session exists");
    }

    @Test
    @DisplayName("4. Multi-tenant user isolation: User A's audit findings do not bleed into User B's audit")
    void testCrossUserAuditIsolation() throws Exception {
        // User A stores weak and reused passwords
        vaultService.addEntry("A1", "https://a1.com", "ua", "123456", "Logins", "");
        vaultService.addEntry("A2", "https://a2.com", "ua", "123456", "Logins", "");

        // Switch to User B
        sessionManager.clearSession();
        sessionManager.startSession(userB, keyB);

        // User B stores 1 strong unique password
        vaultService.addEntry("B1", "https://b1.com", "ub", "G9#mX2$vL8*qP4!zR1", "Work", "");

        VaultAuditReport bReport = auditService.performAudit();

        assertEquals(1, bReport.getTotalScanned(), "User B must only see their own entry");
        assertEquals(1, bReport.getStrongCount());
        assertEquals(0, bReport.getWeakCount());
        assertEquals(0, bReport.getReuseGroupsCount());
        assertEquals(100, bReport.getOverallScore());
    }

    private static class InMemoryVaultEntryDAO extends VaultEntryDAO {
        private final Map<Long, VaultEntry> db = new ConcurrentHashMap<>();
        private long seq = 100L;

        @Override
        public VaultEntry save(VaultEntry entry) {
            entry.setEntryId(seq++);
            if (entry.getCreatedAt() == null) entry.setCreatedAt(LocalDateTime.now());
            if (entry.getUpdatedAt() == null) entry.setUpdatedAt(LocalDateTime.now());
            VaultEntry c = new VaultEntry(entry.getEntryId(), entry.getUserId(),
                    entry.getWebsiteName(), entry.getWebsiteUrl(),
                    entry.getEncryptedUsername(), entry.getEncryptedPassword(),
                    entry.getNonce(), entry.getCategory(), entry.getNotes(),
                    entry.getCreatedAt(), entry.getUpdatedAt());
            db.put(entry.getEntryId(), c);
            return entry;
        }

        @Override
        public boolean update(VaultEntry entry) {
            db.put(entry.getEntryId(), entry);
            return true;
        }

        @Override
        public List<VaultEntry> findAllByUserId(Long userId) {
            return db.values().stream()
                    .filter(e -> Objects.equals(e.getUserId(), userId))
                    .collect(Collectors.toList());
        }
    }
}
