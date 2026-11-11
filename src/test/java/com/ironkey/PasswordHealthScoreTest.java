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
 * Phase 5: Automated Test Suite for Transparent Vault Security Health Scoring.
 * Verifies that the scoring algorithm is deterministic, strictly bounded between 0 and 100,
 * accounts for empty vaults, explains point deductions transparently, and avoids double-counting.
 */
class PasswordHealthScoreTest {

    private InMemoryVaultEntryDAO mockVaultDAO;
    private SessionManager sessionManager;
    private VaultService vaultService;
    private SecurityAuditService auditService;

    private User testUser;
    private SecretKey vaultKey;

    @BeforeEach
    void setUp() {
        mockVaultDAO = new InMemoryVaultEntryDAO();
        sessionManager = SessionManager.getInstance();
        sessionManager.clearSession();

        vaultService = new VaultService(mockVaultDAO, sessionManager);
        auditService = new SecurityAuditService(vaultService, sessionManager);

        String validSalt = Base64.getEncoder().encodeToString(new byte[32]);
        testUser = new User("health_tester", "health@ironkey.io", "hash", validSalt, validSalt);
        testUser.setUserId(6001L);
        vaultKey = KeyDerivationService.deriveVaultKey("HealthMasterPass#2026!".toCharArray(), testUser.getKeyDerivationSalt());

        sessionManager.startSession(testUser, vaultKey);
    }

    @Test
    @DisplayName("1. Empty vault receives default 100 score with 'Empty Vault' status and no false deductions")
    void testEmptyVaultScoring() throws Exception {
        VaultAuditReport report = auditService.performAudit();

        assertEquals(100, report.getOverallScore(), "Empty vault should have baseline score of 100");
        assertEquals("Empty Vault", report.getScoreRating());
        assertEquals(0, report.getTotalScanned());
        assertTrue(report.getDeductionExplanations().isEmpty(), "Empty vault must have no point deductions");
        assertFalse(report.getRecommendations().isEmpty(), "Must provide guidance on adding first credentials");
    }

    @Test
    @DisplayName("2. Vault with strong, unique, and recent passwords achieves a perfect 100 score")
    void testPerfectVaultScoring() throws Exception {
        vaultService.addEntry("AWS Console", "https://aws.com", "u1", "K8#mX2$vL9*qP4!zR1", "Cloud", "");
        vaultService.addEntry("GitHub", "https://github.com", "u2", "T5@bW9^yH2&uM7*cE3", "Developer", "");
        vaultService.addEntry("ProtonMail", "https://proton.me", "u3", "F4$zQ8#jD1%tN6+sV9", "Personal", "");

        VaultAuditReport report = auditService.performAudit();

        assertEquals(100, report.getOverallScore(), "Perfect vault must achieve score of 100");
        assertEquals("Excellent", report.getScoreRating());
        assertEquals(3, report.getStrongCount());
        assertEquals(0, report.getWeakCount());
        assertEquals(0, report.getReusedAccountsCount());
        assertEquals(0, report.getOutdatedCount());
        assertTrue(report.getDeductionExplanations().isEmpty(), "No deductions for perfect vault");
    }

    @Test
    @DisplayName("3. Very weak passwords trigger significant deductions and critical recommendations")
    void testVeryWeakPasswordDeduction() throws Exception {
        vaultService.addEntry("Site 1", "https://s1.com", "u1", "123456", "Logins", "");
        vaultService.addEntry("Site 2", "https://s2.com", "u2", "password", "Logins", "");

        VaultAuditReport report = auditService.performAudit();

        assertTrue(report.getOverallScore() <= 60, "Very weak passwords must significantly lower score");
        assertEquals(2, report.getVeryWeakCount());
        assertTrue(report.getDeductionExplanations().stream().anyMatch(d -> d.contains("critically weak")),
                "Deduction explanation must mention critically weak passwords");
        assertTrue(report.hasCriticalIssues());
    }

    @Test
    @DisplayName("4. Reused passwords trigger dedicated deductions and credential stuffing warnings")
    void testReusedPasswordDeduction() throws Exception {
        String sharedSecret = "StrongLooking#Shared2026";
        vaultService.addEntry("Site 1", "https://s1.com", "u1", sharedSecret, "Logins", "");
        vaultService.addEntry("Site 2", "https://s2.com", "u2", sharedSecret, "Logins", "");
        vaultService.addEntry("Site 3", "https://s3.com", "u3", sharedSecret, "Logins", "");

        VaultAuditReport report = auditService.performAudit();

        assertTrue(report.getOverallScore() < 100, "Password reuse must trigger deductions");
        assertEquals(3, report.getReusedAccountsCount());
        assertTrue(report.getDeductionExplanations().stream().anyMatch(d -> d.contains("share identical passwords")),
                "Deduction explanation must mention shared passwords");
    }

    @Test
    @DisplayName("5. Outdated passwords trigger age deduction without false compromise claims")
    void testOutdatedPasswordDeduction() throws Exception {
        VaultEntry entry = vaultService.addEntry("Old Site", "https://old.com", "uOld", "SecureKey#Old2025!", "Logins", "");

        // Set creation/update timestamp to 250 days ago
        LocalDateTime past = LocalDateTime.now().minusDays(250);
        entry.setCreatedAt(past);
        entry.setUpdatedAt(past);
        mockVaultDAO.update(entry);

        VaultAuditReport report = auditService.performAudit();

        assertEquals(1, report.getOutdatedCount());
        assertTrue(report.getOverallScore() <= 85, "Outdated credentials must apply point deduction");
        assertTrue(report.getDeductionExplanations().stream().anyMatch(d -> d.contains("unchanged")),
                "Deduction explanation must cite unchanged duration");
    }

    @Test
    @DisplayName("6. Boundary enforcement: Extreme worst-case vault score stays within [0, 100]")
    void testScoreBoundaries() throws Exception {
        // Create 8 worst-case credentials: all "123456", all shared, all outdated
        LocalDateTime past = LocalDateTime.now().minusDays(300);
        for (int i = 0; i < 8; i++) {
            VaultEntry e = vaultService.addEntry("BadSite" + i, "https://bad.com", "user" + i, "123456", "Logins", "");
            e.setCreatedAt(past);
            e.setUpdatedAt(past);
            mockVaultDAO.update(e);
        }

        VaultAuditReport report = auditService.performAudit();

        assertTrue(report.getOverallScore() >= 0, "Score must never drop below 0");
        assertTrue(report.getOverallScore() <= 100, "Score must never exceed 100");
        assertEquals("Critical Risk", report.getScoreRating(), "Worst-case vault must be flagged as Critical Risk");
        assertTrue(report.hasCriticalIssues());
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
