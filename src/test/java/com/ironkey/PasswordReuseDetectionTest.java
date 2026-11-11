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
 * Phase 5: Automated Test Suite for Vault-Wide Password Reuse Detection.
 * Verifies that identical credentials across multiple accounts are accurately detected,
 * grouped, counted, and analyzed strictly in-memory without persistent plaintext storage.
 */
class PasswordReuseDetectionTest {

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
        testUser = new User("auditor", "auditor@ironkey.io", "hash", validSalt, validSalt);
        testUser.setUserId(5001L);
        vaultKey = KeyDerivationService.deriveVaultKey("AuditorMasterKey#2026!".toCharArray(), testUser.getKeyDerivationSalt());

        sessionManager.startSession(testUser, vaultKey);
    }

    @Test
    @DisplayName("1. No duplicate groups detected when all credentials have distinct passwords")
    void testNoReuseInDistinctPasswords() throws Exception {
        vaultService.addEntry("GitHub", "https://github.com", "dev1", "UniquePass#Alpha1", "Logins", "");
        vaultService.addEntry("AWS Console", "https://aws.amazon.com", "dev2", "UniquePass#Beta2", "Cloud", "");
        vaultService.addEntry("ProtonMail", "https://proton.me", "dev3", "UniquePass#Gamma3", "Personal", "");

        VaultAuditReport report = auditService.performAudit();

        assertEquals(3, report.getTotalScanned());
        assertEquals(0, report.getReuseGroupsCount(), "Must have 0 reuse groups for unique passwords");
        assertEquals(0, report.getReusedAccountsCount(), "Must have 0 reused accounts");
        assertTrue(report.getReuseGroups().isEmpty());
    }

    @Test
    @DisplayName("2. Single reuse group identified when multiple accounts share an identical password")
    void testSingleReuseGroupDetected() throws Exception {
        String sharedPass = "CommonSharedSecret#2026";

        vaultService.addEntry("Google", "https://google.com", "user@gmail.com", sharedPass, "Logins", "");
        vaultService.addEntry("Netflix", "https://netflix.com", "user@gmail.com", sharedPass, "Entertainment", "");
        vaultService.addEntry("Spotify", "https://spotify.com", "user@gmail.com", sharedPass, "Entertainment", "");
        vaultService.addEntry("Bank of America", "https://bankofamerica.com", "user_bank", "UniqueBankKey#99!", "Financial", "");

        VaultAuditReport report = auditService.performAudit();

        assertEquals(4, report.getTotalScanned());
        assertEquals(1, report.getReuseGroupsCount(), "Must identify exactly 1 reuse group");
        assertEquals(3, report.getReusedAccountsCount(), "Must identify 3 affected accounts in the reuse group");

        VaultAuditReport.ReusedPasswordGroup group = report.getReuseGroups().get(0);
        assertEquals(3, group.getCount());
        assertEquals(3, group.getAffectedEntries().size());

        Set<String> affectedSites = group.getAffectedEntries().stream()
                .map(VaultEntry::getWebsiteName)
                .collect(Collectors.toSet());

        assertTrue(affectedSites.contains("Google"));
        assertTrue(affectedSites.contains("Netflix"));
        assertTrue(affectedSites.contains("Spotify"));
        assertFalse(affectedSites.contains("Bank of America"));
    }

    @Test
    @DisplayName("3. Multiple independent reuse groups are correctly isolated and counted")
    void testMultipleReuseGroupsDetected() throws Exception {
        String passGroupA = "GroupAPassword#1";
        String passGroupB = "GroupBPassword#2";

        // Group A: 2 accounts
        vaultService.addEntry("Site A1", "https://a1.com", "userA", passGroupA, "Logins", "");
        vaultService.addEntry("Site A2", "https://a2.com", "userA", passGroupA, "Logins", "");

        // Group B: 3 accounts
        vaultService.addEntry("Site B1", "https://b1.com", "userB", passGroupB, "Social", "");
        vaultService.addEntry("Site B2", "https://b2.com", "userB", passGroupB, "Social", "");
        vaultService.addEntry("Site B3", "https://b3.com", "userB", passGroupB, "Social", "");

        // Unique: 1 account
        vaultService.addEntry("Unique Site", "https://u.com", "userU", "UniquePassword#999", "Work", "");

        VaultAuditReport report = auditService.performAudit();

        assertEquals(6, report.getTotalScanned());
        assertEquals(2, report.getReuseGroupsCount(), "Must identify 2 distinct reuse groups");
        assertEquals(5, report.getReusedAccountsCount(), "Must identify 5 total accounts sharing passwords");
    }

    @Test
    @DisplayName("4. Case sensitivity: Different letter case is treated as distinct passwords")
    void testCaseSensitivityInReuseDetection() throws Exception {
        vaultService.addEntry("Service Upper", "https://s1.com", "user1", "SecretPass123", "Logins", "");
        vaultService.addEntry("Service Lower", "https://s2.com", "user2", "secretpass123", "Logins", "");

        VaultAuditReport report = auditService.performAudit();

        assertEquals(2, report.getTotalScanned());
        assertEquals(0, report.getReuseGroupsCount(), "Case-different passwords must not be considered duplicates");
    }

    @Test
    @DisplayName("5. Zero-knowledge privacy: Report models do not store plaintext passwords")
    void testNoPlaintextStoredInReport() throws Exception {
        String secret = "SensitivePlaintext123!";
        vaultService.addEntry("TestSite1", "https://s1.com", "u1", secret, "Logins", "");
        vaultService.addEntry("TestSite2", "https://s2.com", "u2", secret, "Logins", "");

        VaultAuditReport report = auditService.performAudit();

        for (VaultAuditReport.ReusedPasswordGroup g : report.getReuseGroups()) {
            for (VaultEntry e : g.getAffectedEntries()) {
                assertNotEquals(secret, e.getEncryptedPassword(), "VaultEntry must never contain plaintext password");
            }
        }
    }

    private static class InMemoryVaultEntryDAO extends VaultEntryDAO {
        private final Map<Long, VaultEntry> db = new ConcurrentHashMap<>();
        private long seq = 100L;

        @Override
        public VaultEntry save(VaultEntry entry) {
            entry.setEntryId(seq++);
            entry.setCreatedAt(LocalDateTime.now());
            entry.setUpdatedAt(LocalDateTime.now());
            VaultEntry c = new VaultEntry(entry.getEntryId(), entry.getUserId(),
                    entry.getWebsiteName(), entry.getWebsiteUrl(),
                    entry.getEncryptedUsername(), entry.getEncryptedPassword(),
                    entry.getNonce(), entry.getCategory(), entry.getNotes(),
                    entry.getCreatedAt(), entry.getUpdatedAt());
            db.put(entry.getEntryId(), c);
            return entry;
        }

        @Override
        public List<VaultEntry> findAllByUserId(Long userId) {
            return db.values().stream()
                    .filter(e -> Objects.equals(e.getUserId(), userId))
                    .collect(Collectors.toList());
        }

        @Override
        public boolean delete(Long entryId, Long userId) {
            return db.remove(entryId) != null;
        }
    }
}
