package com.ironkey;

import com.ironkey.dao.CategoryDAO;
import com.ironkey.dao.SecurityLogDAO;
import com.ironkey.dao.UserDAO;
import com.ironkey.dao.VaultEntryDAO;
import com.ironkey.model.Category;
import com.ironkey.model.SecurityLog;
import com.ironkey.model.User;
import com.ironkey.model.VaultAuditReport;
import com.ironkey.model.VaultEntry;
import com.ironkey.security.EncryptionManager;
import com.ironkey.security.KeyDerivationService;
import com.ironkey.security.PasswordGenerator;
import com.ironkey.security.PasswordHasher;
import com.ironkey.service.AuthenticationService;
import com.ironkey.service.SecurityAuditService;
import com.ironkey.service.VaultService;
import com.ironkey.util.SessionManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 6: Complete End-to-End Vault Workflow Test Suite.
 * Validates the full 15-step production lifecycle:
 * 1. Launch IRONKEY
 * 2. Register new account
 * 3. Log in with master password
 * 4. Open personal vault
 * 5. Add multiple credentials
 * 6. Reveal and hide passwords
 * 7. Edit an existing credential
 * 8. Delete a credential
 * 9. Search and filter vault
 * 10. Generate replacement password
 * 11. Run security audit
 * 12. Lock vault
 * 13. Log back in
 * 14. Verify remaining credentials decrypt correctly
 * 15. Verify multi-tenant isolation (User B cannot access User A's credentials)
 */
class EndToEndVaultWorkflowTest {

    private InMemoryUserDAO userDAO;
    private InMemoryVaultEntryDAO vaultEntryDAO;
    private InMemorySecurityLogDAO securityLogDAO;
    private InMemoryCategoryDAO categoryDAO;
    private SessionManager sessionManager;
    private AuthenticationService authService;
    private VaultService vaultService;
    private SecurityAuditService auditService;

    @BeforeEach
    void setUp() {
        userDAO = new InMemoryUserDAO();
        vaultEntryDAO = new InMemoryVaultEntryDAO();
        securityLogDAO = new InMemorySecurityLogDAO();
        categoryDAO = new InMemoryCategoryDAO();

        sessionManager = SessionManager.getInstance();
        sessionManager.clearSession();

        authService = new AuthenticationService(userDAO, securityLogDAO, categoryDAO, sessionManager);
        vaultService = new VaultService(vaultEntryDAO, securityLogDAO, sessionManager);
        auditService = new SecurityAuditService(vaultService, sessionManager);
    }

    @Test
    @DisplayName("Complete 15-Step End-to-End User Journey & Security Verification")
    void testComplete15StepWorkflow() throws Exception {
        // -------------------------------------------------------------
        // Step 1: Launch IRONKEY
        // -------------------------------------------------------------
        assertDoesNotThrow(() -> Main.main(new String[0]), "Main application bootstrap must execute cleanly");

        // -------------------------------------------------------------
        // Step 2: Register a new account (Alice)
        // -------------------------------------------------------------
        char[] masterPassAlice = "AliceMasterPass#2026!".toCharArray();
        User alice = authService.register("alice_lead", "alice@ironkey.io", masterPassAlice, masterPassAlice);

        assertNotNull(alice.getUserId(), "User ID must be assigned upon registration");
        assertEquals("alice_lead", alice.getUsername());
        assertEquals("alice@ironkey.io", alice.getEmail());
        assertNotNull(alice.getMasterPasswordHash(), "Password hash must be populated");
        assertNotNull(alice.getMasterPasswordSalt(), "Auth salt must be generated");
        assertNotNull(alice.getKeyDerivationSalt(), "Key derivation salt must be generated");
        assertNotEquals(new String(masterPassAlice), alice.getMasterPasswordHash(), "Plaintext master password must never be stored");

        // -------------------------------------------------------------
        // Step 3: Log in with the master password
        // -------------------------------------------------------------
        User loggedInAlice = authService.login("alice@ironkey.io", masterPassAlice);
        assertNotNull(loggedInAlice);
        assertTrue(sessionManager.isLoggedIn(), "Session must be active after login");
        assertEquals(alice.getUserId(), sessionManager.getUserId());
        assertNotNull(sessionManager.getVaultKey(), "Derived vault encryption key must exist in memory");
        assertEquals(32, sessionManager.getVaultKey().getEncoded().length, "Vault key must be 256 bits (32 bytes)");

        // -------------------------------------------------------------
        // Step 4: Open personal vault
        // -------------------------------------------------------------
        List<VaultEntry> initialEntries = vaultService.getEntriesForCurrentUser();
        assertTrue(initialEntries.isEmpty(), "Brand new vault must be empty");

        // -------------------------------------------------------------
        // Step 5: Add multiple credentials
        // -------------------------------------------------------------
        VaultEntry ghEntry = vaultService.addEntry(
                "GitHub", "https://github.com/login",
                "alice_gh", "GhP@ssw0rd#2026!",
                "Developer", "Personal developer tokens"
        );
        VaultEntry awsEntry = vaultService.addEntry(
                "AWS Console", "https://console.aws.amazon.com",
                "admin_aws", "TempAwsPass#123",
                "Cloud", "Root cloud account"
        );
        VaultEntry protonEntry = vaultService.addEntry(
                "ProtonMail", "https://mail.proton.me",
                "alice_sec", "TempAwsPass#123", // Intentionally shared to test reuse detection
                "Personal", "Recovery email"
        );

        assertNotNull(ghEntry.getEntryId());
        assertNotNull(awsEntry.getEntryId());
        assertNotNull(protonEntry.getEntryId());

        // Verify independent nonces (ciphertexts differ even for identical password)
        assertNotEquals(awsEntry.getEncryptedPassword(), protonEntry.getEncryptedPassword(),
                "Independent nonces must ensure identical passwords produce distinct ciphertexts");

        List<VaultEntry> entriesAfterAdd = vaultService.getEntriesForCurrentUser();
        assertEquals(3, entriesAfterAdd.size(), "Vault must hold 3 credentials");

        // -------------------------------------------------------------
        // Step 6: Reveal and hide passwords (on-demand decryption)
        // -------------------------------------------------------------
        VaultService.DecryptedCredential decGh = vaultService.decryptEntry(ghEntry);
        assertEquals("alice_gh", decGh.getUsername());
        assertEquals("GhP@ssw0rd#2026!", decGh.getPassword());
        assertEquals("Personal developer tokens", decGh.getNotes());

        // Verify VaultEntry model itself never holds plaintext
        assertNotEquals("GhP@ssw0rd#2026!", ghEntry.getEncryptedPassword());
        assertNotEquals("alice_gh", ghEntry.getEncryptedUsername());

        // -------------------------------------------------------------
        // Step 7: Edit an existing credential
        // -------------------------------------------------------------
        String oldGhCiphertext = ghEntry.getEncryptedPassword();
        boolean updated = vaultService.updateEntry(
                ghEntry.getEntryId(),
                "GitHub Enterprise",
                "https://github.com/enterprise",
                "alice_lead_eng",
                "Kx9#vP2$mQ8@wL5!zR4",
                "Work",
                "Updated 2FA seed note"
        );
        assertTrue(updated, "Update must succeed for entry owner");

        VaultEntry updatedGh = vaultEntryDAO.findById(ghEntry.getEntryId(), alice.getUserId()).orElseThrow();
        assertEquals("GitHub Enterprise", updatedGh.getWebsiteName());
        assertNotEquals(oldGhCiphertext, updatedGh.getEncryptedPassword(), "Re-encrypted password must have a new ciphertext");

        VaultService.DecryptedCredential decUpdatedGh = vaultService.decryptEntry(updatedGh);
        assertEquals("alice_lead_eng", decUpdatedGh.getUsername());
        assertEquals("Kx9#vP2$mQ8@wL5!zR4", decUpdatedGh.getPassword());
        assertEquals("Updated 2FA seed note", decUpdatedGh.getNotes());

        // -------------------------------------------------------------
        // Step 8: Delete a credential
        // -------------------------------------------------------------
        boolean deleted = vaultService.deleteEntry(protonEntry.getEntryId());
        assertTrue(deleted, "Owner must be able to delete credential");

        List<VaultEntry> entriesAfterDelete = vaultService.getEntriesForCurrentUser();
        assertEquals(2, entriesAfterDelete.size(), "Vault should have 2 credentials remaining");
        assertFalse(vaultEntryDAO.findById(protonEntry.getEntryId(), alice.getUserId()).isPresent());

        // -------------------------------------------------------------
        // Step 9: Search and filter the vault
        // -------------------------------------------------------------
        List<VaultEntry> searchResults = vaultService.searchEntries("Enter");
        assertEquals(1, searchResults.size(), "Search for 'Enter' should match GitHub Enterprise");
        assertEquals("GitHub Enterprise", searchResults.get(0).getWebsiteName());

        List<VaultEntry> awsSearch = vaultService.searchEntries("amazon.com");
        assertEquals(1, awsSearch.size());
        assertEquals("AWS Console", awsSearch.get(0).getWebsiteName());

        List<VaultEntry> protonSearch = vaultService.searchEntries("Proton");
        assertTrue(protonSearch.isEmpty(), "Deleted entry must not appear in search results");

        // -------------------------------------------------------------
        // Step 10: Generate a replacement password
        // -------------------------------------------------------------
        String generatedPass = PasswordGenerator.generate(24, true, true, true, true, false);
        assertEquals(24, generatedPass.length());
        assertTrue(PasswordGenerator.calculateEntropy(24, true, true, true, true) >= 80.0);

        // Update AWS Console with the generated password
        vaultService.updateEntry(
                awsEntry.getEntryId(),
                "AWS Console",
                "https://console.aws.amazon.com",
                "admin_aws",
                generatedPass,
                "Cloud",
                "Rotated root key using generator"
        );

        // -------------------------------------------------------------
        // Step 11: Run the security audit
        // -------------------------------------------------------------
        VaultAuditReport auditReport = auditService.performAudit();
        assertEquals(2, auditReport.getTotalScanned());
        assertEquals(2, auditReport.getStrongCount(), "Both GitHub and AWS have strong unique passwords");
        assertEquals(0, auditReport.getWeakCount());
        assertEquals(0, auditReport.getReuseGroupsCount(), "Zero duplicate passwords remain");
        assertEquals(100, auditReport.getOverallScore(), "Score must be 100 for clean vault");
        assertEquals("Excellent", auditReport.getScoreRating());

        // -------------------------------------------------------------
        // Step 12: Lock the vault
        // -------------------------------------------------------------
        authService.logout();
        assertFalse(sessionManager.isLoggedIn(), "Session must be terminated after logout");
        assertNull(sessionManager.getVaultKey(), "Derived vault key must be cleared from memory");

        // Verify unauthenticated operations are blocked
        assertThrows(IllegalStateException.class, () -> vaultService.getEntriesForCurrentUser());
        assertThrows(IllegalStateException.class, () -> vaultService.addEntry("S", "u", "u", "p", "c", "n"));
        assertThrows(IllegalStateException.class, () -> auditService.performAudit());

        // -------------------------------------------------------------
        // Step 13: Log back in (Alice)
        // -------------------------------------------------------------
        User reloggedAlice = authService.login("alice_lead", masterPassAlice);
        assertNotNull(reloggedAlice);
        assertTrue(sessionManager.isLoggedIn());
        assertNotNull(sessionManager.getVaultKey());

        // -------------------------------------------------------------
        // Step 14: Verify that all remaining credentials are available and decrypt correctly
        // -------------------------------------------------------------
        List<VaultEntry> persistedEntries = vaultService.getEntriesForCurrentUser();
        assertEquals(2, persistedEntries.size());

        for (VaultEntry entry : persistedEntries) {
            VaultService.DecryptedCredential dec = vaultService.decryptEntry(entry);
            if ("GitHub Enterprise".equals(entry.getWebsiteName())) {
                assertEquals("alice_lead_eng", dec.getUsername());
                assertEquals("Kx9#vP2$mQ8@wL5!zR4", dec.getPassword());
            } else if ("AWS Console".equals(entry.getWebsiteName())) {
                assertEquals("admin_aws", dec.getUsername());
                assertEquals(generatedPass, dec.getPassword());
            } else {
                fail("Unexpected entry in Alice's vault: " + entry.getWebsiteName());
            }
        }

        // -------------------------------------------------------------
        // Step 15: User Isolation (User B - Bob cannot access Alice's data)
        // -------------------------------------------------------------
        authService.logout();
        char[] masterPassBob = "BobMasterPass#2026!Sec".toCharArray();
        User bob = authService.register("bob_dev", "bob@ironkey.io", masterPassBob, masterPassBob);
        authService.login("bob@ironkey.io", masterPassBob);

        // Bob's vault is completely empty
        List<VaultEntry> bobEntries = vaultService.getEntriesForCurrentUser();
        assertTrue(bobEntries.isEmpty(), "Bob must not see Alice's credentials");

        // Bob cannot read Alice's record by ID
        Optional<VaultEntry> stolen = vaultEntryDAO.findById(ghEntry.getEntryId(), bob.getUserId());
        assertTrue(stolen.isEmpty(), "Bob cannot query Alice's record ID");

        // Bob cannot delete Alice's record
        boolean bobDelete = vaultService.deleteEntry(ghEntry.getEntryId());
        assertFalse(bobDelete, "Bob cannot delete Alice's record");

        // Bob cannot update Alice's record
        boolean bobUpdate = vaultService.updateEntry(ghEntry.getEntryId(), "Hacked", "url", "u", "p", "c", "n");
        assertFalse(bobUpdate, "Bob cannot modify Alice's record");

        // Cryptographic isolation: Even if Bob had Alice's ciphertext, Bob's key fails tag verification
        assertThrows(GeneralSecurityException.class, () -> {
            EncryptionManager.decrypt(ghEntry.getEncryptedPassword(), sessionManager.getVaultKey());
        }, "Decryption with another user's derived AES key must fail GCM authentication");

        authService.logout();
    }

    // -------------------------------------------------------------------------
    // IN-MEMORY DAO STUBS TO TEST REAL TRANSACTIONS AND PERSISTENCE OFF-LINE
    // -------------------------------------------------------------------------

    private static class InMemoryUserDAO extends UserDAO {
        private final Map<Long, User> usersById = new ConcurrentHashMap<>();
        private final Map<String, User> usersByEmail = new ConcurrentHashMap<>();
        private final Map<String, User> usersByUsername = new ConcurrentHashMap<>();
        private long seq = 1000L;

        @Override
        public User save(User user) {
            user.setUserId(seq++);
            user.setCreatedAt(LocalDateTime.now());
            usersById.put(user.getUserId(), user);
            usersByEmail.put(user.getEmail().toLowerCase(), user);
            usersByUsername.put(user.getUsername().toLowerCase(), user);
            return user;
        }

        @Override
        public Optional<User> findById(Long id) {
            return Optional.ofNullable(usersById.get(id));
        }

        @Override
        public Optional<User> findByEmail(String email) {
            return Optional.ofNullable(usersByEmail.get(email.toLowerCase()));
        }

        @Override
        public Optional<User> findByUsername(String username) {
            return Optional.ofNullable(usersByUsername.get(username.toLowerCase()));
        }

        public Optional<User> findByUsernameOrEmail(String identifier) {
            String lower = identifier.toLowerCase();
            if (usersByEmail.containsKey(lower)) return Optional.of(usersByEmail.get(lower));
            if (usersByUsername.containsKey(lower)) return Optional.of(usersByUsername.get(lower));
            return Optional.empty();
        }

        @Override
        public boolean existsByEmail(String email) {
            return usersByEmail.containsKey(email.toLowerCase());
        }

        @Override
        public boolean existsByUsername(String username) {
            return usersByUsername.containsKey(username.toLowerCase());
        }
    }

    private static class InMemoryVaultEntryDAO extends VaultEntryDAO {
        private final Map<Long, VaultEntry> db = new ConcurrentHashMap<>();
        private long seq = 2000L;

        @Override
        public VaultEntry save(VaultEntry entry) {
            entry.setEntryId(seq++);
            if (entry.getCreatedAt() == null) entry.setCreatedAt(LocalDateTime.now());
            if (entry.getUpdatedAt() == null) entry.setUpdatedAt(LocalDateTime.now());
            VaultEntry copy = new VaultEntry(entry.getEntryId(), entry.getUserId(),
                    entry.getWebsiteName(), entry.getWebsiteUrl(),
                    entry.getEncryptedUsername(), entry.getEncryptedPassword(),
                    entry.getNonce(), entry.getCategory(), entry.getNotes(),
                    entry.getCreatedAt(), entry.getUpdatedAt());
            db.put(entry.getEntryId(), copy);
            return entry;
        }

        @Override
        public Optional<VaultEntry> findById(Long entryId, Long userId) {
            VaultEntry e = db.get(entryId);
            if (e != null && Objects.equals(e.getUserId(), userId)) {
                return Optional.of(e);
            }
            return Optional.empty();
        }

        @Override
        public List<VaultEntry> findAllByUserId(Long userId) {
            return db.values().stream()
                    .filter(e -> Objects.equals(e.getUserId(), userId))
                    .sorted(Comparator.comparing(VaultEntry::getWebsiteName, String.CASE_INSENSITIVE_ORDER))
                    .collect(Collectors.toList());
        }

        @Override
        public List<VaultEntry> search(Long userId, String queryFilter) {
            String q = queryFilter.toLowerCase();
            return db.values().stream()
                    .filter(e -> Objects.equals(e.getUserId(), userId))
                    .filter(e -> (e.getWebsiteName() != null && e.getWebsiteName().toLowerCase().contains(q)) ||
                                 (e.getWebsiteUrl() != null && e.getWebsiteUrl().toLowerCase().contains(q)))
                    .sorted(Comparator.comparing(VaultEntry::getWebsiteName, String.CASE_INSENSITIVE_ORDER))
                    .collect(Collectors.toList());
        }

        @Override
        public boolean update(VaultEntry entry) {
            VaultEntry existing = db.get(entry.getEntryId());
            if (existing != null && Objects.equals(existing.getUserId(), entry.getUserId())) {
                entry.setCreatedAt(existing.getCreatedAt());
                entry.setUpdatedAt(LocalDateTime.now());
                db.put(entry.getEntryId(), entry);
                return true;
            }
            return false;
        }

        @Override
        public boolean delete(Long entryId, Long userId) {
            VaultEntry existing = db.get(entryId);
            if (existing != null && Objects.equals(existing.getUserId(), userId)) {
                db.remove(entryId);
                return true;
            }
            return false;
        }

        @Override
        public int countByUserId(Long userId) {
            return (int) db.values().stream().filter(e -> Objects.equals(e.getUserId(), userId)).count();
        }
    }

    private static class InMemorySecurityLogDAO extends SecurityLogDAO {
        private final List<SecurityLog> logs = Collections.synchronizedList(new ArrayList<>());
        private long seq = 1L;

        @Override
        public SecurityLog logEvent(SecurityLog log) {
            log.setLogId(seq++);
            log.setTimestamp(LocalDateTime.now());
            logs.add(log);
            return log;
        }

        @Override
        public List<SecurityLog> findRecentByUserId(Long userId, int limit) {
            return logs.stream()
                    .filter(l -> Objects.equals(l.getUserId(), userId))
                    .limit(limit)
                    .collect(Collectors.toList());
        }
    }

    private static class InMemoryCategoryDAO extends CategoryDAO {
        private final List<Category> categories = Collections.synchronizedList(new ArrayList<>());
        private long idSequence = 1;

        @Override
        public Category save(Category category) {
            return save(category, null);
        }

        @Override
        public Category save(Category category, Connection conn) {
            category.setCategoryId(idSequence++);
            categories.add(category);
            return category;
        }

        @Override
        public List<Category> findAllByUserId(Long userId) {
            return categories.stream()
                    .filter(c -> c.getUserId() == null || Objects.equals(c.getUserId(), userId))
                    .collect(Collectors.toList());
        }
    }
}
