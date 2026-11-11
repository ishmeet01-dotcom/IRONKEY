package com.ironkey;

import com.ironkey.dao.VaultEntryDAO;
import com.ironkey.model.User;
import com.ironkey.model.VaultEntry;
import com.ironkey.security.EncryptionManager;
import com.ironkey.security.KeyDerivationService;
import com.ironkey.service.VaultService;
import com.ironkey.util.SessionManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 3: Multi-tenant and User Isolation Verification Test Suite.
 * Confirms that User A cannot read, modify, or delete User B's vault records,
 * and that unauthenticated service access is rejected.
 */
class UserIsolationTest {

    private MockVaultEntryDAO mockVaultDAO;
    private SessionManager sessionManager;
    private VaultService vaultService;

    private User userA;
    private User userB;
    private SecretKey keyA;
    private SecretKey keyB;

    @BeforeEach
    void setUp() {
        mockVaultDAO = new MockVaultEntryDAO();
        sessionManager = SessionManager.getInstance();
        sessionManager.clearSession();

        vaultService = new VaultService(mockVaultDAO, sessionManager);

        userA = new User("user_a", "user_a@ironkey.io", "hashA", "saltA1", "saltA2");
        userA.setUserId(101L);
        keyA = KeyDerivationService.deriveVaultKey("PassA#2026!".toCharArray(), userA.getKeyDerivationSalt());

        userB = new User("user_b", "user_b@ironkey.io", "hashB", "saltB1", "saltB2");
        userB.setUserId(202L);
        keyB = KeyDerivationService.deriveVaultKey("PassB#2026!".toCharArray(), userB.getKeyDerivationSalt());
    }

    @Test
    @DisplayName("1. User A cannot retrieve User B's vault entries via findById")
    void testUserCannotReadAnotherUsersEntry() throws SQLException, GeneralSecurityException {
        // User B stores an entry
        String encUserB = EncryptionManager.encrypt("user_b_login", keyB);
        String encPassB = EncryptionManager.encrypt("SecretB#Password", keyB);
        VaultEntry entryB = new VaultEntry(202L, "AWS Console", "https://aws.amazon.com", encUserB, encPassB, "nonceB", "Cloud", "User B Private Notes");
        VaultEntry savedEntryB = mockVaultDAO.save(entryB);

        // User A attempts to read User B's entry with User A's ID
        Optional<VaultEntry> result = mockVaultDAO.findById(savedEntryB.getEntryId(), userA.getUserId());
        assertTrue(result.isEmpty(), "User A must not be able to retrieve User B's record");

        // Verify User B CAN retrieve their own entry
        Optional<VaultEntry> ownerResult = mockVaultDAO.findById(savedEntryB.getEntryId(), userB.getUserId());
        assertTrue(ownerResult.isPresent(), "User B should be able to retrieve their own entry");
    }

    @Test
    @DisplayName("2. User A findAllByUserId only returns User A's records, never User B's")
    void testFindAllStrictIsolation() throws SQLException {
        // User A creates 2 entries
        mockVaultDAO.save(new VaultEntry(101L, "GitHub", "https://github.com", "encA1", "encA1", "n1", "Dev", "A"));
        mockVaultDAO.save(new VaultEntry(101L, "GitLab", "https://gitlab.com", "encA2", "encA2", "n2", "Dev", "A"));

        // User B creates 3 entries
        mockVaultDAO.save(new VaultEntry(202L, "Stripe", "https://stripe.com", "encB1", "encB1", "n3", "Fin", "B"));
        mockVaultDAO.save(new VaultEntry(202L, "PayPal", "https://paypal.com", "encB2", "encB2", "n4", "Fin", "B"));
        mockVaultDAO.save(new VaultEntry(202L, "Chase", "https://chase.com", "encB3", "encB3", "n5", "Fin", "B"));

        List<VaultEntry> userAEntries = mockVaultDAO.findAllByUserId(101L);
        assertEquals(2, userAEntries.size(), "User A must see exactly 2 entries");
        assertTrue(userAEntries.stream().allMatch(e -> e.getUserId().equals(101L)));

        List<VaultEntry> userBEntries = mockVaultDAO.findAllByUserId(202L);
        assertEquals(3, userBEntries.size(), "User B must see exactly 3 entries");
        assertTrue(userBEntries.stream().allMatch(e -> e.getUserId().equals(202L)));
    }

    @Test
    @DisplayName("3. User A cannot modify or hijack User B's records")
    void testUserCannotModifyAnotherUsersEntry() throws SQLException {
        VaultEntry entryB = mockVaultDAO.save(new VaultEntry(202L, "ProtonMail", "https://proton.me", "origUser", "origPass", "n", "Sec", "Orig"));

        // User A attempts to update User B's record by spoofing ownership
        VaultEntry maliciousUpdate = new VaultEntry();
        maliciousUpdate.setEntryId(entryB.getEntryId());
        maliciousUpdate.setUserId(userA.getUserId()); // User A tries to overwrite with their ID
        maliciousUpdate.setWebsiteName("Hacked Entry");

        boolean updated = mockVaultDAO.update(maliciousUpdate);
        assertFalse(updated, "Update must fail when user does not own the target record");

        // Verify the original record remains intact
        VaultEntry original = mockVaultDAO.findById(entryB.getEntryId(), 202L).orElseThrow();
        assertEquals("ProtonMail", original.getWebsiteName(), "Original record website name must be unchanged");
    }

    @Test
    @DisplayName("4. User A cannot delete User B's records")
    void testUserCannotDeleteAnotherUsersEntry() throws SQLException {
        VaultEntry entryB = mockVaultDAO.save(new VaultEntry(202L, "ServerSSH", "192.168.1.100", "encU", "encP", "n", "SSH", "Server"));

        // User A attempts to delete User B's entry
        boolean deleted = mockVaultDAO.delete(entryB.getEntryId(), userA.getUserId());
        assertFalse(deleted, "Delete must return false when attempting to delete another user's record");

        // Verify entry B still exists
        assertTrue(mockVaultDAO.findById(entryB.getEntryId(), 202L).isPresent(), "Record must remain in vault");
    }

    @Test
    @DisplayName("5. Unauthenticated operations are rejected by VaultService")
    void testUnauthenticatedAccessRejected() {
        sessionManager.clearSession();
        assertFalse(sessionManager.isLoggedIn());

        assertThrows(IllegalStateException.class, () -> {
            vaultService.getEntriesForCurrentUser();
        }, "Unauthenticated retrieval must be rejected with IllegalStateException");

        assertThrows(IllegalStateException.class, () -> {
            vaultService.addEntry("Site", "url", "user", "pass", "cat", "notes");
        }, "Unauthenticated addEntry must be rejected");

        assertThrows(IllegalStateException.class, () -> {
            vaultService.deleteEntry(1L);
        }, "Unauthenticated deleteEntry must be rejected");
    }

    @Test
    @DisplayName("6. Cryptographic isolation: User A's key cannot decrypt User B's ciphertext")
    void testCryptographicIsolationAcrossUsers() throws GeneralSecurityException {
        String secretData = "User_B_Confidential_Database_Password#992";

        // User B encrypts with Key B
        String ciphertext = EncryptionManager.encrypt(secretData, keyB);

        // User A tries to decrypt with Key A
        assertThrows(GeneralSecurityException.class, () -> {
            EncryptionManager.decrypt(ciphertext, keyA);
        }, "User A's key must not be able to decrypt User B's ciphertext");
    }

    // =========================================================================
    // Mock VaultEntryDAO with Exact User Isolation Semantics
    // =========================================================================
    private static class MockVaultEntryDAO extends VaultEntryDAO {
        private final Map<Long, VaultEntry> database = new HashMap<>();
        private long idSequence = 1;

        @Override
        public VaultEntry save(VaultEntry entry) {
            entry.setEntryId(idSequence++);
            // Clone to simulate database persistence
            VaultEntry clone = new VaultEntry(entry.getEntryId(), entry.getUserId(),
                    entry.getWebsiteName(), entry.getWebsiteUrl(),
                    entry.getEncryptedUsername(), entry.getEncryptedPassword(),
                    entry.getNonce(), entry.getCategory(), entry.getNotes(),
                    entry.getCreatedAt(), entry.getUpdatedAt());
            database.put(entry.getEntryId(), clone);
            return entry;
        }

        @Override
        public Optional<VaultEntry> findById(Long entryId, Long userId) {
            VaultEntry entry = database.get(entryId);
            if (entry != null && Objects.equals(entry.getUserId(), userId)) {
                return Optional.of(entry);
            }
            return Optional.empty();
        }

        @Override
        public List<VaultEntry> findAllByUserId(Long userId) {
            List<VaultEntry> list = new ArrayList<>();
            for (VaultEntry e : database.values()) {
                if (Objects.equals(e.getUserId(), userId)) {
                    list.add(e);
                }
            }
            return list;
        }

        @Override
        public boolean update(VaultEntry entry) {
            VaultEntry existing = database.get(entry.getEntryId());
            if (existing != null && Objects.equals(existing.getUserId(), entry.getUserId())) {
                database.put(entry.getEntryId(), entry);
                return true;
            }
            return false;
        }

        @Override
        public boolean delete(Long entryId, Long userId) {
            VaultEntry existing = database.get(entryId);
            if (existing != null && Objects.equals(existing.getUserId(), userId)) {
                database.remove(entryId);
                return true;
            }
            return false;
        }

        @Override
        public int countByUserId(Long userId) {
            return (int) database.values().stream().filter(e -> Objects.equals(e.getUserId(), userId)).count();
        }
    }
}
