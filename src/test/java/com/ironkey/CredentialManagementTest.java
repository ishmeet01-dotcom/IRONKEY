package com.ironkey;

import com.ironkey.dao.VaultEntryDAO;
import com.ironkey.model.User;
import com.ironkey.model.VaultEntry;
import com.ironkey.security.EncryptionManager;
import com.ironkey.security.KeyDerivationService;
import com.ironkey.service.VaultService;
import com.ironkey.util.ClipboardManager;
import com.ironkey.util.SessionManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.awt.GraphicsEnvironment;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 4: Complete Credential Management & Persistent Vault Test Suite.
 * Validates the full credential lifecycle, including:
 * - Credential creation and AES-256-GCM encryption of sensitive fields (username, password, notes).
 * - Fresh, independent nonces eliminating nonce reuse across fields and operations.
 * - Retrieval and in-memory decryption of credentials.
 * - Credential editing with re-encryption and fresh nonce generation.
 * - Credential deletion with user ownership enforcement.
 * - Multi-user isolation in retrieval, editing, and deletion.
 * - Search by website name and URL.
 * - Tampering detection and wrong-key rejection via GCM authentication tags.
 * - Clipboard auto-scrubbing behavior.
 * - Session expiration protection.
 */
class CredentialManagementTest {

    private InMemoryVaultEntryDAO mockVaultDAO;
    private SessionManager sessionManager;
    private VaultService vaultService;

    private User user1;
    private User user2;
    private SecretKey key1;
    private SecretKey key2;

    @BeforeEach
    void setUp() {
        mockVaultDAO = new InMemoryVaultEntryDAO();
        sessionManager = SessionManager.getInstance();
        sessionManager.clearSession();

        vaultService = new VaultService(mockVaultDAO, sessionManager);

        user1 = new User("alice", "alice@ironkey.io", "authHashAlice", "saltAlice1", "saltAlice2");
        user1.setUserId(1001L);
        key1 = KeyDerivationService.deriveVaultKey("AliceMasterPass#2026".toCharArray(), user1.getKeyDerivationSalt());

        user2 = new User("bob", "bob@ironkey.io", "authHashBob", "saltBob1", "saltBob2");
        user2.setUserId(2002L);
        key2 = KeyDerivationService.deriveVaultKey("BobMasterPass#2026".toCharArray(), user2.getKeyDerivationSalt());

        // Default login as user1
        sessionManager.startSession(user1, key1);
    }

    @Test
    @DisplayName("1. Credential creation encrypts username, password, and notes with independent nonces")
    void testCreateCredentialEncryptsSensitiveFieldsWithFreshNonces() throws Exception {
        String plainUser = "alice_dev";
        String plainPass = "SuperSecret#2026!";
        String plainNotes = "Recovery code: 9982-1140";

        VaultEntry saved = vaultService.addEntry(
                "GitHub",
                "https://github.com/login",
                plainUser,
                plainPass,
                "Logins",
                plainNotes
        );

        assertNotNull(saved.getEntryId(), "Saved entry must have an assigned ID");
        assertEquals(user1.getUserId(), saved.getUserId(), "Entry must be associated with active user");
        assertEquals("GitHub", saved.getWebsiteName());
        assertEquals("https://github.com/login", saved.getWebsiteUrl());

        // Verify sensitive fields are encrypted (not plaintext)
        assertNotEquals(plainUser, saved.getEncryptedUsername(), "Username must never be stored in plaintext");
        assertNotEquals(plainPass, saved.getEncryptedPassword(), "Password must never be stored in plaintext");
        assertNotEquals(plainNotes, saved.getNotes(), "Notes must never be stored in plaintext");

        // Verify independent nonces: encrypting identical text produces different ciphertexts
        String enc1 = EncryptionManager.encrypt("SameSecret", key1);
        String enc2 = EncryptionManager.encrypt("SameSecret", key1);
        assertNotEquals(enc1, enc2, "AES-GCM encryption with fresh nonces must produce unique ciphertexts for identical plaintext");
    }

    @Test
    @DisplayName("2. Credential retrieval and decryption in memory restores original plaintext")
    void testRetrieveAndDecryptCredential() throws Exception {
        VaultEntry saved = vaultService.addEntry(
                "ProtonMail",
                "https://mail.proton.me",
                "security@ironkey.io",
                "P@ssw0rd$Proton123",
                "Personal",
                "PGP key fingerprint: 4F2A 99B0 11CE"
        );

        List<VaultEntry> entries = vaultService.getEntriesForCurrentUser();
        assertEquals(1, entries.size(), "User should have exactly 1 saved entry");

        VaultService.DecryptedCredential decrypted = vaultService.decryptEntry(entries.get(0));
        assertEquals("ProtonMail", decrypted.getWebsiteName());
        assertEquals("https://mail.proton.me", decrypted.getWebsiteUrl());
        assertEquals("security@ironkey.io", decrypted.getUsername(), "Decrypted username must match original input");
        assertEquals("P@ssw0rd$Proton123", decrypted.getPassword(), "Decrypted password must match original input");
        assertEquals("Personal", decrypted.getCategory());
        assertEquals("PGP key fingerprint: 4F2A 99B0 11CE", decrypted.getNotes(), "Decrypted notes must match original input");
    }

    @Test
    @DisplayName("3. Credential editing re-encrypts sensitive fields with fresh nonces")
    void testEditCredentialReEncryptsWithFreshNonces() throws Exception {
        VaultEntry original = vaultService.addEntry(
                "AWS Console",
                "https://console.aws.amazon.com",
                "admin-ops",
                "OldAWSKey#2025",
                "Cloud",
                "Old notes"
        );

        String oldEncryptedPassword = original.getEncryptedPassword();
        String oldEncryptedUsername = original.getEncryptedUsername();

        boolean updated = vaultService.updateEntry(
                original.getEntryId(),
                "AWS Console - Prod",
                "https://console.aws.amazon.com/prod",
                "admin-ops-v2",
                "NewAWSKey#2026!",
                "Infrastructure",
                "Rotated root API access key"
        );

        assertTrue(updated, "Update must succeed for entry owner");

        VaultEntry updatedEntry = mockVaultDAO.findById(original.getEntryId(), user1.getUserId()).orElseThrow();
        assertEquals("AWS Console - Prod", updatedEntry.getWebsiteName());
        assertNotEquals(oldEncryptedPassword, updatedEntry.getEncryptedPassword(), "Re-encrypted password ciphertext must differ");
        assertNotEquals(oldEncryptedUsername, updatedEntry.getEncryptedUsername(), "Re-encrypted username ciphertext must differ");

        // Verify updated entry decrypts correctly
        VaultService.DecryptedCredential decrypted = vaultService.decryptEntry(updatedEntry);
        assertEquals("admin-ops-v2", decrypted.getUsername());
        assertEquals("NewAWSKey#2026!", decrypted.getPassword());
        assertEquals("Infrastructure", decrypted.getCategory());
        assertEquals("Rotated root API access key", decrypted.getNotes());
    }

    @Test
    @DisplayName("4. Credential deletion enforces ownership and removes record")
    void testDeleteCredentialWithOwnershipValidation() throws Exception {
        VaultEntry entry = vaultService.addEntry(
                "Temporary Service",
                "https://temp.io",
                "temp_user",
                "tempPass123",
                "General",
                ""
        );

        assertEquals(1, vaultService.getEntriesForCurrentUser().size());

        // Delete existing entry
        boolean deleted = vaultService.deleteEntry(entry.getEntryId());
        assertTrue(deleted, "Owner must be able to delete their own credential");
        assertEquals(0, vaultService.getEntriesForCurrentUser().size(), "Vault should be empty after deletion");

        // Attempt deleting already deleted entry
        boolean deleteAgain = vaultService.deleteEntry(entry.getEntryId());
        assertFalse(deleteAgain, "Deleting non-existent entry ID must return false");
    }

    @Test
    @DisplayName("5. Multi-tenant user isolation: User B cannot access, modify, or delete User A's credentials")
    void testMultiTenantUserIsolation() throws Exception {
        // User 1 creates an entry
        VaultEntry aliceEntry = vaultService.addEntry(
                "Alice Secret Vault",
                "https://alice.internal",
                "alice_admin",
                "AliceUltraSecret#1",
                "Work",
                "Top secret research"
        );

        // Switch active session to User 2 (Bob)
        sessionManager.clearSession();
        sessionManager.startSession(user2, key2);

        // 1. Bob cannot see Alice's credentials
        List<VaultEntry> bobEntries = vaultService.getEntriesForCurrentUser();
        assertTrue(bobEntries.isEmpty(), "Bob must not retrieve Alice's vault records");

        // 2. Bob cannot update Alice's credential
        boolean bobUpdate = vaultService.updateEntry(
                aliceEntry.getEntryId(),
                "Hacked Site",
                "https://hacked.com",
                "bob_hacker",
                "HackedPass#1",
                "Hacked",
                "Malicious overwrite"
        );
        assertFalse(bobUpdate, "Bob must not be allowed to update Alice's record");

        // 3. Bob cannot delete Alice's credential
        boolean bobDelete = vaultService.deleteEntry(aliceEntry.getEntryId());
        assertFalse(bobDelete, "Bob must not be allowed to delete Alice's record");

        // Switch back to Alice and verify record is unmodified
        sessionManager.clearSession();
        sessionManager.startSession(user1, key1);

        VaultService.DecryptedCredential aliceDecrypted = vaultService.decryptEntry(
                mockVaultDAO.findById(aliceEntry.getEntryId(), user1.getUserId()).orElseThrow()
        );
        assertEquals("Alice Secret Vault", aliceDecrypted.getWebsiteName());
        assertEquals("AliceUltraSecret#1", aliceDecrypted.getPassword());
    }

    @Test
    @DisplayName("6. Search filters credentials by website name and URL")
    void testSearchByWebsiteNameAndUrl() throws Exception {
        vaultService.addEntry("GitHub", "https://github.com", "gh_user", "pass1", "Logins", "");
        vaultService.addEntry("GitLab", "https://gitlab.com", "gl_user", "pass2", "Logins", "");
        vaultService.addEntry("AWS Console", "https://aws.amazon.com", "aws_user", "pass3", "Cloud", "");

        List<VaultEntry> gitResults = vaultService.searchEntries("git");
        assertEquals(2, gitResults.size(), "Search for 'git' should return GitHub and GitLab");

        List<VaultEntry> awsResults = vaultService.searchEntries("amazon.com");
        assertEquals(1, awsResults.size(), "Search for 'amazon.com' should return AWS Console");

        List<VaultEntry> emptyResults = vaultService.searchEntries("NonExistentSite");
        assertTrue(emptyResults.isEmpty(), "Search for non-existent term must return empty list");
    }

    @Test
    @DisplayName("7. Cryptographic integrity: Tampered ciphertext or auth tag fails GCM decryption")
    void testTamperedCiphertextAndAuthTagFailsDecryption() throws Exception {
        VaultEntry entry = vaultService.addEntry("Bank", "https://bank.com", "user", "secretPass", "Financial", "notes");

        // 1. Tamper with ciphertext
        byte[] rawPayload = Base64.getDecoder().decode(entry.getEncryptedPassword());
        rawPayload[rawPayload.length - 1] ^= 0x55; // flip bit in tag
        entry.setEncryptedPassword(Base64.getEncoder().encodeToString(rawPayload));

        assertThrows(GeneralSecurityException.class, () -> {
            vaultService.decryptEntry(entry);
        }, "Tampered ciphertext or authentication tag must fail AES-GCM verification");
    }

    @Test
    @DisplayName("8. Wrong decryption key fails GCM authentication tag validation")
    void testWrongKeyDecryptionFails() throws Exception {
        VaultEntry entry = vaultService.addEntry("Bank", "https://bank.com", "user", "secretPass", "Financial", "notes");

        // Switch session to Bob (different key)
        sessionManager.clearSession();
        sessionManager.startSession(user2, key2);

        assertThrows(GeneralSecurityException.class, () -> {
            vaultService.decryptEntry(entry);
        }, "Decrypting Alice's entry with Bob's derived key must fail tag validation");
    }

    @Test
    @DisplayName("9. ClipboardManager copies password and non-sensitive text properly")
    void testClipboardManagerOperations() throws Exception {
        if (GraphicsEnvironment.isHeadless()) {
            assertFalse(ClipboardManager.copyText("someUsername"));
            return;
        }

        boolean copiedUser = ClipboardManager.copyText("test_username_copy");
        org.junit.jupiter.api.Assumptions.assumeTrue(copiedUser, "System clipboard not accessible in current terminal session");
        assertEquals("test_username_copy", ClipboardManager.getClipboardText());

        // Test password copy with fast 1-second auto-scrub
        boolean copiedPass = ClipboardManager.copyPassword("EphemeralSecret#99", 1);
        org.junit.jupiter.api.Assumptions.assumeTrue(copiedPass, "System clipboard not accessible in current terminal session");
        assertEquals("EphemeralSecret#99", ClipboardManager.getClipboardText());

        // Wait 1.3 seconds for daemon scheduler to scrub
        Thread.sleep(1300);
        String scrubbed = ClipboardManager.getClipboardText();
        assertTrue(scrubbed == null || scrubbed.isEmpty(), "Clipboard must be scrubbed after scheduled timeout");
    }

    @Test
    @DisplayName("10. Unauthenticated or expired session blocks vault operations")
    void testSessionExpirationGuardsCredentialAccess() {
        sessionManager.clearSession();
        assertFalse(sessionManager.isLoggedIn());

        assertThrows(IllegalStateException.class, () -> vaultService.getEntriesForCurrentUser());
        assertThrows(IllegalStateException.class, () -> vaultService.addEntry("Site", "url", "u", "p", "cat", ""));
        assertThrows(IllegalStateException.class, () -> vaultService.updateEntry(1L, "Site", "url", "u", "p", "cat", ""));
        assertThrows(IllegalStateException.class, () -> vaultService.deleteEntry(1L));
        assertThrows(IllegalStateException.class, () -> vaultService.searchEntries("test"));
    }

    @Test
    @DisplayName("11. Input validation rejects blank website name, username, or password")
    void testInputValidation() {
        assertThrows(IllegalArgumentException.class, () -> {
            vaultService.addEntry("", "https://url.com", "user", "pass", "cat", "");
        }, "Empty website name must be rejected");

        assertThrows(IllegalArgumentException.class, () -> {
            vaultService.addEntry("Site", "https://url.com", "", "pass", "cat", "");
        }, "Empty username must be rejected");

        assertThrows(IllegalArgumentException.class, () -> {
            vaultService.addEntry("Site", "https://url.com", "user", "", "cat", "");
        }, "Empty password must be rejected");

        assertThrows(IllegalArgumentException.class, () -> {
            vaultService.updateEntry(null, "Site", "https://url.com", "user", "pass", "cat", "");
        }, "Null entry ID for update must be rejected");
    }

    /**
     * In-memory mock DAO mimicking MySQL persistence for isolated unit testing.
     */
    private static class InMemoryVaultEntryDAO extends VaultEntryDAO {
        private final Map<Long, VaultEntry> db = new ConcurrentHashMap<>();
        private long idSequence = 100L;

        @Override
        public VaultEntry save(VaultEntry entry) {
            entry.setEntryId(idSequence++);
            entry.setCreatedAt(LocalDateTime.now());
            entry.setUpdatedAt(LocalDateTime.now());
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
            VaultEntry entry = db.get(entryId);
            if (entry != null && Objects.equals(entry.getUserId(), userId)) {
                return Optional.of(entry);
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
}
