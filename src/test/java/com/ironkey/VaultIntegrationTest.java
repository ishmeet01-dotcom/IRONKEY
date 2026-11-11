package com.ironkey;

import com.ironkey.config.DatabaseConfig;
import com.ironkey.model.User;
import com.ironkey.model.VaultEntry;
import com.ironkey.service.AuthenticationService;
import com.ironkey.service.VaultService;
import com.ironkey.util.SessionManager;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Live MySQL Integration Test for Phase 4 Persistent Credential Management.
 * Verifies end-to-end CRUD persistence in MySQL with real AES-256-GCM ciphertexts
 * when MySQL is online, or gracefully skips when offline.
 */
class VaultIntegrationTest {

    @Test
    @DisplayName("Live MySQL: End-to-end credential persistence, retrieval, update, and deletion")
    void testLiveMySQLVaultLifecycle() {
        DatabaseConfig dbConfig = DatabaseConfig.getInstance();
        DatabaseConfig.ConnectionTestResult testResult = dbConfig.testConnection();

        // Skip gracefully if MySQL is not reachable on localhost:3306
        Assumptions.assumeTrue(testResult.isSuccess(),
                "MySQL is offline (" + testResult.getMessage() + "); skipping live integration test.");

        AuthenticationService authService = new AuthenticationService();
        VaultService vaultService = new VaultService();
        SessionManager sessionManager = SessionManager.getInstance();
        sessionManager.clearSession();

        long ts = System.currentTimeMillis();
        String username = "vault_integ_" + ts;
        String email = "vault_" + ts + "@ironkey.io";
        char[] masterPass = "IntegrationKey#2026!".toCharArray();

        try {
            // 1. Register & Login
            authService.register(username, email, masterPass, masterPass);
            authService.login(email, masterPass);
            assertTrue(sessionManager.isLoggedIn());

            // 2. Add Credential
            VaultEntry created = vaultService.addEntry(
                    "AWS Production",
                    "https://aws.amazon.com",
                    "devops-admin",
                    "P@ssw0rdProd#2026",
                    "Servers",
                    "Live MySQL integration test entry"
            );
            assertNotNull(created.getEntryId(), "Generated entry ID must not be null");

            // 3. Retrieve and Decrypt
            List<VaultEntry> entries = vaultService.getEntriesForCurrentUser();
            assertFalse(entries.isEmpty(), "Vault must contain the persisted credential");

            VaultService.DecryptedCredential decrypted = vaultService.decryptEntry(entries.get(0));
            assertEquals("AWS Production", decrypted.getWebsiteName());
            assertEquals("devops-admin", decrypted.getUsername());
            assertEquals("P@ssw0rdProd#2026", decrypted.getPassword());
            assertEquals("Servers", decrypted.getCategory());

            // 4. Update Credential
            boolean updated = vaultService.updateEntry(
                    created.getEntryId(),
                    "AWS Production - Primary",
                    "https://aws.amazon.com/console",
                    "devops-admin-v2",
                    "RotatedProdKey#2026!",
                    "Infrastructure",
                    "Rotated during test"
            );
            assertTrue(updated, "Update in MySQL must succeed");

            // 5. Search
            List<VaultEntry> searchResults = vaultService.searchEntries("AWS Production");
            assertFalse(searchResults.isEmpty());

            // 6. Delete Credential
            boolean deleted = vaultService.deleteEntry(created.getEntryId());
            assertTrue(deleted, "Deletion from MySQL must succeed");

            List<VaultEntry> postDeleteEntries = vaultService.getEntriesForCurrentUser();
            assertTrue(postDeleteEntries.isEmpty(), "Vault must be empty after deletion");

        } catch (Exception e) {
            fail("Live MySQL vault integration test failed: " + e.getMessage(), e);
        } finally {
            authService.logout();
        }
    }
}
