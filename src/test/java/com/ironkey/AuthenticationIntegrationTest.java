package com.ironkey;

import com.ironkey.config.DatabaseConfig;
import com.ironkey.model.User;
import com.ironkey.service.AuthenticationService;
import com.ironkey.util.SessionManager;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Live MySQL integration test for Authentication and Database transactions.
 * Automatically executes against MySQL if the server is running on localhost:3306,
 * or gracefully skips if MySQL is offline.
 */
class AuthenticationIntegrationTest {

    @Test
    @DisplayName("Live MySQL Integration: Registration and Login Transaction")
    void testLiveMySQLIntegration() {
        DatabaseConfig dbConfig = DatabaseConfig.getInstance();
        DatabaseConfig.ConnectionTestResult testResult = dbConfig.testConnection();

        // Only run live integration test if MySQL is genuinely reachable
        Assumptions.assumeTrue(testResult.isSuccess(),
                "MySQL is offline (" + testResult.getMessage() + "); skipping live integration test.");

        AuthenticationService authService = new AuthenticationService();
        SessionManager sessionManager = SessionManager.getInstance();
        sessionManager.clearSession();

        long timestamp = System.currentTimeMillis();
        String username = "integ_" + timestamp;
        String email = "integ_" + timestamp + "@ironkey.io";
        char[] masterPass = "IntegrationPass#2026!".toCharArray();

        try {
            // 1. Register user
            User registeredUser = authService.register(username, email, masterPass, masterPass);
            assertNotNull(registeredUser);
            assertNotNull(registeredUser.getUserId());

            // 2. Authenticate using email
            User loggedIn = authService.login(email, masterPass);
            assertNotNull(loggedIn);
            assertTrue(sessionManager.isLoggedIn());
            assertNotNull(sessionManager.getVaultKey());
            assertEquals(32, sessionManager.getVaultKey().getEncoded().length);

            // 3. Logout
            authService.logout();
            assertFalse(sessionManager.isLoggedIn());
            assertNull(sessionManager.getVaultKey());
        } catch (Exception e) {
            fail("Live MySQL integration test failed: " + e.getMessage(), e);
        }
    }
}
