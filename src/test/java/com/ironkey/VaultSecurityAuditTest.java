package com.ironkey;

import com.ironkey.model.User;
import com.ironkey.model.VaultEntry;
import com.ironkey.security.EncryptionManager;
import com.ironkey.security.KeyDerivationService;
import com.ironkey.security.PasswordHasher;
import com.ironkey.service.AuthenticationService;
import com.ironkey.ui.DashboardFrame;
import com.ironkey.util.SessionManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import java.awt.GraphicsEnvironment;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 3: Comprehensive Cryptographic and Vault Security Audit Test Suite.
 * Validates AES-256-GCM integrity, tamper detection, key separation,
 * session lifecycle, and memory management constraints.
 */
class VaultSecurityAuditTest {

    private SecretKey sampleKey;
    private SessionManager sessionManager;

    @BeforeEach
    void setUp() {
        sessionManager = SessionManager.getInstance();
        sessionManager.clearSession();
        sessionManager.setTimeoutMinutes(15);

        char[] masterPass = "MasterSecurityAudit#2026!".toCharArray();
        String kdfSalt = KeyDerivationService.generateKeyDerivationSalt();
        sampleKey = KeyDerivationService.deriveVaultKey(masterPass, kdfSalt);
    }

    @Test
    @DisplayName("1. AES-256-GCM self-contained encryption & decryption round-trip")
    void testSelfContainedRoundTrip() throws GeneralSecurityException {
        String sensitiveSecret = "SuperSecret_API_Token_#99824_AlphaBetaGamma";

        String ciphertextPayload = EncryptionManager.encrypt(sensitiveSecret, sampleKey);
        assertNotNull(ciphertextPayload);
        assertNotEquals(sensitiveSecret, ciphertextPayload);

        String decrypted = EncryptionManager.decrypt(ciphertextPayload, sampleKey);
        assertEquals(sensitiveSecret, decrypted, "Decrypted text must match original plaintext");
    }

    @Test
    @DisplayName("2. AES-256-GCM tampering detection: modified ciphertext fails authentication tag")
    void testTamperingCiphertextFails() throws GeneralSecurityException {
        String sensitive = "SensitiveDataPayload";
        String payloadBase64 = EncryptionManager.encrypt(sensitive, sampleKey);

        byte[] payloadBytes = Base64.getDecoder().decode(payloadBase64);
        // Tamper with a byte inside the ciphertext region (between nonce and tag)
        payloadBytes[EncryptionManager.NONCE_LENGTH_BYTES + 2] ^= 0x55;
        String tamperedBase64 = Base64.getEncoder().encodeToString(payloadBytes);

        assertThrows(GeneralSecurityException.class, () -> {
            EncryptionManager.decrypt(tamperedBase64, sampleKey);
        }, "Tampered ciphertext must fail GCM tag validation");
    }

    @Test
    @DisplayName("3. AES-256-GCM tampering detection: modified authentication tag fails decryption")
    void testTamperingAuthTagFails() throws GeneralSecurityException {
        String sensitive = "CriticalVaultPassword#123";
        String payloadBase64 = EncryptionManager.encrypt(sensitive, sampleKey);

        byte[] payloadBytes = Base64.getDecoder().decode(payloadBase64);
        // Tamper with the very last byte (inside the 128-bit authentication tag)
        payloadBytes[payloadBytes.length - 1] ^= 0x01;
        String tamperedBase64 = Base64.getEncoder().encodeToString(payloadBytes);

        assertThrows(GeneralSecurityException.class, () -> {
            EncryptionManager.decrypt(tamperedBase64, sampleKey);
        }, "Tampered authentication tag must cause GeneralSecurityException");
    }

    @Test
    @DisplayName("4. AES-256-GCM tampering detection: modified nonce fails decryption")
    void testTamperingNonceFails() throws GeneralSecurityException {
        String sensitive = "SecretPayload";
        String payloadBase64 = EncryptionManager.encrypt(sensitive, sampleKey);

        byte[] payloadBytes = Base64.getDecoder().decode(payloadBase64);
        // Tamper with the first byte (inside the 12-byte IV/nonce)
        payloadBytes[0] ^= 0xAA;
        String tamperedBase64 = Base64.getEncoder().encodeToString(payloadBytes);

        assertThrows(GeneralSecurityException.class, () -> {
            EncryptionManager.decrypt(tamperedBase64, sampleKey);
        }, "Modified nonce must fail GCM authentication verification");
    }

    @Test
    @DisplayName("5. Decryption with wrong key must fail GCM tag verification")
    void testWrongKeyDecryptionFails() throws GeneralSecurityException {
        SecretKey wrongKey = KeyDerivationService.deriveVaultKey(
                "EntirelyDifferentPassphrase#999!".toCharArray(),
                KeyDerivationService.generateKeyDerivationSalt()
        );

        String payloadBase64 = EncryptionManager.encrypt("UltraSecretPassword", sampleKey);

        assertThrows(GeneralSecurityException.class, () -> {
            EncryptionManager.decrypt(payloadBase64, wrongKey);
        }, "Decrypting with incorrect key must fail authentication");
    }

    @Test
    @DisplayName("6. Nonce uniqueness: 10,000 consecutive nonces must all be strictly distinct")
    void testNonceUniqueness() {
        int count = 10_000;
        Set<String> nonceSet = new HashSet<>(count);

        for (int i = 0; i < count; i++) {
            byte[] nonce = EncryptionManager.generateNonce();
            assertEquals(12, nonce.length, "GCM nonce must be exactly 12 bytes");
            String nonceBase64 = Base64.getEncoder().encodeToString(nonce);
            boolean added = nonceSet.add(nonceBase64);
            assertTrue(added, "Duplicate nonce generated: " + nonceBase64);
        }

        assertEquals(count, nonceSet.size());
    }

    @Test
    @DisplayName("7. Plaintext master passwords and keys are never stored in entity toString")
    void testNoPlaintextInToString() {
        User user = new User("alice", "alice@test.com", "fakeHash123", "fakeSaltA", "fakeSaltB");
        String userStr = user.toString();

        assertFalse(userStr.contains("fakeHash123"));
        assertFalse(userStr.contains("fakeSaltA"));
        assertFalse(userStr.contains("fakeSaltB"));
        assertTrue(userStr.contains("[PROTECTED]"));

        VaultEntry entry = new VaultEntry(1L, "Bank", "https://bank.com", "encUser", "encPass", "nonce", "Fin", "note");
        String entryStr = entry.toString();
        assertFalse(entryStr.contains("encUser"));
        assertFalse(entryStr.contains("encPass"));
        assertTrue(entryStr.contains("[ENCRYPTED]"));
    }

    @Test
    @DisplayName("8. Session lifecycle: creation, activity touch, and inactivity expiration")
    void testSessionInactivityExpiration() {
        User user = new User("tester", "tester@ironkey.io", "hash", "salt1", "salt2");
        user.setUserId(42L);

        sessionManager.startSession(user, sampleKey);
        assertTrue(sessionManager.isLoggedIn());
        assertEquals(42L, sessionManager.getUserId());

        // Simulate 20 minutes of inactivity (timeout is set to 15 min)
        sessionManager.setLastActivityTime(Instant.now().minus(20, ChronoUnit.MINUTES));

        assertTrue(sessionManager.isExpired(), "Session should be expired after 20 minutes of inactivity");
        assertFalse(sessionManager.isLoggedIn(), "isLoggedIn should return false when expired");
        assertNull(sessionManager.getCurrentUser(), "Current user should be cleared when session expires");
        assertNull(sessionManager.getVaultKey(), "Vault key should be wiped when session expires");
    }

    @Test
    @DisplayName("9. Repeated logout calls are safe and idempotent")
    void testRepeatedLogoutIdempotency() {
        User user = new User("idempotent_user", "idem@ironkey.io", "hash", "salt1", "salt2");
        sessionManager.startSession(user, sampleKey);
        assertTrue(sessionManager.isLoggedIn());

        AuthenticationService service = new AuthenticationService();
        assertDoesNotThrow(() -> {
            service.logout();
            service.logout();
            service.logout();
        }, "Repeated logout calls must never throw exceptions");

        assertFalse(sessionManager.isLoggedIn());
    }

    @Test
    @DisplayName("10. Unauthenticated dashboard access is rejected and guarded")
    void testUnauthenticatedDashboardAccessRejected() {
        sessionManager.clearSession();
        assertFalse(sessionManager.isLoggedIn());

        if (GraphicsEnvironment.isHeadless()) {
            assertThrows(SecurityException.class, () -> {
                new DashboardFrame();
            }, "Creating DashboardFrame without active session must throw SecurityException in headless test");
        }
    }
}
