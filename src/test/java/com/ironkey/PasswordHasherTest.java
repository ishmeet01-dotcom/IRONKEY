package com.ironkey;

import com.ironkey.security.KeyDerivationService;
import com.ironkey.security.PasswordHasher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.*;

class PasswordHasherTest {

    @Test
    @DisplayName("Should successfully hash and verify password with constant-time comparison")
    void testPasswordHashingAndVerification() {
        char[] password = "SecureMasterPassword#2026".toCharArray();
        String salt = PasswordHasher.generateSalt();
        assertNotNull(salt);
        assertFalse(salt.isEmpty());

        String hash = PasswordHasher.hashPassword(password, salt);
        assertNotNull(hash);

        // Verification should succeed with identical password
        assertTrue(PasswordHasher.verifyPassword(password, salt, hash));

        // Verification should fail with wrong password
        assertFalse(PasswordHasher.verifyPassword("WrongPassword#999".toCharArray(), salt, hash));
    }

    @Test
    @DisplayName("Authentication hash and Vault Key must be completely separate cryptographic outputs")
    void testAuthHashAndKeyDerivationSeparation() {
        char[] password = "IdenticalPassword#12345".toCharArray();
        String authSalt = PasswordHasher.generateSalt();
        String kdfSalt = KeyDerivationService.generateKeyDerivationSalt();

        String authHash = PasswordHasher.hashPassword(password, authSalt);
        SecretKey vaultKey = KeyDerivationService.deriveVaultKey(password, kdfSalt);

        // Secret key bytes must not match authentication hash
        byte[] keyBytes = vaultKey.getEncoded();
        assertNotEquals(authHash, java.util.Base64.getEncoder().encodeToString(keyBytes),
                "Authentication hash must NEVER match derived AES vault encryption key.");
    }
}
