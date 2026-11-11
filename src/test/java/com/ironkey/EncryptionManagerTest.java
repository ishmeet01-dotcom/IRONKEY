package com.ironkey;

import com.ironkey.security.EncryptionManager;
import com.ironkey.security.KeyDerivationService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionManagerTest {

    @Test
    @DisplayName("Should successfully encrypt and decrypt string using AES-256-GCM")
    void testEncryptDecryptSuccess() throws GeneralSecurityException {
        char[] masterPass = "SuperSecretPassphrase#2026!".toCharArray();
        String salt = KeyDerivationService.generateKeyDerivationSalt();
        SecretKey vaultKey = KeyDerivationService.deriveVaultKey(masterPass, salt);

        byte[] nonce = EncryptionManager.generateNonce();
        assertEquals(12, nonce.length, "GCM nonce must be 12 bytes");

        String plaintext = "SuperVaultPassword_XYZ!#$";
        String ciphertext = EncryptionManager.encrypt(plaintext, vaultKey, nonce);

        assertNotNull(ciphertext);
        assertNotEquals(plaintext, ciphertext);

        String decrypted = EncryptionManager.decrypt(ciphertext, vaultKey, nonce);
        assertEquals(plaintext, decrypted, "Decrypted text must match original plaintext");
    }

    @Test
    @DisplayName("Should fail decryption if ciphertext or authentication tag is tampered with")
    void testGcmIntegrityVerificationFailsOnTampering() throws GeneralSecurityException {
        char[] masterPass = "MasterKey@12345678".toCharArray();
        String salt = KeyDerivationService.generateKeyDerivationSalt();
        SecretKey vaultKey = KeyDerivationService.deriveVaultKey(masterPass, salt);
        byte[] nonce = EncryptionManager.generateNonce();

        String plaintext = "SecretPayload";
        String ciphertextBase64 = EncryptionManager.encrypt(plaintext, vaultKey, nonce);

        byte[] cipherBytes = Base64.getDecoder().decode(ciphertextBase64);
        // Tamper with the last byte (part of authentication tag)
        cipherBytes[cipherBytes.length - 1] ^= 0x01;
        String tamperedCiphertext = Base64.getEncoder().encodeToString(cipherBytes);

        assertThrows(GeneralSecurityException.class, () -> {
            EncryptionManager.decrypt(tamperedCiphertext, vaultKey, nonce);
        }, "Tampered ciphertext must cause GeneralSecurityException due to tag mismatch");
    }

    @Test
    @DisplayName("Should fail decryption if wrong key is used")
    void testDecryptionWithWrongKeyFails() throws GeneralSecurityException {
        SecretKey correctKey = KeyDerivationService.deriveVaultKey("CorrectKey#12345".toCharArray(), KeyDerivationService.generateKeyDerivationSalt());
        SecretKey wrongKey = KeyDerivationService.deriveVaultKey("WrongKey#9999999".toCharArray(), KeyDerivationService.generateKeyDerivationSalt());
        byte[] nonce = EncryptionManager.generateNonce();

        String plaintext = "SecretData";
        String ciphertext = EncryptionManager.encrypt(plaintext, correctKey, nonce);

        assertThrows(GeneralSecurityException.class, () -> {
            EncryptionManager.decrypt(ciphertext, wrongKey, nonce);
        });
    }
}
