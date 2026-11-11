package com.ironkey.security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Manages AES-256-GCM symmetric encryption and decryption of credentials.
 * Provides confidentiality, integrity, and authenticity verification through GCM authentication tags.
 *
 * SECURITY DESIGN:
 * Follows the standard NIST SP 800-38D / RFC 5116 format:
 *   [12-byte random IV/Nonce] || [AES-GCM Ciphertext] || [16-byte GCM Tag]
 *
 * Each encryption operation produces an independent 12-byte nonce, guaranteeing that
 * nonce reuse NEVER occurs even across multiple attributes of the same vault entry.
 */
public final class EncryptionManager {

    public static final String TRANSFORMATION = "AES/GCM/NoPadding";
    public static final int GCM_TAG_LENGTH_BITS = 128; // 16 bytes auth tag
    public static final int NONCE_LENGTH_BYTES = 12;   // 12 bytes recommended for GCM

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private EncryptionManager() {
    }

    /**
     * Generates a 12-byte cryptographically secure initialization vector (nonce).
     *
     * @return 12 random bytes
     */
    public static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(nonce);
        return nonce;
    }

    /**
     * Generates a 12-byte nonce encoded in Base64.
     *
     * @return Base64-encoded nonce
     */
    public static String generateNonceBase64() {
        return Base64.getEncoder().encodeToString(generateNonce());
    }

    /**
     * Encrypts plaintext string using AES-256-GCM with an automatically generated,
     * unique 12-byte nonce prepended to the ciphertext (NIST SP 800-38D standard).
     *
     * @param plaintext sensitive plaintext to encrypt
     * @param key       AES SecretKey
     * @return Base64-encoded payload containing [nonce || ciphertext || tag]
     * @throws GeneralSecurityException if encryption fails
     */
    public static String encrypt(String plaintext, SecretKey key) throws GeneralSecurityException {
        if (plaintext == null) {
            return null;
        }
        if (key == null) {
            throw new IllegalArgumentException("Encryption key cannot be null.");
        }
        byte[] nonce = generateNonce();
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] cipherWithTag = encrypt(plaintextBytes, key, nonce);

        byte[] combined = new byte[NONCE_LENGTH_BYTES + cipherWithTag.length];
        System.arraycopy(nonce, 0, combined, 0, NONCE_LENGTH_BYTES);
        System.arraycopy(cipherWithTag, 0, combined, NONCE_LENGTH_BYTES, cipherWithTag.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    /**
     * Decrypts a Base64-encoded self-contained payload [nonce || ciphertext || tag].
     *
     * @param combinedBase64 Base64 ciphertext with prepended nonce
     * @param key            AES SecretKey
     * @return decrypted plaintext string
     * @throws GeneralSecurityException if decryption or authentication tag verification fails
     */
    public static String decrypt(String combinedBase64, SecretKey key) throws GeneralSecurityException {
        if (combinedBase64 == null) {
            return null;
        }
        if (key == null) {
            throw new IllegalArgumentException("Decryption key cannot be null.");
        }

        byte[] combined = Base64.getDecoder().decode(combinedBase64);
        int minLength = NONCE_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8);
        if (combined.length < minLength) {
            throw new GeneralSecurityException("Ciphertext payload is truncated: minimum " + minLength + " bytes required.");
        }

        byte[] nonce = new byte[NONCE_LENGTH_BYTES];
        System.arraycopy(combined, 0, nonce, 0, NONCE_LENGTH_BYTES);

        byte[] cipherWithTag = new byte[combined.length - NONCE_LENGTH_BYTES];
        System.arraycopy(combined, NONCE_LENGTH_BYTES, cipherWithTag, 0, cipherWithTag.length);

        try {
            byte[] decryptedBytes = decrypt(cipherWithTag, key, nonce);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(nonce, (byte) 0);
        }
    }

    /**
     * Encrypts plaintext string using AES-256-GCM with an explicit nonce.
     *
     * @param plaintext sensitive plaintext to encrypt
     * @param key       AES SecretKey
     * @param nonce     12-byte initialization vector
     * @return Base64-encoded ciphertext (including GCM auth tag)
     * @throws GeneralSecurityException if encryption fails
     */
    public static String encrypt(String plaintext, SecretKey key, byte[] nonce) throws GeneralSecurityException {
        if (plaintext == null) {
            return null;
        }
        if (key == null) {
            throw new IllegalArgumentException("Encryption key cannot be null.");
        }
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = encrypt(plaintextBytes, key, nonce);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    /**
     * Encrypts raw plaintext bytes using AES-256-GCM.
     *
     * @param plaintextBytes raw bytes
     * @param key            AES SecretKey
     * @param nonce          12-byte initialization vector
     * @return ciphertext bytes with appended 128-bit authentication tag
     * @throws GeneralSecurityException if encryption fails
     */
    public static byte[] encrypt(byte[] plaintextBytes, SecretKey key, byte[] nonce) throws GeneralSecurityException {
        if (key == null) {
            throw new IllegalArgumentException("Encryption key cannot be null.");
        }
        if (nonce == null || nonce.length != NONCE_LENGTH_BYTES) {
            throw new IllegalArgumentException("GCM nonce must be exactly " + NONCE_LENGTH_BYTES + " bytes.");
        }
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        return cipher.doFinal(plaintextBytes);
    }

    /**
     * Decrypts Base64 ciphertext using AES-256-GCM with an explicit nonce.
     *
     * @param ciphertextBase64 Base64 ciphertext
     * @param key              AES SecretKey
     * @param nonce            12-byte initialization vector
     * @return decrypted plaintext string
     * @throws GeneralSecurityException if decryption or authentication tag verification fails
     */
    public static String decrypt(String ciphertextBase64, SecretKey key, byte[] nonce) throws GeneralSecurityException {
        if (ciphertextBase64 == null) {
            return null;
        }
        if (key == null) {
            throw new IllegalArgumentException("Decryption key cannot be null.");
        }
        byte[] ciphertext = Base64.getDecoder().decode(ciphertextBase64);
        byte[] decrypted = decrypt(ciphertext, key, nonce);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    /**
     * Decrypts raw ciphertext bytes using AES-256-GCM.
     *
     * @param ciphertextBytes raw ciphertext with tag
     * @param key             AES SecretKey
     * @param nonce           12-byte initialization vector
     * @return raw decrypted bytes
     * @throws GeneralSecurityException if decryption or authentication tag verification fails
     */
    public static byte[] decrypt(byte[] ciphertextBytes, SecretKey key, byte[] nonce) throws GeneralSecurityException {
        if (key == null) {
            throw new IllegalArgumentException("Decryption key cannot be null.");
        }
        if (nonce == null || nonce.length != NONCE_LENGTH_BYTES) {
            throw new IllegalArgumentException("GCM nonce must be exactly " + NONCE_LENGTH_BYTES + " bytes.");
        }
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        return cipher.doFinal(ciphertextBytes);
    }
}
