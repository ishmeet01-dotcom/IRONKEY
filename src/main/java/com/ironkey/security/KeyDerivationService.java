package com.ironkey.security;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Dedicated service to derive the AES-256 vault encryption key from the master password.
 *
 * CRITICAL ARCHITECTURAL SEPARATION:
 * This service is strictly separate from {@link PasswordHasher}. The authentication hash
 * is NEVER reused as an encryption key. Even if the authentication database is compromised,
 * an attacker cannot decrypt vault credentials without knowing the master password and key derivation salt.
 */
public final class KeyDerivationService {

    public static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int KEY_LENGTH_BITS = 256;
    public static final int KDF_ITERATIONS = 310_000;
    public static final int SALT_LENGTH_BYTES = 32;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private KeyDerivationService() {
    }

    /**
     * Generates a unique cryptographically secure salt specifically for key derivation.
     *
     * @return Base64-encoded salt
     */
    public static String generateKeyDerivationSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Derives an AES-256 SecretKey from the master password and a distinct key derivation salt.
     *
     * @param masterPassword          the user's master password
     * @param keyDerivationSaltBase64 the unique salt assigned to the user for key derivation
     * @return SecretKey suitable for AES-256-GCM encryption/decryption
     */
    public static SecretKey deriveVaultKey(char[] masterPassword, String keyDerivationSaltBase64) {
        if (masterPassword == null || masterPassword.length == 0) {
            throw new IllegalArgumentException("Master password cannot be empty.");
        }
        if (keyDerivationSaltBase64 == null || keyDerivationSaltBase64.trim().isEmpty()) {
            throw new IllegalArgumentException("Key derivation salt cannot be empty.");
        }

        byte[] salt = Base64.getDecoder().decode(keyDerivationSaltBase64);
        PBEKeySpec spec = new PBEKeySpec(masterPassword, salt, KDF_ITERATIONS, KEY_LENGTH_BITS);

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGORITHM);
            byte[] rawKey = factory.generateSecret(spec).getEncoded();
            try {
                return new SecretKeySpec(rawKey, "AES");
            } finally {
                // Scrub temporary raw key buffer
                Arrays.fill(rawKey, (byte) 0);
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new SecurityException("Failed to derive vault key using " + KDF_ALGORITHM, e);
        } finally {
            spec.clearPassword();
        }
    }
}
