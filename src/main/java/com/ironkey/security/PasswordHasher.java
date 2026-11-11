package com.ironkey.security;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Handles master password hashing using PBKDF2WithHmacSHA256.
 * Enforces OWASP-recommended iteration counts and constant-time comparison.
 *
 * Note: Authentication hashing is strictly separate from vault key derivation.
 */
public final class PasswordHasher {

    public static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int ITERATIONS = 310_000; // OWASP recommendation for PBKDF2-HMAC-SHA256
    public static final int HASH_LENGTH_BITS = 256;
    public static final int SALT_LENGTH_BYTES = 16;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private PasswordHasher() {
    }

    /**
     * Generates a cryptographically secure random salt.
     *
     * @return Base64-encoded salt string
     */
    public static String generateSalt() {
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Hashes a master password with a given salt using PBKDF2WithHmacSHA256.
     *
     * @param password char array of master password
     * @param saltBase64 Base64-encoded salt
     * @return Base64-encoded PBKDF2 hash
     */
    public static String hashPassword(char[] password, String saltBase64) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password cannot be empty.");
        }
        if (saltBase64 == null || saltBase64.trim().isEmpty()) {
            throw new IllegalArgumentException("Salt cannot be empty.");
        }

        byte[] salt = Base64.getDecoder().decode(saltBase64);
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, HASH_LENGTH_BITS);

        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new SecurityException("Failed to hash password with " + ALGORITHM, e);
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * Verifies an entered password against a stored PBKDF2 hash using constant-time comparison
     * to prevent timing attacks.
     *
     * @param enteredPassword candidate master password
     * @param saltBase64      Base64 salt
     * @param expectedHash    Base64 expected hash
     * @return true if password matches
     */
    public static boolean verifyPassword(char[] enteredPassword, String saltBase64, String expectedHash) {
        if (enteredPassword == null || saltBase64 == null || expectedHash == null) {
            return false;
        }

        String computedHash = hashPassword(enteredPassword, saltBase64);
        byte[] computedBytes = Base64.getDecoder().decode(computedHash);
        byte[] expectedBytes = Base64.getDecoder().decode(expectedHash);

        return MessageDigest.isEqual(computedBytes, expectedBytes);
    }
}
