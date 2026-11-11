package com.ironkey.security;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Utility to generate cryptographically strong, customizable passwords
 * and calculate password entropy/strength scores.
 */
public final class PasswordGenerator {

    public static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    public static final String DIGITS = "0123456789";
    public static final String SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?";
    public static final String AMBIGUOUS = "0Ool1I";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private PasswordGenerator() {
    }

    /**
     * Generates a strong password with default settings (length 18, all character sets enabled).
     *
     * @return generated password
     */
    public static String generateDefault() {
        return generate(18, true, true, true, true, false);
    }

    /**
     * Generates a customized secure password.
     *
     * @param length           desired password length (min 8, max 128)
     * @param useUpper         include uppercase characters
     * @param useLower         include lowercase characters
     * @param useDigits        include numeric digits
     * @param useSpecial       include special characters
     * @param excludeAmbiguous exclude ambiguous characters like 0/O, 1/l/I
     * @return generated password string
     */
    public static String generate(int length, boolean useUpper, boolean useLower,
                                  boolean useDigits, boolean useSpecial, boolean excludeAmbiguous) {
        if (length < 8) length = 8;
        if (length > 128) length = 128;

        StringBuilder pool = new StringBuilder();
        List<Character> mandatory = new ArrayList<>();

        if (useUpper) {
            String chars = filter(UPPERCASE, excludeAmbiguous);
            pool.append(chars);
            mandatory.add(chars.charAt(SECURE_RANDOM.nextInt(chars.length())));
        }
        if (useLower) {
            String chars = filter(LOWERCASE, excludeAmbiguous);
            pool.append(chars);
            mandatory.add(chars.charAt(SECURE_RANDOM.nextInt(chars.length())));
        }
        if (useDigits) {
            String chars = filter(DIGITS, excludeAmbiguous);
            pool.append(chars);
            mandatory.add(chars.charAt(SECURE_RANDOM.nextInt(chars.length())));
        }
        if (useSpecial) {
            String chars = filter(SPECIAL, excludeAmbiguous);
            pool.append(chars);
            mandatory.add(chars.charAt(SECURE_RANDOM.nextInt(chars.length())));
        }

        if (pool.length() == 0) {
            // Fallback if nothing was selected
            pool.append(LOWERCASE).append(DIGITS);
        }

        List<Character> result = new ArrayList<>(mandatory);
        int remaining = length - mandatory.size();
        for (int i = 0; i < remaining; i++) {
            int idx = SECURE_RANDOM.nextInt(pool.length());
            result.add(pool.charAt(idx));
        }

        // Shuffle to avoid predictable character group positions
        Collections.shuffle(result, SECURE_RANDOM);

        StringBuilder sb = new StringBuilder(length);
        for (char c : result) {
            sb.append(c);
        }
        return sb.toString();
    }

    private static String filter(String source, boolean excludeAmbiguous) {
        if (!excludeAmbiguous) return source;
        StringBuilder sb = new StringBuilder();
        for (char c : source.toCharArray()) {
            if (AMBIGUOUS.indexOf(c) == -1) {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Calculates theoretical entropy in bits based on length and active character sets:
     * Entropy = Length * log2(PoolSize)
     *
     * @param length     password length
     * @param useUpper   include uppercase
     * @param useLower   include lowercase
     * @param useDigits  include digits
     * @param useSpecial include symbols
     * @return entropy in bits
     */
    public static double calculateEntropy(int length, boolean useUpper, boolean useLower,
                                          boolean useDigits, boolean useSpecial) {
        int poolSize = 0;
        if (useLower) poolSize += 26;
        if (useUpper) poolSize += 26;
        if (useDigits) poolSize += 10;
        if (useSpecial) poolSize += 33;

        if (poolSize == 0 || length <= 0) return 0.0;
        double bits = length * (Math.log(poolSize) / Math.log(2));
        return Math.round(bits * 10.0) / 10.0;
    }

    /**
     * Calculates an approximate password strength score between 0 and 100
     * using the unified PasswordStrengthAnalyzer engine.
     *
     * @param password candidate password
     * @return strength score (0 = very weak, 100 = very strong)
     */
    public static int calculateStrength(char[] password) {
        return PasswordStrengthAnalyzer.analyze(password).getScore();
    }
}
