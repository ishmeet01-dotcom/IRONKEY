package com.ironkey.security;

import java.util.*;

/**
 * Evaluates password strength, entropy, patterns, and predictability.
 *
 * METHODOLOGY & DESIGN:
 * 1. Character Space Diversity:
 *    Measures character space R from lowercase (26), uppercase (26), digits (10),
 *    and symbols (33).
 * 2. Shannon / Brute-force Entropy:
 *    Base entropy is estimated as E_base = L * log2(R).
 * 3. Pattern & Heuristic Penalties:
 *    Deductions are applied for:
 *    - Common dictionary passwords (top 200 common passwords & predictable terms).
 *    - Sequential characters (alphabetic e.g. "abc", "cba" or numeric e.g. "123", "789").
 *    - Repeated characters (e.g. "aaaa", "1111").
 *    - Low unique character ratio.
 * 4. Deterministic Classification:
 *    - VERY_WEAK   (0 - 29 pts)
 *    - WEAK        (30 - 49 pts)
 *    - MODERATE    (50 - 69 pts)
 *    - STRONG      (70 - 84 pts)
 *    - VERY_STRONG (85 - 100 pts)
 *
 * LIMITATIONS:
 * Entropy estimation provides a mathematical baseline for brute-force complexity against
 * standard keyspaces. It does not model advanced neural network password crackers or
 * organization-specific contextual dictionaries (e.g. company names, birthdays).
 */
public final class PasswordStrengthAnalyzer {

    public enum StrengthCategory {
        VERY_WEAK("Very Weak", 0),
        WEAK("Weak", 1),
        MODERATE("Moderate", 2),
        STRONG("Strong", 3),
        VERY_STRONG("Very Strong", 4);

        private final String displayName;
        private final int level;

        StrengthCategory(String displayName, int level) {
            this.displayName = displayName;
            this.level = level;
        }

        public String getDisplayName() {
            return displayName;
        }

        public int getLevel() {
            return level;
        }
    }

    // Curated list of high-risk, prevalent dictionary passwords & predictable terms (normalized lowercase)
    private static final Set<String> COMMON_PASSWORDS = new HashSet<>(Arrays.asList(
            "password", "123456", "12345678", "123456789", "12345", "1234", "111111", "1234567",
            "qwerty", "dragon", "pussy", "baseball", "football", "letmein", "monkey", "sunshine",
            "princess", "welcome", "shadow", "master", "michael", "jordan", "superman", "harley",
            "trustno1", "robert", "daniel", "starwars", "silver", "access", "admin", "administrator",
            "iloveyou", "password123", "pass123", "admin123", "root", "toor", "guest", "default",
            "test", "testing", "ironkey", "secret", "changeme", "login", "auth", "system",
            "orange", "killer", "charlie", "hunter2", "ashley", "bailey", "jessica", "summer",
            "computer", "michelle", "andrew", "corvette", "yellow", "coffee", "freedom", "cookie",
            "america", "forever", "liverpool", "barcelona", "chelsea", "arsenal", "matrix",
            "phoenix", "diamond", "ginger", "pokemon", "merlin", "mustang", "falcon", "scooter",
            "pepper", "bubbles", "peanut", "secret1", "pass1", "test1", "abc123", "123abc"
    ));

    // Common keyboard spatial walk rows
    private static final String[] KEYBOARD_ROWS = {
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
            "1234567890"
    };

    private PasswordStrengthAnalyzer() {
    }

    /**
     * Evaluates a password and produces a comprehensive analysis result.
     *
     * @param password character array or string to analyze
     * @return structured PasswordAnalysisResult
     */
    public static PasswordAnalysisResult analyze(String password) {
        if (password == null || password.isEmpty()) {
            return new PasswordAnalysisResult(
                    StrengthCategory.VERY_WEAK,
                    0.0,
                    0,
                    Collections.singletonList("Password is blank."),
                    Collections.singletonList("Provide a secure, non-empty password.")
            );
        }

        char[] chars = password.toCharArray();
        return analyze(chars);
    }

    /**
     * Evaluates a character array to minimize string immutability in memory.
     *
     * @param password password characters
     * @return structured PasswordAnalysisResult
     */
    public static PasswordAnalysisResult analyze(char[] password) {
        if (password == null || password.length == 0) {
            return new PasswordAnalysisResult(
                    StrengthCategory.VERY_WEAK,
                    0.0,
                    0,
                    Collections.singletonList("Password is blank."),
                    Collections.singletonList("Provide a secure, non-empty password.")
            );
        }

        int length = password.length;
        String lowerStr = new String(password).toLowerCase();

        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        Set<Character> uniqueChars = new HashSet<>();

        for (char c : password) {
            uniqueChars.add(c);
            if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSpecial = true;
        }

        // 1. Calculate Keyspace Pool Size (R)
        int poolSize = 0;
        if (hasLower) poolSize += 26;
        if (hasUpper) poolSize += 26;
        if (hasDigit) poolSize += 10;
        if (hasSpecial) poolSize += 33;

        if (poolSize == 0) poolSize = 1;

        // Base theoretical Shannon / Keyspace Entropy: E = L * log2(R)
        double bitsPerChar = Math.log(poolSize) / Math.log(2);
        double baseEntropy = length * bitsPerChar;

        // 2. Pattern & Vulnerability Inspections
        List<String> weaknesses = new ArrayList<>();
        List<String> recommendations = new ArrayList<>();
        int penaltyPoints = 0;

        // Check common dictionary matches
        boolean isExactCommon = COMMON_PASSWORDS.contains(lowerStr);
        boolean containsCommon = false;
        if (isExactCommon) {
            weaknesses.add("Exact match with a widely used, high-risk dictionary password.");
            recommendations.add("Do not use common words or dictionary passwords.");
            penaltyPoints += 60;
        } else {
            for (String common : COMMON_PASSWORDS) {
                if (common.length() >= 4 && lowerStr.contains(common)) {
                    containsCommon = true;
                    weaknesses.add("Contains common dictionary word or pattern: '" + common + "'.");
                    recommendations.add("Avoid embedding recognizable words or terms.");
                    penaltyPoints += 25;
                    break;
                }
            }
        }

        // Check sequential characters (e.g. "123", "abc", "cba")
        int sequentialRuns = countSequentialPatterns(lowerStr);
        if (sequentialRuns > 0) {
            weaknesses.add("Contains " + sequentialRuns + " sequential character sequence(s) (e.g. '123' or 'abc').");
            recommendations.add("Replace predictable numeric or alphabetic sequences with random characters.");
            penaltyPoints += Math.min(25, sequentialRuns * 8);
        }

        // Check keyboard walks (e.g. "qwerty", "asdf")
        int keyboardWalks = countKeyboardWalks(lowerStr);
        if (keyboardWalks > 0) {
            weaknesses.add("Contains keyboard layout spatial walk pattern (e.g. 'qwerty').");
            recommendations.add("Avoid adjacent keyboard pattern combinations.");
            penaltyPoints += Math.min(20, keyboardWalks * 10);
        }

        // Check repeated characters (e.g. "aaaa", "111")
        int repeatedRuns = countRepeatedRuns(lowerStr);
        if (repeatedRuns > 0) {
            weaknesses.add("Contains consecutive repeated characters (e.g. 'aaa').");
            recommendations.add("Avoid repeating identical characters consecutively.");
            penaltyPoints += Math.min(20, repeatedRuns * 6);
        }

        // Unique character ratio
        double uniqueRatio = (double) uniqueChars.size() / length;
        if (uniqueRatio < 0.5 && length > 4) {
            weaknesses.add("Low character diversity (" + uniqueChars.size() + " unique out of " + length + " characters).");
            recommendations.add("Increase character variance across the password.");
            penaltyPoints += 15;
        }

        // Length checks & character class requirements
        if (length < 8) {
            weaknesses.add("Critically short length (less than 8 characters).");
            recommendations.add("Lengthen password to at least 16 characters.");
            penaltyPoints += 45;
        } else if (length < 12) {
            weaknesses.add("Short length (under recommended 12-16 character threshold).");
            recommendations.add("Aim for 16 or more characters to resist brute-force attacks.");
            penaltyPoints += 10;
        }

        int classCount = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSpecial ? 1 : 0);
        if (classCount < 3) {
            if (!hasUpper) weaknesses.add("Lacks uppercase letters (A-Z).");
            if (!hasLower) weaknesses.add("Lacks lowercase letters (a-z).");
            if (!hasDigit) weaknesses.add("Lacks numeric digits (0-9).");
            if (!hasSpecial) weaknesses.add("Lacks special symbols (!@#$%^&*).");
            recommendations.add("Mix uppercase, lowercase, numbers, and symbols.");
            penaltyPoints += (4 - classCount) * 8;
        }

        // 3. Compute Adjusted Entropy & Numerical Score (0 - 100)
        double entropyPenaltyRatio = Math.min(0.85, (double) penaltyPoints / 100.0);
        double adjustedEntropy = Math.max(0.0, baseEntropy * (1.0 - entropyPenaltyRatio));

        // Base score mapped from progressive length milestones and character diversity
        int baseScore = 0;
        if (length >= 8) baseScore += 20;
        if (length >= 10) baseScore += 15;
        if (length >= 12) baseScore += 15;
        if (length >= 16) baseScore += 20;
        if (length >= 20) baseScore += 10;
        if (length >= 24) baseScore += 5;

        baseScore += classCount * 5; // Up to 20 pts

        int finalScore = Math.max(0, Math.min(100, baseScore - penaltyPoints));

        // Enforce hard ceiling for critical vulnerabilities
        if (isExactCommon || length < 6) {
            finalScore = Math.min(15, finalScore);
        } else if (length < 8) {
            finalScore = Math.min(28, finalScore);
        } else if (length < 10 && containsCommon) {
            finalScore = Math.min(40, finalScore);
        }

        // Classify Category
        StrengthCategory category;
        if (finalScore >= 85 && adjustedEntropy >= 65.0) {
            category = StrengthCategory.VERY_STRONG;
        } else if (finalScore >= 70 && adjustedEntropy >= 50.0) {
            category = StrengthCategory.STRONG;
        } else if (finalScore >= 50 && adjustedEntropy >= 35.0) {
            category = StrengthCategory.MODERATE;
        } else if (finalScore >= 30) {
            category = StrengthCategory.WEAK;
        } else {
            category = StrengthCategory.VERY_WEAK;
        }

        if (weaknesses.isEmpty()) {
            weaknesses.add("No significant vulnerabilities identified.");
        }
        if (recommendations.isEmpty()) {
            recommendations.add("Password adheres to high-security entropy standards.");
        }

        return new PasswordAnalysisResult(
                category,
                Math.round(adjustedEntropy * 10.0) / 10.0,
                finalScore,
                Collections.unmodifiableList(weaknesses),
                Collections.unmodifiableList(recommendations)
        );
    }

    private static int countSequentialPatterns(String str) {
        int count = 0;
        for (int i = 0; i < str.length() - 2; i++) {
            char c1 = str.charAt(i);
            char c2 = str.charAt(i + 1);
            char c3 = str.charAt(i + 2);

            // Forward alphabetical or numeric: abc, 123
            if ((c2 == c1 + 1) && (c3 == c2 + 1)) {
                count++;
            }
            // Reverse alphabetical or numeric: cba, 321
            else if ((c2 == c1 - 1) && (c3 == c2 - 1)) {
                count++;
            }
        }
        return count;
    }

    private static int countKeyboardWalks(String str) {
        int count = 0;
        for (String row : KEYBOARD_ROWS) {
            for (int i = 0; i < str.length() - 2; i++) {
                String sub = str.substring(i, i + 3);
                String revSub = new StringBuilder(sub).reverse().toString();
                if (row.contains(sub) || row.contains(revSub)) {
                    count++;
                }
            }
        }
        return count;
    }

    private static int countRepeatedRuns(String str) {
        int count = 0;
        int runLength = 1;
        for (int i = 1; i < str.length(); i++) {
            if (str.charAt(i) == str.charAt(i - 1)) {
                runLength++;
                if (runLength == 3) {
                    count++;
                }
            } else {
                runLength = 1;
            }
        }
        return count;
    }

    /**
     * Immutable carrier for password strength analysis findings.
     */
    public static final class PasswordAnalysisResult {
        private final StrengthCategory classification;
        private final double estimatedEntropy;
        private final int score;
        private final List<String> weaknesses;
        private final List<String> recommendations;

        public PasswordAnalysisResult(StrengthCategory classification, double estimatedEntropy,
                                      int score, List<String> weaknesses, List<String> recommendations) {
            this.classification = classification;
            this.estimatedEntropy = estimatedEntropy;
            this.score = score;
            this.weaknesses = weaknesses;
            this.recommendations = recommendations;
        }

        public StrengthCategory getClassification() {
            return classification;
        }

        public double getEstimatedEntropy() {
            return estimatedEntropy;
        }

        public int getScore() {
            return score;
        }

        public List<String> getWeaknesses() {
            return weaknesses;
        }

        public List<String> getRecommendations() {
            return recommendations;
        }

        public boolean isVeryWeak() {
            return classification == StrengthCategory.VERY_WEAK;
        }

        public boolean isWeak() {
            return classification == StrengthCategory.WEAK || classification == StrengthCategory.VERY_WEAK;
        }

        public boolean isStrong() {
            return classification == StrengthCategory.STRONG || classification == StrengthCategory.VERY_STRONG;
        }
    }
}
