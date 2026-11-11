package com.ironkey;

import com.ironkey.security.PasswordStrengthAnalyzer;
import com.ironkey.security.PasswordStrengthAnalyzer.PasswordAnalysisResult;
import com.ironkey.security.PasswordStrengthAnalyzer.StrengthCategory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 5: Automated Test Suite for PasswordStrengthAnalyzer.
 * Verifies entropy estimation, common dictionary word detection, sequential patterns,
 * character diversity, and deterministic strength classification.
 */
class PasswordStrengthAnalyzerTest {

    @Test
    @DisplayName("1. Blank and null passwords are classified as VERY_WEAK with zero score")
    void testBlankAndNullPasswords() {
        PasswordAnalysisResult res1 = PasswordStrengthAnalyzer.analyze((String) null);
        assertEquals(StrengthCategory.VERY_WEAK, res1.getClassification());
        assertEquals(0, res1.getScore());
        assertEquals(0.0, res1.getEstimatedEntropy());
        assertTrue(res1.isVeryWeak());

        PasswordAnalysisResult res2 = PasswordStrengthAnalyzer.analyze("");
        assertEquals(StrengthCategory.VERY_WEAK, res2.getClassification());
        assertEquals(0, res2.getScore());

        PasswordAnalysisResult res3 = PasswordStrengthAnalyzer.analyze(new char[0]);
        assertEquals(StrengthCategory.VERY_WEAK, res3.getClassification());
    }

    @ParameterizedTest
    @ValueSource(strings = {"password", "123456", "admin", "welcome", "qwerty", "iloveyou", "letmein"})
    @DisplayName("2. Prevalent dictionary passwords receive severe penalties and VERY_WEAK classification")
    void testCommonDictionaryPasswords(String commonPass) {
        PasswordAnalysisResult result = PasswordStrengthAnalyzer.analyze(commonPass);
        assertEquals(StrengthCategory.VERY_WEAK, result.getClassification(),
                "Common password '" + commonPass + "' must be classified as VERY_WEAK");
        assertTrue(result.getScore() <= 20, "Score must be heavily penalised for dictionary word");
        assertTrue(result.getWeaknesses().stream().anyMatch(w -> w.toLowerCase().contains("dictionary") || w.toLowerCase().contains("common")),
                "Weaknesses must mention dictionary or common word");
    }

    @Test
    @DisplayName("3. Predictable sequential character runs (e.g. 123, abc) are detected and penalized")
    void testSequentialPatterns() {
        PasswordAnalysisResult result = PasswordStrengthAnalyzer.analyze("abc123XYZ!");
        assertTrue(result.getWeaknesses().stream().anyMatch(w -> w.contains("sequential")),
                "Must flag sequential characters");
        assertTrue(result.getScore() < 70, "Sequential patterns must reduce the score");
    }

    @Test
    @DisplayName("4. Consecutive repeated characters (e.g. aaaa, 1111) are detected and penalized")
    void testRepeatedCharacters() {
        PasswordAnalysisResult result = PasswordStrengthAnalyzer.analyze("aaaa1111!!!!");
        assertTrue(result.getWeaknesses().stream().anyMatch(w -> w.contains("repeated")),
                "Must flag repeated characters");
    }

    @Test
    @DisplayName("5. Short length cannot be compensated for by character diversity alone")
    void testShortLengthWithHighDiversity() {
        // Contains upper, lower, digit, symbol, but only 4 characters
        PasswordAnalysisResult result = PasswordStrengthAnalyzer.analyze("A1!b");
        assertEquals(StrengthCategory.VERY_WEAK, result.getClassification(),
                "4-character password must remain VERY_WEAK despite full character class diversity");
        assertTrue(result.getScore() <= 28, "Score must be capped due to dangerously short length");
        assertTrue(result.getWeaknesses().stream().anyMatch(w -> w.contains("short length")),
                "Must note short length weakness");
    }

    @Test
    @DisplayName("6. Keyboard walk patterns (e.g. qwerty, asdf) are detected")
    void testKeyboardWalks() {
        PasswordAnalysisResult result = PasswordStrengthAnalyzer.analyze("qwertyuiop");
        assertTrue(result.getWeaknesses().stream().anyMatch(w -> w.contains("keyboard") || w.contains("dictionary")),
                "Must flag keyboard walk or common word");
        assertTrue(result.isVeryWeak());
    }

    @Test
    @DisplayName("7. High-entropy, randomized passwords are classified as VERY_STRONG")
    void testStrongAndVeryStrongPasswords() {
        // 18 characters, high entropy, no patterns
        String strongPass = "K9#mX2$vL8*qP4!zR1";
        PasswordAnalysisResult result = PasswordStrengthAnalyzer.analyze(strongPass);

        assertEquals(StrengthCategory.VERY_STRONG, result.getClassification());
        assertTrue(result.getScore() >= 85, "Score must be in VERY_STRONG tier");
        assertTrue(result.getEstimatedEntropy() >= 65.0, "Entropy must exceed 65 bits");
        assertTrue(result.isStrong());
        assertFalse(result.isWeak());
    }

    @Test
    @DisplayName("8. Missing character classes generate specific actionable recommendations")
    void testMissingCharacterClasses() {
        PasswordAnalysisResult result = PasswordStrengthAnalyzer.analyze("alllowercaselettersonly");
        assertTrue(result.getWeaknesses().stream().anyMatch(w -> w.contains("uppercase")), "Must identify missing uppercase");
        assertTrue(result.getWeaknesses().stream().anyMatch(w -> w.contains("digits")), "Must identify missing digits");
        assertTrue(result.getWeaknesses().stream().anyMatch(w -> w.contains("symbols")), "Must identify missing symbols");
    }

    @Test
    @DisplayName("9. Moderate password classification for intermediate complexity")
    void testModeratePassword() {
        // 10 characters, upper, lower, digits, but under 12 length
        PasswordAnalysisResult result = PasswordStrengthAnalyzer.analyze("Berlin2024!");
        assertTrue(result.getClassification() == StrengthCategory.MODERATE || result.getClassification() == StrengthCategory.WEAK);
        assertTrue(result.getScore() >= 30 && result.getScore() <= 70);
    }
}
