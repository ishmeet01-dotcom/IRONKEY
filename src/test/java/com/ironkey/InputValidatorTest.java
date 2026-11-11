package com.ironkey;

import com.ironkey.util.InputValidator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class InputValidatorTest {

    @Test
    @DisplayName("Should validate username constraints")
    void testUsernameValidation() {
        assertTrue(InputValidator.validateUsername("alex_99").isValid());
        assertTrue(InputValidator.validateUsername("john.doe").isValid());

        assertFalse(InputValidator.validateUsername("").isValid());
        assertFalse(InputValidator.validateUsername("al").isValid(), "Too short (< 3)");
        assertFalse(InputValidator.validateUsername("alex; DROP TABLE users;").isValid(), "Illegal chars");
    }

    @Test
    @DisplayName("Should validate email format")
    void testEmailValidation() {
        assertTrue(InputValidator.validateEmail("user@domain.com").isValid());
        assertTrue(InputValidator.validateEmail("test.user+vault@sub.domain.org").isValid());

        assertFalse(InputValidator.validateEmail("invalid-email").isValid());
        assertFalse(InputValidator.validateEmail("@nodomain.com").isValid());
        assertFalse(InputValidator.validateEmail("user@").isValid());
    }

    @Test
    @DisplayName("Should validate master password strength")
    void testMasterPasswordValidation() {
        // Strong password: >= 10 chars, upper, lower, digit, special
        assertTrue(InputValidator.validateMasterPassword("StrongP@ssw0rd!".toCharArray()).isValid());

        // Weak: too short
        assertFalse(InputValidator.validateMasterPassword("Short#1".toCharArray()).isValid());

        // Weak: no uppercase
        assertFalse(InputValidator.validateMasterPassword("weakpassword123!".toCharArray()).isValid());

        // Weak: no digit
        assertFalse(InputValidator.validateMasterPassword("NoDigitsInThisPass!".toCharArray()).isValid());

        // Weak: no special char
        assertFalse(InputValidator.validateMasterPassword("NoSpecialChars12345".toCharArray()).isValid());
    }
}
