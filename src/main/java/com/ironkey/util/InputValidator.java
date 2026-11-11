package com.ironkey.util;

import java.util.regex.Pattern;

/**
 * Validates user inputs across authentication and vault forms.
 * Enforces strong security requirements and prevents malformed data entry.
 */
public final class InputValidator {

    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_.-]{3,30}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final Pattern URL_PATTERN = Pattern.compile("^(https?://)?[a-zA-Z0-9.-]+(?:\\.[a-zA-Z]{2,})+(?::[0-9]{1,5})?(?:/[^\\s]*)?$");

    private InputValidator() {
    }

    /**
     * Validates username requirements: 3-30 characters, alphanumeric, dots, dashes, underscores.
     *
     * @param username username string
     * @return ValidationResult indicating valid or failure reason
     */
    public static ValidationResult validateUsername(String username) {
        if (username == null || username.trim().isEmpty()) {
            return ValidationResult.error("Username cannot be empty.");
        }
        String trimmed = username.trim();
        if (trimmed.length() < 3 || trimmed.length() > 30) {
            return ValidationResult.error("Username must be between 3 and 30 characters.");
        }
        if (!USERNAME_PATTERN.matcher(trimmed).matches()) {
            return ValidationResult.error("Username may only contain letters, numbers, periods, dashes, or underscores.");
        }
        return ValidationResult.ok();
    }

    /**
     * Validates email format according to standard structure.
     *
     * @param email email string
     * @return ValidationResult
     */
    public static ValidationResult validateEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            return ValidationResult.error("Email address cannot be empty.");
        }
        String trimmed = email.trim();
        if (!EMAIL_PATTERN.matcher(trimmed).matches()) {
            return ValidationResult.error("Please enter a valid email address (e.g., user@domain.com).");
        }
        return ValidationResult.ok();
    }

    /**
     * Validates master password strength.
     * Requirements: at least 10 characters, including lowercase, uppercase, number, and special character.
     *
     * @param password character array of the password
     * @return ValidationResult
     */
    public static ValidationResult validateMasterPassword(char[] password) {
        if (password == null || password.length == 0) {
            return ValidationResult.error("Master password cannot be empty.");
        }
        if (password.length < 10) {
            return ValidationResult.error("Master password must be at least 10 characters long.");
        }

        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (char c : password) {
            if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSpecial = true;
        }

        if (!hasUpper) return ValidationResult.error("Master password must contain at least one uppercase letter.");
        if (!hasLower) return ValidationResult.error("Master password must contain at least one lowercase letter.");
        if (!hasDigit) return ValidationResult.error("Master password must contain at least one digit.");
        if (!hasSpecial) return ValidationResult.error("Master password must contain at least one special character.");

        return ValidationResult.ok();
    }

    /**
     * Validates optional website URL.
     *
     * @param url URL string
     * @return ValidationResult
     */
    public static ValidationResult validateUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            return ValidationResult.ok(); // Optional field
        }
        if (!URL_PATTERN.matcher(url.trim()).matches()) {
            return ValidationResult.error("Please enter a valid website URL (e.g. https://example.com).");
        }
        return ValidationResult.ok();
    }

    /**
     * Data structure encapsulating validation outcome.
     */
    public static class ValidationResult {
        private final boolean valid;
        private final String message;

        private ValidationResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }

        public static ValidationResult ok() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult error(String message) {
            return new ValidationResult(false, message);
        }

        public boolean isValid() {
            return valid;
        }

        public String getMessage() {
            return message;
        }
    }
}
