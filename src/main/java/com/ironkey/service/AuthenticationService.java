package com.ironkey.service;

import com.ironkey.config.DatabaseConfig;
import com.ironkey.dao.CategoryDAO;
import com.ironkey.dao.SecurityLogDAO;
import com.ironkey.dao.UserDAO;
import com.ironkey.model.Category;
import com.ironkey.model.SecurityLog;
import com.ironkey.model.User;
import com.ironkey.security.KeyDerivationService;
import com.ironkey.security.PasswordHasher;
import com.ironkey.util.InputValidator;
import com.ironkey.util.SessionManager;

import javax.crypto.SecretKey;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Optional;

/**
 * Service managing user registration, authentication, and session lifecycle.
 * Coordinates cryptographic key derivation with ACID database transactions.
 * Enforces zero-knowledge isolation and constant-time authentication.
 */
public class AuthenticationService {

    // Constant dummy Base64 salt used to eliminate user-enumeration timing attacks
    private static final String DUMMY_SALT = "c29tZWR1bW15c2FsdGZvcmNvbnN0YW50dGltZQ==";

    private final UserDAO userDAO;
    private final SecurityLogDAO securityLogDAO;
    private final CategoryDAO categoryDAO;
    private final SessionManager sessionManager;
    private final DatabaseConfig databaseConfig;

    public AuthenticationService() {
        this(new UserDAO(), new SecurityLogDAO(), new CategoryDAO(), SessionManager.getInstance(), DatabaseConfig.getInstance());
    }

    public AuthenticationService(UserDAO userDAO, SecurityLogDAO securityLogDAO,
                                 CategoryDAO categoryDAO, SessionManager sessionManager) {
        this(userDAO, securityLogDAO, categoryDAO, sessionManager, null);
    }

    public AuthenticationService(UserDAO userDAO, SecurityLogDAO securityLogDAO,
                                 CategoryDAO categoryDAO, SessionManager sessionManager,
                                 DatabaseConfig databaseConfig) {
        this.userDAO = userDAO;
        this.securityLogDAO = securityLogDAO;
        this.categoryDAO = categoryDAO;
        this.sessionManager = sessionManager;
        this.databaseConfig = databaseConfig;
    }

    /**
     * Registers a new user account with password confirmation validation.
     *
     * @param username        unique username
     * @param email           unique email
     * @param masterPassword  master password character array
     * @param confirmPassword confirmation password character array
     * @return registered User instance
     * @throws IllegalArgumentException if validation fails or passwords do not match
     * @throws SQLException             if database operations fail
     */
    public User register(String username, String email, char[] masterPassword, char[] confirmPassword) throws SQLException {
        if (confirmPassword == null || !Arrays.equals(masterPassword, confirmPassword)) {
            throw new IllegalArgumentException("Master passwords do not match.");
        }
        return register(username, email, masterPassword);
    }

    /**
     * Registers a new user account.
     * Generates independent cryptographic salts for authentication and vault key derivation.
     * Executes within an ACID database transaction.
     *
     * @param username       unique username
     * @param email          unique email
     * @param masterPassword master password character array
     * @return registered User instance
     * @throws IllegalArgumentException if input validation fails or duplicates exist
     * @throws SQLException             if database operations fail
     */
    public User register(String username, String email, char[] masterPassword) throws SQLException {
        // 1. Input Validation
        InputValidator.ValidationResult userVal = InputValidator.validateUsername(username);
        if (!userVal.isValid()) {
            throw new IllegalArgumentException(userVal.getMessage());
        }

        InputValidator.ValidationResult emailVal = InputValidator.validateEmail(email);
        if (!emailVal.isValid()) {
            throw new IllegalArgumentException(emailVal.getMessage());
        }

        InputValidator.ValidationResult passVal = InputValidator.validateMasterPassword(masterPassword);
        if (!passVal.isValid()) {
            throw new IllegalArgumentException(passVal.getMessage());
        }

        String normalizedUsername = username.trim();
        String normalizedEmail = email.trim().toLowerCase();

        // 2. Duplicate checks
        if (userDAO.existsByUsername(normalizedUsername)) {
            throw new IllegalArgumentException("Username is already taken.");
        }
        if (userDAO.existsByEmail(normalizedEmail)) {
            throw new IllegalArgumentException("An account with this email already exists.");
        }

        // 3. Generate distinct, independent cryptographic salts
        String authSalt = PasswordHasher.generateSalt();
        String keyDerivationSalt = KeyDerivationService.generateKeyDerivationSalt();

        // 4. Hash master password for authentication (PBKDF2WithHmacSHA256, 310k iterations)
        String passwordHash = PasswordHasher.hashPassword(masterPassword, authSalt);

        User newUser = new User(normalizedUsername, normalizedEmail, passwordHash, authSalt, keyDerivationSalt);

        // 5. Transactional Persistence: User + Default Categories + Audit Log
        User savedUser;
        if (databaseConfig != null && databaseConfig.isDriverLoaded()) {
            try (Connection conn = databaseConfig.getConnection()) {
                boolean initialAutoCommit = conn.getAutoCommit();
                conn.setAutoCommit(false);
                try {
                    savedUser = userDAO.save(newUser, conn);

                    // Seed standard starter categories for the new user
                    categoryDAO.save(new Category(savedUser.getUserId(), "Logins", "key"), conn);
                    categoryDAO.save(new Category(savedUser.getUserId(), "Financial", "credit-card"), conn);
                    categoryDAO.save(new Category(savedUser.getUserId(), "Secure Notes", "file-text"), conn);
                    categoryDAO.save(new Category(savedUser.getUserId(), "Identities", "user"), conn);
                    categoryDAO.save(new Category(savedUser.getUserId(), "Servers & SSH", "server"), conn);

                    // Record registration audit log
                    securityLogDAO.logEvent(new SecurityLog(savedUser.getUserId(), "USER_REGISTERED", "User vault initialized."), conn);

                    conn.commit();
                } catch (Exception ex) {
                    conn.rollback();
                    throw ex;
                } finally {
                    conn.setAutoCommit(initialAutoCommit);
                }
            } catch (SQLException e) {
                // If direct JDBC transaction fails or connection error, rethrow
                throw e;
            }
        } else {
            // Standalone or mock DAO fallback (e.g. during isolated unit tests)
            savedUser = userDAO.save(newUser);
            try {
                categoryDAO.save(new Category(savedUser.getUserId(), "Logins", "key"));
                categoryDAO.save(new Category(savedUser.getUserId(), "Financial", "credit-card"));
                categoryDAO.save(new Category(savedUser.getUserId(), "Secure Notes", "file-text"));
                securityLogDAO.logEvent(new SecurityLog(savedUser.getUserId(), "USER_REGISTERED", "User vault initialized."));
            } catch (Exception ex) {
                try {
                    userDAO.delete(savedUser.getUserId());
                } catch (Exception ignored) {
                }
                throw ex;
            }
        }

        return savedUser;
    }

    /**
     * Authenticates a user and derives their private AES-256 vault encryption key.
     * Prevents timing attacks and account enumeration by always executing a constant-time hashing operation.
     *
     * @param identifier     username or email
     * @param masterPassword master password character array
     * @return authenticated User entity
     * @throws AuthenticationException if authentication fails
     * @throws SQLException            if a database access error occurs
     */
    public User login(String identifier, char[] masterPassword) throws AuthenticationException, SQLException {
        if (identifier == null || identifier.trim().isEmpty()) {
            throw new AuthenticationException("Email or username is required.");
        }
        if (masterPassword == null || masterPassword.length == 0) {
            throw new AuthenticationException("Master password is required.");
        }

        String rawId = identifier.trim();
        Optional<User> userOpt;

        if (rawId.contains("@")) {
            userOpt = userDAO.findByEmail(rawId.toLowerCase());
        } else {
            userOpt = userDAO.findByUsername(rawId);
            if (userOpt.isEmpty()) {
                userOpt = userDAO.findByEmail(rawId.toLowerCase());
            }
        }

        // Counteract timing attacks and account enumeration:
        // If user does not exist, compute a dummy PBKDF2 hash so response time is indistinguishable.
        if (userOpt.isEmpty()) {
            PasswordHasher.hashPassword(masterPassword, DUMMY_SALT);
            throw new AuthenticationException("Invalid email/username or master password.");
        }

        User user = userOpt.get();

        // Constant-time password verification using MessageDigest.isEqual
        boolean verified = PasswordHasher.verifyPassword(masterPassword, user.getMasterPasswordSalt(), user.getMasterPasswordHash());
        if (!verified) {
            try {
                securityLogDAO.logEvent(new SecurityLog(user.getUserId(), "AUTH_FAILURE", "Failed authentication attempt."));
            } catch (Exception ignored) {
            }
            throw new AuthenticationException("Invalid email/username or master password.");
        }

        // Derive the vault encryption key from master password + user's distinct key derivation salt.
        // Critical: Authentication hash is NEVER used as the encryption key.
        SecretKey vaultKey = KeyDerivationService.deriveVaultKey(masterPassword, user.getKeyDerivationSalt());

        // Initialize in-memory session (never persisted to disk)
        sessionManager.startSession(user, vaultKey);

        try {
            securityLogDAO.logEvent(new SecurityLog(user.getUserId(), "AUTH_SUCCESS", "Vault unlocked successfully."));
        } catch (Exception ignored) {
        }

        return user;
    }

    /**
     * Terminates the active user session and scrubs encryption keys from memory.
     */
    public void logout() {
        if (sessionManager.isLoggedIn()) {
            Long userId = sessionManager.getCurrentUser().getUserId();
            try {
                securityLogDAO.logEvent(new SecurityLog(userId, "VAULT_LOCKED", "User logged out / vault locked."));
            } catch (Exception ignored) {
            }
        }
        sessionManager.clearSession();
    }

    /**
     * Exception thrown when user authentication fails.
     */
    public static class AuthenticationException extends Exception {
        public AuthenticationException(String message) {
            super(message);
        }
    }
}
