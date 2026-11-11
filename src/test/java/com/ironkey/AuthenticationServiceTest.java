package com.ironkey;

import com.ironkey.dao.CategoryDAO;
import com.ironkey.dao.SecurityLogDAO;
import com.ironkey.dao.UserDAO;
import com.ironkey.model.Category;
import com.ironkey.model.SecurityLog;
import com.ironkey.model.User;
import com.ironkey.service.AuthenticationService;
import com.ironkey.util.SessionManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive test suite for Phase 2 User Registration and Authentication.
 * Uses isolated in-memory DAO mocks to test all security workflows deterministically
 * without requiring an external MySQL service.
 */
class AuthenticationServiceTest {

    private MockUserDAO mockUserDAO;
    private MockSecurityLogDAO mockSecurityLogDAO;
    private MockCategoryDAO mockCategoryDAO;
    private SessionManager sessionManager;
    private AuthenticationService authService;

    @BeforeEach
    void setUp() {
        mockUserDAO = new MockUserDAO();
        mockSecurityLogDAO = new MockSecurityLogDAO();
        mockCategoryDAO = new MockCategoryDAO();
        sessionManager = SessionManager.getInstance();
        sessionManager.clearSession();

        authService = new AuthenticationService(mockUserDAO, mockSecurityLogDAO, mockCategoryDAO, sessionManager);
    }

    @Test
    @DisplayName("1. Successful user registration generates unique salts and hashes password")
    void testSuccessfulRegistration() throws SQLException {
        char[] password = "SecureMasterPass#2026".toCharArray();
        char[] confirm = "SecureMasterPass#2026".toCharArray();

        User user = authService.register("alice_vault", "alice@ironkey.io", password, confirm);

        assertNotNull(user);
        assertNotNull(user.getUserId(), "User must be assigned an ID");
        assertEquals("alice_vault", user.getUsername());
        assertEquals("alice@ironkey.io", user.getEmail());

        // Cryptographic properties validation
        assertNotNull(user.getMasterPasswordHash(), "Hash must be populated");
        assertNotEquals("SecureMasterPass#2026", user.getMasterPasswordHash(), "Master password must never be stored in plaintext");
        assertNotNull(user.getMasterPasswordSalt(), "Authentication salt must be present");
        assertNotNull(user.getKeyDerivationSalt(), "Key derivation salt must be present");
        assertNotEquals(user.getMasterPasswordSalt(), user.getKeyDerivationSalt(), "Salts must be strictly independent");

        // Verify user is persisted in DAO
        assertTrue(mockUserDAO.existsByUsername("alice_vault"));
        assertTrue(mockUserDAO.existsByEmail("alice@ironkey.io"));

        // Verify audit log
        assertEquals(1, mockSecurityLogDAO.getLogs().size());
        assertEquals("USER_REGISTERED", mockSecurityLogDAO.getLogs().get(0).getEventType());
    }

    @Test
    @DisplayName("2. Duplicate email registration must be rejected")
    void testDuplicateEmailRejection() throws SQLException {
        char[] pass = "Passphrase#12345678".toCharArray();
        authService.register("first_user", "common@ironkey.io", pass);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> {
            authService.register("second_user", "common@ironkey.io", pass);
        });

        assertTrue(ex.getMessage().contains("email already exists"), "Should reject duplicate email");
    }

    @Test
    @DisplayName("3. Duplicate username registration must be rejected")
    void testDuplicateUsernameRejection() throws SQLException {
        char[] pass = "Passphrase#12345678".toCharArray();
        authService.register("unique_alias", "first@domain.com", pass);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> {
            authService.register("unique_alias", "second@domain.com", pass);
        });

        assertTrue(ex.getMessage().contains("Username is already taken"), "Should reject duplicate username");
    }

    @Test
    @DisplayName("4. Invalid email format must be rejected")
    void testInvalidEmailRejection() {
        char[] pass = "Passphrase#12345678".toCharArray();

        assertThrows(IllegalArgumentException.class, () -> {
            authService.register("test_user", "invalid-email-address", pass);
        });

        assertThrows(IllegalArgumentException.class, () -> {
            authService.register("test_user", "@missinguser.com", pass);
        });

        assertThrows(IllegalArgumentException.class, () -> {
            authService.register("test_user", "", pass);
        });
    }

    @Test
    @DisplayName("5. Password confirmation mismatch must be rejected")
    void testPasswordConfirmationMismatch() {
        char[] pass = "Passphrase#12345678".toCharArray();
        char[] mismatch = "DifferentPass#99999".toCharArray();

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> {
            authService.register("test_user", "user@domain.com", pass, mismatch);
        });

        assertTrue(ex.getMessage().contains("do not match"));
    }

    @Test
    @DisplayName("6. Successful login derives vault key and initializes in-memory session")
    void testSuccessfulLogin() throws Exception {
        char[] password = "MasterPassphrase#2026!".toCharArray();
        authService.register("bob_crypto", "bob@ironkey.io", password);

        // Login using email
        User loggedInUser = authService.login("bob@ironkey.io", password);

        assertNotNull(loggedInUser);
        assertEquals("bob_crypto", loggedInUser.getUsername());

        // Verify session management
        assertTrue(sessionManager.isLoggedIn());
        assertEquals(loggedInUser.getUserId(), sessionManager.getUserId());
        assertEquals(loggedInUser, sessionManager.getCurrentUser());

        // Verify derived AES-256 vault key
        SecretKey vaultKey = sessionManager.getVaultKey();
        assertNotNull(vaultKey, "Vault encryption key must be derived upon login");
        assertEquals("AES", vaultKey.getAlgorithm());
        assertEquals(32, vaultKey.getEncoded().length, "AES key length must be 256 bits (32 bytes)");

        // Verify audit log
        boolean foundSuccessLog = mockSecurityLogDAO.getLogs().stream()
                .anyMatch(l -> "AUTH_SUCCESS".equals(l.getEventType()));
        assertTrue(foundSuccessLog, "Successful authentication must be logged");
    }

    @Test
    @DisplayName("7. Login using username instead of email succeeds")
    void testLoginWithUsername() throws Exception {
        char[] password = "MasterPassphrase#2026!".toCharArray();
        authService.register("charlie_ops", "charlie@ironkey.io", password);

        sessionManager.clearSession();

        // Login using username
        User user = authService.login("charlie_ops", password);
        assertNotNull(user);
        assertTrue(sessionManager.isLoggedIn());
    }

    @Test
    @DisplayName("8. Incorrect master password must be rejected with generic error")
    void testIncorrectMasterPassword() throws Exception {
        char[] correctPassword = "CorrectPassphrase#2026!".toCharArray();
        char[] wrongPassword = "WrongPassphrase#2026!".toCharArray();
        authService.register("david_sec", "david@ironkey.io", correctPassword);

        AuthenticationService.AuthenticationException ex = assertThrows(
                AuthenticationService.AuthenticationException.class, () -> {
                    authService.login("david@ironkey.io", wrongPassword);
                });

        assertEquals("Invalid email/username or master password.", ex.getMessage(),
                "Must show generic error without exposing specifics");
        assertFalse(sessionManager.isLoggedIn(), "Session must not be created on failed login");

        // Verify audit log recorded failure
        boolean foundFailureLog = mockSecurityLogDAO.getLogs().stream()
                .anyMatch(l -> "AUTH_FAILURE".equals(l.getEventType()));
        assertTrue(foundFailureLog, "Authentication failure must be audited");
    }

    @Test
    @DisplayName("9. Unknown account login returns generic error without revealing existence")
    void testUnknownAccountLogin() {
        char[] password = "AnyPassphrase#2026!".toCharArray();

        AuthenticationService.AuthenticationException ex = assertThrows(
                AuthenticationService.AuthenticationException.class, () -> {
                    authService.login("ghost@ironkey.io", password);
                });

        assertEquals("Invalid email/username or master password.", ex.getMessage(),
                "Must return generic error to prevent account enumeration");
        assertFalse(sessionManager.isLoggedIn());
    }

    @Test
    @DisplayName("10. Session initialization and active requirement guard")
    void testSessionInitializationAndGuard() throws Exception {
        // When not logged in, requireActiveSession must throw
        assertThrows(SecurityException.class, () -> sessionManager.requireActiveSession());

        char[] pass = "SessionPass#2026!".toCharArray();
        User user = authService.register("eve_session", "eve@ironkey.io", pass);
        authService.login("eve@ironkey.io", pass);

        // When logged in, requireActiveSession succeeds
        assertDoesNotThrow(() -> sessionManager.requireActiveSession());
        assertNotNull(sessionManager.getSessionToken());
        assertEquals(64, sessionManager.getSessionToken().length(), "Token should be 64 hex characters (32 bytes)");
        assertNotNull(sessionManager.getLoginTime());
        assertNotNull(sessionManager.getLastActivityTime());
    }

    @Test
    @DisplayName("11. Session logout cleans up in-memory keys and user references")
    void testSessionLogoutAndKeyClearing() throws Exception {
        char[] pass = "LogoutPass#2026!".toCharArray();
        authService.register("frank_vault", "frank@ironkey.io", pass);
        authService.login("frank@ironkey.io", pass);

        assertTrue(sessionManager.isLoggedIn());
        assertNotNull(sessionManager.getVaultKey());

        // Perform logout
        authService.logout();

        assertFalse(sessionManager.isLoggedIn(), "User must be logged out");
        assertNull(sessionManager.getCurrentUser(), "User reference must be cleared");
        assertNull(sessionManager.getVaultKey(), "Encryption key must be scrubbed");
        assertNull(sessionManager.getUserId(), "User ID must be null");
        assertThrows(SecurityException.class, () -> sessionManager.requireActiveSession());

        // Verify audit log recorded VAULT_LOCKED
        boolean foundLockLog = mockSecurityLogDAO.getLogs().stream()
                .anyMatch(l -> "VAULT_LOCKED".equals(l.getEventType()));
        assertTrue(foundLockLog, "Vault lock must be audited upon logout");
    }

    @Test
    @DisplayName("12. Independent authentication hashing and vault key derivation")
    void testIndependentHashingAndVaultKeyDerivation() throws Exception {
        char[] pass = "DualSalts#2026!".toCharArray();
        User user = authService.register("grace_audit", "grace@ironkey.io", pass);

        authService.login("grace@ironkey.io", pass);
        SecretKey vaultKey = sessionManager.getVaultKey();

        // The derived AES key bytes must never match the PBKDF2 authentication hash
        String vaultKeyHex = Base64.getEncoder().encodeToString(vaultKey.getEncoded());
        assertNotEquals(user.getMasterPasswordHash(), vaultKeyHex,
                "Authentication hash and AES vault encryption key must be strictly distinct cryptographic values");
    }

    // =========================================================================
    // In-Memory Test Doubles (Mocks) for Isolated Unit Testing
    // =========================================================================

    private static class MockUserDAO extends UserDAO {
        private final Map<Long, User> usersById = new HashMap<>();
        private final Map<String, User> usersByUsername = new HashMap<>();
        private final Map<String, User> usersByEmail = new HashMap<>();
        private long idSequence = 1;

        @Override
        public User save(User user) {
            return save(user, null);
        }

        @Override
        public User save(User user, Connection conn) {
            user.setUserId(idSequence++);
            usersById.put(user.getUserId(), user);
            usersByUsername.put(user.getUsername(), user);
            usersByEmail.put(user.getEmail().toLowerCase(), user);
            return user;
        }

        @Override
        public Optional<User> findById(Long userId) {
            return Optional.ofNullable(usersById.get(userId));
        }

        @Override
        public Optional<User> findByUsername(String username) {
            return Optional.ofNullable(usersByUsername.get(username));
        }

        @Override
        public Optional<User> findByEmail(String email) {
            return Optional.ofNullable(usersByEmail.get(email.toLowerCase()));
        }

        @Override
        public boolean existsByUsername(String username) {
            return usersByUsername.containsKey(username);
        }

        @Override
        public boolean existsByEmail(String email) {
            return usersByEmail.containsKey(email.toLowerCase());
        }
    }

    private static class MockSecurityLogDAO extends SecurityLogDAO {
        private final List<SecurityLog> logs = new ArrayList<>();
        private long idSequence = 1;

        @Override
        public SecurityLog logEvent(SecurityLog log) {
            return logEvent(log, null);
        }

        @Override
        public SecurityLog logEvent(SecurityLog log, Connection conn) {
            log.setLogId(idSequence++);
            logs.add(log);
            return log;
        }

        public List<SecurityLog> getLogs() {
            return logs;
        }
    }

    private static class MockCategoryDAO extends CategoryDAO {
        private final List<Category> categories = new ArrayList<>();
        private long idSequence = 1;

        @Override
        public Category save(Category category) {
            return save(category, null);
        }

        @Override
        public Category save(Category category, Connection conn) {
            category.setCategoryId(idSequence++);
            categories.add(category);
            return category;
        }
    }
}
