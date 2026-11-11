package com.ironkey;

import com.ironkey.config.DatabaseConfig;
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

import java.sql.Connection;
import java.sql.SQLException;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 3: Transaction Rollback and Connection Failure Diagnostics Test Suite.
 * Validates that transactional registration rolls back atomically on failure,
 * leaving no orphan records, and tests database error handling.
 */
class TransactionRollbackTest {

    private RollbackTestUserDAO userDAO;
    private RollbackTestCategoryDAO categoryDAO;
    private RollbackTestSecurityLogDAO securityLogDAO;
    private SessionManager sessionManager;

    @BeforeEach
    void setUp() {
        userDAO = new RollbackTestUserDAO();
        categoryDAO = new RollbackTestCategoryDAO();
        securityLogDAO = new RollbackTestSecurityLogDAO();
        sessionManager = SessionManager.getInstance();
        sessionManager.clearSession();
    }

    @Test
    @DisplayName("1. Registration transaction rolls back if category initialization fails")
    void testRegistrationRollbackOnCategoryFailure() {
        // Configure categoryDAO to throw an error simulating a DB constraint or disk failure
        categoryDAO.setSimulateFailure(true);

        AuthenticationService authService = new AuthenticationService(userDAO, securityLogDAO, categoryDAO, sessionManager);

        assertThrows(SQLException.class, () -> {
            authService.register("rollback_user", "rollback@ironkey.io", "StrongPass#2026!".toCharArray());
        }, "Should throw SQLException when simulated category creation fails");

        // Verify that rollback occurred: no user record must remain
        assertFalse(userDAO.existsByUsername("rollback_user"), "User record must not persist when transaction fails");
        assertFalse(userDAO.existsByEmail("rollback@ironkey.io"), "Email must not persist when transaction fails");
        assertEquals(0, categoryDAO.getCategories().size(), "No categories should be persisted");
        assertEquals(0, securityLogDAO.getLogs().size(), "No security logs should be persisted");
    }

    @Test
    @DisplayName("2. DatabaseConfig gracefully diagnoses offline MySQL without throwing uncaught exceptions")
    void testDatabaseConnectionFailureDiagnostics() {
        DatabaseConfig config = DatabaseConfig.getInstance();
        DatabaseConfig.ConnectionTestResult result = config.testConnection();

        assertNotNull(result);
        assertNotNull(result.getMessage());
        assertTrue(result.getLatencyMs() >= 0);

        // Result correctly reports status without raising uncaught exceptions
        if (!result.isSuccess()) {
            assertTrue(result.getMessage().contains("MySQL server unreachable") ||
                       result.getMessage().contains("Access denied") ||
                       result.getMessage().contains("Connection check"),
                    "Error message should contain actionable diagnostics: " + result.getMessage());
        }
    }

    // =========================================================================
    // Mock DAOs with Transaction Rollback Capabilities
    // =========================================================================

    private static class RollbackTestUserDAO extends UserDAO {
        private final Map<Long, User> users = new HashMap<>();
        private long idSequence = 1;

        @Override
        public User save(User user) {
            user.setUserId(idSequence++);
            users.put(user.getUserId(), user);
            return user;
        }

        @Override
        public boolean existsByUsername(String username) {
            return users.values().stream().anyMatch(u -> u.getUsername().equals(username));
        }

        @Override
        public boolean existsByEmail(String email) {
            return users.values().stream().anyMatch(u -> u.getEmail().equalsIgnoreCase(email));
        }

        @Override
        public boolean delete(Long userId) {
            return users.remove(userId) != null;
        }

        public void remove(Long id) {
            users.remove(id);
        }
    }

    private static class RollbackTestCategoryDAO extends CategoryDAO {
        private final List<Category> categories = new ArrayList<>();
        private boolean simulateFailure = false;

        public void setSimulateFailure(boolean simulateFailure) {
            this.simulateFailure = simulateFailure;
        }

        @Override
        public Category save(Category category) throws SQLException {
            if (simulateFailure) {
                throw new SQLException("Simulated database failure during category creation.");
            }
            category.setCategoryId((long) (categories.size() + 1));
            categories.add(category);
            return category;
        }

        public List<Category> getCategories() {
            return categories;
        }
    }

    private static class RollbackTestSecurityLogDAO extends SecurityLogDAO {
        private final List<SecurityLog> logs = new ArrayList<>();

        @Override
        public SecurityLog logEvent(SecurityLog log) {
            log.setLogId((long) (logs.size() + 1));
            logs.add(log);
            return log;
        }

        public List<SecurityLog> getLogs() {
            return logs;
        }
    }
}
