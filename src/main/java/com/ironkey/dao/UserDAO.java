package com.ironkey.dao;

import com.ironkey.config.DatabaseConfig;
import com.ironkey.model.User;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.Optional;

/**
 * Data Access Object for {@link User} entities.
 * Enforces prepared statements and prevents SQL injection vulnerabilities.
 */
public class UserDAO {

    private final DatabaseConfig databaseConfig;

    public UserDAO() {
        this(DatabaseConfig.getInstance());
    }

    public UserDAO(DatabaseConfig databaseConfig) {
        this.databaseConfig = databaseConfig;
    }

    /**
     * Persists a new user record into MySQL using an auto-managed connection.
     *
     * @param user user entity with hashed credentials and unique salts
     * @return the persisted user with generated primary key
     * @throws SQLException if a database error occurs
     */
    public User save(User user) throws SQLException {
        try (Connection conn = databaseConfig.getConnection()) {
            return save(user, conn);
        }
    }

    /**
     * Persists a new user record into MySQL using the provided connection,
     * enabling external transaction coordination.
     *
     * @param user user entity with hashed credentials and unique salts
     * @param conn existing JDBC connection
     * @return the persisted user with generated primary key
     * @throws SQLException if a database error occurs
     */
    public User save(User user, Connection conn) throws SQLException {
        String sql = "INSERT INTO users (username, email, master_password_hash, master_password_salt, key_derivation_salt) " +
                     "VALUES (?, ?, ?, ?, ?)";

        try (PreparedStatement stmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, user.getUsername());
            stmt.setString(2, user.getEmail());
            stmt.setString(3, user.getMasterPasswordHash());
            stmt.setString(4, user.getMasterPasswordSalt());
            stmt.setString(5, user.getKeyDerivationSalt());

            stmt.executeUpdate();

            try (ResultSet generatedKeys = stmt.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    user.setUserId(generatedKeys.getLong(1));
                }
            }
        }
        return user;
    }

    /**
     * Finds a user by their unique primary key ID.
     *
     * @param userId user primary key
     * @return Optional containing the user if found
     * @throws SQLException if a database error occurs
     */
    public Optional<User> findById(Long userId) throws SQLException {
        String sql = "SELECT user_id, username, email, master_password_hash, master_password_salt, " +
                     "key_derivation_salt, created_at FROM users WHERE user_id = ?";

        try (Connection conn = databaseConfig.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapResultSetToUser(rs));
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Finds a user by their unique username.
     *
     * @param username username to look up
     * @return Optional containing the user if found
     * @throws SQLException if a database error occurs
     */
    public Optional<User> findByUsername(String username) throws SQLException {
        String sql = "SELECT user_id, username, email, master_password_hash, master_password_salt, " +
                     "key_derivation_salt, created_at FROM users WHERE username = ?";

        try (Connection conn = databaseConfig.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapResultSetToUser(rs));
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Finds a user by their unique email.
     *
     * @param email email address to look up
     * @return Optional containing the user if found
     * @throws SQLException if a database error occurs
     */
    public Optional<User> findByEmail(String email) throws SQLException {
        String sql = "SELECT user_id, username, email, master_password_hash, master_password_salt, " +
                     "key_derivation_salt, created_at FROM users WHERE email = ?";

        try (Connection conn = databaseConfig.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, email);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapResultSetToUser(rs));
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Checks whether a username already exists.
     *
     * @param username username to check
     * @return true if exists
     * @throws SQLException if a database error occurs
     */
    public boolean existsByUsername(String username) throws SQLException {
        String sql = "SELECT 1 FROM users WHERE username = ? LIMIT 1";
        try (Connection conn = databaseConfig.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Checks whether an email address already exists.
     *
     * @param email email to check
     * @return true if exists
     * @throws SQLException if a database error occurs
     */
    public boolean existsByEmail(String email) throws SQLException {
        String sql = "SELECT 1 FROM users WHERE email = ? LIMIT 1";
        try (Connection conn = databaseConfig.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, email);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Deletes a user by ID. Cascades to associated vault entries, categories, and logs.
     *
     * @param userId user ID
     * @return true if deleted
     * @throws SQLException if a database error occurs
     */
    public boolean delete(Long userId) throws SQLException {
        try (Connection conn = databaseConfig.getConnection()) {
            return delete(userId, conn);
        }
    }

    /**
     * Deletes a user within an existing transaction.
     *
     * @param userId user ID
     * @param conn   existing database connection
     * @return true if deleted
     * @throws SQLException if a database error occurs
     */
    public boolean delete(Long userId, Connection conn) throws SQLException {
        String sql = "DELETE FROM users WHERE user_id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setLong(1, userId);
            return stmt.executeUpdate() > 0;
        }
    }

    private User mapResultSetToUser(ResultSet rs) throws SQLException {
        User user = new User();
        user.setUserId(rs.getLong("user_id"));
        user.setUsername(rs.getString("username"));
        user.setEmail(rs.getString("email"));
        user.setMasterPasswordHash(rs.getString("master_password_hash"));
        user.setMasterPasswordSalt(rs.getString("master_password_salt"));
        user.setKeyDerivationSalt(rs.getString("key_derivation_salt"));
        Timestamp ts = rs.getTimestamp("created_at");
        if (ts != null) {
            user.setCreatedAt(ts.toLocalDateTime());
        }
        return user;
    }
}
