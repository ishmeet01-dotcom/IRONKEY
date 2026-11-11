package com.ironkey.dao;

import com.ironkey.config.DatabaseConfig;
import com.ironkey.model.VaultEntry;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Data Access Object for {@link VaultEntry} records.
 * Strictly guarantees multi-tenant isolation by enforcing userId on all operations.
 */
public class VaultEntryDAO {

    private final DatabaseConfig databaseConfig;

    public VaultEntryDAO() {
        this(DatabaseConfig.getInstance());
    }

    public VaultEntryDAO(DatabaseConfig databaseConfig) {
        this.databaseConfig = databaseConfig;
    }

    /**
     * Persists an encrypted vault entry.
     *
     * @param entry entry containing encrypted fields and nonce
     * @return the saved entry with generated primary key
     * @throws SQLException if a database error occurs
     */
    public VaultEntry save(VaultEntry entry) throws SQLException {
        String sql = "INSERT INTO vault_entries (user_id, website_name, website_url, encrypted_username, " +
                     "encrypted_password, nonce, category, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

        try (Connection conn = databaseConfig.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            stmt.setLong(1, entry.getUserId());
            stmt.setString(2, entry.getWebsiteName());
            stmt.setString(3, entry.getWebsiteUrl());
            stmt.setString(4, entry.getEncryptedUsername());
            stmt.setString(5, entry.getEncryptedPassword());
            stmt.setString(6, entry.getNonce());
            stmt.setString(7, entry.getCategory());
            stmt.setString(8, entry.getNotes());

            stmt.executeUpdate();

            try (ResultSet generatedKeys = stmt.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    entry.setEntryId(generatedKeys.getLong(1));
                }
            }
        }
        return entry;
    }

    /**
     * Finds a single vault entry by its ID and user ID to ensure user isolation.
     *
     * @param entryId entry primary key
     * @param userId  owner user ID
     * @return Optional containing the entry if found and owned by the user
     * @throws SQLException if a database error occurs
     */
    public Optional<VaultEntry> findById(Long entryId, Long userId) throws SQLException {
        String sql = "SELECT entry_id, user_id, website_name, website_url, encrypted_username, " +
                     "encrypted_password, nonce, category, notes, created_at, updated_at " +
                     "FROM vault_entries WHERE entry_id = ? AND user_id = ?";

        try (Connection conn = databaseConfig.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setLong(1, entryId);
            stmt.setLong(2, userId);

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapResultSetToEntry(rs));
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Retrieves all encrypted vault entries belonging to the specified user.
     *
     * @param userId owner user ID
     * @return list of vault entries
     * @throws SQLException if a database error occurs
     */
    public List<VaultEntry> findAllByUserId(Long userId) throws SQLException {
        String sql = "SELECT entry_id, user_id, website_name, website_url, encrypted_username, " +
                     "encrypted_password, nonce, category, notes, created_at, updated_at " +
                     "FROM vault_entries WHERE user_id = ? ORDER BY website_name ASC";

        List<VaultEntry> list = new ArrayList<>();
        try (Connection conn = databaseConfig.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    list.add(mapResultSetToEntry(rs));
                }
            }
        }
        return list;
    }

    /**
     * Searches vault entries by website name or URL.
     *
     * @param userId      owner user ID
     * @param queryFilter search keyword
     * @return matching vault entries
     * @throws SQLException if a database error occurs
     */
    public List<VaultEntry> search(Long userId, String queryFilter) throws SQLException {
        String sql = "SELECT entry_id, user_id, website_name, website_url, encrypted_username, " +
                     "encrypted_password, nonce, category, notes, created_at, updated_at " +
                     "FROM vault_entries WHERE user_id = ? AND (website_name LIKE ? OR website_url LIKE ?) " +
                     "ORDER BY website_name ASC";

        List<VaultEntry> list = new ArrayList<>();
        try (Connection conn = databaseConfig.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            String term = "%" + queryFilter + "%";
            stmt.setLong(1, userId);
            stmt.setString(2, term);
            stmt.setString(3, term);

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    list.add(mapResultSetToEntry(rs));
                }
            }
        }
        return list;
    }

    /**
     * Updates an existing vault entry.
     *
     * @param entry updated vault entry
     * @return true if updated, false if not found or unauthorized
     * @throws SQLException if a database error occurs
     */
    public boolean update(VaultEntry entry) throws SQLException {
        String sql = "UPDATE vault_entries SET website_name = ?, website_url = ?, encrypted_username = ?, " +
                     "encrypted_password = ?, nonce = ?, category = ?, notes = ? " +
                     "WHERE entry_id = ? AND user_id = ?";

        try (Connection conn = databaseConfig.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, entry.getWebsiteName());
            stmt.setString(2, entry.getWebsiteUrl());
            stmt.setString(3, entry.getEncryptedUsername());
            stmt.setString(4, entry.getEncryptedPassword());
            stmt.setString(5, entry.getNonce());
            stmt.setString(6, entry.getCategory());
            stmt.setString(7, entry.getNotes());
            stmt.setLong(8, entry.getEntryId());
            stmt.setLong(9, entry.getUserId());

            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * Deletes a vault entry, ensuring user ownership.
     *
     * @param entryId entry ID to delete
     * @param userId  owner user ID
     * @return true if deleted
     * @throws SQLException if a database error occurs
     */
    public boolean delete(Long entryId, Long userId) throws SQLException {
        String sql = "DELETE FROM vault_entries WHERE entry_id = ? AND user_id = ?";

        try (Connection conn = databaseConfig.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setLong(1, entryId);
            stmt.setLong(2, userId);
            return stmt.executeUpdate() > 0;
        }
    }

    /**
     * Counts the total number of credentials owned by the user.
     *
     * @param userId user ID
     * @return total count
     * @throws SQLException if a database error occurs
     */
    public int countByUserId(Long userId) throws SQLException {
        String sql = "SELECT COUNT(*) FROM vault_entries WHERE user_id = ?";
        try (Connection conn = databaseConfig.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        }
        return 0;
    }

    private VaultEntry mapResultSetToEntry(ResultSet rs) throws SQLException {
        VaultEntry entry = new VaultEntry();
        entry.setEntryId(rs.getLong("entry_id"));
        entry.setUserId(rs.getLong("user_id"));
        entry.setWebsiteName(rs.getString("website_name"));
        entry.setWebsiteUrl(rs.getString("website_url"));
        entry.setEncryptedUsername(rs.getString("encrypted_username"));
        entry.setEncryptedPassword(rs.getString("encrypted_password"));
        entry.setNonce(rs.getString("nonce"));
        entry.setCategory(rs.getString("category"));
        entry.setNotes(rs.getString("notes"));

        Timestamp created = rs.getTimestamp("created_at");
        if (created != null) {
            entry.setCreatedAt(created.toLocalDateTime());
        }
        Timestamp updated = rs.getTimestamp("updated_at");
        if (updated != null) {
            entry.setUpdatedAt(updated.toLocalDateTime());
        }
        return entry;
    }
}
