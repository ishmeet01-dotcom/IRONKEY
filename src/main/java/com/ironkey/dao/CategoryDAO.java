package com.ironkey.dao;

import com.ironkey.config.DatabaseConfig;
import com.ironkey.model.Category;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;

/**
 * Data Access Object for credential categories.
 */
public class CategoryDAO {

    private final DatabaseConfig databaseConfig;

    public CategoryDAO() {
        this(DatabaseConfig.getInstance());
    }

    public CategoryDAO(DatabaseConfig databaseConfig) {
        this.databaseConfig = databaseConfig;
    }

    /**
     * Retrieves all categories available for a user (both global defaults and custom user categories).
     *
     * @param userId current user ID
     * @return list of categories
     * @throws SQLException if a database error occurs
     */
    public List<Category> findAllByUserId(Long userId) throws SQLException {
        String sql = "SELECT category_id, user_id, name, icon, created_at FROM categories " +
                     "WHERE user_id IS NULL OR user_id = ? ORDER BY name ASC";

        List<Category> list = new ArrayList<>();
        try (Connection conn = databaseConfig.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setLong(1, userId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    list.add(mapResultSetToCategory(rs));
                }
            }
        }
        return list;
    }

    /**
     * Saves a new custom category for a user using an auto-managed connection.
     *
     * @param category category to save
     * @return saved category with generated ID
     * @throws SQLException if a database error occurs
     */
    public Category save(Category category) throws SQLException {
        try (Connection conn = databaseConfig.getConnection()) {
            return save(category, conn);
        }
    }

    /**
     * Saves a category within an existing transaction.
     *
     * @param category category to save
     * @param conn     existing database connection
     * @return saved category with generated ID
     * @throws SQLException if a database error occurs
     */
    public Category save(Category category, Connection conn) throws SQLException {
        String sql = "INSERT INTO categories (user_id, name, icon) VALUES (?, ?, ?)";

        try (PreparedStatement stmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            if (category.getUserId() != null) {
                stmt.setLong(1, category.getUserId());
            } else {
                stmt.setNull(1, Types.BIGINT);
            }
            stmt.setString(2, category.getName());
            stmt.setString(3, category.getIcon() != null ? category.getIcon() : "folder");

            stmt.executeUpdate();

            try (ResultSet generatedKeys = stmt.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    category.setCategoryId(generatedKeys.getLong(1));
                }
            }
        }
        return category;
    }

    /**
     * Deletes a custom user category. Default system categories (user_id IS NULL) cannot be deleted.
     *
     * @param categoryId category ID
     * @param userId     owner user ID
     * @return true if deleted
     * @throws SQLException if a database error occurs
     */
    public boolean delete(Long categoryId, Long userId) throws SQLException {
        String sql = "DELETE FROM categories WHERE category_id = ? AND user_id = ?";

        try (Connection conn = databaseConfig.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setLong(1, categoryId);
            stmt.setLong(2, userId);
            return stmt.executeUpdate() > 0;
        }
    }

    private Category mapResultSetToCategory(ResultSet rs) throws SQLException {
        Category category = new Category();
        category.setCategoryId(rs.getLong("category_id"));
        long uid = rs.getLong("user_id");
        if (!rs.wasNull()) {
            category.setUserId(uid);
        }
        category.setName(rs.getString("name"));
        category.setIcon(rs.getString("icon"));
        Timestamp ts = rs.getTimestamp("created_at");
        if (ts != null) {
            category.setCreatedAt(ts.toLocalDateTime());
        }
        return category;
    }
}
