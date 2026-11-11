package com.ironkey.dao;

import com.ironkey.config.DatabaseConfig;
import com.ironkey.model.SecurityLog;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

/**
 * Data Access Object for audit logging events.
 */
public class SecurityLogDAO {

    private final DatabaseConfig databaseConfig;

    public SecurityLogDAO() {
        this(DatabaseConfig.getInstance());
    }

    public SecurityLogDAO(DatabaseConfig databaseConfig) {
        this.databaseConfig = databaseConfig;
    }

    /**
     * Records a security audit event in the database using an auto-managed connection.
     *
     * @param log security event entry
     * @return persisted log with ID
     * @throws SQLException if a database error occurs
     */
    public SecurityLog logEvent(SecurityLog log) throws SQLException {
        try (Connection conn = databaseConfig.getConnection()) {
            return logEvent(log, conn);
        }
    }

    /**
     * Records a security audit event in the database within an existing transaction.
     *
     * @param log  security event entry
     * @param conn active database connection
     * @return persisted log with ID
     * @throws SQLException if a database error occurs
     */
    public SecurityLog logEvent(SecurityLog log, Connection conn) throws SQLException {
        String sql = "INSERT INTO security_logs (user_id, event_type, description) VALUES (?, ?, ?)";

        try (PreparedStatement stmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setLong(1, log.getUserId());
            stmt.setString(2, log.getEventType());
            stmt.setString(3, log.getDescription());

            stmt.executeUpdate();

            try (ResultSet generatedKeys = stmt.getGeneratedKeys()) {
                if (generatedKeys.next()) {
                    log.setLogId(generatedKeys.getLong(1));
                }
            }
        }
        return log;
    }

    /**
     * Retrieves the most recent security log entries for a given user.
     *
     * @param userId user ID
     * @param limit  maximum number of entries to return
     * @return list of recent security logs
     * @throws SQLException if a database error occurs
     */
    public List<SecurityLog> findRecentByUserId(Long userId, int limit) throws SQLException {
        String sql = "SELECT log_id, user_id, event_type, description, timestamp " +
                     "FROM security_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?";

        List<SecurityLog> list = new ArrayList<>();
        try (Connection conn = databaseConfig.getConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setLong(1, userId);
            stmt.setInt(2, Math.max(1, limit));

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    SecurityLog log = new SecurityLog();
                    log.setLogId(rs.getLong("log_id"));
                    log.setUserId(rs.getLong("user_id"));
                    log.setEventType(rs.getString("event_type"));
                    log.setDescription(rs.getString("description"));
                    Timestamp ts = rs.getTimestamp("timestamp");
                    if (ts != null) {
                        log.setTimestamp(ts.toLocalDateTime());
                    }
                    list.add(log);
                }
            }
        }
        return list;
    }
}
