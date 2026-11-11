package com.ironkey.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Manages JDBC database connectivity for IRONKEY.
 *
 * Supports hierarchical configuration loading:
 * 1. Environment variables (highest priority for containerized/secure runtime)
 * 2. Local properties file (e.g., config/application-local.properties, ignored by VCS)
 * 3. Classpath application.properties (safe defaults/fallback)
 *
 * Never hardcodes database credentials.
 */
public final class DatabaseConfig {

    private static final Logger LOGGER = Logger.getLogger(DatabaseConfig.class.getName());
    private static final String DEFAULT_PROPERTIES_FILE = "/application.properties";
    private static final String LOCAL_OVERRIDE_FILE = "config/application-local.properties";

    private static DatabaseConfig instance;

    private String host;
    private int port;
    private String database;
    private String username;
    private String password;
    private String driverClassName;
    private String jdbcUrl;
    private boolean driverLoaded = false;

    private DatabaseConfig() {
        loadConfiguration();
        initializeDriver();
    }

    /**
     * Retrieves the thread-safe singleton instance of DatabaseConfig.
     *
     * @return DatabaseConfig instance
     */
    public static synchronized DatabaseConfig getInstance() {
        if (instance == null) {
            instance = new DatabaseConfig();
        }
        return instance;
    }

    /**
     * Loads database configuration from classpath properties, optional local override file,
     * and environment variables.
     */
    private void loadConfiguration() {
        Properties props = new Properties();

        // 1. Load from classpath application.properties
        try (InputStream in = getClass().getResourceAsStream(DEFAULT_PROPERTIES_FILE)) {
            if (in != null) {
                props.load(in);
            } else {
                LOGGER.log(Level.WARNING, "Classpath {0} not found, relying on environment variables.", DEFAULT_PROPERTIES_FILE);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to read classpath properties: {0}", e.getMessage());
        }

        // 2. Load from optional local file (application-local.properties)
        File localFile = new File(LOCAL_OVERRIDE_FILE);
        if (localFile.exists() && localFile.canRead()) {
            try (FileInputStream fis = new FileInputStream(localFile)) {
                props.load(fis);
                LOGGER.log(Level.INFO, "Loaded local database configuration overrides from {0}", LOCAL_OVERRIDE_FILE);
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Failed to load local properties from {0}: {1}", new Object[]{LOCAL_OVERRIDE_FILE, e.getMessage()});
            }
        }

        // 3. Resolve properties with Environment Variable overrides
        this.host = getEnvOrProperty("IRONKEY_DB_HOST", props.getProperty("db.host", "localhost"));
        this.port = Integer.parseInt(getEnvOrProperty("IRONKEY_DB_PORT", props.getProperty("db.port", "3306")));
        this.database = getEnvOrProperty("IRONKEY_DB_NAME", props.getProperty("db.name", "ironkey_db"));
        this.username = getEnvOrProperty("IRONKEY_DB_USER", props.getProperty("db.user", "root"));
        this.password = getEnvOrProperty("IRONKEY_DB_PASS", props.getProperty("db.password", ""));
        this.driverClassName = props.getProperty("db.driver", "com.mysql.cj.jdbc.Driver");

        // Construct standard JDBC connection URL with security and compatibility flags
        String useSSL = props.getProperty("db.useSSL", "false");
        String allowPublicKey = props.getProperty("db.allowPublicKeyRetrieval", "true");
        String serverTimezone = props.getProperty("db.serverTimezone", "UTC");

        this.jdbcUrl = String.format(
                "jdbc:mysql://%s:%d/%s?useSSL=%s&allowPublicKeyRetrieval=%s&serverTimezone=%s&connectTimeout=3000&socketTimeout=5000",
                this.host, this.port, this.database, useSSL, allowPublicKey, serverTimezone
        );
    }

    private String getEnvOrProperty(String envVar, String defaultValue) {
        String value = System.getenv(envVar);
        if (value != null && !value.trim().isEmpty()) {
            return value.trim();
        }
        return defaultValue != null ? defaultValue.trim() : "";
    }

    /**
     * Ensures MySQL JDBC Driver is registered in the runtime.
     */
    private void initializeDriver() {
        try {
            Class.forName(driverClassName);
            this.driverLoaded = true;
            LOGGER.log(Level.INFO, "MySQL JDBC Driver successfully loaded: {0}", driverClassName);
        } catch (ClassNotFoundException e) {
            this.driverLoaded = false;
            LOGGER.log(Level.SEVERE, "MySQL JDBC Driver class not found in classpath: {0}", driverClassName);
        }
    }

    /**
     * Establishes a new JDBC connection to the MySQL database.
     *
     * @return active java.sql.Connection
     * @throws SQLException if a database access error occurs or driver is missing
     */
    public Connection getConnection() throws SQLException {
        if (!driverLoaded) {
            throw new SQLException("MySQL JDBC Driver [" + driverClassName + "] is not loaded in classpath.");
        }
        return DriverManager.getConnection(jdbcUrl, username, password);
    }

    /**
     * Tests connectivity to the database and measures response latency.
     *
     * @return ConnectionTestResult with status, latency, and descriptive message
     */
    public ConnectionTestResult testConnection() {
        long start = System.currentTimeMillis();
        try (Connection conn = getConnection()) {
            boolean valid = conn.isValid(3);
            long latency = System.currentTimeMillis() - start;
            if (valid) {
                return new ConnectionTestResult(true, "Successfully connected to MySQL database [" + database + "]", latency);
            } else {
                return new ConnectionTestResult(false, "Connection check returned invalid.", latency);
            }
        } catch (SQLException e) {
            long latency = System.currentTimeMillis() - start;
            String msg = parseSqlErrorMessage(e);
            return new ConnectionTestResult(false, msg, latency);
        }
    }

    private String parseSqlErrorMessage(SQLException e) {
        String raw = e.getMessage();
        if (raw == null) return "Unknown database connection error.";
        if (raw.contains("Communications link failure") || raw.contains("Connection refused")) {
            return "MySQL server unreachable at " + host + ":" + port + ". Ensure MySQL service is running.";
        }
        if (raw.contains("Access denied for user")) {
            return "Access denied for user '" + username + "'. Check database credentials.";
        }
        if (raw.contains("Unknown database")) {
            return "Database '" + database + "' does not exist. Please execute schema.sql first.";
        }
        return "Database error: " + raw;
    }

    // --- Diagnostic getters (safe, never revealing password) ---

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public String getDatabase() {
        return database;
    }

    public String getUsername() {
        return username;
    }

    public String getJdbcUrl() {
        return jdbcUrl;
    }

    public boolean isDriverLoaded() {
        return driverLoaded;
    }

    /**
     * Diagnostic result data carrier for connection checks.
     */
    public static class ConnectionTestResult {
        private final boolean success;
        private final String message;
        private final long latencyMs;

        public ConnectionTestResult(boolean success, String message, long latencyMs) {
            this.success = success;
            this.message = message;
            this.latencyMs = latencyMs;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getMessage() {
            return message;
        }

        public long getLatencyMs() {
            return latencyMs;
        }

        @Override
        public String toString() {
            return String.format("[%s] %s (%d ms)", success ? "CONNECTED" : "OFFLINE", message, latencyMs);
        }
    }
}
