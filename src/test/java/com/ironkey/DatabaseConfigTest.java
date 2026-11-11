package com.ironkey;

import com.ironkey.config.DatabaseConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DatabaseConfigTest {

    @Test
    @DisplayName("DatabaseConfig should load defaults without throwing exceptions")
    void testDatabaseConfigLoad() {
        DatabaseConfig config = DatabaseConfig.getInstance();
        assertNotNull(config, "DatabaseConfig instance must not be null");
        assertEquals("ironkey_db", config.getDatabase(), "Default database name should be ironkey_db");
        assertEquals(3306, config.getPort(), "Default port should be 3306");
        assertTrue(config.getJdbcUrl().startsWith("jdbc:mysql://"), "JDBC URL must start with standard protocol prefix");
    }

    @Test
    @DisplayName("testConnection should execute safely and return structured ConnectionTestResult")
    void testConnectionExecution() {
        DatabaseConfig config = DatabaseConfig.getInstance();
        DatabaseConfig.ConnectionTestResult result = config.testConnection();

        assertNotNull(result, "ConnectionTestResult must not be null");
        assertNotNull(result.getMessage(), "Diagnostic message must not be null");
        assertTrue(result.getLatencyMs() >= 0, "Latency must be non-negative");
    }
}
