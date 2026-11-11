package com.ironkey;

import com.ironkey.config.DatabaseConfig;
import com.ironkey.ui.LoginFrame;

import javax.swing.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Main application entry point for IRONKEY — Encrypted Password Management System.
 * Initializes desktop environment settings, verifies connectivity, and launches GUI.
 */
public class Main {

    private static final Logger LOGGER = Logger.getLogger(Main.class.getName());

    public static void main(String[] args) {
        // Configure font rendering and anti-aliasing properties for crisp UI display
        System.setProperty("awt.useSystemAAFontSettings", "on");
        System.setProperty("swing.aatext", "true");

        printBanner();

        // Check database status gracefully without blocking startup
        DatabaseConfig.ConnectionTestResult testResult = DatabaseConfig.getInstance().testConnection();
        LOGGER.log(Level.INFO, "Database Connectivity Check: {0}", testResult.toString());

        // Check if graphics display environment is available
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            LOGGER.log(Level.INFO, "Running in headless mode. GUI display skipped.");
            return;
        }

        // Apply System Look and Feel if compatible
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to apply system look and feel: {0}", e.getMessage());
        }

        // Launch initial Swing window on Event Dispatch Thread
        SwingUtilities.invokeLater(() -> {
            try {
                LoginFrame loginFrame = new LoginFrame();
                loginFrame.setVisible(true);
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Fatal error launching IRONKEY UI", e);
                JOptionPane.showMessageDialog(null,
                        "Failed to launch IRONKEY interface:\n" + e.getMessage(),
                        "Launch Error", JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    private static void printBanner() {
        System.out.println("==================================================================");
        System.out.println("               IRONKEY — Encrypted Password Manager               ");
        System.out.println("                 \"Your Credentials. Your Control.\"               ");
        System.out.println("==================================================================");
        System.out.println(" [✓] Core Layered Architecture (Phase 1)");
        System.out.println(" [✓] PBKDF2 (310,000 iter) Zero-Knowledge Authentication (Phase 2)");
        System.out.println(" [✓] Multi-Tenant Isolation & Cryptographic Hardening (Phase 3)");
        System.out.println(" [✓] AES-256-GCM Persistent Credential Management (Phase 4)");
        System.out.println(" [✓] Password Health Analyzer & Security Audit Suite (Phase 5)");
        System.out.println(" [✓] Security Hardening & Release Stabilization (Phase 6)");
        System.out.println("==================================================================");
    }
}
