package com.ironkey.util;

import javax.swing.JOptionPane;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Manages system clipboard operations with automatic time-delayed memory scrubbing.
 *
 * SECURITY DESIGN:
 * Sensitive items (passwords) are copied to the system clipboard and scheduled for automatic
 * clearing after 30 seconds. If the user copies something else in the interim, the clipboard
 * is left untouched to preserve their workflow.
 *
 * BEST-EFFORT LIMITATION:
 * Clipboard clearing cannot prevent external third-party clipboard monitors, clipboard history
 * managers, or keyloggers from capturing data while it resides on the system clipboard.
 */
public final class ClipboardManager {

    private static final Logger LOGGER = Logger.getLogger(ClipboardManager.class.getName());
    public static final int AUTO_CLEAR_SECONDS = 30;

    private static final ScheduledExecutorService SCHEDULER = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "IronKey-ClipboardScrubber");
        t.setDaemon(true);
        return t;
    });

    private static String lastCopiedPassword = null;

    private ClipboardManager() {
    }

    /**
     * Copies non-sensitive text (e.g. username or URL) to the system clipboard without auto-clearing.
     * Retries briefly if clipboard is momentarily locked by another process.
     *
     * @param text string to copy
     * @return true if clipboard operation succeeded
     */
    public static boolean copyText(String text) {
        if (text == null) return false;
        if (GraphicsEnvironment.isHeadless()) return false;

        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(new StringSelection(text), null);
                return true;
            } catch (Exception e) {
                try {
                    Thread.sleep(50);
                } catch (InterruptedException ignored) {
                }
            }
        }
        LOGGER.log(Level.FINE, "Failed to access system clipboard for copyText");
        return false;
    }

    /**
     * Copies non-sensitive text and shows a friendly toast/notification.
     *
     * @param text   string to copy
     * @param label  label of the field copied
     * @param parent parent component for notification
     */
    public static void copyText(String text, String label, Component parent) {
        boolean ok = copyText(text);
        if (parent != null && !GraphicsEnvironment.isHeadless()) {
            if (ok) {
                JOptionPane.showMessageDialog(parent, label + " copied to clipboard.", "IRONKEY Clipboard", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(parent, "Could not open system clipboard.", "Clipboard Warning", JOptionPane.WARNING_MESSAGE);
            }
        }
    }

    /**
     * Copies a password to the system clipboard and schedules its removal after 30 seconds.
     *
     * @param password sensitive password to copy
     * @return true if clipboard operation succeeded
     */
    public static boolean copyPassword(String password) {
        return copyPassword(password, AUTO_CLEAR_SECONDS);
    }

    /**
     * Copies a password with a custom scrub delay in seconds (useful for unit testing).
     *
     * @param password       sensitive password to copy
     * @param delayInSeconds seconds before scrub
     * @return true if clipboard operation succeeded
     */
    public static boolean copyPassword(String password, int delayInSeconds) {
        if (password == null || password.isEmpty()) return false;
        if (GraphicsEnvironment.isHeadless()) return false;

        boolean success = false;
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(new StringSelection(password), null);
                success = true;
                break;
            } catch (Exception e) {
                try {
                    Thread.sleep(50);
                } catch (InterruptedException ignored) {
                }
            }
        }

        if (success) {
            lastCopiedPassword = password;
            // Schedule best-effort clearing after delay
            SCHEDULER.schedule(() -> {
                for (int attempt = 0; attempt < 3; attempt++) {
                    try {
                        Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
                        if (cb.isDataFlavorAvailable(DataFlavor.stringFlavor)) {
                            String current = (String) cb.getData(DataFlavor.stringFlavor);
                            // Only wipe if the clipboard still contains the password we copied
                            if (current != null && current.equals(lastCopiedPassword)) {
                                cb.setContents(new StringSelection(""), null);
                                LOGGER.log(Level.INFO, "Auto-cleared sensitive password from clipboard after {0}s.", delayInSeconds);
                            }
                        }
                        break;
                    } catch (Exception ex) {
                        try {
                            Thread.sleep(50);
                        } catch (InterruptedException ignored) {
                        }
                    }
                }
                lastCopiedPassword = null;
            }, delayInSeconds, TimeUnit.SECONDS);
        } else {
            LOGGER.log(Level.FINE, "Failed to access system clipboard for copyPassword");
        }
        return success;
    }

    /**
     * Copies a password and shows a notification about the 30-second auto-clear policy.
     *
     * @param password sensitive password to copy
     * @param parent   parent component
     */
    public static void copyPassword(String password, Component parent) {
        boolean ok = copyPassword(password);
        if (parent != null && !GraphicsEnvironment.isHeadless()) {
            if (ok) {
                JOptionPane.showMessageDialog(parent,
                        "Password copied to clipboard.\nWill automatically clear in " + AUTO_CLEAR_SECONDS + " seconds for security.",
                        "IRONKEY Clipboard", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(parent, "Could not open system clipboard.", "Clipboard Warning", JOptionPane.WARNING_MESSAGE);
            }
        }
    }

    /**
     * Retrieves the current string contents of the system clipboard (helper for testing).
     *
     * @return current clipboard string or null
     */
    public static String getClipboardText() {
        if (GraphicsEnvironment.isHeadless()) return null;
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
                if (cb.isDataFlavorAvailable(DataFlavor.stringFlavor)) {
                    return (String) cb.getData(DataFlavor.stringFlavor);
                }
                return null;
            } catch (Exception ignored) {
                try {
                    Thread.sleep(50);
                } catch (InterruptedException ignored2) {
                }
            }
        }
        return null;
    }
}
