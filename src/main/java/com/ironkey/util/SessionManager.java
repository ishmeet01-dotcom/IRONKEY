package com.ironkey.util;

import com.ironkey.model.User;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;

/**
 * Manages the authenticated user's session in memory.
 * Stores ephemeral vault encryption keys while the user is actively logged in.
 * Includes explicit memory scrubbing upon logout or session timeout.
 *
 * SECURITY & MEMORY MANAGEMENT NOTES:
 * 1. The vault encryption key is held strictly in volatile RAM and is NEVER serialized to disk.
 * 2. In standard OpenJDK runtime, {@link javax.crypto.spec.SecretKeySpec} does not support
 *    the {@link javax.security.auth.Destroyable} interface. While {@link #clearSession()}
 *    calls {@code destroy()} when supported and sets all references to null, the JVM heap
 *    garbage collector ultimately manages reclamation of the underlying byte buffer.
 *    True guaranteed zeroization requires native OS memory locking (e.g. mlock via JNI),
 *    which is not available in pure standard Java without third-party native libraries.
 * 3. Session expiration: An inactivity timeout (default 15 minutes, configurable) invalidates
 *    the session if no user activity occurs within the timeout window.
 */
public final class SessionManager {

    public static final int DEFAULT_TIMEOUT_MINUTES = 15;

    private static SessionManager instance;

    private User currentUser;
    private SecretKey vaultKey;
    private Instant loginTime;
    private Instant lastActivityTime;
    private String sessionToken;
    private int timeoutMinutes = DEFAULT_TIMEOUT_MINUTES;

    private SessionManager() {
    }

    public static synchronized SessionManager getInstance() {
        if (instance == null) {
            instance = new SessionManager();
        }
        return instance;
    }

    /**
     * Initializes an active session for the authenticated user.
     *
     * @param user     authenticated User
     * @param vaultKey derived AES-256 vault encryption key
     */
    public synchronized void startSession(User user, SecretKey vaultKey) {
        this.currentUser = user;
        this.vaultKey = vaultKey;
        this.loginTime = Instant.now();
        this.lastActivityTime = Instant.now();
        this.sessionToken = generateSessionToken();
    }

    /**
     * Checks if a valid authenticated session is active and has not expired due to inactivity.
     *
     * @return true if user is logged in and session is unexpired
     */
    public synchronized boolean isLoggedIn() {
        if (currentUser == null || vaultKey == null) {
            return false;
        }
        if (isExpired()) {
            clearSession();
            return false;
        }
        return true;
    }

    /**
     * Checks if the session has expired due to elapsed time since last activity.
     *
     * @return true if session exceeded inactivity timeout
     */
    public synchronized boolean isExpired() {
        if (currentUser == null || lastActivityTime == null) {
            return false;
        }
        if (timeoutMinutes <= 0) {
            return false; // Inactivity expiration disabled
        }
        long inactiveSeconds = Duration.between(lastActivityTime, Instant.now()).getSeconds();
        return inactiveSeconds >= (timeoutMinutes * 60L);
    }

    public synchronized User getCurrentUser() {
        if (!isLoggedIn()) {
            return null;
        }
        touch();
        return currentUser;
    }

    /**
     * Returns the unique ID of the currently logged-in user, or null if unauthenticated.
     *
     * @return user ID or null
     */
    public synchronized Long getUserId() {
        if (!isLoggedIn()) {
            return null;
        }
        touch();
        return currentUser.getUserId();
    }

    /**
     * Enforces active session requirement.
     *
     * @throws SecurityException if no active session is present
     */
    public synchronized void requireActiveSession() {
        if (!isLoggedIn()) {
            throw new SecurityException("Unauthorized access: active session required.");
        }
        touch();
    }

    public synchronized SecretKey getVaultKey() {
        if (!isLoggedIn()) {
            return null;
        }
        touch();
        return vaultKey;
    }

    public synchronized Instant getLoginTime() {
        return loginTime;
    }

    public synchronized Instant getLastActivityTime() {
        return lastActivityTime;
    }

    public synchronized String getSessionToken() {
        return sessionToken;
    }

    public synchronized int getTimeoutMinutes() {
        return timeoutMinutes;
    }

    public synchronized void setTimeoutMinutes(int timeoutMinutes) {
        this.timeoutMinutes = timeoutMinutes;
    }

    /**
     * Manually overrides last activity timestamp (useful for simulation and testing).
     *
     * @param time specific Instant
     */
    public synchronized void setLastActivityTime(Instant time) {
        this.lastActivityTime = time;
    }

    /**
     * Updates the last activity timestamp.
     */
    public synchronized void touch() {
        this.lastActivityTime = Instant.now();
    }

    /**
     * Clears session and securely scrubs key material and user state from memory.
     * Safe and idempotent to invoke repeatedly.
     */
    public synchronized void clearSession() {
        if (vaultKey != null) {
            try {
                if (!vaultKey.isDestroyed()) {
                    vaultKey.destroy();
                }
            } catch (Exception ignored) {
                // OpenJDK SecretKeySpec does not support Destroyable; reference nulling triggers GC
            }
            vaultKey = null;
        }

        this.currentUser = null;
        this.loginTime = null;
        this.lastActivityTime = null;
        this.sessionToken = null;
    }

    private String generateSessionToken() {
        byte[] tokenBytes = new byte[32];
        new SecureRandom().nextBytes(tokenBytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : tokenBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
