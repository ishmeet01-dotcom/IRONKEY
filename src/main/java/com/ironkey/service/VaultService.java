package com.ironkey.service;

import com.ironkey.dao.SecurityLogDAO;
import com.ironkey.dao.VaultEntryDAO;
import com.ironkey.model.SecurityLog;
import com.ironkey.model.VaultEntry;
import com.ironkey.security.EncryptionManager;
import com.ironkey.util.SessionManager;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Service managing encrypted vault operations and credential lifecycle.
 * Coordinates client-side AES-256-GCM authenticated encryption/decryption with database persistence.
 * Enforces strict user isolation and comprehensive security audit logging.
 */
public class VaultService {

    private final VaultEntryDAO vaultEntryDAO;
    private final SecurityLogDAO securityLogDAO;
    private final SessionManager sessionManager;

    public VaultService() {
        this(new VaultEntryDAO(), new SecurityLogDAO(), SessionManager.getInstance());
    }

    public VaultService(VaultEntryDAO vaultEntryDAO, SessionManager sessionManager) {
        this(vaultEntryDAO, new SecurityLogDAO(), sessionManager);
    }

    public VaultService(VaultEntryDAO vaultEntryDAO, SecurityLogDAO securityLogDAO, SessionManager sessionManager) {
        this.vaultEntryDAO = vaultEntryDAO;
        this.securityLogDAO = securityLogDAO;
        this.sessionManager = sessionManager;
    }

    private void checkActiveSession() {
        if (!sessionManager.isLoggedIn()) {
            throw new IllegalStateException("Active user session required.");
        }
        sessionManager.requireActiveSession();
    }

    /**
     * Retrieves all encrypted vault entries for the currently authenticated user.
     *
     * @return list of encrypted vault entries
     * @throws SQLException if a database error occurs
     */
    public List<VaultEntry> getEntriesForCurrentUser() throws SQLException {
        checkActiveSession();
        Long userId = sessionManager.getUserId();

        List<VaultEntry> entries = vaultEntryDAO.findAllByUserId(userId);
        logSecurityEvent("VAULT_ACCESSED", "Retrieved " + entries.size() + " encrypted records.");
        return entries;
    }

    /**
     * Encrypts sensitive fields with fresh random nonces and persists the credential entry.
     *
     * @param websiteName       name of the site/service (required)
     * @param websiteUrl        URL of login page (optional)
     * @param plaintextUsername username or email (required)
     * @param plaintextPassword password (required)
     * @param category          category classification
     * @param plaintextNotes    optional notes to encrypt
     * @return persisted VaultEntry
     * @throws GeneralSecurityException if encryption fails
     * @throws SQLException             if database persistence fails
     */
    public VaultEntry addEntry(String websiteName, String websiteUrl,
                               String plaintextUsername, String plaintextPassword,
                               String category, String plaintextNotes) throws GeneralSecurityException, SQLException {
        checkActiveSession();
        SecretKey key = sessionManager.getVaultKey();
        Long userId = sessionManager.getUserId();

        if (websiteName == null || websiteName.trim().isEmpty()) {
            throw new IllegalArgumentException("Website or application name cannot be empty.");
        }
        if (plaintextUsername == null || plaintextUsername.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty.");
        }
        if (plaintextPassword == null || plaintextPassword.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty.");
        }

        // Encrypt each attribute with an independent, fresh 12-byte nonce (eliminates GCM nonce reuse)
        String encryptedUsername = EncryptionManager.encrypt(plaintextUsername.trim(), key);
        String encryptedPassword = EncryptionManager.encrypt(plaintextPassword, key);
        String encryptedNotes = (plaintextNotes != null && !plaintextNotes.trim().isEmpty())
                ? EncryptionManager.encrypt(plaintextNotes.trim(), key)
                : null;
        String entryNonce = EncryptionManager.generateNonceBase64();

        String cat = (category != null && !category.trim().isEmpty()) ? category.trim() : "Logins";

        VaultEntry entry = new VaultEntry(userId, websiteName.trim(),
                websiteUrl != null ? websiteUrl.trim() : "",
                encryptedUsername, encryptedPassword,
                entryNonce, cat, encryptedNotes);

        VaultEntry saved = vaultEntryDAO.save(entry);
        logSecurityEvent("CREDENTIAL_CREATED", "Saved credential for: " + websiteName.trim());
        return saved;
    }

    /**
     * Re-encrypts modified credential fields with fresh independent nonces and updates database.
     *
     * @param entryId           unique ID of entry to update
     * @param websiteName       website or service name
     * @param websiteUrl        URL
     * @param plaintextUsername updated username
     * @param plaintextPassword updated password
     * @param category          category name
     * @param plaintextNotes    updated notes
     * @return true if updated, false if entry not found or unauthorized
     * @throws GeneralSecurityException if encryption fails
     * @throws SQLException             if database persistence fails
     */
    public boolean updateEntry(Long entryId, String websiteName, String websiteUrl,
                               String plaintextUsername, String plaintextPassword,
                               String category, String plaintextNotes) throws GeneralSecurityException, SQLException {
        checkActiveSession();
        SecretKey key = sessionManager.getVaultKey();
        Long userId = sessionManager.getUserId();

        if (entryId == null) {
            throw new IllegalArgumentException("Entry ID cannot be null.");
        }
        if (websiteName == null || websiteName.trim().isEmpty()) {
            throw new IllegalArgumentException("Website or application name cannot be empty.");
        }
        if (plaintextUsername == null || plaintextUsername.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be empty.");
        }
        if (plaintextPassword == null || plaintextPassword.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty.");
        }

        // Re-encrypt with fresh, independent 12-byte nonces
        String encryptedUsername = EncryptionManager.encrypt(plaintextUsername.trim(), key);
        String encryptedPassword = EncryptionManager.encrypt(plaintextPassword, key);
        String encryptedNotes = (plaintextNotes != null && !plaintextNotes.trim().isEmpty())
                ? EncryptionManager.encrypt(plaintextNotes.trim(), key)
                : null;
        String entryNonce = EncryptionManager.generateNonceBase64();

        String cat = (category != null && !category.trim().isEmpty()) ? category.trim() : "Logins";

        VaultEntry updatedEntry = new VaultEntry(entryId, userId, websiteName.trim(),
                websiteUrl != null ? websiteUrl.trim() : "",
                encryptedUsername, encryptedPassword,
                entryNonce, cat, encryptedNotes, null, null);

        boolean updated = vaultEntryDAO.update(updatedEntry);
        if (updated) {
            logSecurityEvent("CREDENTIAL_UPDATED", "Updated credential for: " + websiteName.trim());
        }
        return updated;
    }

    /**
     * Decrypts username, password, and notes for a vault entry in memory.
     * Supports both NIST SP 800-38D self-contained payloads and legacy separate nonce formats.
     *
     * @param entry vault entry
     * @return DecryptedCredential carrier containing ephemeral plaintext
     * @throws GeneralSecurityException if decryption or authentication tag verification fails
     */
    public DecryptedCredential decryptEntry(VaultEntry entry) throws GeneralSecurityException {
        checkActiveSession();
        SecretKey key = sessionManager.getVaultKey();

        // 1. Decrypt Username
        String username;
        try {
            username = EncryptionManager.decrypt(entry.getEncryptedUsername(), key);
        } catch (GeneralSecurityException e) {
            byte[] nonce = Base64.getDecoder().decode(entry.getNonce());
            username = EncryptionManager.decrypt(entry.getEncryptedUsername(), key, nonce);
        }

        // 2. Decrypt Password
        String password;
        try {
            password = EncryptionManager.decrypt(entry.getEncryptedPassword(), key);
        } catch (GeneralSecurityException e) {
            byte[] nonce = Base64.getDecoder().decode(entry.getNonce());
            password = EncryptionManager.decrypt(entry.getEncryptedPassword(), key, nonce);
        }

        // 3. Decrypt Notes (if present)
        String notes = "";
        if (entry.getNotes() != null && !entry.getNotes().isEmpty()) {
            try {
                notes = EncryptionManager.decrypt(entry.getNotes(), key);
            } catch (GeneralSecurityException e) {
                // If notes were legacy plaintext, preserve
                notes = entry.getNotes();
            }
        }

        return new DecryptedCredential(entry.getEntryId(), entry.getWebsiteName(),
                entry.getWebsiteUrl(), username, password,
                entry.getCategory(), notes);
    }

    /**
     * Deletes a vault entry ensuring strict user ownership constraint in the database.
     *
     * @param entryId ID of entry to delete
     * @return true if deleted, false if unauthorized or not found
     * @throws SQLException if database error occurs
     */
    public boolean deleteEntry(Long entryId) throws SQLException {
        checkActiveSession();
        Long userId = sessionManager.getUserId();

        boolean deleted = vaultEntryDAO.delete(entryId, userId);
        if (deleted) {
            logSecurityEvent("CREDENTIAL_DELETED", "Deleted entry ID: " + entryId);
        }
        return deleted;
    }

    /**
     * Searches vault entries by website name or URL in the database.
     *
     * @param query search query
     * @return list of matching entries
     * @throws SQLException if database error occurs
     */
    public List<VaultEntry> searchEntries(String query) throws SQLException {
        checkActiveSession();
        Long userId = sessionManager.getUserId();
        return vaultEntryDAO.search(userId, query != null ? query.trim() : "");
    }

    /**
     * Counts credentials saved in the user's vault.
     *
     * @return total count
     * @throws SQLException if database error occurs
     */
    public int getCredentialCount() throws SQLException {
        if (!sessionManager.isLoggedIn()) return 0;
        return vaultEntryDAO.countByUserId(sessionManager.getUserId());
    }

    private void logSecurityEvent(String eventType, String description) {
        if (securityLogDAO != null && sessionManager.isLoggedIn()) {
            try {
                securityLogDAO.logEvent(new SecurityLog(sessionManager.getUserId(), eventType, description));
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Ephemeral carrier for decrypted credentials in volatile memory.
     */
    public static class DecryptedCredential {
        private final Long entryId;
        private final String websiteName;
        private final String websiteUrl;
        private final String username;
        private final String password;
        private final String category;
        private final String notes;

        public DecryptedCredential(Long entryId, String websiteName, String websiteUrl,
                                   String username, String password, String category, String notes) {
            this.entryId = entryId;
            this.websiteName = websiteName;
            this.websiteUrl = websiteUrl;
            this.username = username;
            this.password = password;
            this.category = category;
            this.notes = notes;
        }

        public Long getEntryId() { return entryId; }
        public String getWebsiteName() { return websiteName; }
        public String getWebsiteUrl() { return websiteUrl; }
        public String getUsername() { return username; }
        public String getPassword() { return password; }
        public String getCategory() { return category; }
        public String getNotes() { return notes; }
    }
}
