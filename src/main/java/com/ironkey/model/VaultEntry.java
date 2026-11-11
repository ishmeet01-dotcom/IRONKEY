package com.ironkey.model;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Represents an encrypted credential entry in a user's vault.
 * Username and password are stored exclusively in encrypted form with their initialization nonce.
 */
public class VaultEntry {

    private Long entryId;
    private Long userId;
    private String websiteName;
    private String websiteUrl;
    private String encryptedUsername;
    private String encryptedPassword;
    private String nonce; // 12-byte initialization vector (Base64)
    private String category;
    private String notes;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public VaultEntry() {
    }

    /**
     * Constructor for creating a new vault entry prior to database persistence.
     *
     * @param userId            owner of the vault entry
     * @param websiteName       human-readable service or website name
     * @param websiteUrl        URL of the login page
     * @param encryptedUsername AES-256-GCM encrypted username
     * @param encryptedPassword AES-256-GCM encrypted password
     * @param nonce             12-byte initialization vector (Base64)
     * @param category          classification category
     * @param notes             optional user notes
     */
    public VaultEntry(Long userId, String websiteName, String websiteUrl,
                      String encryptedUsername, String encryptedPassword,
                      String nonce, String category, String notes) {
        this(null, userId, websiteName, websiteUrl, encryptedUsername, encryptedPassword,
             nonce, category, notes, LocalDateTime.now(), LocalDateTime.now());
    }

    /**
     * Full constructor for hydrating a vault entry from the database.
     *
     * @param entryId           unique entry identifier
     * @param userId            owner of the vault entry
     * @param websiteName       human-readable service or website name
     * @param websiteUrl        URL of the login page
     * @param encryptedUsername AES-256-GCM encrypted username
     * @param encryptedPassword AES-256-GCM encrypted password
     * @param nonce             12-byte initialization vector (Base64)
     * @param category          classification category
     * @param notes             optional user notes
     * @param createdAt         timestamp when record was created
     * @param updatedAt         timestamp when record was last updated
     */
    public VaultEntry(Long entryId, Long userId, String websiteName, String websiteUrl,
                      String encryptedUsername, String encryptedPassword,
                      String nonce, String category, String notes,
                      LocalDateTime createdAt, LocalDateTime updatedAt) {
        this.entryId = entryId;
        this.userId = userId;
        this.websiteName = websiteName;
        this.websiteUrl = websiteUrl;
        this.encryptedUsername = encryptedUsername;
        this.encryptedPassword = encryptedPassword;
        this.nonce = nonce;
        this.category = category;
        this.notes = notes;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    // --- Getters & Setters ---

    public Long getEntryId() {
        return entryId;
    }

    public void setEntryId(Long entryId) {
        this.entryId = entryId;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getWebsiteName() {
        return websiteName;
    }

    public void setWebsiteName(String websiteName) {
        this.websiteName = websiteName;
    }

    public String getWebsiteUrl() {
        return websiteUrl;
    }

    public void setWebsiteUrl(String websiteUrl) {
        this.websiteUrl = websiteUrl;
    }

    public String getEncryptedUsername() {
        return encryptedUsername;
    }

    public void setEncryptedUsername(String encryptedUsername) {
        this.encryptedUsername = encryptedUsername;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public void setEncryptedPassword(String encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VaultEntry that = (VaultEntry) o;
        return Objects.equals(entryId, that.entryId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(entryId);
    }

    /**
     * Safe string representation masking encrypted secrets.
     */
    @Override
    public String toString() {
        return "VaultEntry{" +
                "entryId=" + entryId +
                ", userId=" + userId +
                ", websiteName='" + websiteName + '\'' +
                ", websiteUrl='" + websiteUrl + '\'' +
                ", encryptedUsername='[ENCRYPTED]'" +
                ", encryptedPassword='[ENCRYPTED]'" +
                ", category='" + category + '\'' +
                ", createdAt=" + createdAt +
                ", updatedAt=" + updatedAt +
                '}';
    }
}
