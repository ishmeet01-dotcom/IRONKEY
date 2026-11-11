package com.ironkey.model;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Represents an authenticated user in the IRONKEY system.
 * Contains user credentials, authentication salt, and key derivation salt.
 *
 * Note: Master passwords are never stored in plaintext.
 */
public class User {

    private Long userId;
    private String username;
    private String email;
    private String masterPasswordHash;
    private String masterPasswordSalt;
    private String keyDerivationSalt;
    private LocalDateTime createdAt;

    /**
     * Default constructor.
     */
    public User() {
    }

    /**
     * Constructor for creating a new user prior to database persistence.
     *
     * @param username           unique username
     * @param email              unique email address
     * @param masterPasswordHash PBKDF2 hash of master password
     * @param masterPasswordSalt salt used for authentication hashing
     * @param keyDerivationSalt  separate salt used strictly for AES vault key derivation
     */
    public User(String username, String email, String masterPasswordHash,
                String masterPasswordSalt, String keyDerivationSalt) {
        this(null, username, email, masterPasswordHash, masterPasswordSalt, keyDerivationSalt, LocalDateTime.now());
    }

    /**
     * Full constructor for hydrating a user from database persistence.
     *
     * @param userId             primary key identifier
     * @param username           unique username
     * @param email              unique email address
     * @param masterPasswordHash PBKDF2 hash of master password
     * @param masterPasswordSalt salt used for authentication hashing
     * @param keyDerivationSalt  separate salt used strictly for AES vault key derivation
     * @param createdAt          timestamp when user was registered
     */
    public User(Long userId, String username, String email, String masterPasswordHash,
                String masterPasswordSalt, String keyDerivationSalt, LocalDateTime createdAt) {
        this.userId = userId;
        this.username = username;
        this.email = email;
        this.masterPasswordHash = masterPasswordHash;
        this.masterPasswordSalt = masterPasswordSalt;
        this.keyDerivationSalt = keyDerivationSalt;
        this.createdAt = createdAt;
    }

    // --- Getters & Setters ---

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getMasterPasswordHash() {
        return masterPasswordHash;
    }

    public void setMasterPasswordHash(String masterPasswordHash) {
        this.masterPasswordHash = masterPasswordHash;
    }

    public String getMasterPasswordSalt() {
        return masterPasswordSalt;
    }

    public void setMasterPasswordSalt(String masterPasswordSalt) {
        this.masterPasswordSalt = masterPasswordSalt;
    }

    public String getKeyDerivationSalt() {
        return keyDerivationSalt;
    }

    public void setKeyDerivationSalt(String keyDerivationSalt) {
        this.keyDerivationSalt = keyDerivationSalt;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(userId, user.userId) ||
               (Objects.equals(username, user.username) && Objects.equals(email, user.email));
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, username, email);
    }

    /**
     * Safe string representation that masks sensitive cryptographic data.
     */
    @Override
    public String toString() {
        return "User{" +
                "userId=" + userId +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", masterPasswordHash='[PROTECTED]'" +
                ", masterPasswordSalt='[PROTECTED]'" +
                ", keyDerivationSalt='[PROTECTED]'" +
                ", createdAt=" + createdAt +
                '}';
    }
}
