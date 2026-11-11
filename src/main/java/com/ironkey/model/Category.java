package com.ironkey.model;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Represents a credential category in the vault (e.g. Logins, Financial, Secure Notes).
 */
public class Category {

    private Long categoryId;
    private Long userId; // null for system-wide default categories
    private String name;
    private String icon;
    private LocalDateTime createdAt;

    public Category() {
    }

    public Category(Long userId, String name, String icon) {
        this(null, userId, name, icon, LocalDateTime.now());
    }

    public Category(Long categoryId, Long userId, String name, String icon, LocalDateTime createdAt) {
        this.categoryId = categoryId;
        this.userId = userId;
        this.name = name;
        this.icon = icon;
        this.createdAt = createdAt;
    }

    public Long getCategoryId() {
        return categoryId;
    }

    public void setCategoryId(Long categoryId) {
        this.categoryId = categoryId;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getIcon() {
        return icon;
    }

    public void setIcon(String icon) {
        this.icon = icon;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public boolean isSystemDefault() {
        return userId == null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Category category = (Category) o;
        return Objects.equals(categoryId, category.categoryId) ||
               (Objects.equals(userId, category.userId) && Objects.equals(name, category.name));
    }

    @Override
    public int hashCode() {
        return Objects.hash(categoryId, userId, name);
    }

    @Override
    public String toString() {
        return name;
    }
}
