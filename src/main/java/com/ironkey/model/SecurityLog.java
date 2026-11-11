package com.ironkey.model;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Represents an immutable audit trail entry for security events in the IRONKEY application.
 */
public class SecurityLog {

    private Long logId;
    private Long userId;
    private String eventType;
    private String description;
    private LocalDateTime timestamp;

    public SecurityLog() {
    }

    public SecurityLog(Long userId, String eventType, String description) {
        this(null, userId, eventType, description, LocalDateTime.now());
    }

    public SecurityLog(Long logId, Long userId, String eventType, String description, LocalDateTime timestamp) {
        this.logId = logId;
        this.userId = userId;
        this.eventType = eventType;
        this.description = description;
        this.timestamp = timestamp;
    }

    public Long getLogId() {
        return logId;
    }

    public void setLogId(Long logId) {
        this.logId = logId;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityLog that = (SecurityLog) o;
        return Objects.equals(logId, that.logId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(logId);
    }

    @Override
    public String toString() {
        return "SecurityLog{" +
                "logId=" + logId +
                ", userId=" + userId +
                ", eventType='" + eventType + '\'' +
                ", description='" + description + '\'' +
                ", timestamp=" + timestamp +
                '}';
    }
}
