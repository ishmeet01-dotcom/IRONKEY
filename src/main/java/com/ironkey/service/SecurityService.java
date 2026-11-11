package com.ironkey.service;

import com.ironkey.dao.SecurityLogDAO;
import com.ironkey.model.SecurityLog;
import com.ironkey.util.SessionManager;

import java.sql.SQLException;
import java.util.Collections;
import java.util.List;

/**
 * Service managing audit logging and security health assessments.
 */
public class SecurityService {

    private final SecurityLogDAO securityLogDAO;
    private final SessionManager sessionManager;

    public SecurityService() {
        this(new SecurityLogDAO(), SessionManager.getInstance());
    }

    public SecurityService(SecurityLogDAO securityLogDAO, SessionManager sessionManager) {
        this.securityLogDAO = securityLogDAO;
        this.sessionManager = sessionManager;
    }

    /**
     * Records an audit event for the currently authenticated user.
     *
     * @param eventType   category/action code (e.g. AUTH_SUCCESS, ENTRY_CREATED)
     * @param description contextual details
     */
    public void recordEvent(String eventType, String description) {
        if (sessionManager.isLoggedIn()) {
            Long userId = sessionManager.getCurrentUser().getUserId();
            try {
                securityLogDAO.logEvent(new SecurityLog(userId, eventType, description));
            } catch (SQLException ignored) {
            }
        }
    }

    /**
     * Retrieves recent security logs for the active user.
     *
     * @param limit maximum records
     * @return list of SecurityLog entries
     */
    public List<SecurityLog> getRecentLogs(int limit) {
        if (!sessionManager.isLoggedIn()) {
            return Collections.emptyList();
        }
        try {
            return securityLogDAO.findRecentByUserId(sessionManager.getCurrentUser().getUserId(), limit);
        } catch (SQLException e) {
            return Collections.emptyList();
        }
    }

    /**
     * Calculates an overall vault security score (0 to 100%) by auditing the active user's credentials.
     *
     * @return security percentage score
     */
    public int calculateOverallScore() {
        if (!sessionManager.isLoggedIn()) {
            return 100;
        }
        try {
            SecurityAuditService auditService = new SecurityAuditService(new VaultService(), sessionManager);
            return auditService.performAudit().getOverallScore();
        } catch (Exception e) {
            return 100;
        }
    }
}
