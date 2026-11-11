package com.ironkey.service;

import com.ironkey.model.VaultAuditReport;
import com.ironkey.model.VaultEntry;
import com.ironkey.security.PasswordStrengthAnalyzer;
import com.ironkey.util.SessionManager;

import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Service orchestrating privacy-preserving password health analysis and security auditing.
 *
 * SECURITY ARCHITECTURE & PRIVACY DESIGN:
 * 1. Zero Network Leakage:
 *    Audit runs 100% locally in-memory. No passwords or hashes are ever transmitted externally.
 * 2. Ephemeral In-Memory Evaluation:
 *    Plaintext passwords exist only during the transient execution of {@link #performAudit(int)}.
 *    They are never written to logs, disk, or the database.
 * 3. Session Expiration Protection:
 *    If the session expires or is locked while an audit is executing, the audit immediately aborts,
 *    scrubs temporary data structures, and raises an {@link IllegalStateException}.
 * 4. Deterministic Scoring Algorithm:
 *    Health score is evaluated on a strict 0-100 scale using measurable metrics:
 *    - Very Weak password percentage and count (up to 40 pts deduction)
 *    - Weak password percentage (up to 25 pts deduction)
 *    - Reused password accounts and groups (up to 30 pts deduction)
 *    - Outdated credentials (> 180 days) (up to 15 pts deduction)
 */
public class SecurityAuditService {

    public static final int DEFAULT_OUTDATED_DAYS = 180;

    private final VaultService vaultService;
    private final SessionManager sessionManager;

    public SecurityAuditService() {
        this(new VaultService(), SessionManager.getInstance());
    }

    public SecurityAuditService(VaultService vaultService, SessionManager sessionManager) {
        this.vaultService = vaultService;
        this.sessionManager = sessionManager;
    }

    /**
     * Executes a full password health analysis using the default 180-day age threshold.
     *
     * @return comprehensive VaultAuditReport
     * @throws GeneralSecurityException if cryptographic decryption fails
     * @throws SQLException             if database access fails
     */
    public VaultAuditReport performAudit() throws GeneralSecurityException, SQLException {
        return performAudit(DEFAULT_OUTDATED_DAYS);
    }

    /**
     * Executes a full password health analysis with a custom outdated threshold.
     *
     * @param outdatedDaysThreshold age in days before a password is flagged as outdated
     * @return comprehensive VaultAuditReport
     * @throws GeneralSecurityException if cryptographic decryption fails
     * @throws SQLException             if database access fails
     */
    public VaultAuditReport performAudit(int outdatedDaysThreshold) throws GeneralSecurityException, SQLException {
        // 1. Session verification
        if (!sessionManager.isLoggedIn()) {
            throw new IllegalStateException("Active user session required to perform vault security audit.");
        }
        sessionManager.requireActiveSession();

        List<VaultEntry> entries = vaultService.getEntriesForCurrentUser();
        LocalDateTime now = LocalDateTime.now();

        if (entries == null || entries.isEmpty()) {
            return createEmptyVaultReport(now);
        }

        // Ephemeral in-memory structures for duplicate detection and classification
        // Key: plaintext password (strictly transient), Value: associated entries & decrypted usernames
        Map<String, List<EntryPair>> passwordToEntries = new HashMap<>();

        List<VaultAuditReport.WeakPasswordFinding> weakFindings = new ArrayList<>();
        List<VaultAuditReport.OutdatedPasswordFinding> outdatedFindings = new ArrayList<>();

        int strongCount = 0;
        int weakCount = 0;
        int veryWeakCount = 0;

        try {
            for (VaultEntry entry : entries) {
                // Abort if session expired mid-audit
                if (!sessionManager.isLoggedIn()) {
                    throw new IllegalStateException("User session expired during security audit execution.");
                }

                VaultService.DecryptedCredential decrypted = vaultService.decryptEntry(entry);
                String plainPassword = decrypted.getPassword();
                String plainUsername = decrypted.getUsername();

                // 2. Password Strength Evaluation
                PasswordStrengthAnalyzer.PasswordAnalysisResult analysis = PasswordStrengthAnalyzer.analyze(plainPassword);

                if (analysis.isVeryWeak()) {
                    veryWeakCount++;
                    weakFindings.add(new VaultAuditReport.WeakPasswordFinding(entry, plainUsername, analysis));
                } else if (analysis.isWeak()) {
                    weakCount++;
                    weakFindings.add(new VaultAuditReport.WeakPasswordFinding(entry, plainUsername, analysis));
                } else if (analysis.isStrong()) {
                    strongCount++;
                }

                // 3. Password Age Analysis
                LocalDateTime lastUpdated = entry.getUpdatedAt() != null ? entry.getUpdatedAt() : entry.getCreatedAt();
                if (lastUpdated != null) {
                    long daysOld = Duration.between(lastUpdated, now).toDays();
                    if (daysOld >= outdatedDaysThreshold) {
                        outdatedFindings.add(new VaultAuditReport.OutdatedPasswordFinding(entry, plainUsername, daysOld));
                    }
                }

                // 4. In-Memory Grouping for Reuse Detection
                passwordToEntries.computeIfAbsent(plainPassword, k -> new ArrayList<>())
                        .add(new EntryPair(entry, plainUsername));
            }

            // 5. Build Reused Password Groups
            List<VaultAuditReport.ReusedPasswordGroup> reuseGroups = new ArrayList<>();
            int totalReusedAccounts = 0;
            int groupId = 1;

            for (Map.Entry<String, List<EntryPair>> mapEntry : passwordToEntries.entrySet()) {
                List<EntryPair> pairs = mapEntry.getValue();
                if (pairs.size() > 1) {
                    List<VaultEntry> groupEntries = new ArrayList<>();
                    List<String> groupUsers = new ArrayList<>();
                    for (EntryPair p : pairs) {
                        groupEntries.add(p.entry);
                        groupUsers.add(p.username);
                    }
                    reuseGroups.add(new VaultAuditReport.ReusedPasswordGroup(groupId++, groupEntries, groupUsers));
                    totalReusedAccounts += pairs.size();
                }
            }

            // 6. Calculate Deterministic Health Score
            int total = entries.size();
            ScoreEvaluation scoreEval = calculateScore(total, veryWeakCount, weakCount, totalReusedAccounts,
                    reuseGroups.size(), outdatedFindings.size());

            return new VaultAuditReport(
                    scoreEval.score,
                    scoreEval.rating,
                    now,
                    total,
                    strongCount,
                    weakCount,
                    veryWeakCount,
                    totalReusedAccounts,
                    reuseGroups.size(),
                    outdatedFindings.size(),
                    weakFindings,
                    reuseGroups,
                    outdatedFindings,
                    scoreEval.deductions,
                    scoreEval.recommendations
            );

        } finally {
            // Guarantee in-memory scrubbing of transient plaintext passwords
            passwordToEntries.clear();
        }
    }

    /**
     * Deterministic scoring calculation formula:
     * Score = 100 - (VeryWeakPenalty + WeakPenalty + ReusedPenalty + OutdatedPenalty)
     * Bound strictly between 0 and 100.
     */
    private ScoreEvaluation calculateScore(int total, int veryWeakCount, int weakCount,
                                           int reusedAccounts, int reuseGroups, int outdatedCount) {
        if (total <= 0) {
            return new ScoreEvaluation(100, "Excellent",
                    Collections.emptyList(),
                    Collections.singletonList("Vault is empty. Add credentials to begin security monitoring."));
        }

        List<String> deductions = new ArrayList<>();
        List<String> recommendations = new ArrayList<>();

        // 1. Very Weak Passwords Penalty (Max 40 pts)
        double vwRatio = (double) veryWeakCount / total;
        int vwPenalty = (int) Math.round(Math.min(40.0, (vwRatio * 35.0) + (veryWeakCount * 5.0)));
        if (vwPenalty > 0) {
            deductions.add("Deducted " + vwPenalty + " pts: " + veryWeakCount + " critically weak or common password(s) found.");
            recommendations.add("Replace critically weak passwords immediately using the password generator.");
        }

        // 2. Weak Passwords Penalty (excluding very weak; Max 25 pts)
        double wRatio = (double) weakCount / total;
        int wPenalty = (int) Math.round(Math.min(25.0, wRatio * 25.0));
        if (wPenalty > 0) {
            deductions.add("Deducted " + wPenalty + " pts: " + weakCount + " weak password(s) below recommended standards.");
            recommendations.add("Strengthen weak passwords to at least 16 characters with mixed character sets.");
        }

        // 3. Reused Passwords Penalty (Max 30 pts)
        double reuseRatio = (double) reusedAccounts / total;
        int reusePenalty = (int) Math.round(Math.min(30.0, (reuseRatio * 25.0) + (reuseGroups * 3.0)));
        if (reusePenalty > 0) {
            deductions.add("Deducted " + reusePenalty + " pts: " + reusedAccounts + " account(s) share identical passwords across " + reuseGroups + " group(s).");
            recommendations.add("Assign unique passwords to each account to prevent credential stuffing.");
        }

        // 4. Outdated Passwords Penalty (Max 15 pts)
        double outdatedRatio = (double) outdatedCount / total;
        int outdatedPenalty = (int) Math.round(Math.min(15.0, outdatedRatio * 15.0));
        if (outdatedPenalty > 0) {
            deductions.add("Deducted " + outdatedPenalty + " pts: " + outdatedCount + " password(s) unchanged for over " + DEFAULT_OUTDATED_DAYS + " days.");
            recommendations.add("Review outdated credentials and update any that may no longer be secure.");
        }

        int totalDeductions = Math.min(100, vwPenalty + wPenalty + reusePenalty + outdatedPenalty);
        int finalScore = Math.max(0, 100 - totalDeductions);

        String rating;
        if (finalScore >= 90) rating = "Excellent";
        else if (finalScore >= 75) rating = "Good";
        else if (finalScore >= 50) rating = "Fair";
        else rating = "Critical Risk";

        if (recommendations.isEmpty()) {
            recommendations.add("Your vault meets all security health benchmarks. Excellent posture!");
        }

        return new ScoreEvaluation(finalScore, rating, deductions, recommendations);
    }

    private VaultAuditReport createEmptyVaultReport(LocalDateTime now) {
        return new VaultAuditReport(
                100,
                "Empty Vault",
                now,
                0, 0, 0, 0, 0, 0, 0,
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.singletonList("No credentials stored in vault yet. Add credentials to analyze security health.")
        );
    }

    private static class EntryPair {
        final VaultEntry entry;
        final String username;

        EntryPair(VaultEntry entry, String username) {
            this.entry = entry;
            this.username = username;
        }
    }

    private static class ScoreEvaluation {
        final int score;
        final String rating;
        final List<String> deductions;
        final List<String> recommendations;

        ScoreEvaluation(int score, String rating, List<String> deductions, List<String> recommendations) {
            this.score = score;
            this.rating = rating;
            this.deductions = deductions;
            this.recommendations = recommendations;
        }
    }
}
