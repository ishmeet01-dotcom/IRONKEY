package com.ironkey.model;

import com.ironkey.security.PasswordStrengthAnalyzer;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

/**
 * Structured report encapsulating the findings of a vault-wide password security audit.
 * Designed with zero-knowledge privacy: sensitive plaintext passwords are never retained.
 */
public class VaultAuditReport {

    private final int overallScore;
    private final String scoreRating;
    private final LocalDateTime auditTimestamp;
    private final int totalScanned;
    private final int strongCount;
    private final int weakCount;
    private final int veryWeakCount;
    private final int reusedAccountsCount;
    private final int reuseGroupsCount;
    private final int outdatedCount;

    private final List<WeakPasswordFinding> weakFindings;
    private final List<ReusedPasswordGroup> reuseGroups;
    private final List<OutdatedPasswordFinding> outdatedFindings;
    private final List<String> deductionExplanations;
    private final List<String> recommendations;

    public VaultAuditReport(int overallScore, String scoreRating, LocalDateTime auditTimestamp,
                            int totalScanned, int strongCount, int weakCount, int veryWeakCount,
                            int reusedAccountsCount, int reuseGroupsCount, int outdatedCount,
                            List<WeakPasswordFinding> weakFindings,
                            List<ReusedPasswordGroup> reuseGroups,
                            List<OutdatedPasswordFinding> outdatedFindings,
                            List<String> deductionExplanations,
                            List<String> recommendations) {
        this.overallScore = overallScore;
        this.scoreRating = scoreRating;
        this.auditTimestamp = auditTimestamp;
        this.totalScanned = totalScanned;
        this.strongCount = strongCount;
        this.weakCount = weakCount;
        this.veryWeakCount = veryWeakCount;
        this.reusedAccountsCount = reusedAccountsCount;
        this.reuseGroupsCount = reuseGroupsCount;
        this.outdatedCount = outdatedCount;
        this.weakFindings = Collections.unmodifiableList(weakFindings);
        this.reuseGroups = Collections.unmodifiableList(reuseGroups);
        this.outdatedFindings = Collections.unmodifiableList(outdatedFindings);
        this.deductionExplanations = Collections.unmodifiableList(deductionExplanations);
        this.recommendations = Collections.unmodifiableList(recommendations);
    }

    public int getOverallScore() { return overallScore; }
    public String getScoreRating() { return scoreRating; }
    public LocalDateTime getAuditTimestamp() { return auditTimestamp; }
    public int getTotalScanned() { return totalScanned; }
    public int getStrongCount() { return strongCount; }
    public int getWeakCount() { return weakCount; }
    public int getVeryWeakCount() { return veryWeakCount; }
    public int getReusedAccountsCount() { return reusedAccountsCount; }
    public int getReuseGroupsCount() { return reuseGroupsCount; }
    public int getOutdatedCount() { return outdatedCount; }

    public List<WeakPasswordFinding> getWeakFindings() { return weakFindings; }
    public List<ReusedPasswordGroup> getReuseGroups() { return reuseGroups; }
    public List<OutdatedPasswordFinding> getOutdatedFindings() { return outdatedFindings; }
    public List<String> getDeductionExplanations() { return deductionExplanations; }
    public List<String> getRecommendations() { return recommendations; }

    public boolean hasCriticalIssues() {
        return veryWeakCount > 0 || reusedAccountsCount > 0;
    }

    /**
     * Finding record for an individual credential identified as weak or very weak.
     */
    public static class WeakPasswordFinding {
        private final VaultEntry entry;
        private final String decryptedUsername;
        private final PasswordStrengthAnalyzer.PasswordAnalysisResult analysis;

        public WeakPasswordFinding(VaultEntry entry, String decryptedUsername,
                                   PasswordStrengthAnalyzer.PasswordAnalysisResult analysis) {
            this.entry = entry;
            this.decryptedUsername = decryptedUsername;
            this.analysis = analysis;
        }

        public VaultEntry getEntry() { return entry; }
        public String getDecryptedUsername() { return decryptedUsername; }
        public PasswordStrengthAnalyzer.PasswordAnalysisResult getAnalysis() { return analysis; }
        public String getWebsiteName() { return entry.getWebsiteName(); }
        public String getWebsiteUrl() { return entry.getWebsiteUrl(); }
    }

    /**
     * Group of distinct credentials sharing identical passwords.
     */
    public static class ReusedPasswordGroup {
        private final int groupId;
        private final List<VaultEntry> affectedEntries;
        private final List<String> decryptedUsernames;

        public ReusedPasswordGroup(int groupId, List<VaultEntry> affectedEntries, List<String> decryptedUsernames) {
            this.groupId = groupId;
            this.affectedEntries = Collections.unmodifiableList(affectedEntries);
            this.decryptedUsernames = Collections.unmodifiableList(decryptedUsernames);
        }

        public int getGroupId() { return groupId; }
        public List<VaultEntry> getAffectedEntries() { return affectedEntries; }
        public List<String> getDecryptedUsernames() { return decryptedUsernames; }
        public int getCount() { return affectedEntries.size(); }
    }

    /**
     * Finding record for credentials that haven't been updated in over the threshold days.
     */
    public static class OutdatedPasswordFinding {
        private final VaultEntry entry;
        private final String decryptedUsername;
        private final long daysOld;

        public OutdatedPasswordFinding(VaultEntry entry, String decryptedUsername, long daysOld) {
            this.entry = entry;
            this.decryptedUsername = decryptedUsername;
            this.daysOld = daysOld;
        }

        public VaultEntry getEntry() { return entry; }
        public String getDecryptedUsername() { return decryptedUsername; }
        public long getDaysOld() { return daysOld; }
        public String getWebsiteName() { return entry.getWebsiteName(); }
    }
}
