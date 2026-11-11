package com.ironkey.ui;

import com.ironkey.config.DatabaseConfig;
import com.ironkey.dao.CategoryDAO;
import com.ironkey.model.User;
import com.ironkey.model.VaultAuditReport;
import com.ironkey.model.VaultEntry;
import com.ironkey.service.AuthenticationService;
import com.ironkey.service.SecurityAuditService;
import com.ironkey.service.VaultService;
import com.ironkey.ui.components.CredentialCard;
import com.ironkey.ui.components.Sidebar;
import com.ironkey.util.SessionManager;
import com.ironkey.util.UITheme;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.sql.SQLException;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Main dashboard window for IRONKEY.
 * Provides sidebar navigation, overview metrics, search bar, category filtering,
 * live decrypted personal vault credential cards, and a dedicated Password Health & Security Audit dashboard.
 */
public class DashboardFrame extends JFrame {

    private static final DateTimeFormatter AUDIT_DATE_FORMATTER = DateTimeFormatter.ofPattern("MMM dd, yyyy • hh:mm a");

    private final AuthenticationService authService = new AuthenticationService();
    private final VaultService vaultService;
    private final SecurityAuditService auditService;
    private final CategoryDAO categoryDAO = new CategoryDAO();

    private Sidebar sidebar;
    private JTextField searchField;
    private JComboBox<String> categoryFilterCombo;
    private JButton addCredentialBtn;
    private JPanel credentialsListPanel;
    private JPanel emptyStatePanel;
    private JPanel noMatchPanel;

    private JLabel totalCredentialsVal;
    private JLabel vaultHealthScoreVal;
    private JLabel securityAuditVal;
    private JLabel dbStatusLabel;

    private CardLayout mainCardLayout;
    private JPanel mainContentHolder;

    // Audit Dashboard Components
    private JPanel auditContainer;
    private JLabel auditHeroScoreLabel;
    private JLabel auditHeroRatingLabel;
    private JLabel auditHeroMetaLabel;
    private JLabel auditStrongCountLabel;
    private JLabel auditWeakCountLabel;
    private JLabel auditReusedCountLabel;
    private JLabel auditOutdatedCountLabel;
    private JPanel auditTabCardsHolder;
    private CardLayout auditTabCardLayout;
    private JButton tabWeakBtn;
    private JButton tabReusedBtn;
    private JButton tabOutdatedBtn;
    private JButton tabTipsBtn;
    private JPanel weakListPanel;
    private JPanel reusedListPanel;
    private JPanel outdatedListPanel;
    private JPanel tipsListPanel;

    private final List<CachedEntry> allCachedEntries = new ArrayList<>();
    private String selectedCategory = "All Categories";
    private VaultAuditReport latestAuditReport = null;

    public DashboardFrame() {
        this(new VaultService());
    }

    public DashboardFrame(VaultService vaultService) {
        this.vaultService = vaultService;
        this.auditService = new SecurityAuditService(vaultService, SessionManager.getInstance());

        // Enforce active authenticated session requirement
        if (!SessionManager.getInstance().isLoggedIn()) {
            dispose();
            if (GraphicsEnvironment.isHeadless()) {
                throw new SecurityException("Unauthorized access: active session required.");
            }
            SwingUtilities.invokeLater(() -> {
                JOptionPane.showMessageDialog(null,
                        "Access Denied: Please unlock your vault with your master password.",
                        "Authentication Required", JOptionPane.WARNING_MESSAGE);
                LoginFrame login = new LoginFrame();
                login.setVisible(true);
            });
            return;
        }

        if (!GraphicsEnvironment.isHeadless()) {
            setTitle("IRONKEY — Vault Dashboard (" + SessionManager.getInstance().getCurrentUser().getUsername() + ")");
            setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            setSize(1140, 780);
            setMinimumSize(new Dimension(900, 620));
            setLocationRelativeTo(null);
            getContentPane().setBackground(UITheme.BG_DARKEST);

            initUI();
            loadCredentials();
        }
    }

    private void initUI() {
        setLayout(new BorderLayout());

        // 1. Sidebar on the West
        sidebar = new Sidebar(this::handleNavigation, this::handleLogout);
        add(sidebar, BorderLayout.WEST);

        // 2. Main Content Container
        JPanel mainContent = new JPanel(new BorderLayout());
        mainContent.setOpaque(false);

        // Top Navigation / Header Bar
        JPanel topBar = createTopBar();
        mainContent.add(topBar, BorderLayout.NORTH);

        // View Holder with CardLayout (View 1: Vault Credentials, View 2: Security Audit)
        mainCardLayout = new CardLayout();
        mainContentHolder = new JPanel(mainCardLayout);
        mainContentHolder.setOpaque(false);

        // View 1: Vault Credentials Scrollable View
        JScrollPane vaultScrollPane = new JScrollPane(createVaultBodyContainer());
        vaultScrollPane.setBorder(null);
        vaultScrollPane.setOpaque(false);
        vaultScrollPane.getViewport().setOpaque(false);
        vaultScrollPane.getVerticalScrollBar().setUnitIncrement(16);
        mainContentHolder.add(vaultScrollPane, "VAULT_VIEW");

        // View 2: Security Audit Dashboard Scrollable View
        JScrollPane auditScrollPane = new JScrollPane(createAuditBodyContainer());
        auditScrollPane.setBorder(null);
        auditScrollPane.setOpaque(false);
        auditScrollPane.getViewport().setOpaque(false);
        auditScrollPane.getVerticalScrollBar().setUnitIncrement(16);
        mainContentHolder.add(auditScrollPane, "AUDIT_VIEW");

        mainContent.add(mainContentHolder, BorderLayout.CENTER);

        // Footer Status Bar
        mainContent.add(createFooterStatusBar(), BorderLayout.SOUTH);

        add(mainContent, BorderLayout.CENTER);
    }

    private JPanel createTopBar() {
        JPanel bar = new JPanel(new BorderLayout(16, 0));
        bar.setOpaque(false);
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, UITheme.BORDER_DEFAULT),
                new EmptyBorder(16, 28, 16, 28)
        ));

        // Search Bar with Real-Time Filtering
        JPanel searchBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        searchBox.setOpaque(false);

        searchField = UITheme.createModernTextField("Search credentials by site, username, or URL...");
        searchField.setPreferredSize(new Dimension(380, 38));
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { applyFilterAndRender(); }
            @Override
            public void removeUpdate(DocumentEvent e) { applyFilterAndRender(); }
            @Override
            public void changedUpdate(DocumentEvent e) { applyFilterAndRender(); }
        });
        searchBox.add(searchField);
        bar.add(searchBox, BorderLayout.WEST);

        // Actions: Add Credential, Generator & Quick Lock
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        actions.setOpaque(false);

        JButton generatorBtn = UITheme.createSecondaryButton("🎲 Generator");
        generatorBtn.setPreferredSize(new Dimension(115, 38));
        generatorBtn.addActionListener(e -> new PasswordGeneratorDialog(this, null).setVisible(true));
        actions.add(generatorBtn);

        addCredentialBtn = UITheme.createPrimaryButton("+ Add Credential");
        addCredentialBtn.setPreferredSize(new Dimension(150, 38));
        addCredentialBtn.addActionListener(e -> showAddCredentialDialog());
        actions.add(addCredentialBtn);

        JButton lockButton = UITheme.createSecondaryButton("🔒 Lock");
        lockButton.setPreferredSize(new Dimension(80, 38));
        lockButton.addActionListener(e -> handleLogout());
        actions.add(lockButton);

        bar.add(actions, BorderLayout.EAST);
        return bar;
    }

    private JPanel createVaultBodyContainer() {
        JPanel bodyContainer = new JPanel();
        bodyContainer.setLayout(new BoxLayout(bodyContainer, BoxLayout.Y_AXIS));
        bodyContainer.setOpaque(false);
        bodyContainer.setBorder(new EmptyBorder(24, 28, 24, 28));

        // Welcome & Overview Section
        bodyContainer.add(createWelcomeSection());
        bodyContainer.add(Box.createVerticalStrut(20));

        // Metrics Summary Cards
        bodyContainer.add(createMetricsRow());
        bodyContainer.add(Box.createVerticalStrut(24));

        // Credentials Section Header with Category Filter & Refresh
        bodyContainer.add(createSectionHeader());
        bodyContainer.add(Box.createVerticalStrut(12));

        // Credentials Container (Holds either Empty State or Cards)
        credentialsListPanel = new JPanel();
        credentialsListPanel.setLayout(new BoxLayout(credentialsListPanel, BoxLayout.Y_AXIS));
        credentialsListPanel.setOpaque(false);

        emptyStatePanel = createEmptyStatePanel();
        noMatchPanel = createNoMatchPanel();
        credentialsListPanel.add(emptyStatePanel);

        bodyContainer.add(credentialsListPanel);
        bodyContainer.add(Box.createVerticalGlue());

        return bodyContainer;
    }

    private JPanel createWelcomeSection() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setOpaque(false);

        User currentUser = SessionManager.getInstance().getCurrentUser();
        String name = (currentUser != null) ? currentUser.getUsername() : "Vault Owner";
        String email = (currentUser != null) ? currentUser.getEmail() : "unauthenticated";

        JPanel textPanel = new JPanel();
        textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.Y_AXIS));
        textPanel.setOpaque(false);

        JLabel welcomeLabel = new JLabel("Welcome back, " + name);
        welcomeLabel.setFont(UITheme.FONT_HEADER);
        welcomeLabel.setForeground(UITheme.TEXT_PRIMARY);

        JLabel subLabel = new JLabel("Account: " + email + " • AES-256-GCM Vault Unlocked & Isolated");
        subLabel.setFont(UITheme.FONT_BODY);
        subLabel.setForeground(UITheme.TEXT_SECONDARY);

        textPanel.add(welcomeLabel);
        textPanel.add(Box.createVerticalStrut(4));
        textPanel.add(subLabel);

        panel.add(textPanel, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createMetricsRow() {
        JPanel row = new JPanel(new GridLayout(1, 3, 16, 0));
        row.setOpaque(false);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 100));

        totalCredentialsVal = new JLabel("0");
        totalCredentialsVal.setFont(UITheme.FONT_BRAND_TITLE);
        totalCredentialsVal.setForeground(UITheme.ACCENT_EMERALD);

        vaultHealthScoreVal = new JLabel("100%");
        vaultHealthScoreVal.setFont(UITheme.FONT_BRAND_TITLE);
        vaultHealthScoreVal.setForeground(UITheme.ACCENT_BRONZE);

        securityAuditVal = new JLabel("0 At Risk");
        securityAuditVal.setFont(UITheme.FONT_BRAND_TITLE);
        securityAuditVal.setForeground(UITheme.STATUS_SUCCESS);

        JPanel totalCard = createMetricCard("Total Credentials", totalCredentialsVal, "Encrypted in MySQL");
        JPanel healthCard = createMetricCard("Vault Health Score", vaultHealthScoreVal, "Click to view full audit");
        JPanel auditCard = createMetricCard("Security Audit", securityAuditVal, "Click to analyze passwords");

        // Make health and audit cards interactive shortcuts to the audit dashboard
        healthCard.setCursor(new Cursor(Cursor.HAND_CURSOR));
        healthCard.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) { showAuditView(); }
        });

        auditCard.setCursor(new Cursor(Cursor.HAND_CURSOR));
        auditCard.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) { showAuditView(); }
        });

        row.add(totalCard);
        row.add(healthCard);
        row.add(auditCard);

        return row;
    }

    private JPanel createMetricCard(String label, JLabel valLbl, String footer) {
        JPanel card = UITheme.createCardPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));

        JLabel titleLbl = new JLabel(label);
        titleLbl.setFont(UITheme.FONT_SMALL);
        titleLbl.setForeground(UITheme.TEXT_SECONDARY);

        JLabel footLbl = new JLabel(footer);
        footLbl.setFont(UITheme.FONT_SMALL);
        footLbl.setForeground(UITheme.TEXT_MUTED);

        card.add(titleLbl);
        card.add(Box.createVerticalStrut(4));
        card.add(valLbl);
        card.add(Box.createVerticalStrut(4));
        card.add(footLbl);

        return card;
    }

    private JPanel createSectionHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setOpaque(false);

        JLabel label = new JLabel("Personal Credentials");
        label.setFont(UITheme.FONT_SECTION_TITLE);
        label.setForeground(UITheme.TEXT_PRIMARY);
        header.add(label, BorderLayout.WEST);

        // Right side controls: Category Filter & Refresh
        JPanel filterControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        filterControls.setOpaque(false);

        JLabel filterLabel = new JLabel("Category:");
        filterLabel.setFont(UITheme.FONT_SMALL);
        filterLabel.setForeground(UITheme.TEXT_SECONDARY);
        filterControls.add(filterLabel);

        categoryFilterCombo = new JComboBox<>(new String[]{
                "All Categories", "Logins", "Financial", "Secure Notes", "Servers", "Social", "Work"
        });
        categoryFilterCombo.setBackground(UITheme.BG_INPUT);
        categoryFilterCombo.setForeground(UITheme.TEXT_PRIMARY);
        categoryFilterCombo.setFont(UITheme.FONT_SMALL);
        categoryFilterCombo.setPreferredSize(new Dimension(140, 30));
        categoryFilterCombo.addActionListener(e -> {
            selectedCategory = (String) categoryFilterCombo.getSelectedItem();
            applyFilterAndRender();
        });
        filterControls.add(categoryFilterCombo);

        JButton refreshBtn = UITheme.createSecondaryButton("🔄 Refresh");
        refreshBtn.setPreferredSize(new Dimension(95, 30));
        refreshBtn.setFont(UITheme.FONT_SMALL);
        refreshBtn.addActionListener(e -> loadCredentials());
        filterControls.add(refreshBtn);

        header.add(filterControls, BorderLayout.EAST);
        return header;
    }

    // =========================================================================
    // SECURITY AUDIT DASHBOARD VIEW BUILDER
    // =========================================================================

    private JPanel createAuditBodyContainer() {
        auditContainer = new JPanel();
        auditContainer.setLayout(new BoxLayout(auditContainer, BoxLayout.Y_AXIS));
        auditContainer.setOpaque(false);
        auditContainer.setBorder(new EmptyBorder(24, 28, 24, 28));

        // 1. Audit Header
        JPanel auditHeader = new JPanel(new BorderLayout());
        auditHeader.setOpaque(false);

        JPanel titlePanel = new JPanel();
        titlePanel.setLayout(new BoxLayout(titlePanel, BoxLayout.Y_AXIS));
        titlePanel.setOpaque(false);

        JLabel headerTitle = new JLabel("🛡️ Password Health & Security Audit");
        headerTitle.setFont(UITheme.FONT_HEADER);
        headerTitle.setForeground(UITheme.TEXT_PRIMARY);

        JLabel headerSubtitle = new JLabel("Privacy-preserving local audit: Identifies weak, reused, and outdated credentials.");
        headerSubtitle.setFont(UITheme.FONT_BODY);
        headerSubtitle.setForeground(UITheme.TEXT_SECONDARY);

        titlePanel.add(headerTitle);
        titlePanel.add(Box.createVerticalStrut(4));
        titlePanel.add(headerSubtitle);
        auditHeader.add(titlePanel, BorderLayout.WEST);

        JButton runAuditBtn = UITheme.createPrimaryButton("🔄 Re-Scan Vault");
        runAuditBtn.setPreferredSize(new Dimension(150, 38));
        runAuditBtn.addActionListener(e -> runSecurityAuditAsync());
        auditHeader.add(runAuditBtn, BorderLayout.EAST);

        auditContainer.add(auditHeader);
        auditContainer.add(Box.createVerticalStrut(20));

        // 2. Health Score Hero Row
        JPanel heroRow = new JPanel(new BorderLayout(16, 0));
        heroRow.setOpaque(false);
        heroRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 120));

        // Hero Card (Left)
        JPanel heroCard = UITheme.createCardPanel();
        heroCard.setLayout(new BorderLayout(16, 0));
        heroCard.setPreferredSize(new Dimension(360, 110));

        auditHeroScoreLabel = new JLabel("100%");
        auditHeroScoreLabel.setFont(new Font("Segoe UI", Font.BOLD, 42));
        auditHeroScoreLabel.setForeground(UITheme.ACCENT_EMERALD);
        heroCard.add(auditHeroScoreLabel, BorderLayout.WEST);

        JPanel heroTextPanel = new JPanel();
        heroTextPanel.setLayout(new BoxLayout(heroTextPanel, BoxLayout.Y_AXIS));
        heroTextPanel.setOpaque(false);

        auditHeroRatingLabel = new JLabel("Vault Status: Excellent");
        auditHeroRatingLabel.setFont(UITheme.FONT_HEADER);
        auditHeroRatingLabel.setForeground(UITheme.TEXT_PRIMARY);

        auditHeroMetaLabel = new JLabel("Audited: Ready to scan • 0 credentials");
        auditHeroMetaLabel.setFont(UITheme.FONT_SMALL);
        auditHeroMetaLabel.setForeground(UITheme.TEXT_MUTED);

        heroTextPanel.add(Box.createVerticalGlue());
        heroTextPanel.add(auditHeroRatingLabel);
        heroTextPanel.add(Box.createVerticalStrut(4));
        heroTextPanel.add(auditHeroMetaLabel);
        heroTextPanel.add(Box.createVerticalGlue());
        heroCard.add(heroTextPanel, BorderLayout.CENTER);

        heroRow.add(heroCard, BorderLayout.WEST);

        // 4 Summary Metrics (Right)
        JPanel statsRow = new JPanel(new GridLayout(1, 4, 12, 0));
        statsRow.setOpaque(false);

        auditStrongCountLabel = new JLabel("0");
        auditStrongCountLabel.setFont(UITheme.FONT_BRAND_TITLE);
        auditStrongCountLabel.setForeground(UITheme.STATUS_SUCCESS);

        auditWeakCountLabel = new JLabel("0");
        auditWeakCountLabel.setFont(UITheme.FONT_BRAND_TITLE);
        auditWeakCountLabel.setForeground(UITheme.STATUS_DANGER);

        auditReusedCountLabel = new JLabel("0");
        auditReusedCountLabel.setFont(UITheme.FONT_BRAND_TITLE);
        auditReusedCountLabel.setForeground(UITheme.STATUS_WARNING);

        auditOutdatedCountLabel = new JLabel("0");
        auditOutdatedCountLabel.setFont(UITheme.FONT_BRAND_TITLE);
        auditOutdatedCountLabel.setForeground(UITheme.ACCENT_BRONZE);

        statsRow.add(createMetricCard("Strong Passwords", auditStrongCountLabel, "High entropy"));
        statsRow.add(createMetricCard("Weak Passwords", auditWeakCountLabel, "Needs attention"));
        statsRow.add(createMetricCard("Reused Passwords", auditReusedCountLabel, "Credential stuffing risk"));
        statsRow.add(createMetricCard("Outdated (>180d)", auditOutdatedCountLabel, "Age indicator"));

        heroRow.add(statsRow, BorderLayout.CENTER);
        auditContainer.add(heroRow);
        auditContainer.add(Box.createVerticalStrut(24));

        // 3. Segmented Navigation Bar for Audit Details
        JPanel segmentBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        segmentBar.setOpaque(false);
        segmentBar.setAlignmentX(Component.LEFT_ALIGNMENT);

        tabWeakBtn = createAuditTabButton("⚠️ Weak Passwords (0)", true);
        tabReusedBtn = createAuditTabButton("🔁 Reused Passwords (0)", false);
        tabOutdatedBtn = createAuditTabButton("⏰ Outdated Passwords (0)", false);
        tabTipsBtn = createAuditTabButton("📋 Recommendations & Score Breakdown", false);

        tabWeakBtn.addActionListener(e -> selectAuditTab("WEAK"));
        tabReusedBtn.addActionListener(e -> selectAuditTab("REUSED"));
        tabOutdatedBtn.addActionListener(e -> selectAuditTab("OUTDATED"));
        tabTipsBtn.addActionListener(e -> selectAuditTab("TIPS"));

        segmentBar.add(tabWeakBtn);
        segmentBar.add(tabReusedBtn);
        segmentBar.add(tabOutdatedBtn);
        segmentBar.add(tabTipsBtn);

        auditContainer.add(segmentBar);
        auditContainer.add(Box.createVerticalStrut(14));

        // 4. Tab Panels Holder
        auditTabCardLayout = new CardLayout();
        auditTabCardsHolder = new JPanel(auditTabCardLayout);
        auditTabCardsHolder.setOpaque(false);
        auditTabCardsHolder.setAlignmentX(Component.LEFT_ALIGNMENT);

        weakListPanel = createScrollableFindingPanel();
        reusedListPanel = createScrollableFindingPanel();
        outdatedListPanel = createScrollableFindingPanel();
        tipsListPanel = createScrollableFindingPanel();

        auditTabCardsHolder.add(weakListPanel, "WEAK");
        auditTabCardsHolder.add(reusedListPanel, "REUSED");
        auditTabCardsHolder.add(outdatedListPanel, "OUTDATED");
        auditTabCardsHolder.add(tipsListPanel, "TIPS");

        auditContainer.add(auditTabCardsHolder);
        auditContainer.add(Box.createVerticalGlue());

        return auditContainer;
    }

    private JPanel createScrollableFindingPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setOpaque(false);
        return panel;
    }

    private JButton createAuditTabButton(String text, boolean active) {
        JButton btn = UITheme.createSecondaryButton(text);
        btn.setPreferredSize(new Dimension(220, 34));
        btn.setFont(UITheme.FONT_BODY_BOLD);
        if (active) {
            btn.setForeground(UITheme.ACCENT_EMERALD);
        }
        return btn;
    }

    private void selectAuditTab(String tabName) {
        auditTabCardLayout.show(auditTabCardsHolder, tabName);

        tabWeakBtn.setForeground("WEAK".equals(tabName) ? UITheme.ACCENT_EMERALD : UITheme.TEXT_SECONDARY);
        tabReusedBtn.setForeground("REUSED".equals(tabName) ? UITheme.ACCENT_EMERALD : UITheme.TEXT_SECONDARY);
        tabOutdatedBtn.setForeground("OUTDATED".equals(tabName) ? UITheme.ACCENT_EMERALD : UITheme.TEXT_SECONDARY);
        tabTipsBtn.setForeground("TIPS".equals(tabName) ? UITheme.ACCENT_EMERALD : UITheme.TEXT_SECONDARY);
    }

    public void showVaultView() {
        if (mainCardLayout != null) {
            mainCardLayout.show(mainContentHolder, "VAULT_VIEW");
        }
    }

    public void showAuditView() {
        if (mainCardLayout != null) {
            mainCardLayout.show(mainContentHolder, "AUDIT_VIEW");
            runSecurityAuditAsync();
        }
    }

    /**
     * Executes the vault password security audit in a background thread
     * and refreshes the Audit Dashboard UI.
     */
    public void runSecurityAuditAsync() {
        SwingWorker<VaultAuditReport, Void> worker = new SwingWorker<>() {
            @Override
            protected VaultAuditReport doInBackground() throws Exception {
                return auditService.performAudit();
            }

            @Override
            protected void done() {
                try {
                    latestAuditReport = get();
                    renderAuditReport(latestAuditReport);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(DashboardFrame.this,
                            "Security audit failed: " + ex.getMessage(),
                            "Audit Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }

    private void renderAuditReport(VaultAuditReport report) {
        if (report == null) return;

        // 1. Update Hero Card
        int score = report.getOverallScore();
        auditHeroScoreLabel.setText(score + "%");
        if (score >= 90) {
            auditHeroScoreLabel.setForeground(UITheme.STATUS_SUCCESS);
        } else if (score >= 70) {
            auditHeroScoreLabel.setForeground(UITheme.ACCENT_BRONZE);
        } else if (score >= 50) {
            auditHeroScoreLabel.setForeground(UITheme.STATUS_WARNING);
        } else {
            auditHeroScoreLabel.setForeground(UITheme.STATUS_DANGER);
        }

        auditHeroRatingLabel.setText("Vault Status: " + report.getScoreRating());
        auditHeroMetaLabel.setText("Scanned: " + report.getTotalScanned() + " accounts • Audited: " +
                report.getAuditTimestamp().format(AUDIT_DATE_FORMATTER));

        // 2. Update Metric Numbers
        auditStrongCountLabel.setText(String.valueOf(report.getStrongCount()));
        auditWeakCountLabel.setText(String.valueOf(report.getWeakCount() + report.getVeryWeakCount()));
        auditReusedCountLabel.setText(report.getReusedAccountsCount() + " (" + report.getReuseGroupsCount() + " groups)");
        auditOutdatedCountLabel.setText(String.valueOf(report.getOutdatedCount()));

        // Update Overview Cards on Vault View too
        vaultHealthScoreVal.setText(score + "%");
        vaultHealthScoreVal.setForeground(auditHeroScoreLabel.getForeground());
        if (report.hasCriticalIssues()) {
            securityAuditVal.setText((report.getWeakCount() + report.getVeryWeakCount()) + " Weak / " + report.getReusedAccountsCount() + " Reused");
            securityAuditVal.setForeground(UITheme.STATUS_DANGER);
        } else {
            securityAuditVal.setText("0 At Risk");
            securityAuditVal.setForeground(UITheme.STATUS_SUCCESS);
        }

        // 3. Update Segment Tab Labels
        tabWeakBtn.setText("⚠️ Weak Passwords (" + report.getWeakFindings().size() + ")");
        tabReusedBtn.setText("🔁 Reused Passwords (" + report.getReusedAccountsCount() + ")");
        tabOutdatedBtn.setText("⏰ Outdated Passwords (" + report.getOutdatedCount() + ")");

        // 4. Populate Weak Passwords Tab
        weakListPanel.removeAll();
        if (report.getWeakFindings().isEmpty()) {
            weakListPanel.add(createPositiveStateCard("🛡️ All Passwords Secure",
                    "No weak or predictable passwords detected in your vault. Excellent password entropy!"));
        } else {
            for (VaultAuditReport.WeakPasswordFinding finding : report.getWeakFindings()) {
                weakListPanel.add(createWeakPasswordCard(finding));
                weakListPanel.add(Box.createVerticalStrut(10));
            }
        }

        // 5. Populate Reused Passwords Tab
        reusedListPanel.removeAll();
        if (report.getReuseGroups().isEmpty()) {
            reusedListPanel.add(createPositiveStateCard("✨ Zero Password Reuse",
                    "All credentials have unique, independent passwords. You are protected against credential stuffing!"));
        } else {
            for (VaultAuditReport.ReusedPasswordGroup group : report.getReuseGroups()) {
                reusedListPanel.add(createReusedGroupCard(group));
                reusedListPanel.add(Box.createVerticalStrut(12));
            }
        }

        // 6. Populate Outdated Passwords Tab
        outdatedListPanel.removeAll();
        if (report.getOutdatedFindings().isEmpty()) {
            outdatedListPanel.add(createPositiveStateCard("⏰ Up-to-Date Vault",
                    "All credentials have been created or rotated within the last 180 days."));
        } else {
            JLabel ageDisclaimer = new JLabel("<html><i>Note: Password age is a health indicator to review credentials periodically, not proof that a password is compromised.</i></html>");
            ageDisclaimer.setFont(UITheme.FONT_SMALL);
            ageDisclaimer.setForeground(UITheme.TEXT_MUTED);
            ageDisclaimer.setBorder(new EmptyBorder(0, 4, 10, 4));
            outdatedListPanel.add(ageDisclaimer);

            for (VaultAuditReport.OutdatedPasswordFinding finding : report.getOutdatedFindings()) {
                outdatedListPanel.add(createOutdatedPasswordCard(finding));
                outdatedListPanel.add(Box.createVerticalStrut(10));
            }
        }

        // 7. Populate Tips & Deductions Tab
        tipsListPanel.removeAll();
        tipsListPanel.add(createTipsAndDeductionsCard(report));

        auditTabCardsHolder.revalidate();
        auditTabCardsHolder.repaint();
    }

    private JPanel createPositiveStateCard(String title, String message) {
        JPanel card = UITheme.createCardPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setMaximumSize(new Dimension(Integer.MAX_VALUE, 120));
        card.setBorder(new EmptyBorder(20, 24, 20, 24));

        JLabel titleLbl = new JLabel(title);
        titleLbl.setFont(UITheme.FONT_BODY_BOLD);
        titleLbl.setForeground(UITheme.STATUS_SUCCESS);

        JLabel msgLbl = new JLabel("<html>" + message + "</html>");
        msgLbl.setFont(UITheme.FONT_BODY);
        msgLbl.setForeground(UITheme.TEXT_SECONDARY);

        card.add(titleLbl);
        card.add(Box.createVerticalStrut(6));
        card.add(msgLbl);
        return card;
    }

    private JPanel createWeakPasswordCard(VaultAuditReport.WeakPasswordFinding finding) {
        JPanel card = UITheme.createCardPanel();
        card.setLayout(new BorderLayout(14, 0));
        card.setMaximumSize(new Dimension(Integer.MAX_VALUE, 92));
        card.setBorder(new EmptyBorder(12, 16, 12, 16));

        JPanel leftPanel = new JPanel();
        leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.Y_AXIS));
        leftPanel.setOpaque(false);

        // Row 1: Site + Category + Username
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        row1.setOpaque(false);

        JLabel siteLabel = new JLabel(finding.getWebsiteName());
        siteLabel.setFont(UITheme.FONT_BODY_BOLD);
        siteLabel.setForeground(UITheme.TEXT_PRIMARY);

        JLabel userLabel = new JLabel("•  👤 " + finding.getDecryptedUsername());
        userLabel.setFont(UITheme.FONT_BODY);
        userLabel.setForeground(UITheme.TEXT_SECONDARY);

        String cat = finding.getEntry().getCategory() != null ? finding.getEntry().getCategory() : "General";
        JLabel badge = new JLabel(" " + cat + " ");
        badge.setFont(UITheme.FONT_SMALL);
        badge.setForeground(UITheme.ACCENT_BRONZE);
        badge.setBackground(UITheme.BG_INPUT);
        badge.setOpaque(true);

        row1.add(siteLabel);
        row1.add(badge);
        row1.add(userLabel);
        leftPanel.add(row1);
        leftPanel.add(Box.createVerticalStrut(4));

        // Row 2: Weakness reasons (NEVER showing the password)
        StringBuilder weaknessText = new StringBuilder();
        for (String w : finding.getAnalysis().getWeaknesses()) {
            if (weaknessText.length() > 0) weaknessText.append("  |  ");
            weaknessText.append("⚠️ ").append(w);
        }
        JLabel reasonLabel = new JLabel(weaknessText.toString());
        reasonLabel.setFont(UITheme.FONT_SMALL);
        reasonLabel.setForeground(finding.getAnalysis().isVeryWeak() ? UITheme.STATUS_DANGER : UITheme.STATUS_WARNING);
        leftPanel.add(reasonLabel);

        card.add(leftPanel, BorderLayout.CENTER);

        // Action button to launch replacement generator and update dialog
        JButton fixBtn = UITheme.createPrimaryButton("⚡ Fix Password");
        fixBtn.setPreferredSize(new Dimension(135, 34));
        fixBtn.setFont(UITheme.FONT_SMALL);
        fixBtn.addActionListener(e -> {
            CredentialDialog dialog = new CredentialDialog(this, vaultService, finding.getEntry(), () -> {
                loadCredentials();
                runSecurityAuditAsync();
            });
            dialog.setVisible(true);
        });
        card.add(fixBtn, BorderLayout.EAST);

        return card;
    }

    private JPanel createReusedGroupCard(VaultAuditReport.ReusedPasswordGroup group) {
        JPanel card = UITheme.createCardPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setMaximumSize(new Dimension(Integer.MAX_VALUE, 160));
        card.setBorder(new EmptyBorder(14, 18, 14, 18));

        JLabel titleLbl = new JLabel("🔁 Duplicate Password Group #" + group.getGroupId() + " (" + group.getCount() + " accounts share identical password)");
        titleLbl.setFont(UITheme.FONT_BODY_BOLD);
        titleLbl.setForeground(UITheme.STATUS_WARNING);
        card.add(titleLbl);
        card.add(Box.createVerticalStrut(8));

        for (int i = 0; i < group.getAffectedEntries().size(); i++) {
            VaultEntry entry = group.getAffectedEntries().get(i);
            String user = group.getDecryptedUsernames().get(i);

            JPanel itemRow = new JPanel(new BorderLayout());
            itemRow.setOpaque(false);
            itemRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));

            JLabel entryLbl = new JLabel("•  " + entry.getWebsiteName() + " (" + user + ") — [" + entry.getCategory() + "]");
            entryLbl.setFont(UITheme.FONT_BODY);
            entryLbl.setForeground(UITheme.TEXT_PRIMARY);

            JButton changeBtn = UITheme.createSecondaryButton("✏️ Make Unique");
            changeBtn.setPreferredSize(new Dimension(110, 24));
            changeBtn.setFont(UITheme.FONT_SMALL);
            changeBtn.addActionListener(e -> {
                CredentialDialog dialog = new CredentialDialog(this, vaultService, entry, () -> {
                    loadCredentials();
                    runSecurityAuditAsync();
                });
                dialog.setVisible(true);
            });

            itemRow.add(entryLbl, BorderLayout.WEST);
            itemRow.add(changeBtn, BorderLayout.EAST);

            card.add(itemRow);
            card.add(Box.createVerticalStrut(4));
        }

        return card;
    }

    private JPanel createOutdatedPasswordCard(VaultAuditReport.OutdatedPasswordFinding finding) {
        JPanel card = UITheme.createCardPanel();
        card.setLayout(new BorderLayout(14, 0));
        card.setMaximumSize(new Dimension(Integer.MAX_VALUE, 65));
        card.setBorder(new EmptyBorder(10, 16, 10, 16));

        JPanel left = new JPanel();
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));
        left.setOpaque(false);

        JLabel siteLbl = new JLabel(finding.getWebsiteName() + " (👤 " + finding.getDecryptedUsername() + ")");
        siteLbl.setFont(UITheme.FONT_BODY_BOLD);
        siteLbl.setForeground(UITheme.TEXT_PRIMARY);

        JLabel daysLbl = new JLabel("Unchanged for " + finding.getDaysOld() + " days (Threshold: 180 days)");
        daysLbl.setFont(UITheme.FONT_SMALL);
        daysLbl.setForeground(UITheme.TEXT_MUTED);

        left.add(siteLbl);
        left.add(Box.createVerticalStrut(2));
        left.add(daysLbl);
        card.add(left, BorderLayout.CENTER);

        JButton updateBtn = UITheme.createSecondaryButton("✏️ Rotate");
        updateBtn.setPreferredSize(new Dimension(90, 30));
        updateBtn.setFont(UITheme.FONT_SMALL);
        updateBtn.addActionListener(e -> {
            CredentialDialog dialog = new CredentialDialog(this, vaultService, finding.getEntry(), () -> {
                loadCredentials();
                runSecurityAuditAsync();
            });
            dialog.setVisible(true);
        });
        card.add(updateBtn, BorderLayout.EAST);

        return card;
    }

    private JPanel createTipsAndDeductionsCard(VaultAuditReport report) {
        JPanel card = UITheme.createCardPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(new EmptyBorder(18, 20, 18, 20));

        // Deductions Breakdown
        JLabel dedTitle = new JLabel("📊 Health Score Points Deduction Breakdown");
        dedTitle.setFont(UITheme.FONT_BODY_BOLD);
        dedTitle.setForeground(UITheme.TEXT_PRIMARY);
        card.add(dedTitle);
        card.add(Box.createVerticalStrut(8));

        if (report.getDeductionExplanations().isEmpty()) {
            JLabel cleanLbl = new JLabel("• Full score awarded (100/100). No deductions applied.");
            cleanLbl.setFont(UITheme.FONT_BODY);
            cleanLbl.setForeground(UITheme.STATUS_SUCCESS);
            card.add(cleanLbl);
        } else {
            for (String ded : report.getDeductionExplanations()) {
                JLabel line = new JLabel("• " + ded);
                line.setFont(UITheme.FONT_BODY);
                line.setForeground(UITheme.STATUS_DANGER);
                card.add(line);
                card.add(Box.createVerticalStrut(4));
            }
        }

        card.add(Box.createVerticalStrut(16));

        // Recommendations
        JLabel recTitle = new JLabel("💡 Actionable Security Recommendations");
        recTitle.setFont(UITheme.FONT_BODY_BOLD);
        recTitle.setForeground(UITheme.ACCENT_BRONZE);
        card.add(recTitle);
        card.add(Box.createVerticalStrut(8));

        for (String rec : report.getRecommendations()) {
            JLabel line = new JLabel("• " + rec);
            line.setFont(UITheme.FONT_BODY);
            line.setForeground(UITheme.TEXT_SECONDARY);
            card.add(line);
            card.add(Box.createVerticalStrut(4));
        }

        return card;
    }

    // =========================================================================
    // VAULT CREDENTIALS VIEW
    // =========================================================================

    private JPanel createEmptyStatePanel() {
        JPanel card = UITheme.createCardPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.setMaximumSize(new Dimension(Integer.MAX_VALUE, 260));
        card.setBorder(new EmptyBorder(32, 24, 32, 24));

        JLabel shield = new JLabel("🛡️");
        shield.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 44));
        shield.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.add(shield);
        card.add(Box.createVerticalStrut(12));

        JLabel heading = new JLabel("Your Vault is Empty & Encrypted");
        heading.setFont(UITheme.FONT_HEADER);
        heading.setForeground(UITheme.TEXT_PRIMARY);
        heading.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.add(heading);
        card.add(Box.createVerticalStrut(6));

        JLabel info = new JLabel("<html><center>No credentials have been saved yet.<br>" +
                "All items stored in IRONKEY are protected with client-side AES-256-GCM encryption.</center></html>");
        info.setFont(UITheme.FONT_BODY);
        info.setForeground(UITheme.TEXT_SECONDARY);
        info.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.add(info);
        card.add(Box.createVerticalStrut(18));

        JButton addBtn = UITheme.createBronzeButton("+ Add First Credential");
        addBtn.setAlignmentX(Component.CENTER_ALIGNMENT);
        addBtn.addActionListener(e -> showAddCredentialDialog());
        card.add(addBtn);

        return card;
    }

    private JPanel createNoMatchPanel() {
        JPanel card = UITheme.createCardPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.setMaximumSize(new Dimension(Integer.MAX_VALUE, 180));
        card.setBorder(new EmptyBorder(28, 24, 28, 24));

        JLabel icon = new JLabel("🔍");
        icon.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 36));
        icon.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.add(icon);
        card.add(Box.createVerticalStrut(8));

        JLabel heading = new JLabel("No Matching Credentials");
        heading.setFont(UITheme.FONT_BODY_BOLD);
        heading.setForeground(UITheme.TEXT_PRIMARY);
        heading.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.add(heading);
        card.add(Box.createVerticalStrut(4));

        JLabel info = new JLabel("No entries match the current search keyword or category filter.");
        info.setFont(UITheme.FONT_SMALL);
        info.setForeground(UITheme.TEXT_MUTED);
        info.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.add(info);

        return card;
    }

    private JPanel createFooterStatusBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setOpaque(false);
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, UITheme.BORDER_DEFAULT),
                new EmptyBorder(8, 20, 8, 20)
        ));

        JLabel cryptoInfo = new JLabel("🔒 Encryption: AES-256-GCM • PBKDF2 310k Iterations • Zero Plaintext Storage");
        cryptoInfo.setFont(UITheme.FONT_SMALL);
        cryptoInfo.setForeground(UITheme.TEXT_MUTED);

        DatabaseConfig.ConnectionTestResult testResult = DatabaseConfig.getInstance().testConnection();
        String dbStr = testResult.isSuccess()
                ? "MySQL: Connected (" + testResult.getLatencyMs() + "ms)"
                : "MySQL: Offline (Local Mode)";

        dbStatusLabel = new JLabel(dbStr);
        dbStatusLabel.setFont(UITheme.FONT_SMALL);
        dbStatusLabel.setForeground(testResult.isSuccess() ? UITheme.STATUS_SUCCESS : UITheme.TEXT_MUTED);

        bar.add(cryptoInfo, BorderLayout.WEST);
        bar.add(dbStatusLabel, BorderLayout.EAST);
        return bar;
    }

    /**
     * Loads credentials asynchronously from database for the active user,
     * decrypts usernames for search indexing, and renders the list.
     */
    public void loadCredentials() {
        SwingWorker<List<CachedEntry>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<CachedEntry> doInBackground() throws Exception {
                List<VaultEntry> entries = vaultService.getEntriesForCurrentUser();
                List<CachedEntry> list = new ArrayList<>();
                for (VaultEntry entry : entries) {
                    String plainUsername = "";
                    try {
                        VaultService.DecryptedCredential decrypted = vaultService.decryptEntry(entry);
                        plainUsername = decrypted.getUsername();
                    } catch (Exception e) {
                        plainUsername = "[Decryption Error]";
                    }
                    list.add(new CachedEntry(entry, plainUsername));
                }
                return list;
            }

            @Override
            protected void done() {
                try {
                    List<CachedEntry> results = get();
                    allCachedEntries.clear();
                    allCachedEntries.addAll(results);

                    // Update metrics
                    totalCredentialsVal.setText(String.valueOf(allCachedEntries.size()));

                    applyFilterAndRender();

                    // Trigger background audit refresh to update health scores
                    runSecurityAuditAsync();
                } catch (Exception ex) {
                    DatabaseConfig.ConnectionTestResult testResult = DatabaseConfig.getInstance().testConnection();
                    if (!testResult.isSuccess()) {
                        dbStatusLabel.setText("MySQL: Offline");
                        dbStatusLabel.setForeground(UITheme.STATUS_WARNING);
                    }
                    credentialsListPanel.removeAll();
                    credentialsListPanel.add(emptyStatePanel);
                    credentialsListPanel.revalidate();
                    credentialsListPanel.repaint();
                }
            }
        };
        worker.execute();
    }

    /**
     * Filters the cached entries according to search query and selected category,
     * then refreshes the cards in the view.
     */
    private void applyFilterAndRender() {
        if (credentialsListPanel == null) return;

        String query = (searchField != null && searchField.getText() != null)
                ? searchField.getText().trim().toLowerCase() : "";

        List<CachedEntry> filtered = allCachedEntries.stream()
                .filter(cached -> {
                    // Category filter
                    if (selectedCategory != null && !selectedCategory.equalsIgnoreCase("All Categories")) {
                        String cat = cached.entry.getCategory();
                        if (cat == null || !cat.equalsIgnoreCase(selectedCategory)) {
                            return false;
                        }
                    }
                    // Search query filter
                    if (query.isEmpty()) {
                        return true;
                    }
                    String site = cached.entry.getWebsiteName() != null ? cached.entry.getWebsiteName().toLowerCase() : "";
                    String url = cached.entry.getWebsiteUrl() != null ? cached.entry.getWebsiteUrl().toLowerCase() : "";
                    String user = cached.plainUsername != null ? cached.plainUsername.toLowerCase() : "";

                    return site.contains(query) || url.contains(query) || user.contains(query);
                })
                .collect(Collectors.toList());

        credentialsListPanel.removeAll();

        if (allCachedEntries.isEmpty()) {
            credentialsListPanel.add(emptyStatePanel);
        } else if (filtered.isEmpty()) {
            credentialsListPanel.add(noMatchPanel);
        } else {
            for (CachedEntry cached : filtered) {
                CredentialCard card = new CredentialCard(
                        cached.entry,
                        vaultService,
                        this::handleEditCredential,
                        this::handleDeleteCredential
                );
                credentialsListPanel.add(card);
                credentialsListPanel.add(Box.createVerticalStrut(10));
            }
        }

        credentialsListPanel.revalidate();
        credentialsListPanel.repaint();
    }

    private void showAddCredentialDialog() {
        CredentialDialog dialog = new CredentialDialog(this, vaultService, null, this::loadCredentials);
        dialog.setVisible(true);
    }

    private void handleEditCredential(VaultEntry entry) {
        CredentialDialog dialog = new CredentialDialog(this, vaultService, entry, () -> {
            loadCredentials();
            runSecurityAuditAsync();
        });
        dialog.setVisible(true);
    }

    private void handleDeleteCredential(VaultEntry entry) {
        try {
            boolean deleted = vaultService.deleteEntry(entry.getEntryId());
            if (deleted) {
                loadCredentials();
                runSecurityAuditAsync();
                JOptionPane.showMessageDialog(this,
                        "Credential for '" + entry.getWebsiteName() + "' was permanently removed from your encrypted vault.",
                        "Deleted", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(this,
                        "Could not delete credential. Entry not found or unauthorized.",
                        "Delete Failed", JOptionPane.ERROR_MESSAGE);
            }
        } catch (SQLException ex) {
            JOptionPane.showMessageDialog(this,
                    "Database error during deletion: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void handleNavigation(String section) {
        if ("VAULT".equals(section)) {
            showVaultView();
            selectedCategory = "All Categories";
            if (categoryFilterCombo != null) {
                categoryFilterCombo.setSelectedItem("All Categories");
            }
            if (searchField != null) {
                searchField.setText("");
            }
            applyFilterAndRender();
        } else if ("AUDIT".equals(section)) {
            showAuditView();
        } else if ("GENERATOR".equals(section)) {
            new PasswordGeneratorDialog(this, null).setVisible(true);
        } else if ("CATEGORIES".equals(section)) {
            showVaultView();
            String[] options = {"All Categories", "Logins", "Financial", "Secure Notes", "Servers", "Social", "Work"};
            String chosen = (String) JOptionPane.showInputDialog(
                    this,
                    "Select category to filter:",
                    "Filter by Category",
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    options,
                    selectedCategory
            );
            if (chosen != null) {
                selectedCategory = chosen;
                if (categoryFilterCombo != null) {
                    categoryFilterCombo.setSelectedItem(chosen);
                }
                applyFilterAndRender();
            }
        } else {
            JOptionPane.showMessageDialog(this,
                    "Section '" + section + "' placeholder initialized.\nFull workflow will be active in upcoming phases.",
                    "IRONKEY Navigation", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void handleLogout() {
        authService.logout();
        LoginFrame loginFrame = new LoginFrame();
        loginFrame.setVisible(true);
        this.dispose();
    }

    /**
     * Internal container storing an encrypted entry alongside its decrypted username for client filtering.
     */
    private static class CachedEntry {
        final VaultEntry entry;
        final String plainUsername;

        CachedEntry(VaultEntry entry, String plainUsername) {
            this.entry = entry;
            this.plainUsername = plainUsername;
        }
    }
}
