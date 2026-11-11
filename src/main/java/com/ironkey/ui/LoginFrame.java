package com.ironkey.ui;

import com.ironkey.config.DatabaseConfig;
import com.ironkey.service.AuthenticationService;
import com.ironkey.util.UITheme;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;

/**
 * Login window for IRONKEY.
 * Allows users to unlock their encrypted vault by authenticating with their master password.
 */
public class LoginFrame extends JFrame {

    private JTextField usernameOrEmailField;
    private JPasswordField passwordField;
    private JButton showPasswordBtn;
    private JButton loginButton;
    private JButton registerLinkButton;
    private JLabel statusLabel;
    private JLabel dbStatusIndicator;

    private boolean isPasswordVisible = false;
    private final AuthenticationService authService = new AuthenticationService();

    public LoginFrame() {
        this("");
    }

    public LoginFrame(String prefilledIdentifier) {
        setTitle("IRONKEY — Encrypted Password Management System");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(480, 660);
        setMinimumSize(new Dimension(420, 580));
        setLocationRelativeTo(null);
        getContentPane().setBackground(UITheme.BG_DARKEST);

        initUI(prefilledIdentifier);
    }

    private void initUI(String prefilledIdentifier) {
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(0, 0, 0, 0);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.NONE;

        // Centered Card Container
        JPanel card = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                UITheme.enableAntialiasing(g2d);
                g2d.setColor(UITheme.BG_PANEL);
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 16, 16);
                g2d.setColor(UITheme.BORDER_DEFAULT);
                g2d.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 16, 16);
                g2d.dispose();
                super.paintComponent(g);
            }
        };
        card.setOpaque(false);
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBorder(new EmptyBorder(36, 40, 36, 40));
        card.setPreferredSize(new Dimension(400, 550));

        // 1. Branding Header
        JPanel brandPanel = new JPanel();
        brandPanel.setOpaque(false);
        brandPanel.setLayout(new BoxLayout(brandPanel, BoxLayout.Y_AXIS));
        brandPanel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel logoIcon = new JLabel("🛡️");
        logoIcon.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 40));
        logoIcon.setAlignmentX(Component.CENTER_ALIGNMENT);
        brandPanel.add(logoIcon);
        brandPanel.add(Box.createVerticalStrut(8));

        JLabel titleLabel = new JLabel("IRONKEY");
        titleLabel.setFont(UITheme.FONT_BRAND_TITLE);
        titleLabel.setForeground(UITheme.TEXT_PRIMARY);
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        brandPanel.add(titleLabel);
        brandPanel.add(Box.createVerticalStrut(4));

        JLabel tagline = new JLabel("Your Credentials. Your Control.");
        tagline.setFont(UITheme.FONT_SMALL);
        tagline.setForeground(UITheme.ACCENT_BRONZE);
        tagline.setAlignmentX(Component.CENTER_ALIGNMENT);
        brandPanel.add(tagline);
        brandPanel.add(Box.createVerticalStrut(8));

        JLabel badge = new JLabel("AES-256-GCM • Zero-Knowledge Vault");
        badge.setFont(UITheme.FONT_SMALL);
        badge.setForeground(UITheme.TEXT_MUTED);
        badge.setAlignmentX(Component.CENTER_ALIGNMENT);
        brandPanel.add(badge);

        card.add(brandPanel);
        card.add(Box.createVerticalStrut(28));

        // 2. Email or Username Field
        JLabel userLabel = new JLabel("Email or Username");
        userLabel.setFont(UITheme.FONT_BODY_BOLD);
        userLabel.setForeground(UITheme.TEXT_SECONDARY);
        userLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(userLabel);
        card.add(Box.createVerticalStrut(6));

        usernameOrEmailField = UITheme.createModernTextField("e.g. user@secure.io or alex");
        if (prefilledIdentifier != null && !prefilledIdentifier.isEmpty()) {
            usernameOrEmailField.setText(prefilledIdentifier);
        }
        usernameOrEmailField.setAlignmentX(Component.LEFT_ALIGNMENT);
        usernameOrEmailField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        card.add(usernameOrEmailField);
        card.add(Box.createVerticalStrut(16));

        // 3. Master Password Field with Eye Toggle
        JLabel passLabel = new JLabel("Master Password");
        passLabel.setFont(UITheme.FONT_BODY_BOLD);
        passLabel.setForeground(UITheme.TEXT_SECONDARY);
        passLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(passLabel);
        card.add(Box.createVerticalStrut(6));

        JPanel passwordContainer = new JPanel(new BorderLayout(4, 0));
        passwordContainer.setOpaque(false);
        passwordContainer.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        passwordContainer.setAlignmentX(Component.LEFT_ALIGNMENT);

        passwordField = UITheme.createModernPasswordField("Enter master password");
        passwordField.addActionListener(this::handleLogin);
        passwordContainer.add(passwordField, BorderLayout.CENTER);

        showPasswordBtn = UITheme.createSecondaryButton("👁️");
        showPasswordBtn.setPreferredSize(new Dimension(42, 40));
        showPasswordBtn.setToolTipText("Show/Hide Password");
        showPasswordBtn.addActionListener(e -> togglePasswordVisibility());
        passwordContainer.add(showPasswordBtn, BorderLayout.EAST);

        card.add(passwordContainer);
        card.add(Box.createVerticalStrut(10));

        // Status Feedback Message
        statusLabel = new JLabel(" ");
        statusLabel.setFont(UITheme.FONT_SMALL);
        statusLabel.setForeground(UITheme.STATUS_DANGER);
        statusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(statusLabel);
        card.add(Box.createVerticalStrut(14));

        // 4. Primary Login Action
        loginButton = UITheme.createPrimaryButton("Unlock Vault");
        loginButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, 42));
        loginButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        loginButton.addActionListener(this::handleLogin);
        card.add(loginButton);
        card.add(Box.createVerticalStrut(14));

        // 5. Navigation: Register link
        JPanel navRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 4, 0));
        navRow.setOpaque(false);
        navRow.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel noAccLabel = new JLabel("New to IRONKEY?");
        noAccLabel.setFont(UITheme.FONT_BODY);
        noAccLabel.setForeground(UITheme.TEXT_MUTED);
        navRow.add(noAccLabel);

        registerLinkButton = UITheme.createLinkButton("Create Vault Account");
        registerLinkButton.addActionListener(e -> openRegisterFrame());
        navRow.add(registerLinkButton);

        card.add(navRow);
        card.add(Box.createVerticalGlue());

        // 6. DB Status Footer
        DatabaseConfig.ConnectionTestResult testResult = DatabaseConfig.getInstance().testConnection();
        String dbText = testResult.isSuccess()
                ? "● MySQL: Connected (" + testResult.getLatencyMs() + "ms)"
                : "○ MySQL: Offline (localhost:3306)";

        dbStatusIndicator = new JLabel(dbText);
        dbStatusIndicator.setFont(UITheme.FONT_SMALL);
        dbStatusIndicator.setForeground(testResult.isSuccess() ? UITheme.STATUS_SUCCESS : UITheme.TEXT_MUTED);
        dbStatusIndicator.setAlignmentX(Component.CENTER_ALIGNMENT);
        card.add(dbStatusIndicator);

        add(card, gbc);
    }

    private void togglePasswordVisibility() {
        isPasswordVisible = !isPasswordVisible;
        if (isPasswordVisible) {
            passwordField.setEchoChar((char) 0);
            showPasswordBtn.setText("🙈");
        } else {
            passwordField.setEchoChar('•');
            showPasswordBtn.setText("👁️");
        }
    }

    private void handleLogin(ActionEvent e) {
        String identifier = usernameOrEmailField.getText().trim();
        char[] password = passwordField.getPassword();

        if (identifier.isEmpty() || password.length == 0) {
            statusLabel.setText("Please enter both email/username and master password.");
            statusLabel.setForeground(UITheme.STATUS_DANGER);
            return;
        }

        // Disable button and indicate authentication in progress
        loginButton.setEnabled(false);
        loginButton.setText("Verifying Credentials...");
        statusLabel.setText("Unlocking encrypted vault...");
        statusLabel.setForeground(UITheme.TEXT_SECONDARY);

        // Run authentication asynchronously to keep UI responsive
        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            private String errorMessage = null;
            private boolean success = false;

            @Override
            protected Void doInBackground() {
                try {
                    authService.login(identifier, password);
                    success = true;
                } catch (AuthenticationService.AuthenticationException ex) {
                    errorMessage = ex.getMessage();
                } catch (Exception ex) {
                    errorMessage = "Database connection error. Ensure MySQL is running.";
                }
                return null;
            }

            @Override
            protected void done() {
                loginButton.setEnabled(true);
                loginButton.setText("Unlock Vault");

                if (success) {
                    statusLabel.setText("Vault unlocked. Opening Dashboard...");
                    statusLabel.setForeground(UITheme.STATUS_SUCCESS);
                    openDashboard();
                } else {
                    statusLabel.setText(errorMessage != null ? errorMessage : "Authentication failed.");
                    statusLabel.setForeground(UITheme.STATUS_DANGER);
                }
            }
        };

        worker.execute();
    }

    private void openRegisterFrame() {
        RegisterFrame registerFrame = new RegisterFrame();
        registerFrame.setVisible(true);
        this.dispose();
    }

    private void openDashboard() {
        DashboardFrame dashboard = new DashboardFrame();
        dashboard.setVisible(true);
        this.dispose();
    }
}
