package com.ironkey.ui;

import com.ironkey.security.PasswordGenerator;
import com.ironkey.service.AuthenticationService;
import com.ironkey.util.InputValidator;
import com.ironkey.util.UITheme;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.Arrays;

/**
 * Registration window for IRONKEY.
 * Initializes a new user account with dedicated salts for authentication and vault encryption.
 */
public class RegisterFrame extends JFrame {

    private JTextField usernameField;
    private JTextField emailField;
    private JPasswordField passwordField;
    private JPasswordField confirmPasswordField;
    private JProgressBar strengthMeter;
    private JLabel strengthLabel;
    private JLabel statusLabel;
    private JButton registerButton;
    private JButton backToLoginButton;

    private final AuthenticationService authService = new AuthenticationService();

    public RegisterFrame() {
        setTitle("IRONKEY — Initialize New Encrypted Vault");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(520, 780);
        setMinimumSize(new Dimension(460, 700));
        setLocationRelativeTo(null);
        getContentPane().setBackground(UITheme.BG_DARKEST);

        initUI();
    }

    private void initUI() {
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(0, 0, 0, 0);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.NONE;

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
        card.setBorder(new EmptyBorder(32, 40, 32, 40));
        card.setPreferredSize(new Dimension(440, 690));

        // 1. Branding Header
        JPanel brandPanel = new JPanel();
        brandPanel.setOpaque(false);
        brandPanel.setLayout(new BoxLayout(brandPanel, BoxLayout.Y_AXIS));
        brandPanel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel logoIcon = new JLabel("🛡️");
        logoIcon.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 36));
        logoIcon.setAlignmentX(Component.CENTER_ALIGNMENT);
        brandPanel.add(logoIcon);
        brandPanel.add(Box.createVerticalStrut(6));

        JLabel titleLabel = new JLabel("Create Master Vault");
        titleLabel.setFont(UITheme.FONT_BRAND_TITLE);
        titleLabel.setForeground(UITheme.TEXT_PRIMARY);
        titleLabel.setAlignmentX(Component.CENTER_ALIGNMENT);
        brandPanel.add(titleLabel);
        brandPanel.add(Box.createVerticalStrut(4));

        JLabel subtitle = new JLabel("Your Credentials. Your Control.");
        subtitle.setFont(UITheme.FONT_SMALL);
        subtitle.setForeground(UITheme.ACCENT_BRONZE);
        subtitle.setAlignmentX(Component.CENTER_ALIGNMENT);
        brandPanel.add(subtitle);

        card.add(brandPanel);
        card.add(Box.createVerticalStrut(18));

        // Security Notice Box
        JPanel noticeBox = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                UITheme.enableAntialiasing(g2d);
                g2d.setColor(new Color(197, 160, 89, 20));
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                g2d.setColor(new Color(197, 160, 89, 80));
                g2d.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 8, 8);
                g2d.dispose();
                super.paintComponent(g);
            }
        };
        noticeBox.setOpaque(false);
        noticeBox.setLayout(new BoxLayout(noticeBox, BoxLayout.Y_AXIS));
        noticeBox.setBorder(new EmptyBorder(8, 12, 8, 12));
        noticeBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        noticeBox.setMaximumSize(new Dimension(Integer.MAX_VALUE, 58));

        JLabel noticeTitle = new JLabel("⚠️ Zero-Knowledge Architecture");
        noticeTitle.setFont(UITheme.FONT_BODY_BOLD);
        noticeTitle.setForeground(UITheme.ACCENT_BRONZE);

        JLabel noticeBody = new JLabel("<html>Your master password cannot be reset if lost. Memorize your passphrase.</html>");
        noticeBody.setFont(UITheme.FONT_SMALL);
        noticeBody.setForeground(UITheme.TEXT_SECONDARY);

        noticeBox.add(noticeTitle);
        noticeBox.add(Box.createVerticalStrut(2));
        noticeBox.add(noticeBody);
        card.add(noticeBox);
        card.add(Box.createVerticalStrut(16));

        // 2. Username Field
        JLabel userLabel = new JLabel("Username");
        userLabel.setFont(UITheme.FONT_BODY_BOLD);
        userLabel.setForeground(UITheme.TEXT_SECONDARY);
        userLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(userLabel);
        card.add(Box.createVerticalStrut(4));

        usernameField = UITheme.createModernTextField("e.g. alex_cipher");
        usernameField.setAlignmentX(Component.LEFT_ALIGNMENT);
        usernameField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        card.add(usernameField);
        card.add(Box.createVerticalStrut(12));

        // 3. Email Field
        JLabel emailLabel = new JLabel("Email Address");
        emailLabel.setFont(UITheme.FONT_BODY_BOLD);
        emailLabel.setForeground(UITheme.TEXT_SECONDARY);
        emailLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(emailLabel);
        card.add(Box.createVerticalStrut(4));

        emailField = UITheme.createModernTextField("e.g. alex@proton.me");
        emailField.setAlignmentX(Component.LEFT_ALIGNMENT);
        emailField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        card.add(emailField);
        card.add(Box.createVerticalStrut(12));

        // 4. Master Password Field
        JLabel passLabel = new JLabel("Master Password (min 10 characters)");
        passLabel.setFont(UITheme.FONT_BODY_BOLD);
        passLabel.setForeground(UITheme.TEXT_SECONDARY);
        passLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(passLabel);
        card.add(Box.createVerticalStrut(4));

        passwordField = UITheme.createModernPasswordField("Choose a strong passphrase");
        passwordField.setAlignmentX(Component.LEFT_ALIGNMENT);
        passwordField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        card.add(passwordField);
        card.add(Box.createVerticalStrut(6));

        // Strength Meter Bar
        JPanel meterRow = new JPanel(new BorderLayout(8, 0));
        meterRow.setOpaque(false);
        meterRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 16));
        meterRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        strengthMeter = new JProgressBar(0, 100);
        strengthMeter.setValue(0);
        strengthMeter.setPreferredSize(new Dimension(200, 6));
        strengthMeter.setForeground(UITheme.STATUS_DANGER);
        strengthMeter.setBackground(UITheme.BG_INPUT);
        strengthMeter.setBorderPainted(false);
        meterRow.add(strengthMeter, BorderLayout.CENTER);

        strengthLabel = new JLabel("Entropy: 0%");
        strengthLabel.setFont(UITheme.FONT_SMALL);
        strengthLabel.setForeground(UITheme.TEXT_MUTED);
        meterRow.add(strengthLabel, BorderLayout.EAST);

        card.add(meterRow);
        card.add(Box.createVerticalStrut(10));

        passwordField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) { updateStrength(); }
            @Override
            public void removeUpdate(DocumentEvent e) { updateStrength(); }
            @Override
            public void changedUpdate(DocumentEvent e) { updateStrength(); }
        });

        // 5. Confirm Master Password Field
        JLabel confirmPassLabel = new JLabel("Confirm Master Password");
        confirmPassLabel.setFont(UITheme.FONT_BODY_BOLD);
        confirmPassLabel.setForeground(UITheme.TEXT_SECONDARY);
        confirmPassLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(confirmPassLabel);
        card.add(Box.createVerticalStrut(4));

        confirmPasswordField = UITheme.createModernPasswordField("Re-enter master password");
        confirmPasswordField.setAlignmentX(Component.LEFT_ALIGNMENT);
        confirmPasswordField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        card.add(confirmPasswordField);
        card.add(Box.createVerticalStrut(8));

        // Feedback / Status Label
        statusLabel = new JLabel(" ");
        statusLabel.setFont(UITheme.FONT_SMALL);
        statusLabel.setForeground(UITheme.STATUS_DANGER);
        statusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(statusLabel);
        card.add(Box.createVerticalStrut(10));

        // 6. Action Button
        registerButton = UITheme.createPrimaryButton("Initialize Vault");
        registerButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, 42));
        registerButton.setAlignmentX(Component.CENTER_ALIGNMENT);
        registerButton.addActionListener(this::handleRegister);
        card.add(registerButton);
        card.add(Box.createVerticalStrut(8));

        // 7. Back to Login Navigation
        JPanel navRow = new JPanel(new FlowLayout(FlowLayout.CENTER, 4, 0));
        navRow.setOpaque(false);
        navRow.setAlignmentX(Component.CENTER_ALIGNMENT);

        JLabel alreadyLabel = new JLabel("Already have a vault?");
        alreadyLabel.setFont(UITheme.FONT_BODY);
        alreadyLabel.setForeground(UITheme.TEXT_MUTED);
        navRow.add(alreadyLabel);

        backToLoginButton = UITheme.createLinkButton("Back to Login");
        backToLoginButton.addActionListener(e -> openLoginFrame(null));
        navRow.add(backToLoginButton);

        card.add(navRow);

        add(card, gbc);
    }

    private void updateStrength() {
        char[] pass = passwordField.getPassword();
        int score = PasswordGenerator.calculateStrength(pass);
        strengthMeter.setValue(score);
        strengthLabel.setText("Strength: " + score + "%");

        if (score < 40) {
            strengthMeter.setForeground(UITheme.STATUS_DANGER);
            strengthLabel.setForeground(UITheme.STATUS_DANGER);
        } else if (score < 75) {
            strengthMeter.setForeground(UITheme.STATUS_WARNING);
            strengthLabel.setForeground(UITheme.STATUS_WARNING);
        } else {
            strengthMeter.setForeground(UITheme.STATUS_SUCCESS);
            strengthLabel.setForeground(UITheme.STATUS_SUCCESS);
        }
    }

    private void handleRegister(ActionEvent e) {
        String username = usernameField.getText().trim();
        String email = emailField.getText().trim();
        char[] password = passwordField.getPassword();
        char[] confirm = confirmPasswordField.getPassword();

        // 1. Validation checks
        InputValidator.ValidationResult userVal = InputValidator.validateUsername(username);
        if (!userVal.isValid()) {
            statusLabel.setText(userVal.getMessage());
            statusLabel.setForeground(UITheme.STATUS_DANGER);
            return;
        }

        InputValidator.ValidationResult emailVal = InputValidator.validateEmail(email);
        if (!emailVal.isValid()) {
            statusLabel.setText(emailVal.getMessage());
            statusLabel.setForeground(UITheme.STATUS_DANGER);
            return;
        }

        InputValidator.ValidationResult passVal = InputValidator.validateMasterPassword(password);
        if (!passVal.isValid()) {
            statusLabel.setText(passVal.getMessage());
            statusLabel.setForeground(UITheme.STATUS_DANGER);
            return;
        }

        if (!Arrays.equals(password, confirm)) {
            statusLabel.setText("Master passwords do not match.");
            statusLabel.setForeground(UITheme.STATUS_DANGER);
            return;
        }

        // Disable button during background registration
        registerButton.setEnabled(false);
        registerButton.setText("Initializing Secure Vault...");
        statusLabel.setText("Deriving cryptographic keys & salts...");
        statusLabel.setForeground(UITheme.TEXT_SECONDARY);

        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            private String errorMessage = null;
            private boolean success = false;

            @Override
            protected Void doInBackground() {
                try {
                    authService.register(username, email, password, confirm);
                    success = true;
                } catch (IllegalArgumentException ex) {
                    errorMessage = ex.getMessage();
                } catch (Exception ex) {
                    errorMessage = "Database error: " + ex.getMessage();
                }
                return null;
            }

            @Override
            protected void done() {
                registerButton.setEnabled(true);
                registerButton.setText("Initialize Vault");

                if (success) {
                    JOptionPane.showMessageDialog(RegisterFrame.this,
                            "<html><b>Vault Initialized Successfully!</b><br><br>" +
                            "Account created for: <b>" + username + "</b><br>" +
                            "Please unlock your vault using your master password.</html>",
                            "IRONKEY Registration Complete", JOptionPane.INFORMATION_MESSAGE);
                    openLoginFrame(email);
                } else {
                    statusLabel.setText(errorMessage != null ? errorMessage : "Registration failed.");
                    statusLabel.setForeground(UITheme.STATUS_DANGER);
                }
            }
        };

        worker.execute();
    }

    private void openLoginFrame(String prefilledIdentifier) {
        LoginFrame loginFrame = new LoginFrame(prefilledIdentifier != null ? prefilledIdentifier : "");
        loginFrame.setVisible(true);
        this.dispose();
    }
}
