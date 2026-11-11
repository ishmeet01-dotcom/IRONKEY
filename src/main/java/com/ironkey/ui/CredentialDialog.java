package com.ironkey.ui;

import com.ironkey.dao.CategoryDAO;
import com.ironkey.model.Category;
import com.ironkey.model.VaultEntry;
import com.ironkey.service.VaultService;
import com.ironkey.util.ClipboardManager;
import com.ironkey.util.SessionManager;
import com.ironkey.util.UITheme;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;

/**
 * Modern modal dialog for creating and editing encrypted credentials in IRONKEY.
 * Encrypts sensitive fields with independent 12-byte nonces before persisting to MySQL.
 */
public class CredentialDialog extends JDialog {

    private final VaultService vaultService;
    private final CategoryDAO categoryDAO;
    private final VaultEntry existingEntry;
    private final Runnable onSaveSuccess;

    private JTextField websiteField;
    private JTextField urlField;
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JButton showPasswordBtn;
    private JComboBox<String> categoryCombo;
    private JTextArea notesArea;
    private JLabel statusLabel;
    private JButton saveButton;

    private boolean isPasswordVisible = false;

    public CredentialDialog(Frame parent, VaultService vaultService, VaultEntry existingEntry, Runnable onSaveSuccess) {
        super(parent, existingEntry == null ? "IRONKEY — Add Credential" : "IRONKEY — Edit Credential", true);
        this.vaultService = vaultService;
        this.existingEntry = existingEntry;
        this.onSaveSuccess = onSaveSuccess;
        this.categoryDAO = new CategoryDAO();

        setSize(540, 720);
        setMinimumSize(new Dimension(480, 640));
        setLocationRelativeTo(parent);
        getContentPane().setBackground(UITheme.BG_DARKEST);

        initUI();
        loadCategories();

        if (existingEntry != null) {
            populateExistingData();
        }
    }

    private void initUI() {
        setLayout(new BorderLayout());

        JPanel container = new JPanel();
        container.setLayout(new BoxLayout(container, BoxLayout.Y_AXIS));
        container.setOpaque(false);
        container.setBorder(new EmptyBorder(24, 30, 24, 30));

        // Header Title & Subtitle
        JLabel titleLabel = new JLabel(existingEntry == null ? "🔐 Add New Credential" : "✏️ Edit Credential");
        titleLabel.setFont(UITheme.FONT_HEADER);
        titleLabel.setForeground(UITheme.TEXT_PRIMARY);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        container.add(titleLabel);

        JLabel subLabel = new JLabel("All sensitive credentials are encrypted client-side using AES-256-GCM.");
        subLabel.setFont(UITheme.FONT_SMALL);
        subLabel.setForeground(UITheme.ACCENT_BRONZE);
        subLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        container.add(subLabel);
        container.add(Box.createVerticalStrut(18));

        // 1. Website / App Name (Required)
        container.add(createFieldLabel("Website or Application Name *"));
        container.add(Box.createVerticalStrut(4));
        websiteField = UITheme.createModernTextField("e.g. GitHub, AWS Console, ProtonMail");
        websiteField.setAlignmentX(Component.LEFT_ALIGNMENT);
        websiteField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        container.add(websiteField);
        container.add(Box.createVerticalStrut(12));

        // 2. Website URL (Optional)
        container.add(createFieldLabel("Website URL (Optional)"));
        container.add(Box.createVerticalStrut(4));
        urlField = UITheme.createModernTextField("e.g. https://github.com/login");
        urlField.setAlignmentX(Component.LEFT_ALIGNMENT);
        urlField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        container.add(urlField);
        container.add(Box.createVerticalStrut(12));

        // 3. Username or Email (Required)
        container.add(createFieldLabel("Username or Email *"));
        container.add(Box.createVerticalStrut(4));
        usernameField = UITheme.createModernTextField("e.g. dev@ironkey.io or alex_99");
        usernameField.setAlignmentX(Component.LEFT_ALIGNMENT);
        usernameField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        container.add(usernameField);
        container.add(Box.createVerticalStrut(12));

        // 4. Password (Required) + Toggle + Generator + Copy
        container.add(createFieldLabel("Password *"));
        container.add(Box.createVerticalStrut(4));

        JPanel passRow = new JPanel(new BorderLayout(6, 0));
        passRow.setOpaque(false);
        passRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 38));
        passRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        passwordField = UITheme.createModernPasswordField("Enter or generate password");
        passRow.add(passwordField, BorderLayout.CENTER);

        JPanel passActions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        passActions.setOpaque(false);

        showPasswordBtn = UITheme.createSecondaryButton("👁️");
        showPasswordBtn.setPreferredSize(new Dimension(38, 38));
        showPasswordBtn.setToolTipText("Show/Hide Password");
        showPasswordBtn.addActionListener(e -> togglePasswordVisibility());
        passActions.add(showPasswordBtn);

        JButton copyPassBtn = UITheme.createSecondaryButton("📋");
        copyPassBtn.setPreferredSize(new Dimension(38, 38));
        copyPassBtn.setToolTipText("Copy Password (auto-clears in 30s)");
        copyPassBtn.addActionListener(e -> {
            String p = new String(passwordField.getPassword());
            if (!p.isEmpty()) {
                ClipboardManager.copyPassword(p);
                statusLabel.setText("Password copied. Auto-clearing in 30 seconds.");
                statusLabel.setForeground(UITheme.STATUS_SUCCESS);
            }
        });
        passActions.add(copyPassBtn);

        JButton genBtn = UITheme.createBronzeButton("🎲 Generate");
        genBtn.setPreferredSize(new Dimension(105, 38));
        genBtn.setFont(UITheme.FONT_SMALL);
        genBtn.setToolTipText("Open Cryptographic Password Generator");
        genBtn.addActionListener(e -> openPasswordGenerator());
        passActions.add(genBtn);

        passRow.add(passActions, BorderLayout.EAST);
        container.add(passRow);
        container.add(Box.createVerticalStrut(12));

        // 5. Category Dropdown
        container.add(createFieldLabel("Category"));
        container.add(Box.createVerticalStrut(4));
        categoryCombo = new JComboBox<>(new String[]{"Logins", "Financial", "Secure Notes", "Identities", "Servers & SSH"});
        categoryCombo.setEditable(true);
        categoryCombo.setBackground(UITheme.BG_INPUT);
        categoryCombo.setForeground(UITheme.TEXT_PRIMARY);
        categoryCombo.setFont(UITheme.FONT_BODY);
        categoryCombo.setMaximumSize(new Dimension(Integer.MAX_VALUE, 36));
        categoryCombo.setAlignmentX(Component.LEFT_ALIGNMENT);
        container.add(categoryCombo);
        container.add(Box.createVerticalStrut(12));

        // 6. Notes (Optional, Encrypted)
        container.add(createFieldLabel("Notes (Encrypted)"));
        container.add(Box.createVerticalStrut(4));

        notesArea = new JTextArea(4, 20);
        notesArea.setFont(UITheme.FONT_BODY);
        notesArea.setBackground(UITheme.BG_INPUT);
        notesArea.setForeground(UITheme.TEXT_PRIMARY);
        notesArea.setCaretColor(UITheme.ACCENT_EMERALD);
        notesArea.setLineWrap(true);
        notesArea.setWrapStyleWord(true);
        notesArea.setBorder(new EmptyBorder(8, 10, 8, 10));

        JScrollPane notesScroll = new JScrollPane(notesArea);
        notesScroll.setOpaque(false);
        notesScroll.getViewport().setOpaque(false);
        notesScroll.setBorder(BorderFactory.createLineBorder(UITheme.BORDER_DEFAULT, 1));
        notesScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, 90));
        notesScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        container.add(notesScroll);
        container.add(Box.createVerticalStrut(10));

        // Status Feedback
        statusLabel = new JLabel(" ");
        statusLabel.setFont(UITheme.FONT_SMALL);
        statusLabel.setForeground(UITheme.STATUS_DANGER);
        statusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        container.add(statusLabel);
        container.add(Box.createVerticalStrut(14));

        // 7. Footer Action Buttons
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        buttonRow.setOpaque(false);
        buttonRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        JButton cancelBtn = UITheme.createSecondaryButton("Cancel");
        cancelBtn.setPreferredSize(new Dimension(100, 38));
        cancelBtn.addActionListener(e -> dispose());
        buttonRow.add(cancelBtn);

        saveButton = UITheme.createPrimaryButton(existingEntry == null ? "Save Credential" : "Save Changes");
        saveButton.setPreferredSize(new Dimension(140, 38));
        saveButton.addActionListener(e -> handleSave());
        buttonRow.add(saveButton);

        container.add(buttonRow);

        JScrollPane mainScroll = new JScrollPane(container);
        mainScroll.setBorder(null);
        mainScroll.setOpaque(false);
        mainScroll.getViewport().setOpaque(false);
        mainScroll.getVerticalScrollBar().setUnitIncrement(16);

        add(mainScroll, BorderLayout.CENTER);
    }

    private JLabel createFieldLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(UITheme.FONT_BODY_BOLD);
        label.setForeground(UITheme.TEXT_SECONDARY);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        return label;
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

    private void openPasswordGenerator() {
        PasswordGeneratorDialog genDialog = new PasswordGeneratorDialog(
                (Frame) SwingUtilities.getWindowAncestor(this),
                generatedPassword -> {
                    passwordField.setText(generatedPassword);
                    statusLabel.setText("Applied generated password.");
                    statusLabel.setForeground(UITheme.STATUS_SUCCESS);
                }
        );
        genDialog.setVisible(true);
    }

    private void loadCategories() {
        if (SessionManager.getInstance().isLoggedIn()) {
            try {
                Long userId = SessionManager.getInstance().getUserId();
                List<Category> categories = categoryDAO.findAllByUserId(userId);
                categoryCombo.removeAllItems();
                for (Category cat : categories) {
                    categoryCombo.addItem(cat.getName());
                }
                if (categoryCombo.getItemCount() == 0) {
                    categoryCombo.addItem("Logins");
                }
            } catch (Exception ignored) {
            }
        }
    }

    private void populateExistingData() {
        websiteField.setText(existingEntry.getWebsiteName());
        urlField.setText(existingEntry.getWebsiteUrl() != null ? existingEntry.getWebsiteUrl() : "");
        categoryCombo.setSelectedItem(existingEntry.getCategory());

        // Decrypt username, password, notes in background
        statusLabel.setText("Decrypting record...");
        statusLabel.setForeground(UITheme.TEXT_SECONDARY);

        SwingWorker<VaultService.DecryptedCredential, Void> worker = new SwingWorker<>() {
            @Override
            protected VaultService.DecryptedCredential doInBackground() throws Exception {
                return vaultService.decryptEntry(existingEntry);
            }

            @Override
            protected void done() {
                try {
                    VaultService.DecryptedCredential dec = get();
                    usernameField.setText(dec.getUsername());
                    passwordField.setText(dec.getPassword());
                    notesArea.setText(dec.getNotes());
                    statusLabel.setText(" ");
                } catch (Exception e) {
                    statusLabel.setText("Failed to decrypt credentials: " + e.getMessage());
                    statusLabel.setForeground(UITheme.STATUS_DANGER);
                }
            }
        };
        worker.execute();
    }

    private void handleSave() {
        String website = websiteField.getText().trim();
        String url = urlField.getText().trim();
        String username = usernameField.getText().trim();
        char[] passwordChars = passwordField.getPassword();
        String password = new String(passwordChars);
        String category = categoryCombo.getSelectedItem() != null ? categoryCombo.getSelectedItem().toString().trim() : "Logins";
        String notes = notesArea.getText().trim();

        if (website.isEmpty()) {
            statusLabel.setText("Website or application name is required.");
            statusLabel.setForeground(UITheme.STATUS_DANGER);
            return;
        }
        if (username.isEmpty()) {
            statusLabel.setText("Username or email is required.");
            statusLabel.setForeground(UITheme.STATUS_DANGER);
            return;
        }
        if (password.isEmpty()) {
            statusLabel.setText("Password cannot be empty.");
            statusLabel.setForeground(UITheme.STATUS_DANGER);
            return;
        }

        saveButton.setEnabled(false);
        saveButton.setText("Encrypting & Saving...");
        statusLabel.setText("Encrypting with AES-256-GCM...");
        statusLabel.setForeground(UITheme.TEXT_SECONDARY);

        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            private String error = null;

            @Override
            protected Void doInBackground() {
                try {
                    if (existingEntry == null) {
                        vaultService.addEntry(website, url, username, password, category, notes);
                    } else {
                        vaultService.updateEntry(existingEntry.getEntryId(), website, url, username, password, category, notes);
                    }
                } catch (Exception ex) {
                    error = ex.getMessage();
                }
                return null;
            }

            @Override
            protected void done() {
                saveButton.setEnabled(true);
                saveButton.setText(existingEntry == null ? "Save Credential" : "Save Changes");

                if (error == null) {
                    if (onSaveSuccess != null) {
                        onSaveSuccess.run();
                    }
                    dispose();
                } else {
                    statusLabel.setText("Error: " + error);
                    statusLabel.setForeground(UITheme.STATUS_DANGER);
                }
            }
        };
        worker.execute();
    }
}
