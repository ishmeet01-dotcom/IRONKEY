package com.ironkey.ui.components;

import com.ironkey.model.VaultEntry;
import com.ironkey.service.VaultService;
import com.ironkey.util.ClipboardManager;
import com.ironkey.util.UITheme;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.time.format.DateTimeFormatter;
import java.util.function.Consumer;

/**
 * Interactive card component rendering a credential entry with on-demand AES decryption,
 * password visibility toggling, 30-second clipboard clearing, and edit/delete actions.
 */
public class CredentialCard extends JPanel {

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("MMM dd, yyyy");
    private static final String MASKED_PASSWORD = "••••••••••••";

    private final VaultEntry entry;
    private final VaultService vaultService;
    private final Consumer<VaultEntry> onEdit;
    private final Consumer<VaultEntry> onDelete;

    private String plainUsername = "";
    private boolean passwordRevealed = false;
    private JLabel passwordValueLabel;
    private JButton revealBtn;
    private boolean hovered = false;

    /**
     * Full interactive constructor for a real vault entry.
     *
     * @param entry        vault entry model
     * @param vaultService vault service for on-demand decryption
     * @param onEdit       callback when user clicks edit
     * @param onDelete     callback when user confirms delete
     */
    public CredentialCard(VaultEntry entry, VaultService vaultService,
                          Consumer<VaultEntry> onEdit, Consumer<VaultEntry> onDelete) {
        this.entry = entry;
        this.vaultService = vaultService;
        this.onEdit = onEdit;
        this.onDelete = onDelete;

        // Decrypt username on load (if service is provided)
        if (vaultService != null && entry != null) {
            try {
                VaultService.DecryptedCredential decrypted = vaultService.decryptEntry(entry);
                this.plainUsername = decrypted.getUsername();
            } catch (Exception e) {
                this.plainUsername = "[Decryption Failed]";
            }
        } else if (entry != null) {
            this.plainUsername = entry.getEncryptedUsername();
        }

        initCard();
    }

    /**
     * Convenience constructor for legacy / mock rendering.
     *
     * @param entry vault entry
     */
    public CredentialCard(VaultEntry entry) {
        this(entry, null, null, null);
    }

    /**
     * Preview constructor for standalone mock presentations.
     */
    public CredentialCard(String title, String subtitle, String category, String timestamp) {
        this.entry = new VaultEntry(0L, title, "https://" + title.toLowerCase() + ".com", subtitle, "secret", "nonce", category, "");
        this.vaultService = null;
        this.onEdit = null;
        this.onDelete = null;
        this.plainUsername = subtitle;

        initCard();
    }

    private void initCard() {
        setLayout(new BorderLayout(16, 0));
        setOpaque(false);
        setBorder(new EmptyBorder(12, 16, 12, 16));
        setMaximumSize(new Dimension(Integer.MAX_VALUE, 104));
        setPreferredSize(new Dimension(720, 104));

        // --- Left: Site Icon Glyph ---
        JPanel iconPanel = new JPanel(new GridBagLayout()) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                UITheme.enableAntialiasing(g2d);
                g2d.setColor(new Color(16, 185, 129, 28)); // Soft emerald glow
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 10, 10);
                g2d.setColor(UITheme.ACCENT_EMERALD);
                g2d.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 10, 10);
                g2d.dispose();
            }
        };
        iconPanel.setOpaque(false);
        iconPanel.setPreferredSize(new Dimension(46, 46));

        String siteName = (entry != null && entry.getWebsiteName() != null && !entry.getWebsiteName().isEmpty())
                ? entry.getWebsiteName() : "Vault";
        String firstLetter = siteName.substring(0, 1).toUpperCase();
        JLabel iconLabel = new JLabel(firstLetter);
        iconLabel.setFont(UITheme.FONT_HEADER);
        iconLabel.setForeground(UITheme.ACCENT_EMERALD);
        iconPanel.add(iconLabel);

        add(iconPanel, BorderLayout.WEST);

        // --- Center: Details & Credentials ---
        JPanel centerPanel = new JPanel();
        centerPanel.setOpaque(false);
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.Y_AXIS));

        // Row 1: Site Title + Category Badge + Timestamp
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        row1.setOpaque(false);

        JLabel titleLabel = new JLabel(siteName);
        titleLabel.setFont(UITheme.FONT_BODY_BOLD);
        titleLabel.setForeground(UITheme.TEXT_PRIMARY);
        row1.add(titleLabel);

        String categoryName = (entry != null && entry.getCategory() != null) ? entry.getCategory() : "General";
        JLabel categoryBadge = new JLabel(categoryName) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                UITheme.enableAntialiasing(g2d);
                g2d.setColor(new Color(197, 160, 89, 28));
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 6, 6);
                g2d.dispose();
                super.paintComponent(g);
            }
        };
        categoryBadge.setOpaque(false);
        categoryBadge.setFont(UITheme.FONT_SMALL);
        categoryBadge.setForeground(UITheme.ACCENT_BRONZE);
        categoryBadge.setBorder(new EmptyBorder(2, 6, 2, 6));
        row1.add(categoryBadge);

        String dateStr = (entry != null && entry.getUpdatedAt() != null)
                ? entry.getUpdatedAt().format(DATE_FORMATTER)
                : "Recently";
        JLabel dateLabel = new JLabel("•  " + dateStr);
        dateLabel.setFont(UITheme.FONT_SMALL);
        dateLabel.setForeground(UITheme.TEXT_MUTED);
        row1.add(dateLabel);

        centerPanel.add(row1);
        centerPanel.add(Box.createVerticalStrut(4));

        // Row 2: URL (if present)
        String url = (entry != null && entry.getWebsiteUrl() != null) ? entry.getWebsiteUrl().trim() : "";
        if (!url.isEmpty()) {
            JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
            row2.setOpaque(false);
            JLabel urlLabel = new JLabel(url);
            urlLabel.setFont(UITheme.FONT_SMALL);
            urlLabel.setForeground(UITheme.TEXT_SECONDARY);
            row2.add(urlLabel);
            centerPanel.add(row2);
            centerPanel.add(Box.createVerticalStrut(4));
        }

        // Row 3: Username & Password Controls
        JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        row3.setOpaque(false);

        // Username
        JLabel userIcon = new JLabel("👤");
        userIcon.setFont(UITheme.FONT_SMALL);
        JLabel usernameLabel = new JLabel(plainUsername);
        usernameLabel.setFont(UITheme.FONT_BODY);
        usernameLabel.setForeground(UITheme.TEXT_PRIMARY);

        JButton copyUserBtn = createCompactButton("Copy User");
        copyUserBtn.addActionListener(e -> {
            ClipboardManager.copyText(plainUsername, "Username", this);
        });

        row3.add(userIcon);
        row3.add(usernameLabel);
        row3.add(copyUserBtn);

        row3.add(new JLabel("  |  "));

        // Password & Reveal Toggle
        JLabel passIcon = new JLabel("🔒");
        passIcon.setFont(UITheme.FONT_SMALL);
        passwordValueLabel = new JLabel(MASKED_PASSWORD);
        passwordValueLabel.setFont(UITheme.FONT_MONO);
        passwordValueLabel.setForeground(UITheme.TEXT_SECONDARY);

        revealBtn = createCompactButton("👁 Reveal");
        revealBtn.addActionListener(e -> togglePasswordReveal());

        JButton copyPassBtn = createCompactButton("📋 Copy Pass");
        copyPassBtn.addActionListener(e -> copyPasswordToClipboard());

        row3.add(passIcon);
        row3.add(passwordValueLabel);
        row3.add(revealBtn);
        row3.add(copyPassBtn);

        centerPanel.add(row3);
        add(centerPanel, BorderLayout.CENTER);

        // --- Right: Edit & Delete Actions ---
        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 12));
        actionPanel.setOpaque(false);

        JButton editBtn = UITheme.createSecondaryButton("✏️ Edit");
        editBtn.setPreferredSize(new Dimension(80, 32));
        editBtn.setFont(UITheme.FONT_SMALL);
        editBtn.addActionListener(e -> {
            if (onEdit != null && entry != null) {
                onEdit.accept(entry);
            }
        });
        actionPanel.add(editBtn);

        JButton deleteBtn = new JButton("🗑️ Delete") {
            private boolean btnHovered = false;
            {
                addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseEntered(MouseEvent e) { btnHovered = true; repaint(); }
                    @Override
                    public void mouseExited(MouseEvent e) { btnHovered = false; repaint(); }
                });
            }

            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                UITheme.enableAntialiasing(g2d);
                g2d.setColor(btnHovered ? new Color(239, 68, 68, 48) : UITheme.BG_CARD);
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                g2d.setColor(btnHovered ? UITheme.STATUS_DANGER : UITheme.BORDER_DEFAULT);
                g2d.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 8, 8);

                FontMetrics fm = g2d.getFontMetrics();
                int x = (getWidth() - fm.stringWidth(getText())) / 2;
                int y = (getHeight() + fm.getAscent() - fm.getDescent()) / 2;
                g2d.setColor(btnHovered ? UITheme.STATUS_DANGER : UITheme.TEXT_SECONDARY);
                g2d.setFont(getFont());
                g2d.drawString(getText(), x, y);
                g2d.dispose();
            }
        };
        deleteBtn.setOpaque(false);
        deleteBtn.setContentAreaFilled(false);
        deleteBtn.setBorderPainted(false);
        deleteBtn.setFocusPainted(false);
        deleteBtn.setFont(UITheme.FONT_SMALL);
        deleteBtn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        deleteBtn.setPreferredSize(new Dimension(86, 32));
        deleteBtn.addActionListener(e -> confirmAndDelete());
        actionPanel.add(deleteBtn);

        add(actionPanel, BorderLayout.EAST);

        // Hover effect on the entire card
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                hovered = true;
                repaint();
            }

            @Override
            public void mouseExited(MouseEvent e) {
                hovered = false;
                repaint();
            }
        });
    }

    private void togglePasswordReveal() {
        if (passwordRevealed) {
            // Mask it back
            passwordValueLabel.setText(MASKED_PASSWORD);
            passwordValueLabel.setForeground(UITheme.TEXT_SECONDARY);
            revealBtn.setText("👁 Reveal");
            passwordRevealed = false;
        } else {
            // Decrypt on-demand using active session
            if (vaultService == null || entry == null) {
                JOptionPane.showMessageDialog(this, "Decryption service unavailable.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            try {
                VaultService.DecryptedCredential decrypted = vaultService.decryptEntry(entry);
                passwordValueLabel.setText(decrypted.getPassword());
                passwordValueLabel.setForeground(UITheme.TEXT_EMERALD);
                revealBtn.setText("🙈 Hide");
                passwordRevealed = true;
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this,
                        "Failed to decrypt password: " + ex.getMessage(),
                        "Decryption Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void copyPasswordToClipboard() {
        if (vaultService == null || entry == null) {
            JOptionPane.showMessageDialog(this, "Decryption service unavailable.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        try {
            VaultService.DecryptedCredential decrypted = vaultService.decryptEntry(entry);
            ClipboardManager.copyPassword(decrypted.getPassword(), this);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Failed to decrypt password: " + ex.getMessage(),
                    "Decryption Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void confirmAndDelete() {
        if (onDelete == null || entry == null) return;

        int response = JOptionPane.showConfirmDialog(
                this,
                "Are you sure you want to permanently delete '" + entry.getWebsiteName() + "'?\n" +
                "This action cannot be undone.",
                "Confirm Deletion",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
        );

        if (response == JOptionPane.YES_OPTION) {
            onDelete.accept(entry);
        }
    }

    private JButton createCompactButton(String text) {
        JButton button = new JButton(text) {
            private boolean bHovered = false;
            {
                addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseEntered(MouseEvent e) { bHovered = true; repaint(); }
                    @Override
                    public void mouseExited(MouseEvent e) { bHovered = false; repaint(); }
                });
            }

            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                UITheme.enableAntialiasing(g2d);
                g2d.setColor(bHovered ? UITheme.BG_CARD_HOVER : UITheme.BG_CARD);
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 6, 6);
                g2d.setColor(bHovered ? UITheme.BORDER_HOVER : UITheme.BORDER_DEFAULT);
                g2d.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 6, 6);

                FontMetrics fm = g2d.getFontMetrics();
                int x = (getWidth() - fm.stringWidth(getText())) / 2;
                int y = (getHeight() + fm.getAscent() - fm.getDescent()) / 2;
                g2d.setColor(bHovered ? UITheme.TEXT_PRIMARY : UITheme.TEXT_SECONDARY);
                g2d.setFont(getFont());
                g2d.drawString(getText(), x, y);
                g2d.dispose();
            }
        };

        button.setOpaque(false);
        button.setContentAreaFilled(false);
        button.setBorderPainted(false);
        button.setFocusPainted(false);
        button.setFont(UITheme.FONT_SMALL);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        button.setPreferredSize(new Dimension(84, 24));
        return button;
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2d = (Graphics2D) g.create();
        UITheme.enableAntialiasing(g2d);

        g2d.setColor(hovered ? UITheme.BG_CARD_HOVER : UITheme.BG_CARD);
        g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 10, 10);

        g2d.setColor(hovered ? UITheme.BORDER_HOVER : UITheme.BORDER_DEFAULT);
        g2d.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 10, 10);

        g2d.dispose();
        super.paintComponent(g);
    }
}
