package com.ironkey.ui.components;

import com.ironkey.config.DatabaseConfig;
import com.ironkey.util.SessionManager;
import com.ironkey.util.UITheme;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Sidebar navigation component for the IRONKEY dashboard.
 * Displays application branding, navigation links, DB status, and active user profile.
 */
public class Sidebar extends JPanel {

    private final List<NavItem> navItems = new ArrayList<>();
    private NavItem activeItem;
    private final Consumer<String> onNavigate;
    private final Runnable onLogout;

    public Sidebar(Consumer<String> onNavigate, Runnable onLogout) {
        this.onNavigate = onNavigate;
        this.onLogout = onLogout;

        setLayout(new BorderLayout());
        setBackground(UITheme.BG_DARKEST);
        setPreferredSize(new Dimension(240, 700));
        setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, UITheme.BORDER_DEFAULT));

        initUI();
    }

    private void initUI() {
        // --- Top: Branding Header ---
        JPanel headerPanel = new JPanel();
        headerPanel.setOpaque(false);
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.setBorder(new EmptyBorder(24, 20, 20, 20));

        // Logo with shield glyph
        JPanel logoRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        logoRow.setOpaque(false);

        JLabel logoIcon = new JLabel("🛡️");
        logoIcon.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 24));
        logoRow.add(logoIcon);

        JLabel brandTitle = new JLabel("IRONKEY");
        brandTitle.setFont(UITheme.FONT_BRAND_TITLE);
        brandTitle.setForeground(UITheme.TEXT_PRIMARY);
        logoRow.add(brandTitle);

        JLabel tagline = new JLabel("Your Credentials. Your Control.");
        tagline.setFont(UITheme.FONT_SMALL);
        tagline.setForeground(UITheme.ACCENT_BRONZE);
        tagline.setBorder(new EmptyBorder(6, 4, 0, 0));

        headerPanel.add(logoRow);
        headerPanel.add(tagline);

        add(headerPanel, BorderLayout.NORTH);

        // --- Center: Navigation Items ---
        JPanel menuPanel = new JPanel();
        menuPanel.setOpaque(false);
        menuPanel.setLayout(new BoxLayout(menuPanel, BoxLayout.Y_AXIS));
        menuPanel.setBorder(new EmptyBorder(12, 12, 12, 12));

        addNavItem(menuPanel, "🔑", "Vault Items", "VAULT");
        addNavItem(menuPanel, "⭐", "Favorites", "FAVORITES");
        addNavItem(menuPanel, "📁", "Categories", "CATEGORIES");
        addNavItem(menuPanel, "🎲", "Password Generator", "GENERATOR");
        addNavItem(menuPanel, "🛡️", "Security Audit", "AUDIT");
        addNavItem(menuPanel, "⚙️", "Settings", "SETTINGS");

        // Set default active item
        if (!navItems.isEmpty()) {
            setActiveItem(navItems.get(0));
        }

        add(menuPanel, BorderLayout.CENTER);

        // --- Bottom: Database Status & User Profile ---
        JPanel footerPanel = new JPanel();
        footerPanel.setOpaque(false);
        footerPanel.setLayout(new BoxLayout(footerPanel, BoxLayout.Y_AXIS));
        footerPanel.setBorder(new EmptyBorder(12, 16, 20, 16));

        // DB Status Indicator
        JPanel dbStatusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        dbStatusRow.setOpaque(false);

        DatabaseConfig.ConnectionTestResult testResult = DatabaseConfig.getInstance().testConnection();
        boolean isConnected = testResult.isSuccess();

        JLabel statusDot = new JLabel("●");
        statusDot.setFont(new Font("Segoe UI", Font.BOLD, 14));
        statusDot.setForeground(isConnected ? UITheme.STATUS_SUCCESS : UITheme.STATUS_WARNING);

        JLabel statusText = new JLabel(isConnected ? "MySQL: Connected" : "MySQL: Offline (Demo)");
        statusText.setFont(UITheme.FONT_SMALL);
        statusText.setForeground(UITheme.TEXT_SECONDARY);
        statusText.setToolTipText(testResult.getMessage());

        dbStatusRow.add(statusDot);
        dbStatusRow.add(statusText);
        footerPanel.add(dbStatusRow);

        footerPanel.add(Box.createVerticalStrut(10));

        // User / Session Info
        JPanel userRow = new JPanel(new BorderLayout());
        userRow.setOpaque(false);
        userRow.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, UITheme.BORDER_DEFAULT),
                new EmptyBorder(12, 0, 0, 0)
        ));

        String username = "Security Admin";
        String email = "unauthenticated";
        if (SessionManager.getInstance().isLoggedIn()) {
            username = SessionManager.getInstance().getCurrentUser().getUsername();
            email = SessionManager.getInstance().getCurrentUser().getEmail();
        }

        JPanel userInfoPanel = new JPanel();
        userInfoPanel.setLayout(new BoxLayout(userInfoPanel, BoxLayout.Y_AXIS));
        userInfoPanel.setOpaque(false);

        JLabel userLabel = new JLabel("👤 " + username);
        userLabel.setFont(UITheme.FONT_BODY_BOLD);
        userLabel.setForeground(UITheme.TEXT_PRIMARY);

        JLabel emailLabel = new JLabel(email);
        emailLabel.setFont(UITheme.FONT_SMALL);
        emailLabel.setForeground(UITheme.TEXT_MUTED);

        userInfoPanel.add(userLabel);
        userInfoPanel.add(Box.createVerticalStrut(2));
        userInfoPanel.add(emailLabel);

        JButton lockBtn = UITheme.createSecondaryButton("🔒 Lock");
        lockBtn.setPreferredSize(new Dimension(70, 28));
        lockBtn.setFont(UITheme.FONT_SMALL);
        lockBtn.addActionListener(e -> {
            if (onLogout != null) onLogout.run();
        });

        userRow.add(userInfoPanel, BorderLayout.CENTER);
        userRow.add(lockBtn, BorderLayout.EAST);

        footerPanel.add(userRow);

        add(footerPanel, BorderLayout.SOUTH);
    }

    private void addNavItem(JPanel container, String icon, String title, String code) {
        NavItem item = new NavItem(icon, title, code);
        navItems.add(item);
        container.add(item);
        container.add(Box.createVerticalStrut(4));

        item.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                setActiveItem(item);
                if (onNavigate != null) {
                    onNavigate.accept(code);
                }
            }
        });
    }

    private void setActiveItem(NavItem item) {
        if (activeItem != null) {
            activeItem.setActive(false);
        }
        activeItem = item;
        activeItem.setActive(true);
    }

    /**
     * Individual navigation link button.
     */
    private static class NavItem extends JPanel {
        private final String code;
        private boolean active = false;
        private boolean hovered = false;
        private final JLabel label;

        public NavItem(String icon, String title, String code) {
            this.code = code;
            setLayout(new FlowLayout(FlowLayout.LEFT, 12, 10));
            setOpaque(false);
            setCursor(new Cursor(Cursor.HAND_CURSOR));
            setMaximumSize(new Dimension(220, 42));

            label = new JLabel(icon + "  " + title);
            label.setFont(UITheme.FONT_BODY);
            label.setForeground(UITheme.TEXT_SECONDARY);
            add(label);

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

        public void setActive(boolean active) {
            this.active = active;
            label.setForeground(active ? UITheme.TEXT_PRIMARY : UITheme.TEXT_SECONDARY);
            label.setFont(active ? UITheme.FONT_BODY_BOLD : UITheme.FONT_BODY);
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2d = (Graphics2D) g.create();
            UITheme.enableAntialiasing(g2d);

            if (active) {
                g2d.setColor(UITheme.BG_CARD);
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                // Active indicator line on the left
                g2d.setColor(UITheme.ACCENT_EMERALD);
                g2d.fillRoundRect(0, 4, 3, getHeight() - 8, 2, 2);
            } else if (hovered) {
                g2d.setColor(UITheme.BG_CARD_HOVER);
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
            }
            g2d.dispose();
            super.paintComponent(g);
        }
    }
}
