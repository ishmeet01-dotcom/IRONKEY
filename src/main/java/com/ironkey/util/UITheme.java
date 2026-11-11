package com.ironkey.util;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * Design system and visual styling constants for the IRONKEY desktop interface.
 * Implements a high-end cybersecurity theme with deep charcoal surfaces,
 * emerald security accents, subtle metallic bronze highlights, and clean typography.
 */
public final class UITheme {

    // --- Color Palette ---
    public static final Color BG_DARKEST        = new Color(11, 14, 17);    // Deepest obsidian black
    public static final Color BG_PANEL          = new Color(19, 23, 29);    // Window & sidebar background
    public static final Color BG_CARD           = new Color(27, 32, 40);    // Elevated cards & widgets
    public static final Color BG_CARD_HOVER     = new Color(34, 40, 50);    // Card hover state
    public static final Color BG_INPUT          = new Color(21, 25, 33);    // Input fields background

    public static final Color BORDER_DEFAULT    = new Color(43, 50, 64);    // Subtle boundary stroke
    public static final Color BORDER_HOVER      = new Color(60, 70, 88);    // Input hover stroke
    public static final Color BORDER_FOCUS      = new Color(16, 185, 129);  // Cyber emerald active focus
    public static final Color BORDER_BRONZE     = new Color(197, 160, 89);  // Metallic bronze focus

    public static final Color ACCENT_EMERALD    = new Color(16, 185, 129);  // Primary security green
    public static final Color ACCENT_EMERALD_HOVER = new Color(5, 150, 105);
    public static final Color ACCENT_BRONZE     = new Color(197, 160, 89);  // Metallic bronze accent
    public static final Color ACCENT_BRONZE_HOVER = new Color(179, 142, 70);

    public static final Color TEXT_PRIMARY      = new Color(243, 244, 246); // Crisp white
    public static final Color TEXT_SECONDARY    = new Color(156, 163, 175); // Steel silver
    public static final Color TEXT_MUTED        = new Color(107, 114, 128); // Subtle placeholder gray
    public static final Color TEXT_EMERALD      = new Color(52, 211, 153);  // Highlight green

    public static final Color STATUS_SUCCESS    = new Color(16, 185, 129);
    public static final Color STATUS_WARNING    = new Color(245, 158, 11);
    public static final Color STATUS_DANGER     = new Color(239, 68, 68);

    // --- Typography ---
    public static final Font FONT_BRAND_TITLE   = new Font("Segoe UI", Font.BOLD, 24);
    public static final Font FONT_HEADER        = new Font("Segoe UI", Font.BOLD, 18);
    public static final Font FONT_SECTION_TITLE = new Font("Segoe UI", Font.BOLD, 15);
    public static final Font FONT_BODY          = new Font("Segoe UI", Font.PLAIN, 13);
    public static final Font FONT_BODY_BOLD     = new Font("Segoe UI", Font.BOLD, 13);
    public static final Font FONT_SMALL         = new Font("Segoe UI", Font.PLAIN, 11);
    public static final Font FONT_MONO          = new Font("Consolas", Font.PLAIN, 13);

    private UITheme() {
    }

    /**
     * Enables crisp rendering hints on standard Java2D graphics.
     */
    public static void enableAntialiasing(Graphics g) {
        if (g instanceof Graphics2D g2d) {
            g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_LCD_HRGB);
            g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        }
    }

    /**
     * Creates a styled modern text field with rounded borders and responsive focus glow.
     */
    public static JTextField createModernTextField(String placeholder) {
        JTextField field = new JTextField() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                enableAntialiasing(g2d);
                g2d.setColor(getBackground());
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                super.paintComponent(g2d);

                if (getText().isEmpty() && !hasFocus()) {
                    g2d.setColor(TEXT_MUTED);
                    g2d.setFont(FONT_BODY);
                    Insets insets = getInsets();
                    FontMetrics fm = g2d.getFontMetrics();
                    g2d.drawString(placeholder, insets.left, (getHeight() + fm.getAscent() - fm.getDescent()) / 2);
                }
                g2d.dispose();
            }

            @Override
            protected void paintBorder(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                enableAntialiasing(g2d);
                Color border = hasFocus() ? BORDER_FOCUS : BORDER_DEFAULT;
                g2d.setColor(border);
                g2d.setStroke(new BasicStroke(hasFocus() ? 1.5f : 1.0f));
                g2d.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 8, 8);
                g2d.dispose();
            }
        };

        field.setOpaque(false);
        field.setBackground(BG_INPUT);
        field.setForeground(TEXT_PRIMARY);
        field.setCaretColor(ACCENT_EMERALD);
        field.setFont(FONT_BODY);
        field.setBorder(new EmptyBorder(9, 14, 9, 14));
        field.setPreferredSize(new Dimension(300, 40));

        field.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) { field.repaint(); }
            @Override
            public void focusLost(FocusEvent e) { field.repaint(); }
        });

        return field;
    }

    /**
     * Creates a styled modern password field with rounded borders and responsive focus glow.
     */
    public static JPasswordField createModernPasswordField(String placeholder) {
        JPasswordField field = new JPasswordField() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                enableAntialiasing(g2d);
                g2d.setColor(getBackground());
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);
                super.paintComponent(g2d);

                if (getPassword().length == 0 && !hasFocus()) {
                    g2d.setColor(TEXT_MUTED);
                    g2d.setFont(FONT_BODY);
                    Insets insets = getInsets();
                    FontMetrics fm = g2d.getFontMetrics();
                    g2d.drawString(placeholder, insets.left, (getHeight() + fm.getAscent() - fm.getDescent()) / 2);
                }
                g2d.dispose();
            }

            @Override
            protected void paintBorder(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                enableAntialiasing(g2d);
                Color border = hasFocus() ? BORDER_FOCUS : BORDER_DEFAULT;
                g2d.setColor(border);
                g2d.setStroke(new BasicStroke(hasFocus() ? 1.5f : 1.0f));
                g2d.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 8, 8);
                g2d.dispose();
            }
        };

        field.setOpaque(false);
        field.setBackground(BG_INPUT);
        field.setForeground(TEXT_PRIMARY);
        field.setCaretColor(ACCENT_EMERALD);
        field.setFont(FONT_BODY);
        field.setEchoChar('•');
        field.setBorder(new EmptyBorder(9, 14, 9, 14));
        field.setPreferredSize(new Dimension(300, 40));

        field.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) { field.repaint(); }
            @Override
            public void focusLost(FocusEvent e) { field.repaint(); }
        });

        return field;
    }

    /**
     * Creates a primary rounded action button with cybersecurity emerald theme.
     */
    public static JButton createPrimaryButton(String text) {
        return createCustomButton(text, ACCENT_EMERALD, ACCENT_EMERALD_HOVER, BG_DARKEST, 8);
    }

    /**
     * Creates a secondary rounded action button with subtle metallic bronze accents.
     */
    public static JButton createBronzeButton(String text) {
        return createCustomButton(text, ACCENT_BRONZE, ACCENT_BRONZE_HOVER, BG_DARKEST, 8);
    }

    /**
     * Creates a flat outline secondary button.
     */
    public static JButton createSecondaryButton(String text) {
        JButton button = new JButton(text) {
            private boolean hovered = false;
            {
                addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseEntered(MouseEvent e) { hovered = true; repaint(); }
                    @Override
                    public void mouseExited(MouseEvent e) { hovered = false; repaint(); }
                });
            }

            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                enableAntialiasing(g2d);
                g2d.setColor(hovered ? BG_CARD_HOVER : BG_CARD);
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 8, 8);

                g2d.setColor(hovered ? BORDER_HOVER : BORDER_DEFAULT);
                g2d.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 8, 8);

                FontMetrics fm = g2d.getFontMetrics();
                int x = (getWidth() - fm.stringWidth(getText())) / 2;
                int y = (getHeight() + fm.getAscent() - fm.getDescent()) / 2;
                g2d.setColor(TEXT_PRIMARY);
                g2d.setFont(getFont());
                g2d.drawString(getText(), x, y);
                g2d.dispose();
            }
        };

        button.setOpaque(false);
        button.setContentAreaFilled(false);
        button.setBorderPainted(false);
        button.setFocusPainted(false);
        button.setFont(FONT_BODY_BOLD);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        button.setPreferredSize(new Dimension(140, 38));
        return button;
    }

    /**
     * Creates a link-styled flat button.
     */
    public static JButton createLinkButton(String text) {
        JButton button = new JButton(text) {
            private boolean hovered = false;
            {
                addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseEntered(MouseEvent e) { hovered = true; repaint(); }
                    @Override
                    public void mouseExited(MouseEvent e) { hovered = false; repaint(); }
                });
            }

            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                enableAntialiasing(g2d);
                g2d.setFont(getFont());
                g2d.setColor(hovered ? ACCENT_EMERALD : TEXT_SECONDARY);
                FontMetrics fm = g2d.getFontMetrics();
                int x = 0;
                int y = (getHeight() + fm.getAscent() - fm.getDescent()) / 2;
                g2d.drawString(getText(), x, y);
                if (hovered) {
                    g2d.drawLine(x, y + 2, x + fm.stringWidth(getText()), y + 2);
                }
                g2d.dispose();
            }
        };

        button.setOpaque(false);
        button.setContentAreaFilled(false);
        button.setBorderPainted(false);
        button.setFocusPainted(false);
        button.setFont(FONT_BODY);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        return button;
    }

    private static JButton createCustomButton(String text, Color baseColor, Color hoverColor, Color textColor, int radius) {
        JButton button = new JButton(text) {
            private boolean hovered = false;
            {
                addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseEntered(MouseEvent e) { hovered = true; repaint(); }
                    @Override
                    public void mouseExited(MouseEvent e) { hovered = false; repaint(); }
                });
            }

            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                enableAntialiasing(g2d);
                g2d.setColor(hovered ? hoverColor : baseColor);
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), radius, radius);

                FontMetrics fm = g2d.getFontMetrics();
                int x = (getWidth() - fm.stringWidth(getText())) / 2;
                int y = (getHeight() + fm.getAscent() - fm.getDescent()) / 2;
                g2d.setColor(textColor);
                g2d.setFont(getFont());
                g2d.drawString(getText(), x, y);
                g2d.dispose();
            }
        };

        button.setOpaque(false);
        button.setContentAreaFilled(false);
        button.setBorderPainted(false);
        button.setFocusPainted(false);
        button.setFont(FONT_BODY_BOLD);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        button.setPreferredSize(new Dimension(140, 40));
        return button;
    }

    /**
     * Creates an elevated rounded card panel.
     */
    public static JPanel createCardPanel() {
        JPanel panel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2d = (Graphics2D) g.create();
                enableAntialiasing(g2d);
                g2d.setColor(BG_CARD);
                g2d.fillRoundRect(0, 0, getWidth(), getHeight(), 12, 12);
                g2d.setColor(BORDER_DEFAULT);
                g2d.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 12, 12);
                g2d.dispose();
                super.paintComponent(g);
            }
        };
        panel.setOpaque(false);
        panel.setBorder(new EmptyBorder(16, 16, 16, 16));
        return panel;
    }
}
