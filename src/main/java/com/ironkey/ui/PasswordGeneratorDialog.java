package com.ironkey.ui;

import com.ironkey.security.PasswordGenerator;
import com.ironkey.util.ClipboardManager;
import com.ironkey.util.UITheme;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.function.Consumer;

/**
 * Premium modal dialog for generating configurable, cryptographically secure passwords.
 * Supports customizable lengths, character sets, entropy scores, and 30-second clipboard clearing.
 */
public class PasswordGeneratorDialog extends JDialog {

    private JTextField resultField;
    private JSlider lengthSlider;
    private JLabel lengthValueLabel;
    private JCheckBox upperCheck;
    private JCheckBox lowerCheck;
    private JCheckBox digitsCheck;
    private JCheckBox specialCheck;
    private JCheckBox avoidAmbiguousCheck;
    private JProgressBar entropyMeter;
    private JLabel entropyLabel;

    private final Consumer<String> onPasswordSelected;

    public PasswordGeneratorDialog(Frame parent, Consumer<String> onPasswordSelected) {
        this(parent, "IRONKEY — Cryptographic Password Generator", onPasswordSelected);
    }

    public PasswordGeneratorDialog(Frame parent, String title, Consumer<String> onPasswordSelected) {
        super(parent, title, true);
        this.onPasswordSelected = onPasswordSelected;

        setSize(460, 520);
        setResizable(false);
        setLocationRelativeTo(parent);
        getContentPane().setBackground(UITheme.BG_DARKEST);

        initUI();
        regeneratePassword();
    }

    private void initUI() {
        setLayout(new BorderLayout());

        JPanel container = new JPanel();
        container.setLayout(new BoxLayout(container, BoxLayout.Y_AXIS));
        container.setOpaque(false);
        container.setBorder(new EmptyBorder(24, 28, 24, 28));

        // Header Title
        JLabel titleLabel = new JLabel("🎲 Password Generator");
        titleLabel.setFont(UITheme.FONT_HEADER);
        titleLabel.setForeground(UITheme.TEXT_PRIMARY);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        container.add(titleLabel);

        JLabel subtitle = new JLabel("Cryptographically strong passwords using SecureRandom entropy.");
        subtitle.setFont(UITheme.FONT_SMALL);
        subtitle.setForeground(UITheme.TEXT_MUTED);
        subtitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        container.add(subtitle);
        container.add(Box.createVerticalStrut(18));

        // Generated Password Display Card
        JPanel displayCard = UITheme.createCardPanel();
        displayCard.setLayout(new BorderLayout(8, 0));
        displayCard.setMaximumSize(new Dimension(Integer.MAX_VALUE, 50));
        displayCard.setAlignmentX(Component.LEFT_ALIGNMENT);

        resultField = new JTextField();
        resultField.setEditable(false);
        resultField.setFont(UITheme.FONT_MONO);
        resultField.setForeground(UITheme.TEXT_EMERALD);
        resultField.setBackground(UITheme.BG_CARD);
        resultField.setBorder(null);
        displayCard.add(resultField, BorderLayout.CENTER);

        JButton regenBtn = UITheme.createSecondaryButton("🔄");
        regenBtn.setPreferredSize(new Dimension(42, 34));
        regenBtn.setToolTipText("Regenerate New Password");
        regenBtn.addActionListener(e -> regeneratePassword());
        displayCard.add(regenBtn, BorderLayout.EAST);

        container.add(displayCard);
        container.add(Box.createVerticalStrut(10));

        // Entropy meter
        JPanel entropyRow = new JPanel(new BorderLayout(8, 0));
        entropyRow.setOpaque(false);
        entropyRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 16));
        entropyRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        entropyMeter = new JProgressBar(0, 100);
        entropyMeter.setValue(90);
        entropyMeter.setPreferredSize(new Dimension(180, 6));
        entropyMeter.setForeground(UITheme.STATUS_SUCCESS);
        entropyMeter.setBackground(UITheme.BG_INPUT);
        entropyMeter.setBorderPainted(false);
        entropyRow.add(entropyMeter, BorderLayout.CENTER);

        entropyLabel = new JLabel("Entropy: Strong (95%)");
        entropyLabel.setFont(UITheme.FONT_SMALL);
        entropyLabel.setForeground(UITheme.STATUS_SUCCESS);
        entropyRow.add(entropyLabel, BorderLayout.EAST);

        container.add(entropyRow);
        container.add(Box.createVerticalStrut(20));

        // Length Slider Control
        JPanel lengthRow = new JPanel(new BorderLayout());
        lengthRow.setOpaque(false);
        lengthRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 24));
        lengthRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel lengthTitle = new JLabel("Password Length:");
        lengthTitle.setFont(UITheme.FONT_BODY_BOLD);
        lengthTitle.setForeground(UITheme.TEXT_PRIMARY);

        lengthValueLabel = new JLabel("20 characters");
        lengthValueLabel.setFont(UITheme.FONT_BODY_BOLD);
        lengthValueLabel.setForeground(UITheme.ACCENT_BRONZE);

        lengthRow.add(lengthTitle, BorderLayout.WEST);
        lengthRow.add(lengthValueLabel, BorderLayout.EAST);
        container.add(lengthRow);
        container.add(Box.createVerticalStrut(6));

        lengthSlider = new JSlider(8, 64, 20);
        lengthSlider.setOpaque(false);
        lengthSlider.setBackground(UITheme.BG_DARKEST);
        lengthSlider.setForeground(UITheme.ACCENT_EMERALD);
        lengthSlider.setAlignmentX(Component.LEFT_ALIGNMENT);
        lengthSlider.addChangeListener(e -> {
            lengthValueLabel.setText(lengthSlider.getValue() + " characters");
            regeneratePassword();
        });
        container.add(lengthSlider);
        container.add(Box.createVerticalStrut(16));

        // Character Options
        JLabel optionsTitle = new JLabel("Character Options:");
        optionsTitle.setFont(UITheme.FONT_BODY_BOLD);
        optionsTitle.setForeground(UITheme.TEXT_PRIMARY);
        optionsTitle.setAlignmentX(Component.LEFT_ALIGNMENT);
        container.add(optionsTitle);
        container.add(Box.createVerticalStrut(8));

        upperCheck = createStyledCheck("Uppercase (A-Z)", true);
        lowerCheck = createStyledCheck("Lowercase (a-z)", true);
        digitsCheck = createStyledCheck("Numbers (0-9)", true);
        specialCheck = createStyledCheck("Symbols (!@#$%^&*)", true);
        avoidAmbiguousCheck = createStyledCheck("Avoid Ambiguous Characters (0, O, 1, l, I)", false);

        container.add(upperCheck);
        container.add(lowerCheck);
        container.add(digitsCheck);
        container.add(specialCheck);
        container.add(avoidAmbiguousCheck);
        container.add(Box.createVerticalGlue());

        // Action Buttons Row
        JPanel actionsRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        actionsRow.setOpaque(false);
        actionsRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        JButton copyBtn = UITheme.createSecondaryButton("📋 Copy (30s)");
        copyBtn.setPreferredSize(new Dimension(130, 38));
        copyBtn.addActionListener(e -> {
            ClipboardManager.copyPassword(resultField.getText());
            JOptionPane.showMessageDialog(this,
                    "Password copied to clipboard.\nAuto-clearing in 30 seconds.",
                    "IRONKEY Clipboard", JOptionPane.INFORMATION_MESSAGE);
        });
        actionsRow.add(copyBtn);

        if (onPasswordSelected != null) {
            JButton useBtn = UITheme.createPrimaryButton("✓ Use Password");
            useBtn.setPreferredSize(new Dimension(140, 38));
            useBtn.addActionListener(e -> {
                onPasswordSelected.accept(resultField.getText());
                dispose();
            });
            actionsRow.add(useBtn);
        } else {
            JButton closeBtn = UITheme.createPrimaryButton("Done");
            closeBtn.setPreferredSize(new Dimension(100, 38));
            closeBtn.addActionListener(e -> dispose());
            actionsRow.add(closeBtn);
        }

        container.add(actionsRow);

        add(container, BorderLayout.CENTER);
    }

    private JCheckBox createStyledCheck(String text, boolean selected) {
        JCheckBox cb = new JCheckBox(text, selected);
        cb.setOpaque(false);
        cb.setFont(UITheme.FONT_BODY);
        cb.setForeground(UITheme.TEXT_SECONDARY);
        cb.setFocusPainted(false);
        cb.setAlignmentX(Component.LEFT_ALIGNMENT);
        cb.addActionListener(e -> regeneratePassword());
        return cb;
    }

    private void regeneratePassword() {
        int length = lengthSlider != null ? lengthSlider.getValue() : 20;
        boolean upper = upperCheck == null || upperCheck.isSelected();
        boolean lower = lowerCheck == null || lowerCheck.isSelected();
        boolean digits = digitsCheck == null || digitsCheck.isSelected();
        boolean special = specialCheck == null || specialCheck.isSelected();
        boolean avoidAmbiguous = avoidAmbiguousCheck != null && avoidAmbiguousCheck.isSelected();

        // Enforce at least one selection
        if (!upper && !lower && !digits && !special) {
            lowerCheck.setSelected(true);
            lower = true;
        }

        String pass = PasswordGenerator.generate(length, upper, lower, digits, special, avoidAmbiguous);
        if (resultField != null) {
            resultField.setText(pass);
        }

        int score = PasswordGenerator.calculateStrength(pass.toCharArray());
        double entropyBits = PasswordGenerator.calculateEntropy(length, upper, lower, digits, special);

        if (entropyMeter != null) {
            entropyMeter.setValue(score);
            if (score >= 70) {
                entropyMeter.setForeground(UITheme.STATUS_SUCCESS);
                entropyLabel.setText("Entropy: " + entropyBits + " bits (Strong " + score + "%)");
                entropyLabel.setForeground(UITheme.STATUS_SUCCESS);
            } else if (score >= 45) {
                entropyMeter.setForeground(UITheme.STATUS_WARNING);
                entropyLabel.setText("Entropy: " + entropyBits + " bits (Moderate " + score + "%)");
                entropyLabel.setForeground(UITheme.STATUS_WARNING);
            } else {
                entropyMeter.setForeground(UITheme.STATUS_DANGER);
                entropyLabel.setText("Entropy: " + entropyBits + " bits (Weak " + score + "%)");
                entropyLabel.setForeground(UITheme.STATUS_DANGER);
            }
        }
    }
}
