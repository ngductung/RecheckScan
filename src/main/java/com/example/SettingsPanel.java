package com.example;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import java.awt.*;

public class SettingsPanel {

    public static JPanel create(
            JTextArea extensionArea,
            JTextField excludeStatusCodesField,
            JTextField ipField,
            JTextField portField,
            JTextField dbNameField,
            JTextField usernameField,
            JPasswordField passwordField,
            JButton checkConnectionButton,
            JCheckBox highlightCheckBox,
            JCheckBox noteCheckBox,
            JCheckBox autoBypassCheckBox,
            JButton applyButton,
            JLabel totalLbl,
            JLabel scannedLbl,
            JLabel rejectedLbl,
            JLabel bypassLbl,
            JLabel unverifiedLbl) {

        JPanel settingsPanel = new JPanel(new BorderLayout(10, 10));
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JPanel centerPanel = new JPanel();
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.Y_AXIS));

        // --- Nhóm Cài đặt Kết nối CSDL ---
        JPanel dbSettingsPanel = new JPanel();
        dbSettingsPanel.setLayout(new BoxLayout(dbSettingsPanel, BoxLayout.Y_AXIS));
        dbSettingsPanel.setBorder(createTitledBorder("Database Connection Settings"));

        // Helper để tạo các dòng nhập liệu
        dbSettingsPanel.add(createSettingRow("Server IP:", ipField));
        dbSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));
        dbSettingsPanel.add(createSettingRow("Port:", portField));
        dbSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));
        dbSettingsPanel.add(createSettingRow("ID Project in Xpentest:", dbNameField));
        dbSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));
        dbSettingsPanel.add(createSettingRow("Username:", usernameField));
        dbSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));
        dbSettingsPanel.add(createSettingRow("Password:", passwordField));
        dbSettingsPanel.add(Box.createRigidArea(new Dimension(0, 10)));
        
        JPanel connectionBtnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        connectionBtnPanel.add(checkConnectionButton);
        connectionBtnPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        dbSettingsPanel.add(connectionBtnPanel);
        
        centerPanel.add(dbSettingsPanel);
        centerPanel.add(Box.createRigidArea(new Dimension(0, 10)));

        // --- Nhóm Cài đặt Extension ---
        JPanel extensionSettingsPanel = new JPanel();
        extensionSettingsPanel.setLayout(new BoxLayout(extensionSettingsPanel, BoxLayout.Y_AXIS));
        extensionSettingsPanel.setBorder(createTitledBorder("Extension Settings"));

        // Panel cho Exclude Extensions
        extensionSettingsPanel.add(createSettingRow("Exclude Extensions (comma separated):", new JScrollPane(extensionArea)));
        extensionSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        // Panel cho Exclude Status Codes
        extensionSettingsPanel.add(createSettingRow("Exclude Status Codes (comma separated):", excludeStatusCodesField));
        
        centerPanel.add(extensionSettingsPanel);
        centerPanel.add(Box.createRigidArea(new Dimension(0, 10)));

        // --- Nhóm Controls ---
        JPanel controlsPanel = new JPanel();
        controlsPanel.setLayout(new BoxLayout(controlsPanel, BoxLayout.Y_AXIS));
        controlsPanel.setBorder(createTitledBorder("Controls"));
        controlsPanel.add(highlightCheckBox);
        controlsPanel.add(noteCheckBox);
        controlsPanel.add(autoBypassCheckBox);
        
        centerPanel.add(controlsPanel);
        centerPanel.add(Box.createVerticalGlue());

        // --- Panel Thống kê ---
        JPanel eastPanel = new JPanel(new BorderLayout());
        JPanel statsPanel = new JPanel();
        statsPanel.setBorder(createTitledBorder("Statistics"));
        statsPanel.setLayout(new GridLayout(5, 1, 0, 10));
        statsPanel.setPreferredSize(new Dimension(220, 200));
        Font statFont = totalLbl.getFont().deriveFont(Font.PLAIN, 15f);
        for (JLabel lbl : new JLabel[]{totalLbl, scannedLbl, rejectedLbl, bypassLbl, unverifiedLbl}) {
            lbl.setFont(statFont);
            lbl.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
            statsPanel.add(lbl);
        }
        eastPanel.add(statsPanel, BorderLayout.NORTH);

        // --- Panel Nút Apply ---
        JPanel southPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        applyButton.setPreferredSize(new Dimension(150, 32));
        applyButton.setFont(applyButton.getFont().deriveFont(Font.BOLD, 13f));
        southPanel.add(applyButton);

        settingsPanel.add(centerPanel, BorderLayout.CENTER);
        settingsPanel.add(eastPanel, BorderLayout.EAST);
        settingsPanel.add(southPanel, BorderLayout.SOUTH);

        return settingsPanel;
    }

    private static JPanel createSettingRow(String labelText, JComponent component) {
        JPanel panel = new JPanel(new BorderLayout(10, 0));
        panel.add(new JLabel(labelText), BorderLayout.WEST);
        panel.add(component, BorderLayout.CENTER);
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        // Giới hạn chiều cao để layout đẹp hơn
        int height = component.getPreferredSize().height;
        panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, height + 5));
        return panel;
    }

    private static Border createTitledBorder(String title) {
        TitledBorder border = BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), title);
        border.setTitleFont(border.getTitleFont().deriveFont(Font.BOLD, 13f));
        return BorderFactory.createCompoundBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0), border);
    }
}