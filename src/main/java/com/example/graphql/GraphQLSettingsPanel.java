package com.example.graphql;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Factory tạo panel cho tab "Settings" của phiên bản GraphQL. Chỉ chịu trách nhiệm bố cục UI,
 * không chứa logic nghiệp vụ (các component do lớp chính quản lý).
 */
public class GraphQLSettingsPanel {

    public static JPanel create(
            JTextField outputPathField,
            JButton browseButton,
            JTextField excludeStatusCodesField,
            JTextArea endpointsArea,
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

        // --- Project Settings ---
        JPanel projectSettingsPanel = new JPanel();
        projectSettingsPanel.setLayout(new BoxLayout(projectSettingsPanel, BoxLayout.Y_AXIS));
        projectSettingsPanel.setBorder(createTitledBorder("Project Settings"));

        JPanel outputPathPanel = new JPanel(new BorderLayout(5, 0));
        outputPathPanel.add(new JLabel("GraphQL DB Output Path: "), BorderLayout.WEST);
        outputPathPanel.add(outputPathField, BorderLayout.CENTER);
        outputPathPanel.add(browseButton, BorderLayout.EAST);
        outputPathPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, outputPathField.getPreferredSize().height));
        outputPathPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        projectSettingsPanel.add(outputPathPanel);
        projectSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        JPanel excludeStatusCodePanel = new JPanel(new BorderLayout(5, 0));
        excludeStatusCodePanel.add(new JLabel("Exclude Status Codes (comma separated): "), BorderLayout.WEST);
        excludeStatusCodePanel.add(excludeStatusCodesField, BorderLayout.CENTER);
        excludeStatusCodePanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, excludeStatusCodesField.getPreferredSize().height));
        excludeStatusCodePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        projectSettingsPanel.add(excludeStatusCodePanel);
        projectSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        // Bộ lọc endpoint GraphQL (tùy chọn).
        JPanel endpointsPanel = new JPanel(new BorderLayout(5, 0));
        endpointsPanel.add(new JLabel("GraphQL Endpoint Paths: "), BorderLayout.WEST);
        endpointsArea.setRows(2);
        JScrollPane endpointsScroll = new JScrollPane(endpointsArea);
        JLabel endpointsHelp = new JLabel("Optional filter, comma/newline separated (e.g. /graphql, /api/graphql). "
                + "Leave empty to auto-detect any request whose body contains a GraphQL query.");
        endpointsHelp.setFont(endpointsHelp.getFont().deriveFont(Font.PLAIN, 11f));
        endpointsHelp.setForeground(UIManager.getColor("Label.disabledForeground"));
        JPanel endpointsInput = new JPanel(new BorderLayout(0, 3));
        endpointsInput.add(endpointsScroll, BorderLayout.CENTER);
        endpointsInput.add(endpointsHelp, BorderLayout.SOUTH);
        endpointsPanel.add(endpointsInput, BorderLayout.CENTER);
        endpointsPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, endpointsPanel.getPreferredSize().height));
        endpointsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        projectSettingsPanel.add(endpointsPanel);
        projectSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        centerPanel.add(projectSettingsPanel);
        centerPanel.add(Box.createRigidArea(new Dimension(0, 10)));

        // --- Controls ---
        JPanel controlsPanel = new JPanel();
        controlsPanel.setLayout(new BoxLayout(controlsPanel, BoxLayout.Y_AXIS));
        controlsPanel.setBorder(createTitledBorder("Controls"));
        controlsPanel.add(highlightCheckBox);
        controlsPanel.add(noteCheckBox);
        controlsPanel.add(autoBypassCheckBox);
        centerPanel.add(controlsPanel);

        // --- Statistics (EAST) ---
        JPanel eastPanel = new JPanel(new BorderLayout());
        JPanel statsPanel = new JPanel(new GridLayout(5, 1, 0, 10));
        statsPanel.setBorder(createTitledBorder("Statistics"));
        statsPanel.setPreferredSize(new Dimension(220, 200));
        Font statFont = totalLbl.getFont().deriveFont(Font.PLAIN, 15f);
        for (JLabel lbl : new JLabel[]{totalLbl, scannedLbl, rejectedLbl, bypassLbl, unverifiedLbl}) {
            lbl.setFont(statFont);
            lbl.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
            statsPanel.add(lbl);
        }
        eastPanel.add(statsPanel, BorderLayout.NORTH);

        // --- Apply (SOUTH) ---
        JPanel southPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        applyButton.setPreferredSize(new Dimension(150, 32));
        applyButton.setFont(applyButton.getFont().deriveFont(Font.BOLD, 13f));
        southPanel.add(applyButton);

        settingsPanel.add(centerPanel, BorderLayout.CENTER);
        settingsPanel.add(eastPanel, BorderLayout.EAST);
        settingsPanel.add(southPanel, BorderLayout.SOUTH);
        return settingsPanel;
    }

    private static Border createTitledBorder(String title) {
        TitledBorder border = BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), title);
        border.setTitleFont(border.getTitleFont().deriveFont(Font.BOLD, 13f));
        return BorderFactory.createCompoundBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0), border);
    }
}
