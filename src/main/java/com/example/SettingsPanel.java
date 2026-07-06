// SettingsPanel.java
package com.example;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Lớp này là một "Factory" để tạo ra panel cho tab "Settings".
 * Nó chỉ chịu trách nhiệm sắp xếp các thành phần giao diện (UI components)
 * và không chứa bất kỳ logic nghiệp vụ nào. Các components (như JTextArea, JButton)
 * được tạo và quản lý trong lớp chính (RecheckScanApiExtension).
 */
public class SettingsPanel {

    /**
     * Phương thức tĩnh tạo và trả về một JPanel đã được cấu hình hoàn chỉnh cho tab Settings.
     * @param extensionArea Vùng nhập các extension cần loại trừ.
     * @param outputPathField Trường nhập đường dẫn lưu file log/db.
     * @param browseButton Nút để mở cửa sổ chọn file.
     * @param highlightCheckBox Checkbox để bật/tắt highlight.
     * @param noteCheckBox Checkbox để bật/tắt thêm note.
     * @param autoBypassCheckBox Checkbox để bật/tắt tự động bypass.
     * @param applyButton Nút để áp dụng và lưu cài đặt.
     * @param totalLbl, scannedLbl, etc. Các nhãn để hiển thị thống kê.
     * @param excludeStatusCodesField Trường nhập các status code cần loại trừ.
     * @return Một JPanel chứa toàn bộ giao diện của tab Settings.
     */
    public static JPanel create(
            JTextArea  extensionArea,
            JTextField outputPathField,
            JButton    browseButton,
            JCheckBox  highlightCheckBox,
            JCheckBox  noteCheckBox,
            JCheckBox  autoBypassCheckBox,
            JButton    applyButton,
            JLabel     totalLbl,
            JLabel     scannedLbl,
            JLabel     rejectedLbl,
            JLabel     bypassLbl,
            JLabel     unverifiedLbl,
            JTextField excludeStatusCodesField,
            JTextArea  pathParameterRulesArea) {

        /* ========= PANEL GỐC (ROOT) ========= */
        JPanel settingsPanel = new JPanel();
        // Sử dụng BorderLayout để chia panel thành các khu vực CENTER, EAST, SOUTH.
        settingsPanel.setLayout(new BorderLayout(10, 10));
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        /* ========= PANEL TRUNG TÂM (CENTER) - Chứa các điều khiển chính ========= */
        JPanel centerPanel = new JPanel();
        // BoxLayout theo trục Y để các nhóm panel xếp chồng lên nhau theo chiều dọc.
        centerPanel.setLayout(new BoxLayout(centerPanel, BoxLayout.Y_AXIS));

        // --- Nhóm Cài đặt Project ---
        JPanel projectSettingsPanel = new JPanel();
        projectSettingsPanel.setLayout(new BoxLayout(projectSettingsPanel, BoxLayout.Y_AXIS));
        projectSettingsPanel.setBorder(createTitledBorder("Project Settings")); // Tạo đường viền có tiêu đề

        JLabel outputPathLabel = new JLabel("Log/DB Output Path: ");
        JLabel excludeExtensionLabel = new JLabel("Exclude Extensions (comma separated): ");
        JLabel excludeStatusCodeLabel = new JLabel("Exclude Status Codes (comma separated): ");
        JLabel pathParameterRulesLabel = new JLabel("URL Path Parameter Rules: ");
        int projectSettingsLabelWidth = Math.max(
                Math.max(outputPathLabel.getPreferredSize().width, excludeExtensionLabel.getPreferredSize().width),
                Math.max(excludeStatusCodeLabel.getPreferredSize().width, pathParameterRulesLabel.getPreferredSize().width)
        );
        for (JLabel label : new JLabel[]{outputPathLabel, excludeExtensionLabel, excludeStatusCodeLabel, pathParameterRulesLabel}) {
            Dimension labelSize = new Dimension(projectSettingsLabelWidth, label.getPreferredSize().height);
            label.setPreferredSize(labelSize);
            label.setMinimumSize(labelSize);
            label.setHorizontalAlignment(SwingConstants.LEFT);
        }
        pathParameterRulesLabel.setVerticalAlignment(SwingConstants.TOP);

        // Panel cho đường dẫn output và nút Browse
        JPanel outputPathPanel = new JPanel(new BorderLayout(5, 0));
        outputPathPanel.add(outputPathLabel, BorderLayout.WEST);
        outputPathPanel.add(outputPathField, BorderLayout.CENTER);
        outputPathPanel.add(browseButton, BorderLayout.EAST);
        // Giới hạn chiều cao tối đa để không bị giãn ra quá lớn.
        outputPathPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, outputPathField.getPreferredSize().height));
        outputPathPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        projectSettingsPanel.add(outputPathPanel);
        projectSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        // Panel cho Exclude Extensions
        JPanel excludeExtensionPanel = new JPanel(new BorderLayout(5, 0));
        excludeExtensionPanel.add(excludeExtensionLabel, BorderLayout.WEST);
        extensionArea.setRows(1);
        JScrollPane extScroll = new JScrollPane(extensionArea);
        extScroll.setMaximumSize(new Dimension(Integer.MAX_VALUE, extensionArea.getPreferredSize().height + 10));
        extScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        excludeExtensionPanel.add(extScroll, BorderLayout.CENTER);
        excludeExtensionPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, excludeExtensionPanel.getPreferredSize().height));
        excludeExtensionPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        projectSettingsPanel.add(excludeExtensionPanel);
        projectSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        // Panel cho Exclude Status Codes
        JPanel excludeStatusCodePanel = new JPanel(new BorderLayout(5, 0));
        excludeStatusCodePanel.add(excludeStatusCodeLabel, BorderLayout.WEST);
        excludeStatusCodePanel.add(excludeStatusCodesField, BorderLayout.CENTER);
        excludeStatusCodePanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, excludeStatusCodesField.getPreferredSize().height));
        excludeStatusCodePanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        projectSettingsPanel.add(excludeStatusCodePanel);
        projectSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        // Panel cho rule nhận diện path parameter động
        JPanel pathParameterRulesPanel = new JPanel(new BorderLayout(5, 0));
        pathParameterRulesPanel.add(pathParameterRulesLabel, BorderLayout.WEST);
        pathParameterRulesArea.setRows(3);
        pathParameterRulesArea.setToolTipText("One rule per line. Regex rules containing / can match path context and replace the final matched segment.");
        JScrollPane pathRuleScroll = new JScrollPane(pathParameterRulesArea);
        int pathRuleInitialHeight = pathRuleScroll.getPreferredSize().height;
        pathRuleScroll.setPreferredSize(new Dimension(1, pathRuleInitialHeight));
        JLabel pathRuleHelpLabel = new JLabel("One rule per line. Examples: {id}=number:19, {uuid}=uuid, {memberUUID}=regex:member-invitations\\/[a-z0-9-]{36}");
        pathRuleHelpLabel.setFont(pathRuleHelpLabel.getFont().deriveFont(Font.PLAIN, 11f));
        pathRuleHelpLabel.setForeground(UIManager.getColor("Label.disabledForeground"));

        JPanel pathRuleResizeHandle = new JPanel();
        pathRuleResizeHandle.setPreferredSize(new Dimension(1, 8));
        pathRuleResizeHandle.setCursor(Cursor.getPredefinedCursor(Cursor.S_RESIZE_CURSOR));
        pathRuleResizeHandle.setToolTipText("Drag to resize");
        Color resizeHandleColor = UIManager.getColor("Separator.foreground");
        if (resizeHandleColor == null) {
            resizeHandleColor = UIManager.getColor("controlShadow");
        }
        if (resizeHandleColor == null) {
            resizeHandleColor = Color.LIGHT_GRAY;
        }
        pathRuleResizeHandle.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, resizeHandleColor));

        JPanel pathRuleFooterPanel = new JPanel(new BorderLayout(0, 2));
        pathRuleFooterPanel.add(pathRuleHelpLabel, BorderLayout.CENTER);
        pathRuleFooterPanel.add(pathRuleResizeHandle, BorderLayout.SOUTH);

        JPanel pathRuleInputPanel = new JPanel(new BorderLayout(0, 3));
        pathRuleInputPanel.add(pathRuleScroll, BorderLayout.CENTER);
        pathRuleInputPanel.add(pathRuleFooterPanel, BorderLayout.SOUTH);
        pathParameterRulesPanel.add(pathRuleInputPanel, BorderLayout.CENTER);
        pathParameterRulesPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, pathParameterRulesPanel.getPreferredSize().height));
        pathParameterRulesPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        final int minPathRuleHeight = pathRuleInitialHeight;
        final int maxPathRuleHeight = Math.max(minPathRuleHeight, 260);
        java.awt.event.MouseAdapter pathRuleResizeListener = new java.awt.event.MouseAdapter() {
            private int dragStartY;
            private int dragStartHeight;

            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                dragStartY = e.getLocationOnScreen().y;
                dragStartHeight = pathRuleScroll.getHeight() > 0
                        ? pathRuleScroll.getHeight()
                        : pathRuleScroll.getPreferredSize().height;
            }

            @Override
            public void mouseDragged(java.awt.event.MouseEvent e) {
                int nextHeight = dragStartHeight + e.getLocationOnScreen().y - dragStartY;
                nextHeight = Math.max(minPathRuleHeight, Math.min(maxPathRuleHeight, nextHeight));
                pathRuleScroll.setPreferredSize(new Dimension(pathRuleScroll.getPreferredSize().width, nextHeight));
                pathParameterRulesPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, pathParameterRulesPanel.getPreferredSize().height));
                pathRuleInputPanel.revalidate();
                pathParameterRulesPanel.revalidate();
                projectSettingsPanel.revalidate();
                settingsPanel.revalidate();
                settingsPanel.repaint();
            }
        };
        pathRuleResizeHandle.addMouseListener(pathRuleResizeListener);
        pathRuleResizeHandle.addMouseMotionListener(pathRuleResizeListener);

        projectSettingsPanel.add(pathParameterRulesPanel);
        projectSettingsPanel.add(Box.createRigidArea(new Dimension(0, 5)));

        centerPanel.add(projectSettingsPanel);
        centerPanel.add(Box.createRigidArea(new Dimension(0, 10))); // Thêm khoảng trống giữa các nhóm

        // --- Nhóm Controls ---
        JPanel controlsPanel = new JPanel();
        controlsPanel.setLayout(new BoxLayout(controlsPanel, BoxLayout.Y_AXIS));
        controlsPanel.setBorder(createTitledBorder("Controls"));

        // Thêm trực tiếp các checkbox vào panel.
        controlsPanel.add(highlightCheckBox);
        controlsPanel.add(noteCheckBox);
        controlsPanel.add(autoBypassCheckBox);

        centerPanel.add(controlsPanel);

        /* ========= PANEL PHÍA ĐÔNG (EAST) - Chứa thống kê ========= */
        JPanel eastPanel = new JPanel(new BorderLayout());

        JPanel statsPanel = new JPanel();
        statsPanel.setBorder(createTitledBorder("Statistics"));
        // GridLayout để các label thống kê được xếp đều nhau.
        statsPanel.setLayout(new GridLayout(5, 1, 0, 10));
        statsPanel.setPreferredSize(new Dimension(220, 200));

        // Thiết lập font và border cho các label thống kê.
        Font statFont = totalLbl.getFont().deriveFont(Font.PLAIN, 15f);
        for (JLabel lbl : new JLabel[]{totalLbl, scannedLbl, rejectedLbl, bypassLbl, unverifiedLbl}) {
            lbl.setFont(statFont);
            lbl.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
            statsPanel.add(lbl);
        }

        eastPanel.add(statsPanel, BorderLayout.NORTH);


        /* ========= PANEL PHÍA NAM (SOUTH) - Chứa nút Apply ========= */
        JPanel southPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        applyButton.setPreferredSize(new Dimension(150, 32));
        applyButton.setFont(applyButton.getFont().deriveFont(Font.BOLD, 13f));
        southPanel.add(applyButton);

        /* ========= LẮP RÁP CÁC PANEL VÀO PANEL GỐC ========= */
        settingsPanel.add(centerPanel, BorderLayout.CENTER);
        settingsPanel.add(eastPanel, BorderLayout.EAST);
        settingsPanel.add(southPanel, BorderLayout.SOUTH);

        return settingsPanel;
    }

    /**
     * Phương thức tiện ích để tạo một đường viền có tiêu đề (TitledBorder).
     * @param title Tiêu đề của đường viền.
     * @return một đối tượng Border đã được định dạng.
     */
    private static Border createTitledBorder(String title) {
        TitledBorder border = BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), title
        );
        border.setTitleFont(border.getTitleFont().deriveFont(Font.BOLD, 13f));
        return BorderFactory.createCompoundBorder(
                BorderFactory.createEmptyBorder(5, 0, 5, 0),
                border
        );
    }
}
