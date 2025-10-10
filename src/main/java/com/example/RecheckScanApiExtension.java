package com.example;

import burp.api.montoya.*;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.*;

public class RecheckScanApiExtension implements BurpExtension, ExtensionUnloadingHandler {
    private MontoyaApi api;
    private DatabaseManager databaseManager;

    private String savedExtensions;
    private String savedStatusCodes;
    private String savedDbIp;
    private String savedDbPort;
    private String savedDbName;
    private String savedDbUsername;
    private String savedDbPassword;
    private boolean highlightEnabled = false;
    private boolean noteEnabled = false;
    private boolean autoBypassNoParamGet = false;

    private DefaultTableModel tableModel;
    private final Map<Integer, Integer> modelRowToDbId = new HashMap<>();

    private final JLabel totalLbl = new JLabel("Total: 0");
    private final JLabel scannedLbl = new JLabel("Scanned: 0");
    private final JLabel rejectedLbl = new JLabel("Rejected: 0");
    private final JLabel bypassLbl = new JLabel("Bypass: 0");
    private final JLabel unverifiedLbl = new JLabel("Unverified: 0");

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Recheck Scan API (v3.0 - MySQL)");
        api.extension().registerUnloadingHandler(this);

        loadSavedSettings();
        databaseManager = new DatabaseManager(api);
        if (savedDbIp != null && !savedDbIp.isEmpty()) {
            databaseManager.initialize(savedDbIp, savedDbPort, savedDbName, savedDbUsername, savedDbPassword);
        }

        SwingUtilities.invokeLater(this::createUI);

        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                return RequestToBeSentAction.continueWith(request);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                if (isExcludedStatusCode(response.statusCode()) || !databaseManager.isConnected()) {
                    return ResponseReceivedAction.continueWith(response);
                }

                HttpRequest request = response.initiatingRequest();
                String method = request.method();
                ToolType sourceType = response.toolSource().toolType();

                if (method.equals("OPTIONS") || sourceType == ToolType.INTRUDER || sourceType == ToolType.EXTENSIONS) {
                    return ResponseReceivedAction.continueWith(response);
                }

                String host = request.httpService().host();
                String path = request.pathWithoutQuery();
                Set<String> requestParams = extractParameters(request);

                if (sourceType == ToolType.SCANNER) {
                    new Thread(() -> {
                        if (databaseManager.processScannedParameters(method, host, path, requestParams)) {
                            SwingUtilities.invokeLater(RecheckScanApiExtension.this::loadDataFromDb);
                        }
                    }).start();
                } else if (api.scope().isInScope(request.url()) && !isExcludedByExtension(path)) {
                    if (sourceType == ToolType.REPEATER) {
                        new Thread(() -> {
                            if (databaseManager.updateRepeaterStatus(method, host, path)) {
                                SwingUtilities.invokeLater(RecheckScanApiExtension.this::loadDataFromDb);
                            }
                        }).start();
                    }

                    boolean isGetWithoutParams = "GET".equals(method) && requestParams.isEmpty();
                    if (autoBypassNoParamGet && isGetWithoutParams) {
                        new Thread(() -> {
                            if (databaseManager.autoBypassApi(method, host, path)) {
                                SwingUtilities.invokeLater(RecheckScanApiExtension.this::loadDataFromDb);
                            }
                        }).start();
                        if (highlightEnabled)
                            response.annotations().setHighlightColor(HighlightColor.YELLOW);
                        if (noteEnabled)
                            response.annotations().setNotes("Bypassed");
                    } else {
                        new Thread(() -> {
                            databaseManager.insertOrUpdateApi(method, host, path, requestParams);
                            SwingUtilities.invokeLater(RecheckScanApiExtension.this::loadDataFromDb);
                        }).start();
                    }
                    Object[] status = databaseManager.getApiStatus(method, host, path);
                    if (status != null) {
                        boolean isScanned = (boolean) status[0];
                        boolean isBypassed = (boolean) status[2];
                        if (highlightEnabled && (isScanned || isBypassed)) {
                            response.annotations().setHighlightColor(HighlightColor.YELLOW);
                        }
                        if (noteEnabled) {
                            if (isScanned)
                                response.annotations().setNotes("Scanned");
                            else if (isBypassed)
                                response.annotations().setNotes("Bypassed");
                        }
                    }
                }
                return ResponseReceivedAction.continueWith(response);
            }
        });
    }

    private Set<String> extractParameters(HttpRequest request) {
        Set<String> allParamNames = new HashSet<>();
        List<ParsedHttpParameter> urlParams = request.parameters(HttpParameterType.URL);
        if (urlParams != null)
            urlParams.stream().map(ParsedHttpParameter::name).forEach(allParamNames::add);
        if (request.body().length() > 0) {
            List<ParsedHttpParameter> bodyParams = null;
            switch (request.contentType()) {
                case JSON -> bodyParams = request.parameters(HttpParameterType.JSON);
                case URL_ENCODED, MULTIPART -> bodyParams = request.parameters(HttpParameterType.BODY);
                case XML -> bodyParams = request.parameters(HttpParameterType.XML);
            }
            if (bodyParams != null)
                bodyParams.stream().map(ParsedHttpParameter::name).forEach(allParamNames::add);
        }
        return allParamNames;
    }

    private void createUI() {
        tableModel = new DefaultTableModel(new Object[] { "Method", "Host", "Path", "Unscanned Params", "Scanned",
                "Rejected", "Bypass", "Repeater", "id" }, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                if (Boolean.TRUE.equals(getValueAt(row, 4)))
                    return false;
                if (column == 5)
                    return Boolean.TRUE.equals(getValueAt(row, 7));
                return column == 6;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return switch (columnIndex) {
                    case 4, 5, 6, 7 -> Boolean.class;
                    case 8 -> Integer.class;
                    default -> String.class;
                };
            }

            @Override
            public void setValueAt(Object aValue, int row, int col) {
                super.setValueAt(aValue, row, col);
                if (col == 5 || col == 6) {
                    Integer id = (Integer) getValueAt(row, 8);
                    if (id != null) {
                        if (Boolean.TRUE.equals(aValue)) {
                            if (col == 5)
                                super.setValueAt(false, row, 6);
                            if (col == 6)
                                super.setValueAt(false, row, 5);
                        }
                        String dbColumn = (col == 5) ? "is_rejected" : "is_bypassed";
                        new Thread(() -> databaseManager.updateApiStatus(id, dbColumn, (Boolean) aValue)).start();
                    }
                }
                updateStats();
            }
        };

        JTabbedPane tabs = new JTabbedPane();
        JTable unscannedTable = createCommonTable();
        setupHiddenColumns(unscannedTable);
        final TableRowSorter<DefaultTableModel> unscannedSorter = new TableRowSorter<>(tableModel);
        unscannedTable.setRowSorter(unscannedSorter);
        final RowFilter<Object, Object> unscannedStatusFilter = new RowFilter<Object, Object>() {
            @Override
            public boolean include(Entry<? extends Object, ? extends Object> entry) {
                // Lấy giá trị từ các cột trạng thái
                boolean scanned = Boolean.TRUE.equals(entry.getValue(4));
                boolean rejected = Boolean.TRUE.equals(entry.getValue(5));
                boolean bypassed = Boolean.TRUE.equals(entry.getValue(6));

                // Trả về true chỉ khi tất cả các trạng thái trên đều là false
                return !scanned && !rejected && !bypassed;
            }
        };
        unscannedSorter.setRowFilter(unscannedStatusFilter);
        JButton unscannedRefreshButton = new JButton("Refresh");
        unscannedRefreshButton.addActionListener(e -> unscannedSorter.setRowFilter(unscannedStatusFilter));
        JPanel unscannedPanel = createApiPanel("Search unscanned paths:", unscannedTable, unscannedRefreshButton,
                (keyword, sorter) -> {
                    RowFilter<Object, Object> textFilter = keyword.isEmpty() ? null
                            : RowFilter.regexFilter("(?i)" + keyword, 2);
                    sorter.setRowFilter(
                            textFilter != null ? RowFilter.andFilter(List.of(unscannedStatusFilter, textFilter))
                                    : unscannedStatusFilter);
                });
        tabs.addTab("Unscanned", unscannedPanel);

        JTable logsTable = createCommonTable();
        setupHiddenColumns(logsTable);
        final TableRowSorter<DefaultTableModel> logsSorter = new TableRowSorter<>(tableModel);
        logsTable.setRowSorter(logsSorter);
        JButton logsRefreshButton = new JButton("Refresh");
        logsRefreshButton.addActionListener(e -> logsSorter.setRowFilter(logsSorter.getRowFilter()));
        JPanel logsPanel = createApiPanel("Search all paths:", logsTable, logsRefreshButton, (keyword, sorter) -> sorter
                .setRowFilter(keyword.isEmpty() ? null : RowFilter.regexFilter("(?i)" + keyword, 2)));
        tabs.addTab("Logs", logsPanel);

        // --- Cài đặt Tab "Settings" ---
        JTextArea extensionArea = new JTextArea(savedExtensions != null ? savedExtensions : ".js,.svg,.css,.png,.jpg");
        JTextField excludeStatusCodesField = new JTextField(savedStatusCodes != null ? savedStatusCodes : "404,405");
        JTextField ipField = new JTextField(savedDbIp != null ? savedDbIp : "127.0.0.1");
        JTextField portField = new JTextField(savedDbPort != null ? savedDbPort : "3306");
        JTextField dbNameField = new JTextField(savedDbName != null ? savedDbName : "036");
        JTextField usernameField = new JTextField(savedDbUsername != null ? savedDbUsername : "root");
        JPasswordField passwordField = new JPasswordField(savedDbPassword != null ? savedDbPassword : "");
        JButton checkConnectionButton = new JButton("Check Connection");

        checkConnectionButton.addActionListener(e -> {
            String ip = ipField.getText().trim();
            String port = portField.getText().trim();
            String dbName = dbNameField.getText().trim();
            String username = usernameField.getText().trim();
            String password = new String(passwordField.getPassword());
            new Thread(() -> {
                boolean isConnected = DatabaseManager.testConnection(ip, port, dbName, username, password);
                SwingUtilities.invokeLater(() -> {
                    if (isConnected)
                        JOptionPane.showMessageDialog(null, "Connection Successful!", "Success",
                                JOptionPane.INFORMATION_MESSAGE);
                    else
                        JOptionPane.showMessageDialog(null, "Connection Failed.", "Error", JOptionPane.ERROR_MESSAGE);
                });
            }).start();
        });

        JCheckBox highlightCheckBox = new JCheckBox("Highlight Scanned/Bypassed requests", highlightEnabled);
        highlightCheckBox.addActionListener(e -> {
            highlightEnabled = highlightCheckBox.isSelected();
            saveSettings();
        });
        JCheckBox noteCheckBox = new JCheckBox("Add Note to Scanned/Bypassed requests", noteEnabled);
        noteCheckBox.addActionListener(e -> {
            noteEnabled = noteCheckBox.isSelected();
            saveSettings();
        });
        JCheckBox autoBypassCheckBox = new JCheckBox("Auto-bypass GET APIs without params", autoBypassNoParamGet);
        autoBypassCheckBox.addActionListener(e -> {
            autoBypassNoParamGet = autoBypassCheckBox.isSelected();
            saveSettings();
        });

        JButton applyButton = new JButton("Apply");
        applyButton.addActionListener(e -> {
            savedExtensions = extensionArea.getText().trim();
            savedStatusCodes = excludeStatusCodesField.getText().trim();
            savedDbIp = ipField.getText().trim();
            savedDbPort = portField.getText().trim();
            savedDbName = dbNameField.getText().trim();
            savedDbUsername = usernameField.getText().trim();
            savedDbPassword = new String(passwordField.getPassword());
            saveSettings();
            databaseManager.initialize(savedDbIp, savedDbPort, savedDbName, savedDbUsername, savedDbPassword);
            loadDataFromDb();
            JOptionPane.showMessageDialog(null, "Settings saved and project loaded.");
        });

        tabs.addTab("Settings", SettingsPanel.create(
                extensionArea, excludeStatusCodesField, ipField, portField, dbNameField,
                usernameField, passwordField, checkConnectionButton, highlightCheckBox,
                noteCheckBox, autoBypassCheckBox, applyButton, totalLbl, scannedLbl,
                rejectedLbl, bypassLbl, unverifiedLbl));

        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(tabs, BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("Recheck Scan", mainPanel);

        loadDataFromDb();
    }

    private void setupHiddenColumns(JTable table) {
        TableColumn repeaterCol = table.getColumnModel().getColumn(7);
        repeaterCol.setMinWidth(0);
        repeaterCol.setMaxWidth(0);
        TableColumn idCol = table.getColumnModel().getColumn(8);
        idCol.setMinWidth(0);
        idCol.setMaxWidth(0);
    }

    private void loadDataFromDb() {
        tableModel.setRowCount(0);
        if (!databaseManager.isConnected()) {
            api.logging().logToError("Database not connected. Cannot load data.");
            updateStats();
            return;
        }
        modelRowToDbId.clear();
        List<Object[]> rows = databaseManager.loadApiData();
        for (int i = 0; i < rows.size(); i++) {
            Object[] rowData = rows.get(i);
            tableModel.addRow(rowData);
            modelRowToDbId.put(i, (Integer) rowData[8]);
        }
        updateStats();
    }

    private boolean isExcludedByExtension(String path) {
        if (savedExtensions == null || savedExtensions.isBlank())
            return false;
        return Arrays.stream(savedExtensions.replace(" ", "").split(","))
                .anyMatch(ext -> !ext.isBlank() && path.toLowerCase().endsWith(ext.trim()));
    }

    private JTable createCommonTable() {
        JTable table = new JTable(tableModel);
        table.setRowHeight(28);
        table.setFillsViewportHeight(true);
        table.getTableHeader().setReorderingAllowed(false);
        table.setDefaultRenderer(Boolean.class, (tbl, value, isSelected, hasFocus, row, col) -> {
            JCheckBox checkBox = new JCheckBox("", Boolean.TRUE.equals(value));
            checkBox.setHorizontalAlignment(SwingConstants.CENTER);
            checkBox.setBackground(isSelected ? tbl.getSelectionBackground() : tbl.getBackground());
            if (col == 4)
                checkBox.setEnabled(false);
            return checkBox;
        });
        table.setDefaultRenderer(String.class, new DefaultTableCellRenderer() {
            public Component getTableCellRendererComponent(JTable tbl, Object val, boolean isSel, boolean hasFoc, int r,
                    int c) {
                Component comp = super.getTableCellRendererComponent(tbl, val, isSel, hasFoc, r, c);
                if (c == 3 && val != null && !val.toString().isEmpty())
                    comp.setForeground(Color.RED);
                else
                    comp.setForeground(isSel ? tbl.getSelectionForeground() : tbl.getForeground());
                return comp;
            }
        });
        table.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke("ctrl C"), "copyPath");
        table.getActionMap().put("copyPath", new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                int[] selRows = table.getSelectedRows();
                if (selRows.length > 0) {
                    StringBuilder sb = new StringBuilder();
                    for (int viewRow : selRows) {
                        Object val = table.getModel().getValueAt(table.convertRowIndexToModel(viewRow), 2);
                        if (val != null)
                            sb.append(val).append("\n");
                    }
                    Toolkit.getDefaultToolkit().getSystemClipboard()
                            .setContents(new StringSelection(sb.toString().trim()), null);
                }
            }
        });
        return table;
    }

    private JPanel createApiPanel(String searchLabel, JTable table, JButton refreshButton, SearchHandler handler) {
        JPanel panel = new JPanel(new BorderLayout(0, 5));
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        JPanel topPanel = new JPanel(new BorderLayout(5, 0));
        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        searchPanel.add(new JLabel(searchLabel));
        JTextField searchField = new JTextField(40);
        searchPanel.add(searchField);
        topPanel.add(searchPanel, BorderLayout.CENTER);
        if (refreshButton != null)
            topPanel.add(refreshButton, BorderLayout.EAST);
        panel.add(topPanel, BorderLayout.NORTH);
        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                filter();
            }

            public void removeUpdate(DocumentEvent e) {
                filter();
            }

            public void changedUpdate(DocumentEvent e) {
                filter();
            }

            private void filter() {
                handler.apply(searchField.getText().trim(), (TableRowSorter<DefaultTableModel>) table.getRowSorter());
            }
        });
        return panel;
    }

    @FunctionalInterface
    interface SearchHandler {
        void apply(String keyword, TableRowSorter<DefaultTableModel> sorter);
    }

    private void saveSettings() {
        try {
            File configFile = new File(System.getProperty("user.home"), "AppData/Local/RecheckScan/scan_api.txt");
            if (!configFile.getParentFile().exists())
                configFile.getParentFile().mkdirs();
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(configFile))) {
                writer.write(str(savedExtensions) + "\n" + highlightEnabled + "\n" + noteEnabled + "\n" +
                        str(savedDbIp) + "\n" + str(savedDbPort) + "\n" + str(savedDbName) + "\n" +
                        str(savedDbUsername) + "\n" + str(savedDbPassword) + "\n" +
                        autoBypassNoParamGet + "\n" + str(savedStatusCodes) + "\n");
            }
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(null, "Failed to save settings: " + ex.getMessage());
        }
    }

    private String str(String s) {
        return s != null ? s : "";
    }

    private void loadSavedSettings() {
        try {
            File configFile = new File(System.getProperty("user.home"), "AppData/Local/RecheckScan/scan_api.txt");
            if (configFile.exists()) {
                List<String> lines = Files.readAllLines(configFile.toPath());
                if (lines.size() > 0)
                    savedExtensions = lines.get(0).trim();
                if (lines.size() > 1)
                    highlightEnabled = Boolean.parseBoolean(lines.get(1).trim());
                if (lines.size() > 2)
                    noteEnabled = Boolean.parseBoolean(lines.get(2).trim());
                if (lines.size() > 3)
                    savedDbIp = lines.get(3).trim();
                if (lines.size() > 4)
                    savedDbPort = lines.get(4).trim();
                if (lines.size() > 5)
                    savedDbName = lines.get(5).trim();
                if (lines.size() > 6)
                    savedDbUsername = lines.get(6).trim();
                if (lines.size() > 7)
                    savedDbPassword = lines.get(7).trim();
                if (lines.size() > 8)
                    autoBypassNoParamGet = Boolean.parseBoolean(lines.get(8).trim());
                if (lines.size() > 9)
                    savedStatusCodes = lines.get(9).trim();
            }
        } catch (IOException e) {
            api.logging().logToError("Failed to load settings: " + e.getMessage());
        }
    }

    private boolean isExcludedStatusCode(int statusCode) {
        if (savedStatusCodes == null || savedStatusCodes.isBlank())
            return false;
        Set<Integer> excludedCodes = new HashSet<>();
        for (String s : savedStatusCodes.split(",")) {
            try {
                excludedCodes.add(Integer.parseInt(s.trim()));
            } catch (NumberFormatException e) {
                /* ignore */ }
        }
        return excludedCodes.contains(statusCode);
    }

    private void updateStats() {
        int total = tableModel.getRowCount();
        int scanned = 0, rejected = 0, bypass = 0;
        for (int i = 0; i < total; i++) {
            if (Boolean.TRUE.equals(tableModel.getValueAt(i, 4)))
                scanned++;
            if (Boolean.TRUE.equals(tableModel.getValueAt(i, 5)))
                rejected++;
            if (Boolean.TRUE.equals(tableModel.getValueAt(i, 6)))
                bypass++;
        }
        totalLbl.setText("Total: " + total);
        scannedLbl.setText("Scanned: " + scanned);
        rejectedLbl.setText("Rejected: " + rejected);
        bypassLbl.setText("Bypass: " + bypass);
        unverifiedLbl.setText("Unverified: " + (total - scanned - rejected - bypass));
    }

    @Override
    public void extensionUnloaded() {
        if (databaseManager != null)
            databaseManager.close();
    }
}