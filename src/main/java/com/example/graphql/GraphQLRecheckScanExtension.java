package com.example.graphql;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Phiên bản GraphQL của "Recheck Scan": theo dõi và đánh dấu trạng thái scan cho từng root field
 * (query/mutation/subscription) thay vì theo (method + path) như bản REST.
 * <p>
 * Vòng đời và tư duy giống hệt bản REST:
 * <ol>
 *     <li>Đăng ký một {@link HttpHandler} để lắng nghe traffic.</li>
 *     <li>Nhận diện request GraphQL, bóc tách root field + argument qua {@link GraphQLParser}.</li>
 *     <li>Request từ Scanner -> chuyển argument sang trạng thái đã-scan.</li>
 *     <li>Request từ Proxy/Repeater -> ghi nhận argument mới (chưa-scan) hoặc auto-bypass.</li>
 *     <li>Hiển thị trên tab riêng với hai bảng: Unscanned và Logs.</li>
 * </ol>
 */
public class GraphQLRecheckScanExtension implements BurpExtension, ExtensionUnloadingHandler {

    private MontoyaApi api;
    private GraphQLDatabaseManager databaseManager;

    // Cài đặt của người dùng.
    private String savedOutputPath;
    private String exclude_status_code;
    private String graphqlEndpoints;
    private boolean highlightEnabled = false;
    private boolean noteEnabled = false;
    private boolean autoBypassNoArgs = true;
    private List<String> compiledEndpoints = new ArrayList<>();

    private DefaultTableModel tableModel;

    // Chỉ số cột của TableModel.
    private static final int COL_OP_TYPE = 0;
    private static final int COL_OP_NAME = 1;
    private static final int COL_FIELD = 2;
    private static final int COL_HOST = 3;
    private static final int COL_ENDPOINT = 4;
    private static final int COL_UNSCANNED = 5;
    private static final int COL_SCANNED = 6;
    private static final int COL_REJECTED = 7;
    private static final int COL_BYPASS = 8;
    private static final int COL_REPEATER = 9;
    private static final int COL_ID = 10;

    private final JLabel totalLbl = new JLabel("Total: 0");
    private final JLabel scannedLbl = new JLabel("Scanned: 0");
    private final JLabel rejectedLbl = new JLabel("Rejected: 0");
    private final JLabel bypassLbl = new JLabel("Bypass: 0");
    private final JLabel unverifiedLbl = new JLabel("Unverified: 0");

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Recheck Scan GraphQL");
        api.extension().registerUnloadingHandler(this);

        loadSavedSettings();
        databaseManager = new GraphQLDatabaseManager(api);
        databaseManager.initialize(savedOutputPath);

        SwingUtilities.invokeLater(this::createUI);

        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                return RequestToBeSentAction.continueWith(request);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                try {
                    handleResponse(response);
                } catch (Exception e) {
                    api.logging().logToError("GraphQL handler error: " + e.getMessage(), e);
                }
                return ResponseReceivedAction.continueWith(response);
            }
        });
    }

    /**
     * Xử lý cốt lõi cho mỗi response.
     */
    private void handleResponse(HttpResponseReceived response) {
        if (isExcludedStatusCode(response.statusCode())) {
            return;
        }

        HttpRequest request = response.initiatingRequest();
        String method = request.method();
        ToolType sourceType = response.toolSource().toolType();

        if ("OPTIONS".equals(method) || sourceType == ToolType.INTRUDER || sourceType == ToolType.EXTENSIONS) {
            return;
        }

        String path = request.pathWithoutQuery();

        // Nếu người dùng cấu hình bộ lọc endpoint, chỉ xử lý request khớp endpoint.
        if (!compiledEndpoints.isEmpty() && !matchesEndpoint(path)) {
            return;
        }

        // Bóc tách toàn bộ query GraphQL + variables trong request (hỗ trợ cả batched array).
        List<QueryUnit> units = extractUnits(request);
        if (units.isEmpty()) {
            return;
        }

        // Parse thành danh sách operation; đồng thời "flatten" variables thành pseudo-argument
        // (vd input -> input.expressionOutput, input.filters[].field) để bắt đúng injection point.
        List<GraphQLOperation> operations = new ArrayList<>();
        for (QueryUnit unit : units) {
            for (GraphQLOperation op : GraphQLParser.parse(unit.query)) {
                Set<String> effectiveArgs = flattenArgs(op, unit.variables);
                operations.add(new GraphQLOperation(op.operationType(), op.operationName(), op.rootField(), effectiveArgs));
            }
        }
        if (operations.isEmpty()) {
            return;
        }

        String host = request.httpService().host();
        final String endpoint = path;

        // Request từ Scanner -> đánh dấu argument đã scan.
        if (sourceType == ToolType.SCANNER) {
            new Thread(() -> {
                boolean updated = false;
                for (GraphQLOperation op : operations) {
                    if (databaseManager.processScannedArgs(host, endpoint, op.operationType(), op.rootField(), op.argumentNames())) {
                        updated = true;
                    }
                }
                if (updated) {
                    SwingUtilities.invokeLater(this::loadDataFromDb);
                }
            }).start();
            return;
        }

        // Request từ công cụ khác (Proxy/Repeater) và nằm trong scope.
        if (!api.scope().isInScope(request.url())) {
            return;
        }

        final boolean fromRepeater = sourceType == ToolType.REPEATER;
        new Thread(() -> {
            boolean updated = false;
            for (GraphQLOperation op : operations) {
                if (fromRepeater && databaseManager.updateRepeaterStatus(host, endpoint, op.operationType(), op.rootField())) {
                    updated = true;
                }
                if (op.argumentNames().isEmpty()) {
                    // Root field không có argument -> ứng viên auto-bypass.
                    if (databaseManager.autoBypass(host, endpoint, op.operationType(), op.operationName(), op.rootField())) {
                        updated = true;
                    }
                } else {
                    databaseManager.insertOrUpdate(host, endpoint, op.operationType(), op.operationName(), op.rootField(), op.argumentNames());
                    updated = true;
                }
            }
            if (updated) {
                SwingUtilities.invokeLater(this::loadDataFromDb);
            }
        }).start();

        // Highlight/note dựa trên trạng thái hiện tại trong DB (best-effort).
        applyAnnotations(response, host, endpoint, operations);
    }

    /**
     * Áp dụng highlight và note cho response nếu mọi operation trong request đều đã scanned/bypassed.
     */
    private void applyAnnotations(HttpResponseReceived response, String host, String endpoint, List<GraphQLOperation> operations) {
        if (!highlightEnabled && !noteEnabled) {
            return;
        }
        boolean anyScanned = false;
        boolean anyBypassed = false;
        boolean anyRejected = false;
        boolean allHandled = true;
        for (GraphQLOperation op : operations) {
            Object[] status = databaseManager.getStatus(host, endpoint, op.operationType(), op.rootField());
            boolean scanned = status != null && (boolean) status[0];
            boolean rejected = status != null && (boolean) status[1];
            boolean bypassed = status != null && (boolean) status[2];
            anyScanned |= scanned;
            anyRejected |= rejected;
            anyBypassed |= bypassed;
            if (!(scanned || bypassed || rejected)) {
                allHandled = false;
            }
        }
        if (highlightEnabled && allHandled && (anyScanned || anyBypassed)) {
            response.annotations().setHighlightColor(HighlightColor.CYAN);
        }
        if (noteEnabled) {
            if (anyScanned) {
                response.annotations().setNotes("GraphQL Scanned");
            } else if (anyBypassed) {
                response.annotations().setNotes("GraphQL Bypassed");
            } else if (anyRejected) {
                response.annotations().setNotes("GraphQL Rejected");
            }
        }
    }

    /** Một đơn vị yêu cầu GraphQL: chuỗi query kèm object variables (có thể null). */
    private static final class QueryUnit {
        final String query;
        final JsonObject variables;

        QueryUnit(String query, JsonObject variables) {
            this.query = query;
            this.variables = variables;
        }
    }

    /**
     * Bóc tách toàn bộ query GraphQL + variables từ một request. Hỗ trợ:
     * <ul>
     *     <li>POST JSON: {@code {"query": "...", "variables": {...}}} hoặc mảng batched.</li>
     *     <li>POST application/graphql: toàn bộ body là query (không có variables).</li>
     *     <li>GET: tham số URL {@code ?query=...&variables=...}.</li>
     * </ul>
     */
    private List<QueryUnit> extractUnits(HttpRequest request) {
        List<QueryUnit> units = new ArrayList<>();
        String method = request.method();

        if ("GET".equalsIgnoreCase(method)) {
            String q = request.parameterValue("query", HttpParameterType.URL);
            if (q != null && !q.isBlank()) {
                JsonObject vars = tryParseVariables(request.parameterValue("variables", HttpParameterType.URL));
                units.add(new QueryUnit(q, vars));
            }
            return units;
        }

        if (request.body().length() == 0) {
            return units;
        }

        String body = request.bodyToString();
        ContentType contentType = request.contentType();

        if (contentType == ContentType.JSON || looksLikeJson(body)) {
            try {
                JsonElement root = JsonParser.parseString(body);
                if (root.isJsonArray()) {
                    for (JsonElement element : root.getAsJsonArray()) {
                        addUnitFromJson(element, units);
                    }
                } else if (root.isJsonObject()) {
                    addUnitFromJson(root, units);
                }
            } catch (Exception ignore) {
                // Body không phải JSON hợp lệ -> bỏ qua.
            }
            return units;
        }

        // application/graphql hoặc body thô: coi cả body là một query, không có variables.
        units.add(new QueryUnit(body, null));
        return units;
    }

    private void addUnitFromJson(JsonElement element, List<QueryUnit> units) {
        if (element == null || !element.isJsonObject()) {
            return;
        }
        JsonObject obj = element.getAsJsonObject();
        if (obj.has("query") && obj.get("query").isJsonPrimitive()) {
            String q = obj.get("query").getAsString();
            if (q != null && !q.isBlank()) {
                JsonObject vars = (obj.has("variables") && obj.get("variables").isJsonObject())
                        ? obj.getAsJsonObject("variables") : null;
                units.add(new QueryUnit(q, vars));
            }
        }
    }

    private JsonObject tryParseVariables(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            JsonElement el = JsonParser.parseString(raw);
            return el.isJsonObject() ? el.getAsJsonObject() : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Tính tập argument "hiệu dụng" của một operation: với argument nào trỏ tới một biến là
     * object/array trong {@code variables}, thay tên argument thô bằng các đường dẫn lá đã flatten
     * (vd {@code input} -> {@code input.expressionOutput}, {@code input.filters[].field}). Nhờ đó
     * các injection point nằm sâu trong input object không bị bỏ sót.
     */
    private Set<String> flattenArgs(GraphQLOperation op, JsonObject variables) {
        Set<String> result = new TreeSet<>();
        Map<String, String> argVars = op.argumentVariables();
        for (String arg : op.argumentNames()) {
            String varName = argVars.get(arg);
            if (varName != null && variables != null && variables.has(varName)) {
                JsonElement value = variables.get(varName);
                if (value != null && (value.isJsonObject() || value.isJsonArray())) {
                    Set<String> leaves = new TreeSet<>();
                    flattenJson(value, arg, leaves, 0);
                    if (!leaves.isEmpty()) {
                        result.addAll(leaves);
                        continue; // thay argument thô bằng các leaf cụ thể.
                    }
                }
            }
            result.add(arg); // biến scalar, giá trị inline, hoặc không có variables -> giữ tên arg.
        }
        return result;
    }

    /** Flatten một JsonElement thành các đường dẫn lá; mảng dùng ký hiệu {@code []} để gộp index. */
    private void flattenJson(JsonElement el, String prefix, Set<String> out, int depth) {
        if (out.size() >= 500 || depth > 12) {
            out.add(prefix);
            return;
        }
        if (el == null || el.isJsonNull()) {
            out.add(prefix);
        } else if (el.isJsonObject()) {
            JsonObject obj = el.getAsJsonObject();
            if (obj.size() == 0) {
                out.add(prefix);
                return;
            }
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                flattenJson(entry.getValue(), prefix + "." + entry.getKey(), out, depth + 1);
            }
        } else if (el.isJsonArray()) {
            JsonArray arr = el.getAsJsonArray();
            if (arr.size() == 0) {
                out.add(prefix + "[]");
                return;
            }
            for (JsonElement child : arr) {
                flattenJson(child, prefix + "[]", out, depth + 1);
            }
        } else {
            out.add(prefix); // primitive leaf (string/number/bool)
        }
    }

    private boolean looksLikeJson(String body) {
        if (body == null) {
            return false;
        }
        String trimmed = body.trim();
        return trimmed.startsWith("{") || trimmed.startsWith("[");
    }

    private boolean matchesEndpoint(String path) {
        if (path == null) {
            return false;
        }
        String lower = path.toLowerCase(Locale.ROOT);
        for (String ep : compiledEndpoints) {
            if (!ep.isEmpty() && lower.contains(ep)) {
                return true;
            }
        }
        return false;
    }

    private List<String> compileEndpoints(String raw) {
        List<String> list = new ArrayList<>();
        if (raw == null || raw.isBlank()) {
            return list;
        }
        for (String part : raw.split("[,\\r\\n]+")) {
            String p = part.trim().toLowerCase(Locale.ROOT);
            if (!p.isEmpty()) {
                list.add(p);
            }
        }
        return list;
    }

    // ===================================================================================
    // UI
    // ===================================================================================

    private void createUI() {
        tableModel = new DefaultTableModel(
                new Object[]{"Operation", "Name", "Field", "Host", "Endpoint", "Unscanned Args",
                        "Scanned", "Rejected", "Bypass", "Repeater", "id"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                boolean isScanned = Boolean.TRUE.equals(getValueAt(row, COL_SCANNED));
                if (isScanned) {
                    return false;
                }
                if (column == COL_REJECTED) {
                    return Boolean.TRUE.equals(getValueAt(row, COL_REPEATER));
                }
                return column == COL_BYPASS;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex >= COL_SCANNED && columnIndex <= COL_REPEATER) {
                    return Boolean.class;
                }
                if (columnIndex == COL_ID) {
                    return Integer.class;
                }
                return String.class;
            }

            @Override
            public void setValueAt(Object aValue, int row, int col) {
                super.setValueAt(aValue, row, col);
                if (col == COL_REJECTED || col == COL_BYPASS) {
                    Integer id = (Integer) getValueAt(row, COL_ID);
                    if (id == null) {
                        return;
                    }
                    if (Boolean.TRUE.equals(aValue)) {
                        // Chỉ một trong (rejected, bypass) được bật tại một thời điểm.
                        for (int i = COL_REJECTED; i <= COL_BYPASS; i++) {
                            boolean checked = (i == col);
                            if (!checked) {
                                super.setValueAt(false, row, i);
                            }
                            final int columnIndex = i;
                            new Thread(() -> {
                                String dbColumn = switch (columnIndex) {
                                    case COL_REJECTED -> "is_rejected";
                                    case COL_BYPASS -> "is_bypassed";
                                    default -> null;
                                };
                                if (dbColumn != null) {
                                    databaseManager.updateStatus(id, dbColumn, checked);
                                }
                            }).start();
                        }
                    } else {
                        String dbColumn = switch (col) {
                            case COL_REJECTED -> "is_rejected";
                            case COL_BYPASS -> "is_bypassed";
                            default -> null;
                        };
                        if (dbColumn != null) {
                            new Thread(() -> databaseManager.updateStatus(id, dbColumn, false)).start();
                        }
                    }
                }
                updateStats();
            }
        };

        JTabbedPane tabs = new JTabbedPane();

        // --- Tab Unscanned ---
        JTable unscannedTable = createCommonTable();
        setupHiddenColumns(unscannedTable);
        final TableRowSorter<DefaultTableModel> unscannedSorter = new TableRowSorter<>(tableModel);
        unscannedTable.setRowSorter(unscannedSorter);
        final RowFilter<Object, Object> unscannedStatusFilter = new RowFilter<>() {
            public boolean include(Entry<?, ?> entry) {
                boolean scanned = Boolean.TRUE.equals(entry.getValue(COL_SCANNED));
                boolean rejected = Boolean.TRUE.equals(entry.getValue(COL_REJECTED));
                boolean bypass = Boolean.TRUE.equals(entry.getValue(COL_BYPASS));
                return !scanned && !rejected && !bypass;
            }
        };
        unscannedSorter.setRowFilter(unscannedStatusFilter);
        JButton unscannedRefresh = new JButton("Refresh");
        unscannedRefresh.addActionListener(e -> unscannedSorter.setRowFilter(unscannedStatusFilter));
        JPanel unscannedPanel = createApiPanel("Search unscanned fields:", unscannedTable, unscannedRefresh, (keyword, sorter) -> {
            RowFilter<Object, Object> textFilter = keyword.isEmpty() ? null : RowFilter.regexFilter("(?i)" + keyword, COL_FIELD);
            sorter.setRowFilter(textFilter != null ? RowFilter.andFilter(Arrays.asList(unscannedStatusFilter, textFilter)) : unscannedStatusFilter);
        });
        tabs.addTab("Unscanned", unscannedPanel);

        // --- Tab Logs ---
        JTable logsTable = createCommonTable();
        setupHiddenColumns(logsTable);
        final TableRowSorter<DefaultTableModel> logsSorter = new TableRowSorter<>(tableModel);
        logsTable.setRowSorter(logsSorter);
        JButton logsRefresh = new JButton("Refresh");
        logsRefresh.addActionListener(e -> logsSorter.setRowFilter(logsSorter.getRowFilter()));
        JPanel logsPanel = createApiPanel("Search all fields:", logsTable, logsRefresh, (keyword, sorter) ->
                sorter.setRowFilter(keyword.isEmpty() ? null : RowFilter.regexFilter("(?i)" + keyword, COL_FIELD)));
        tabs.addTab("Logs", logsPanel);

        // --- Tab Settings ---
        JTextField outputPathField = new JTextField(savedOutputPath != null ? savedOutputPath : "");
        JTextField excludeStatusCodesField = new JTextField(exclude_status_code != null ? exclude_status_code : "404,405");
        JTextArea endpointsArea = new JTextArea(graphqlEndpoints != null ? graphqlEndpoints : "/graphql");
        JButton browseButton = new JButton("Browse");
        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
            if (fileChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
                outputPathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });
        JCheckBox highlightCheckBox = new JCheckBox("Highlight fully Scanned/Bypassed GraphQL requests in Proxy history", highlightEnabled);
        highlightCheckBox.addActionListener(e -> {
            highlightEnabled = highlightCheckBox.isSelected();
            saveSettings();
        });
        JCheckBox noteCheckBox = new JCheckBox("Add Note to Scanned/Bypassed GraphQL requests in Proxy history", noteEnabled);
        noteCheckBox.addActionListener(e -> {
            noteEnabled = noteCheckBox.isSelected();
            saveSettings();
        });
        JCheckBox autoBypassCheckBox = new JCheckBox("Auto-bypass fields without arguments", autoBypassNoArgs);
        autoBypassCheckBox.addActionListener(e -> {
            autoBypassNoArgs = autoBypassCheckBox.isSelected();
            saveSettings();
        });
        JButton applyButton = new JButton("Apply");
        applyButton.addActionListener(e -> {
            savedOutputPath = outputPathField.getText().trim();
            exclude_status_code = excludeStatusCodesField.getText().trim();
            graphqlEndpoints = endpointsArea.getText().trim();
            compiledEndpoints = compileEndpoints(graphqlEndpoints);
            autoBypassNoArgs = autoBypassCheckBox.isSelected();
            saveSettings();

            databaseManager.close();
            databaseManager.initialize(savedOutputPath);

            if (autoBypassNoArgs) {
                new Thread(() -> {
                    databaseManager.applyAutoBypassToOldRecords();
                    SwingUtilities.invokeLater(this::loadDataFromDb);
                }).start();
            } else {
                loadDataFromDb();
            }
            JOptionPane.showMessageDialog(null, "GraphQL settings applied and project reloaded from database.");
        });
        tabs.addTab("Settings", GraphQLSettingsPanel.create(outputPathField, browseButton, excludeStatusCodesField,
                endpointsArea, highlightCheckBox, noteCheckBox, autoBypassCheckBox, applyButton,
                totalLbl, scannedLbl, rejectedLbl, bypassLbl, unverifiedLbl));

        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(tabs, BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("Recheck Scan GraphQL", mainPanel);

        loadDataFromDb();
    }

    private void setupHiddenColumns(JTable table) {
        for (int col : new int[]{COL_REPEATER, COL_ID}) {
            TableColumn column = table.getColumnModel().getColumn(col);
            column.setMinWidth(0);
            column.setMaxWidth(0);
            column.setWidth(0);
        }
    }

    private void loadDataFromDb() {
        tableModel.setRowCount(0);
        for (Object[] row : databaseManager.loadData()) {
            tableModel.addRow(row);
        }
        updateStats();
    }

    private JTable createCommonTable() {
        JTable table = new JTable(tableModel);
        table.setRowHeight(28);
        table.setFillsViewportHeight(true);
        table.getTableHeader().setReorderingAllowed(false);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        table.setDefaultRenderer(Boolean.class, (tbl, value, isSelected, hasFocus, row, column) -> {
            JCheckBox checkBox = new JCheckBox();
            checkBox.setSelected(Boolean.TRUE.equals(value));
            checkBox.setHorizontalAlignment(SwingConstants.CENTER);
            checkBox.setOpaque(true);
            checkBox.setBackground(isSelected ? tbl.getSelectionBackground() : tbl.getBackground());
            if (column == COL_SCANNED) {
                checkBox.setEnabled(false);
            }
            return checkBox;
        });

        table.setDefaultRenderer(String.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (column == COL_UNSCANNED && value != null && !((String) value).isEmpty()) {
                    c.setForeground(Color.RED);
                } else {
                    c.setForeground(isSelected ? table.getSelectionForeground() : table.getForeground());
                }
                return c;
            }
        });

        // Ctrl+C: copy "operationType field".
        table.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke("ctrl C"), "copyField");
        table.getActionMap().put("copyField", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = table.getSelectedRows();
                if (selectedRows.length == 0) {
                    return;
                }
                StringBuilder sb = new StringBuilder();
                for (int viewRow : selectedRows) {
                    int modelRow = table.convertRowIndexToModel(viewRow);
                    Object opType = tableModel.getValueAt(modelRow, COL_OP_TYPE);
                    Object field = tableModel.getValueAt(modelRow, COL_FIELD);
                    if (field != null) {
                        sb.append(opType).append(" ").append(field).append("\n");
                    }
                }
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString().trim()), null);
            }
        });

        JPopupMenu contextMenu = new JPopupMenu();
        JMenuItem copyItem = new JMenuItem("Copy Operation List");
        copyItem.addActionListener(e -> {
            int[] selectedRows = table.getSelectedRows();
            if (selectedRows.length == 0) {
                return;
            }
            StringBuilder sb = new StringBuilder();
            for (int viewRow : selectedRows) {
                int modelRow = table.convertRowIndexToModel(viewRow);
                String opType = (String) tableModel.getValueAt(modelRow, COL_OP_TYPE);
                String field = (String) tableModel.getValueAt(modelRow, COL_FIELD);
                Integer id = (Integer) tableModel.getValueAt(modelRow, COL_ID);
                if (opType != null && field != null && id != null) {
                    Set<String> args = databaseManager.getAllArgsById(id);
                    sb.append(opType).append(" ").append(field);
                    if (!args.isEmpty()) {
                        sb.append(" - args: ").append(args.stream().sorted().collect(Collectors.joining(", ")));
                    }
                    sb.append("\n");
                }
            }
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(sb.toString().trim()), null);
        });
        contextMenu.add(copyItem);

        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                showMenu(e);
            }

            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                showMenu(e);
            }

            private void showMenu(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int row = table.rowAtPoint(e.getPoint());
                    if (row >= 0 && !table.isRowSelected(row)) {
                        table.setRowSelectionInterval(row, row);
                    }
                    contextMenu.show(table, e.getX(), e.getY());
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
        JTextField searchField = new JTextField();
        searchField.setPreferredSize(new Dimension(400, 28));
        searchPanel.add(searchField);
        topPanel.add(searchPanel, BorderLayout.CENTER);
        if (refreshButton != null) {
            topPanel.add(refreshButton, BorderLayout.EAST);
        }
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

    private void updateStats() {
        int total = tableModel.getRowCount();
        int scanned = 0, rejected = 0, bypass = 0;
        for (int i = 0; i < total; i++) {
            if (Boolean.TRUE.equals(tableModel.getValueAt(i, COL_SCANNED))) scanned++;
            if (Boolean.TRUE.equals(tableModel.getValueAt(i, COL_REJECTED))) rejected++;
            if (Boolean.TRUE.equals(tableModel.getValueAt(i, COL_BYPASS))) bypass++;
        }
        totalLbl.setText("Total: " + total);
        scannedLbl.setText("Scanned: " + scanned);
        rejectedLbl.setText("Rejected: " + rejected);
        bypassLbl.setText("Bypass: " + bypass);
        unverifiedLbl.setText("Unverified: " + (total - scanned - rejected - bypass));
    }

    // ===================================================================================
    // Settings persistence
    // ===================================================================================

    private void saveSettings() {
        try {
            Properties props = new Properties();
            String settingsStr = api.persistence().extensionData().getString("graphql_settings");
            if (settingsStr != null && !settingsStr.isEmpty()) {
                props.load(new StringReader(settingsStr));
            }
            props.setProperty("highlightEnabled", String.valueOf(highlightEnabled));
            props.setProperty("noteEnabled", String.valueOf(noteEnabled));
            props.setProperty(currentOutputPathKey(), valueOrEmpty(savedOutputPath));
            props.setProperty("autoBypassNoArgs", String.valueOf(autoBypassNoArgs));
            props.setProperty("exclude_status_code", valueOrEmpty(exclude_status_code));
            props.setProperty("graphql_endpoints", valueOrEmpty(graphqlEndpoints));

            StringWriter writer = new StringWriter();
            props.store(writer, null);
            api.persistence().extensionData().setString("graphql_settings", writer.toString());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(null, "Failed to save GraphQL settings: " + ex.getMessage());
        }
    }

    private String valueOrEmpty(String value) {
        return value == null ? "" : value;
    }

    private String currentOutputPathKey() {
        String osName = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (osName.contains("win")) {
            return "outputPath.windows";
        }
        if (osName.contains("linux")) {
            return "outputPath.linux";
        }
        if (osName.contains("mac")) {
            return "outputPath.mac";
        }
        return "outputPath.other";
    }

    private void loadSavedSettings() {
        try {
            String settingsStr = api.persistence().extensionData().getString("graphql_settings");
            if (settingsStr != null && !settingsStr.isEmpty()) {
                Properties props = new Properties();
                props.load(new StringReader(settingsStr));
                highlightEnabled = Boolean.parseBoolean(props.getProperty("highlightEnabled", "false"));
                noteEnabled = Boolean.parseBoolean(props.getProperty("noteEnabled", "false"));
                savedOutputPath = props.getProperty(currentOutputPathKey(), "");
                autoBypassNoArgs = Boolean.parseBoolean(props.getProperty("autoBypassNoArgs", "true"));
                exclude_status_code = props.getProperty("exclude_status_code", "");
                graphqlEndpoints = props.getProperty("graphql_endpoints", "");
            }
            if (graphqlEndpoints == null) {
                graphqlEndpoints = "";
            }
            compiledEndpoints = compileEndpoints(graphqlEndpoints);
        } catch (Exception e) {
            api.logging().logToError("Failed to load GraphQL settings: " + e.getMessage(), e);
        }
    }

    private boolean isExcludedStatusCode(int statusCode) {
        if (exclude_status_code == null || exclude_status_code.isBlank()) {
            return false;
        }
        for (String s : exclude_status_code.split(",")) {
            try {
                if (Integer.parseInt(s.trim()) == statusCode) {
                    return true;
                }
            } catch (NumberFormatException ignore) {
            }
        }
        return false;
    }

    @Override
    public void extensionUnloaded() {
        databaseManager.close();
    }
}
