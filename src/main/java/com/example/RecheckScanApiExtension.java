package com.example;

import burp.api.montoya.*;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.params.*;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.*;
import java.util.List;
import java.util.Properties;

/**
 * Lớp chính của extension "Recheck Scan API".
 * <p>
 * Lớp này thực hiện các nhiệm vụ chính:
 * 1. Khởi tạo giao diện người dùng (một tab mới trong Burp Suite).
 * 2. Đăng ký một {@link HttpHandler} để lắng nghe và xử lý tất cả các request/response.
 * 3. Tương tác với {@link DatabaseManager} để lưu trữ và truy xuất dữ liệu API.
 * 4. Quản lý trạng thái và cài đặt của người dùng.
 */
public class RecheckScanApiExtension implements BurpExtension, ExtensionUnloadingHandler {
    /**
     * Đối tượng API chính của Montoya, cung cấp quyền truy cập vào các chức năng cốt lõi của Burp.
     */
    private MontoyaApi api;
    /**
     * Đối tượng quản lý cơ sở dữ liệu, đóng gói tất cả các thao tác với SQLite.
     */
    private DatabaseManager databaseManager;

    // Các biến lưu trữ cài đặt của người dùng, được tải từ tệp cấu hình.
    private String exclude_extensions;
    private String savedOutputPath;
    private String exclude_status_code;
    private boolean highlightEnabled = false;
    private boolean noteEnabled = false;
    private boolean autoBypassNoParam = false;

    /**
     * Model cho JTable, chứa dữ liệu API được hiển thị trên giao diện.
     */
    private DefaultTableModel tableModel;
    /**
     * Một Map quan trọng để ánh xạ chỉ số dòng hiển thị trên JTable (có thể thay đổi do sắp xếp)
     * sang ID duy nhất trong cơ sở dữ liệu (không đổi).
     * Điều này đảm bảo việc cập nhật trạng thái luôn đúng dòng.
     */
    private final Map<Integer, Integer> modelRowToDbId = new HashMap<>();

    // Các nhãn (JLabel) để hiển thị thống kê trên tab Settings.
    private final JLabel totalLbl = new JLabel("Total: 0");
    private final JLabel scannedLbl = new JLabel("Scanned: 0");
    private final JLabel rejectedLbl = new JLabel("Rejected: 0");
    private final JLabel bypassLbl = new JLabel("Bypass: 0");
    private final JLabel unverifiedLbl = new JLabel("Unverified: 0");

    /**
     * Phương thức chính được Burp gọi khi extension được tải.
     *
     * @param api Đối tượng MontoyaApi do Burp cung cấp.
     */
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Recheck Scan API (v2)");
        // Đăng ký handler để dọn dẹp tài nguyên (đóng kết nối CSDL) khi extension bị gỡ.
        api.extension().registerUnloadingHandler(this);

        // Tải các cài đặt đã lưu từ tệp.
        loadSavedSettings();
        // Khởi tạo trình quản lý CSDL.
        databaseManager = new DatabaseManager(api);
        databaseManager.initialize(savedOutputPath);

        // Tạo giao diện người dùng trên luồng Event Dispatch Thread (EDT) của Swing để đảm bảo an toàn luồng.
        SwingUtilities.invokeLater(this::createUI);

        // Đăng ký HttpHandler để xử lý các request/response đi qua Burp.
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
                // Không cần xử lý request trước khi gửi đi, cho qua.
                return RequestToBeSentAction.continueWith(request);
            }

            /**
             * Xử lý mỗi response HTTP mà Burp nhận được. Đây là nơi logic cốt lõi được thực thi.
             */
            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
                // Lọc bỏ các API trả về status code bị loại trừ.
                if (isExcludedStatusCode(response.statusCode())) {
                    return ResponseReceivedAction.continueWith(response);
                }

                HttpRequest request = response.initiatingRequest();
                String method = request.method();
                ToolType sourceType = response.toolSource().toolType();

                // Lọc bỏ các request không cần thiết (OPTIONS, Intruder, các extension khác).
                if (method.equals("OPTIONS") || sourceType == ToolType.INTRUDER || sourceType == ToolType.EXTENSIONS) {
                    return ResponseReceivedAction.continueWith(response);
                }

                String host = request.httpService().host();
                String path = request.pathWithoutQuery();
                
                // Trích xuất tất cả tham số từ cả URL và body.
                Set<String> requestParams = extractParameters(request);
                
                // Trường hợp 1: Request từ Scanner -> xử lý các tham số đã được quét.
                if (sourceType == ToolType.SCANNER) {
                    new Thread(() -> {
                        boolean updated = databaseManager.processScannedParameters(method, host, path, requestParams);
                        // Nếu CSDL có thay đổi, tải lại dữ liệu trên giao diện.
                        if (updated) {
                            SwingUtilities.invokeLater(RecheckScanApiExtension.this::loadDataFromDb);
                        }
                    }).start();
                } 
                // Trường hợp 2: Request từ các công cụ khác (Proxy, Repeater) và nằm trong scope.
                else if (api.scope().isInScope(request.url()) && !isExcludedByExtension(path)) {
                    // Nếu request từ Repeater, đánh dấu vào DB.
                    if (sourceType == ToolType.REPEATER) {
                        new Thread(() -> {
                            boolean updated = databaseManager.updateRepeaterStatus(method, host, path);
                            // Tải lại dữ liệu nếu trạng thái 'is_from_repeater' vừa được cập nhật.
                            if (updated) {
                                SwingUtilities.invokeLater(RecheckScanApiExtension.this::loadDataFromDb);
                            }
                        }).start();
                    }

                    // Nhánh 2a: Tự động bypass cho API không có tham số.
                    if (requestParams.isEmpty()) {
                        new Thread(() -> {
                            boolean updated = databaseManager.autoBypassApi(method, host, path);
                            if (updated) {
                                SwingUtilities.invokeLater(RecheckScanApiExtension.this::loadDataFromDb);
                            }
                        }).start();
                         // Thêm highlight/note ngay lập tức cho request này.
                         if (highlightEnabled) response.annotations().setHighlightColor(HighlightColor.YELLOW);
                         if (noteEnabled) response.annotations().setNotes("Bypassed");
                    } else {
                        // Nhánh 2b: Xử lý request thông thường để tìm và ghi nhận tham số mới.
                        new Thread(() -> {
                            databaseManager.insertOrUpdateApi(method, host, path, requestParams);
                            // Tải lại UI để phản ánh thay đổi (nếu có param mới được thêm).
                            SwingUtilities.invokeLater(RecheckScanApiExtension.this::loadDataFromDb);
                        }).start();
                    }
                    // Luôn kiểm tra trạng thái cuối cùng trong CSDL để áp dụng highlight và note.
                    Object[] status = databaseManager.getApiStatus(method, host, path);
                    if (status != null) {
                        boolean isScanned = (boolean) status[0];
                        boolean isBypassed = (boolean) status[2];

                        if (highlightEnabled && (isScanned || isBypassed)) {
                            response.annotations().setHighlightColor(HighlightColor.YELLOW);
                        }
                        if (noteEnabled) {
                            if (isScanned) {
                                response.annotations().setNotes("Scanned");
                            } else if (isBypassed) {
                                response.annotations().setNotes("Bypassed");
                            }
                        }
                    }
                }

                return ResponseReceivedAction.continueWith(response);
            }
        });
    }

    /**
     * Trích xuất tham số từ cả URL (query string) và body của request.
     * <p>
     * Phương thức này hợp nhất tham số từ hai nguồn vào một Set duy nhất.
     * Nó sử dụng các parser tích hợp của Montoya API để xử lý các định dạng phổ biến.
     *
     * @param request HttpRequest cần phân tích.
     * @return một Set chứa tên của tất cả các tham số.
     */
    private Set<String> extractParameters(HttpRequest request) {

        Set<String> allParamNames = new HashSet<>();

        // 1. Lấy tham số từ URL (query string)
        List<ParsedHttpParameter> urlParams = request.parameters(HttpParameterType.URL);
        if (urlParams != null && !urlParams.isEmpty()) {
            urlParams.stream()
                    .map(ParsedHttpParameter::name)
                    .forEach(allParamNames::add);
        }

        // 2. Lấy tham số từ Body nếu có
        if (request.body().length() > 0) {
            ContentType contentType = request.contentType();
            
            List<ParsedHttpParameter> bodyParams = null;

            switch (contentType) {
                case JSON:
                    bodyParams = request.parameters(HttpParameterType.JSON);
                    break;
                case URL_ENCODED:
                    bodyParams = request.parameters(HttpParameterType.BODY);
                    break;
                case MULTIPART:
                     bodyParams = request.parameters(HttpParameterType.BODY);
                     break;
                case XML:
                     bodyParams = request.parameters(HttpParameterType.XML);
                     break;
                default:
                    break;
            }

            if (bodyParams != null && !bodyParams.isEmpty()) {
                bodyParams.stream()
                        .map(ParsedHttpParameter::name)
                        .forEach(allParamNames::add);
            }
        }

        return allParamNames;
    }


    /**
     * Cập nhật một dòng đã có hoặc chèn một dòng mới vào JTable.
     * @param rowData Dữ liệu trả về từ DatabaseManager, bao gồm cả ID.
     */
    private void updateOrInsertTableRow(Object[] rowData) {
        int dbId = (int) rowData[8]; // Index của ID
        Integer modelRowIndex = findModelRowByDbId(dbId);

        if (modelRowIndex != null) { // API này đã tồn tại trên bảng -> cập nhật.
            tableModel.setValueAt(rowData[3], modelRowIndex, 3); // Cập nhật cột Unscanned Params.
            tableModel.setValueAt(rowData[4], modelRowIndex, 4); // Cập nhật cột Scanned.
            tableModel.setValueAt(rowData[5], modelRowIndex, 5); // Cập nhật cột Rejected
            tableModel.setValueAt(rowData[6], modelRowIndex, 6); // Cập nhật cột Bypass
            tableModel.setValueAt(rowData[7], modelRowIndex, 7); // Cập nhật cột Repeater
        } else { // API mới -> chèn vào đầu bảng.
            tableModel.insertRow(0, rowData);
            // Sau khi chèn, phải cập nhật lại toàn bộ map ánh xạ.
            remapAllIndices();
        }
        updateStats();
    }

    /**
     * Tìm chỉ số dòng trong TableModel (dữ liệu hiển thị) dựa trên ID trong CSDL.
     * @param dbId ID duy nhất của dòng trong CSDL.
     * @return Chỉ số dòng trên JTable, hoặc null nếu không tìm thấy.
     */
    private Integer findModelRowByDbId(int dbId) {
        return modelRowToDbId.entrySet().stream()
                .filter(entry -> entry.getValue().equals(dbId))
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse(null);
    }

    /**
     * Ánh xạ lại toàn bộ chỉ số dòng trên JTable với ID trong CSDL.
     * Cần được gọi mỗi khi có sự thay đổi về cấu trúc bảng (thêm/xóa dòng).
     */
    private void remapAllIndices() {
        modelRowToDbId.clear();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            Integer id = (Integer) tableModel.getValueAt(i, 8); // Index của ID
            if (id != null) {
                modelRowToDbId.put(i, id);
            }
        }
    }

    /**
     * Khởi tạo toàn bộ giao diện người dùng của extension.
     */
    private void createUI() {
        // Khởi tạo TableModel với các cột
        // Thứ tự rất quan trọng: Method, Host, Path, Unscanned, Scanned, Rejected, Bypass, Repeater(ẩn), id(ẩn)
        tableModel = new DefaultTableModel(new Object[]{"Method", "Host", "Path", "Unscanned Params", "Scanned", "Rejected", "Bypass", "Repeater", "id"}, 0) {
            /**
             * Sửa đổi logic cho phép chỉnh sửa ô.
             * - "Rejected": Chỉ có thể sửa nếu API chưa "Scanned" VÀ đã được gửi từ "Repeater".
             * - "Bypass": Có thể sửa nếu API chưa "Scanned".
             * - Các cột khác không thể sửa trực tiếp trên bảng.
             */
            @Override
            public boolean isCellEditable(int row, int column) {
                boolean isScanned = Boolean.TRUE.equals(getValueAt(row, 4));
                // Nếu đã được quét, không cho phép chỉnh sửa bất kỳ trạng thái nào.
                if (isScanned) {
                    return false;
                }

                // Logic cho cột "Rejected" (index 5)
                if (column == 5) {
                    // Lấy trạng thái từ cột "Repeater" (index 7)
                    boolean isFromRepeater = Boolean.TRUE.equals(getValueAt(row, 7));
                    return isFromRepeater; // Chỉ cho phép sửa nếu `isFromRepeater` là true.
                }

                // Logic cho cột "Bypass" (index 6)
                if (column == 6) {
                    return true;
                }

                return false;
            }

            /**
             * Định nghĩa kiểu dữ liệu cho các cột để JTable có thể render đúng.
             */
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex >= 4 && columnIndex <= 7) return Boolean.class; // Các cột trạng thái (Scanned, Rejected, Bypass, Repeater)
                if (columnIndex == 8) return Integer.class; // Cột ID
                return String.class;
            }

            /**
             * Ghi đè phương thức này để xử lý sự kiện người dùng tick vào các checkbox.
             * Khi một checkbox được tick, trạng thái tương ứng sẽ được cập nhật vào CSDL.
             */
            @Override
            public void setValueAt(Object aValue, int row, int col) {
                // Tạm thời bỏ qua việc cập nhật UI từ chính logic bên trong (tránh lặp vô hạn).
                if (!(Thread.currentThread().getStackTrace()[2].getMethodName().equals("updateOrInsertTableRow"))) {
                    super.setValueAt(aValue, row, col); // Cập nhật giá trị trên UI trước.
                } else {
                     super.setValueAt(aValue, row, col);
                     return;
                }

                // Chỉ xử lý các cột checkbox trạng thái.
                if (col == 5 || col == 6) {
                    Integer id = (Integer) getValueAt(row, 8); // Lấy ID của dòng từ cột ẩn.
                    if (id != null) {
                        // Logic đảm bảo chỉ 1 trong 3 checkbox (Scanned, Rejected, Bypassed) được chọn tại một thời điểm.
                        if (Boolean.TRUE.equals(aValue)) {
                            for (int i = 5; i <= 6; i++) {
                                final boolean isChecked = (i == col);
                                if (!isChecked) {
                                    super.setValueAt(false, row, i); // Bỏ tick các ô khác trên UI.
                                }
                                // Cập nhật CSDL trong một luồng riêng.
                                final int finalI = i;
                                new Thread(() -> {
                                    String dbColumn = switch (finalI) {
                                        case 4 -> "is_scanned";
                                        case 5 -> "is_rejected";
                                        case 6 -> "is_bypassed";
                                        default -> null;
                                    };
                                    if (dbColumn != null) {
                                        databaseManager.updateApiStatus(id, dbColumn, isChecked);
                                    }
                                }).start();
                            }
                        } else {
                             // Nếu người dùng bỏ tick một ô, cập nhật trạng thái đó trong CSDL.
                            String dbColumn = switch (col) {
                                case 5 -> "is_rejected";
                                case 6 -> "is_bypassed";
                                default -> null;
                            };
                             if (dbColumn != null) {
                                 new Thread(() -> databaseManager.updateApiStatus(id, dbColumn, false)).start();
                             }
                        }
                    }
                }
                updateStats(); // Cập nhật các nhãn thống kê.
            }
        };

        // Bố cục chính của tab extension.
        JTabbedPane tabs = new JTabbedPane();

        // --- Cài đặt Tab "Unscanned" ---
        JTable unscannedTable = createCommonTable();
        setupHiddenColumns(unscannedTable); // Ẩn các cột cần thiết (Repeater, id)
        final TableRowSorter<DefaultTableModel> unscannedSorter = new TableRowSorter<>(tableModel);
        unscannedTable.setRowSorter(unscannedSorter);

        // Tạo bộ lọc để chỉ hiển thị các dòng chưa có trạng thái nào (unscanned, unrejected, unbypassed).
        final RowFilter<Object, Object> unscannedStatusFilter = new RowFilter<>() {
            public boolean include(Entry<?, ?> entry) {
                boolean scanned = Boolean.TRUE.equals(entry.getValue(4));
                boolean rejected = Boolean.TRUE.equals(entry.getValue(5));
                boolean bypass = Boolean.TRUE.equals(entry.getValue(6));
                return !scanned && !rejected && !bypass;
            }
        };
        unscannedSorter.setRowFilter(unscannedStatusFilter);
        JButton unscannedRefreshButton = new JButton("Refresh");
        unscannedRefreshButton.addActionListener(e -> unscannedSorter.setRowFilter(unscannedStatusFilter));
        JPanel unscannedPanel = createApiPanel("Search unscanned paths:", unscannedTable, unscannedRefreshButton, (keyword, sorter) -> {
            RowFilter<Object, Object> textFilter = keyword.isEmpty() ? null : RowFilter.regexFilter("(?i)" + keyword, 2);
            sorter.setRowFilter(textFilter != null ? RowFilter.andFilter(Arrays.asList(unscannedStatusFilter, textFilter)) : unscannedStatusFilter);
        });
        tabs.addTab("Unscanned", unscannedPanel);

        // --- Cài đặt Tab "Logs" ---
        JTable logsTable = createCommonTable();
        setupHiddenColumns(logsTable); // Ẩn các cột cần thiết (Repeater, id)
        final TableRowSorter<DefaultTableModel> logsSorter = new TableRowSorter<>(tableModel);
        logsTable.setRowSorter(logsSorter);
        JButton logsRefreshButton = new JButton("Refresh");
        logsRefreshButton.addActionListener(e -> logsSorter.setRowFilter(logsSorter.getRowFilter()));
        JPanel logsPanel = createApiPanel("Search all paths:", logsTable, logsRefreshButton, (keyword, sorter) -> {
            sorter.setRowFilter(keyword.isEmpty() ? null : RowFilter.regexFilter("(?i)" + keyword, 2));
        });
        tabs.addTab("Logs", logsPanel);

        // --- Cài đặt Tab "Settings" ---
        JTextArea extensionArea = new JTextArea(exclude_extensions != null ? exclude_extensions : ".js,.svg,.css,.png,.jpg,.ttf,.ico,.html,.map,.gif,.woff2,.bcmap,.jpeg,.woff");
        JTextField outputPathField = new JTextField(savedOutputPath != null ? savedOutputPath : "");
        JTextField excludeStatusCodesField = new JTextField(exclude_status_code != null ? exclude_status_code : "404,405");
        JButton browseButton = new JButton("Browse");
        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
            if (fileChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
                outputPathField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            }
        });
        JCheckBox highlightCheckBox = new JCheckBox("Highlight Scanned/Bypassed requests in Proxy history", highlightEnabled);
        highlightCheckBox.addActionListener(e -> {
            highlightEnabled = highlightCheckBox.isSelected();
            saveSettings();
        });
        JCheckBox noteCheckBox = new JCheckBox("Add Note to Scanned/Bypassed requests in Proxy history", noteEnabled);
        noteCheckBox.addActionListener(e -> {
            noteEnabled = noteCheckBox.isSelected();
            saveSettings();
        });
        JCheckBox autoBypassCheckBox = new JCheckBox("Auto-bypass APIs without params", autoBypassNoParam);
        autoBypassCheckBox.addActionListener(e -> {
            autoBypassNoParam = autoBypassCheckBox.isSelected();
            saveSettings();
        });
        JButton applyButton = new JButton("Apply");
        applyButton.addActionListener(e -> {
            exclude_extensions = extensionArea.getText().trim();
            savedOutputPath = outputPathField.getText().trim();
            exclude_status_code = excludeStatusCodesField.getText().trim();
            autoBypassNoParam = autoBypassCheckBox.isSelected();
            saveSettings();

            // Khởi tạo lại CSDL trước để đảm bảo đang làm việc với đúng file
            databaseManager.close();
            databaseManager.initialize(savedOutputPath);

            // *** Áp dụng bypass cho dữ liệu cũ ***
            if (autoBypassNoParam) {
                // Chạy trong một luồng riêng để không làm treo giao diện
                new Thread(() -> {
                    databaseManager.applyAutoBypassToOldRecords();
                    // Tải lại dữ liệu trên luồng giao diện sau khi cập nhật xong
                    SwingUtilities.invokeLater(this::loadDataFromDb);
                }).start();
            } else {
                // Nếu không bật, chỉ cần tải lại dữ liệu như bình thường
                loadDataFromDb();
            }

            JOptionPane.showMessageDialog(null, "Settings applied and project reloaded from database.");
        });
        tabs.addTab("Settings", SettingsPanel.create(extensionArea, outputPathField, browseButton, highlightCheckBox, noteCheckBox, autoBypassCheckBox, applyButton, totalLbl, scannedLbl, rejectedLbl, bypassLbl, unverifiedLbl, excludeStatusCodesField));
        
        // Đăng ký tab chính vào giao diện Burp.
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(tabs, BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("Recheck Scan", mainPanel);
        
        // Tải dữ liệu lần đầu.
        loadDataFromDb();
    }

    /**
     * Helper method để ẩn các cột không cần thiết khỏi giao diện người dùng.
     * @param table Bảng cần thao tác.
     */
    private void setupHiddenColumns(JTable table) {
        // Ẩn cột "Repeater" (index 7)
        TableColumn repeaterColumn = table.getColumnModel().getColumn(7);
        repeaterColumn.setMinWidth(0);
        repeaterColumn.setMaxWidth(0);
        repeaterColumn.setWidth(0);

        // Ẩn cột "id" (index 8)
        TableColumn idColumn = table.getColumnModel().getColumn(8);
        idColumn.setMinWidth(0);
        idColumn.setMaxWidth(0);
        idColumn.setWidth(0);
    }

    /**
     * Xóa dữ liệu cũ trên bảng và tải lại toàn bộ từ CSDL.
     * Đồng thời cập nhật lại map `modelRowToDbId`.
     */
    private void loadDataFromDb() {
        tableModel.setRowCount(0);
        modelRowToDbId.clear();
        List<Object[]> rows = databaseManager.loadApiData();
        for (int i = 0; i < rows.size(); i++) {
            Object[] rowData = rows.get(i);
            tableModel.addRow(rowData);
            modelRowToDbId.put(i, (Integer) rowData[8]); // Index của ID
        }
        updateStats();
    }

    /**
     * Kiểm tra xem một đường dẫn có bị loại trừ dựa trên phần mở rộng hay không.
     * @param path Đường dẫn của request.
     * @return true nếu bị loại trừ.
     */
    private boolean isExcludedByExtension(String path) {
        if (exclude_extensions == null || exclude_extensions.isBlank()) return false;
        return Arrays.stream(exclude_extensions.replace(" ", "").split(","))
                     .map(String::trim)
                     .anyMatch(ext -> !ext.isEmpty() && path.toLowerCase().endsWith(ext));
    }
    
    /**
     * Phương thức tiện ích để tạo một JTable với các thuộc tính chung.
     */
    private JTable createCommonTable() {
        JTable table = new JTable(tableModel);
        table.setRowHeight(28);
        table.setFillsViewportHeight(true);
        table.getTableHeader().setReorderingAllowed(false);
        // Tùy chỉnh cách hiển thị cho cột boolean (dùng checkbox).
        table.setDefaultRenderer(Boolean.class, (tbl, value, isSelected, hasFocus, row, column) -> {
            JCheckBox checkBox = new JCheckBox();
            checkBox.setSelected(Boolean.TRUE.equals(value));
            checkBox.setHorizontalAlignment(SwingConstants.CENTER);
            checkBox.setOpaque(true);
            checkBox.setBackground(isSelected ? tbl.getSelectionBackground() : tbl.getBackground());
            if (column == 4) checkBox.setEnabled(false); // Vô hiệu hóa checkbox cột "Scanned".
            return checkBox;
        });
        // Tùy chỉnh cách hiển thị cho cột Note (bôi đỏ nếu có param mới).
        table.setDefaultRenderer(String.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (column == 3 && value != null && !((String)value).isEmpty()) {
                    c.setForeground(Color.RED);
                } else {
                    c.setForeground(isSelected ? table.getSelectionForeground() : table.getForeground());
                }
                return c;
            }
        });
        // Bắt sự kiện Ctrl+C để sao chép đường dẫn.
        table.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke("ctrl C"), "copyPath");
        table.getActionMap().put("copyPath", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] selectedRows = table.getSelectedRows();
                if (selectedRows.length > 0) {
                    StringBuilder sb = new StringBuilder();
                    for (int viewRow : selectedRows) {
                        int modelRow = table.convertRowIndexToModel(viewRow);
                        Object value = tableModel.getValueAt(modelRow, 2);
                        if (value != null) sb.append(value.toString()).append("\n");
                    }
                    StringSelection selection = new StringSelection(sb.toString().trim());
                    Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
                }
            }
        });
        return table;
    }

    /**
     * Phương thức tiện ích để tạo một panel hoàn chỉnh chứa bảng, thanh tìm kiếm và nút refresh.
     */
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
            public void insertUpdate(DocumentEvent e) { filter(); }
            public void removeUpdate(DocumentEvent e) { filter(); }
            public void changedUpdate(DocumentEvent e) { filter(); }
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
    
    /**
     * Lưu các cài đặt hiện tại vào persistence extension data (đi theo project).
     */
    private void saveSettings() {
        try {
            Properties props = new Properties();
            props.setProperty("exclude_extensions", exclude_extensions);
            props.setProperty("highlightEnabled", String.valueOf(highlightEnabled));
            props.setProperty("noteEnabled", String.valueOf(noteEnabled));
            props.setProperty("outputPath", savedOutputPath);
            props.setProperty("autoBypassNoParam", String.valueOf(autoBypassNoParam));
            props.setProperty("exclude_status_code", exclude_status_code);
            
            StringWriter writer = new StringWriter();
            props.store(writer, null);
            api.persistence().extensionData().setString("settings", writer.toString());
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(null, "Failed to save settings: " + ex.getMessage());
        }
    }

    /**
     * Tải các cài đặt từ persistence extension data khi khởi động.
     */
    private void loadSavedSettings() {
        try {
            String settingsStr = api.persistence().extensionData().getString("settings");
            if (settingsStr != null && !settingsStr.isEmpty()) {
                Properties props = new Properties();
                props.load(new StringReader(settingsStr));
                exclude_extensions = props.getProperty("exclude_extensions", "");
                highlightEnabled = Boolean.parseBoolean(props.getProperty("highlightEnabled", "false"));
                noteEnabled = Boolean.parseBoolean(props.getProperty("noteEnabled", "false"));
                savedOutputPath = props.getProperty("outputPath", "");
                autoBypassNoParam = Boolean.parseBoolean(props.getProperty("autoBypassNoParam", "false"));
                exclude_status_code = props.getProperty("exclude_status_code", "");
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to load settings: " + e.getMessage());
        }
    }
    /**
     * Kiểm tra xem một mã trạng thái HTTP nhất định có nên bị loại trừ dựa trên cài đặt của người dùng hay không.
     * @param statusCode Mã trạng thái HTTP cần kiểm tra.
     * @return true nếu mã trạng thái nằm trong danh sách bị loại trừ, ngược lại là false.
     */
    private boolean isExcludedStatusCode(int statusCode) {
        if (exclude_status_code == null || exclude_status_code.isBlank()) {
            return false;
        }

        Set<Integer> excludedCodes = new HashSet<>();
        try {
            for (String s : exclude_status_code.split(",")) {
                try {
                    excludedCodes.add(Integer.parseInt(s.trim()));
                } catch (NumberFormatException e) {
                }
            }
        } catch (Exception e) {
            return false;
        }

        return excludedCodes.contains(statusCode);
    }
    
    /**
     * Tính toán và cập nhật các nhãn thống kê.
     */
    private void updateStats() {
        int total = tableModel.getRowCount();
        int scanned = 0, rejected = 0, bypass = 0;
        for (int i = 0; i < total; i++) {
            if (Boolean.TRUE.equals(tableModel.getValueAt(i, 4))) scanned++;
            if (Boolean.TRUE.equals(tableModel.getValueAt(i, 5))) rejected++;
            if (Boolean.TRUE.equals(tableModel.getValueAt(i, 6))) bypass++;
        }
        totalLbl.setText("Total: " + total);
        scannedLbl.setText("Scanned: " + scanned);
        rejectedLbl.setText("Rejected: " + rejected);
        bypassLbl.setText("Bypass: " + bypass);
        int unverified = total - scanned - rejected - bypass;
        unverifiedLbl.setText("Unverified: " + unverified);
    }

    /**
     * Được gọi khi extension bị gỡ bỏ.
     * Đóng kết nối cơ sở dữ liệu để giải phóng tài nguyên.
     */
    @Override
    public void extensionUnloaded() {
        databaseManager.close();
    }
}