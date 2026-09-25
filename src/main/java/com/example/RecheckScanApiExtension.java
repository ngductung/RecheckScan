package com.example;

import burp.api.montoya.*;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.params.*;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.StringReader;
import java.io.StringWriter;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

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

    /**
     * Toàn bộ thao tác CSDL đi qua đúng một luồng nền.
     * <p>
     * Vừa giới hạn tài nguyên (thay cho việc tạo một Thread mới cho mỗi response),
     * vừa tuần tự hoá truy cập vào {@link java.sql.Connection} của SQLite vốn không thread-safe,
     * đồng thời bảo toàn thứ tự các thao tác ghi cho cùng một API.
     */
    private final ExecutorService dbExecutor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "RecheckScan-DB");
        thread.setDaemon(true);
        return thread;
    });

    /** Chu kỳ quét Proxy history để sửa lại annotation của các API vừa đổi trạng thái. */
    private static final long ANNOTATION_SWEEP_INTERVAL_SECONDS = 30;
    /**
     * Số API tối thiểu trong hàng chờ mới đáng một lượt quét.
     * Montoya không có API lấy N item gần nhất nên mỗi lượt phải duyệt TOÀN BỘ history;
     * gom nhiều thay đổi vào một lượt rẻ hơn rất nhiều so với quét cho từng lần đổi.
     */
    private static final int ANNOTATION_SWEEP_DEFAULT_MIN_BATCH = 10;
    /** Các note do extension này tạo ra - chỉ những giá trị này mới được phép ghi đè. */
    private static final Set<String> MANAGED_NOTES = Set.of("Scanned", "Bypassed", "Rejected");

    /** Hàng chờ các API vừa đổi trạng thái, khoá theo {@link DatabaseManager#statusKey}. */
    private final Set<String> pendingAnnotationKeys = ConcurrentHashMap.newKeySet();
    /** Đảm bảo không có hai lượt quét history chạy song song. */
    private final AtomicBoolean annotationSweepRunning = new AtomicBoolean(false);
    /**
     * Luồng riêng cho việc quét history: không dùng {@link #dbExecutor} vì một lượt quét
     * có thể mất vài giây và sẽ chặn các thao tác ghi CSDL của traffic đang chạy.
     */
    private ScheduledExecutorService annotationSweeper;

    // Các biến lưu trữ cài đặt của người dùng, được tải từ tệp cấu hình.
    // Tất cả đều `volatile`: ghi trên EDT khi người dùng bấm Apply nhưng đọc trên
    // các luồng HTTP của Burp, nên cần đảm bảo thay đổi được nhìn thấy ngay.
    private volatile String exclude_extensions;
    private volatile String savedOutputPath;
    private volatile String exclude_status_code;
    private volatile String path_parameter_rules;
    private volatile String ignored_parameter_rules;
    private volatile boolean highlightEnabled = false;
    private volatile boolean noteEnabled = false;
    private volatile boolean autoBypassNoParam = false;
    /** Tự động sửa lại highlight/note của các request cũ trong Proxy history. */
    private volatile boolean autoAnnotateHistory = false;
    /** Ngưỡng hàng chờ: dưới mức này thì bỏ qua lượt quét, đợi lượt sau. */
    private volatile int annotationSweepMinBatch = ANNOTATION_SWEEP_DEFAULT_MIN_BATCH;
    private volatile List<PathParameterRule> compiledPathParameterRules = List.of();
    private volatile List<Pattern> compiledIgnoredParameterRules = List.of();
    /**
     * Danh sách status code bị loại trừ, biên dịch sẵn để không phải parse lại cho từng response.
     */
    private volatile Set<Integer> excludedStatusCodes = Set.of();

    /**
     * Model cho JTable, chứa dữ liệu API được hiển thị trên giao diện.
     */
    private DefaultTableModel tableModel;
    /**
     * Ánh xạ ID trong CSDL sang chỉ số dòng trong TableModel, cho phép cập nhật
     * đúng một dòng trong O(1) thay vì tải lại toàn bộ bảng sau mỗi thay đổi.
     * Chỉ được truy cập trên EDT.
     */
    private final Map<Integer, Integer> dbIdToModelRow = new HashMap<>();
    /**
     * Trạng thái mới nhất của từng API, khoá theo {@link DatabaseManager#statusKey}.
     * <p>
     * Handler HTTP phải đặt highlight/note trước khi trả response nên không thể chờ
     * luồng CSDL; cache này cho phép tra cứu đồng bộ trong O(1) thay vì chạy SQL
     * trên luồng HTTP của Burp.
     */
    private final Map<String, DatabaseManager.ApiStatus> statusCache = new ConcurrentHashMap<>();
    /**
     * Cờ chặn ghi ngược xuống CSDL khi bảng đang được đồng bộ từ chính CSDL.
     * Chỉ được truy cập trên EDT.
     */
    private boolean suppressDbWrite = false;
    /**
     * Gom nhiều lần cập nhật thống kê liên tiếp thành một lần tính lại.
     */
    private javax.swing.Timer statsRefreshTimer;
    /** Các control trên tab Settings, để nạp lại giá trị khi đổi file DB. Chỉ dùng trên EDT. */
    private SettingsForm settingsForm;

    /** Tham chiếu tới các control của tab Settings. */
    private final class SettingsForm {
        private final JTextArea extensionArea;
        private final JTextField outputPathField;
        private final JTextField excludeStatusCodesField;
        private final JTextArea pathParameterRulesArea;
        private final JTextArea ignoredParameterRulesArea;
        private final JTextField annotationBatchField;
        private final JCheckBox highlightCheckBox;
        private final JCheckBox noteCheckBox;
        private final JCheckBox autoBypassCheckBox;
        private final JCheckBox autoAnnotateHistoryCheckBox;

        private SettingsForm(JTextArea extensionArea, JTextField outputPathField, JTextField excludeStatusCodesField,
                             JTextArea pathParameterRulesArea, JTextArea ignoredParameterRulesArea,
                             JTextField annotationBatchField, JCheckBox highlightCheckBox, JCheckBox noteCheckBox,
                             JCheckBox autoBypassCheckBox, JCheckBox autoAnnotateHistoryCheckBox) {
            this.extensionArea = extensionArea;
            this.outputPathField = outputPathField;
            this.excludeStatusCodesField = excludeStatusCodesField;
            this.pathParameterRulesArea = pathParameterRulesArea;
            this.ignoredParameterRulesArea = ignoredParameterRulesArea;
            this.annotationBatchField = annotationBatchField;
            this.highlightCheckBox = highlightCheckBox;
            this.noteCheckBox = noteCheckBox;
            this.autoBypassCheckBox = autoBypassCheckBox;
            this.autoAnnotateHistoryCheckBox = autoAnnotateHistoryCheckBox;
        }

        /** Đưa cấu hình đang có trong bộ nhớ lên form. Chỉ gọi trên EDT. */
        private void showCurrentValues() {
            extensionArea.setText(valueOrEmpty(exclude_extensions));
            outputPathField.setText(valueOrEmpty(savedOutputPath));
            excludeStatusCodesField.setText(valueOrEmpty(exclude_status_code));
            pathParameterRulesArea.setText(valueOrEmpty(path_parameter_rules));
            ignoredParameterRulesArea.setText(valueOrEmpty(ignored_parameter_rules));
            annotationBatchField.setText(String.valueOf(annotationSweepMinBatch));
            highlightCheckBox.setSelected(highlightEnabled);
            noteCheckBox.setSelected(noteEnabled);
            autoBypassCheckBox.setSelected(autoBypassNoParam);
            autoAnnotateHistoryCheckBox.setSelected(autoAnnotateHistory);
        }
    }

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

        // Burp chỉ giữ đường dẫn file DB (đi theo project); mọi cấu hình khác nằm trong DB
        // để nhiều project Burp trỏ cùng một file dùng chung cấu hình.
        Properties legacyBurpSettings = loadOutputPathFromBurp();
        databaseManager = new DatabaseManager(api);
        databaseManager.initialize(savedOutputPath);
        loadSettingsFromDatabase(legacyBurpSettings);

        // Tạo giao diện người dùng trên luồng Event Dispatch Thread (EDT) của Swing để đảm bảo an toàn luồng.
        SwingUtilities.invokeLater(this::createUI);

        // Bộ quét định kỳ: sửa lại highlight/note trong Proxy history cho các API đã đổi trạng thái.
        annotationSweeper = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "RecheckScan-history-sweeper");
            thread.setDaemon(true);
            return thread;
        });
        annotationSweeper.scheduleWithFixedDelay(this::sweepPendingAnnotations,
                ANNOTATION_SWEEP_INTERVAL_SECONDS, ANNOTATION_SWEEP_INTERVAL_SECONDS, TimeUnit.SECONDS);

        // Menu chuột phải trong Repeater/Intruder: Extensions > Recheck Scan API (v2).
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                // Chỉ hiện ở editor sửa được; các editor chỉ đọc không nhận setRequest().
                if (event.messageEditorRequestResponse().isEmpty()
                        || !event.isFromTool(ToolType.REPEATER, ToolType.INTRUDER)) {
                    return List.of();
                }
                MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();

                JMenuItem fillItem = new JMenuItem("Fill missing params (from Recheck Scan)");
                fillItem.addActionListener(e -> fillMissingParamsInEditor(editor, false));

                JMenuItem fillWithCookiesItem = new JMenuItem("Fill missing params + refresh cookies");
                fillWithCookiesItem.addActionListener(e -> fillMissingParamsInEditor(editor, true));

                return List.of(fillItem, fillWithCookiesItem);
            }
        });

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

                // Ngoài scope thì không làm gì cả: API ngoài scope không bao giờ được ghi nhận,
                // nên không cần normalize path hay parse param (việc tốn CPU nhất, nhất là body JSON/XML).
                if (!api.scope().isInScope(request.url())) {
                    return ResponseReceivedAction.continueWith(response);
                }
                String rawPath = request.pathWithoutQuery();
                boolean fromScanner = sourceType == ToolType.SCANNER;
                // File tĩnh bị loại trừ cũng không bao giờ được ghi nhận (Scanner giữ nguyên hành vi cũ).
                if (!fromScanner && isExcludedByExtension(rawPath)) {
                    return ResponseReceivedAction.continueWith(response);
                }

                String host = request.httpService().host();
                String path = normalizePath(rawPath);

                // Trích xuất tất cả tham số từ cả URL và body.
                Set<String> requestParams = extractParameters(request);

                // Trường hợp 1: Request từ Scanner -> xử lý các tham số đã được quét.
                if (fromScanner) {
                    submitDbTask(() -> databaseManager.processScannedParameters(method, host, path, requestParams));
                }
                // Trường hợp 2: Request từ các công cụ khác (Proxy, Repeater) đã qua lọc scope/extension ở trên.
                else {
                    // Nếu request từ Repeater, đánh dấu vào DB.
                    if (sourceType == ToolType.REPEATER) {
                        submitDbTask(() -> databaseManager.updateRepeaterStatus(method, host, path));
                    }

                    // Nhánh 2a: Tự động bypass cho API không có tham số.
                    if (requestParams.isEmpty() && autoBypassNoParam) {
                        if (needsAutoBypassWrite(method, host, path)) {
                            submitDbTask(() -> databaseManager.autoBypassApi(method, host, path));
                        }
                         // Thêm highlight/note ngay lập tức cho request này.
                         if (highlightEnabled) response.annotations().setHighlightColor(HighlightColor.YELLOW);
                         if (noteEnabled) response.annotations().setNotes("Bypassed");
                    } else {
                        // Nhánh 2b: Xử lý request thông thường để tìm và ghi nhận tham số mới.
                        // Annotation được suy ra từ cache trạng thái, cho ra đúng kết quả mà
                        // insertOrUpdateApi sẽ để lại, nhưng không phải chạy SQL trên luồng HTTP.
                        applyAnnotations(response, method, host, path, requestParams);
                        if (hasUnknownParams(method, host, path, requestParams)) {
                            submitDbTask(() -> databaseManager.insertOrUpdateApi(method, host, path, requestParams));
                        }
                    }
                }

                return ResponseReceivedAction.continueWith(response);
            }
        });
    }

    /**
     * Đặt highlight/note cho response dựa trên trạng thái API trong cache.
     * <p>
     * Kết quả khớp với trạng thái mà {@code insertOrUpdateApi} sắp ghi xuống CSDL:
     * API chưa từng thấy sẽ được chèn với mọi cờ bằng 0, còn API phát hiện thêm
     * tham số mới sẽ bị reset {@code is_scanned} và {@code is_bypassed}. Nhờ vậy
     * annotation giữ nguyên ngữ nghĩa cũ mà không cần truy vấn trên luồng HTTP.
     */
    private void applyAnnotations(HttpResponseReceived response, String method, String host, String path, Set<String> requestParams) {
        if (!highlightEnabled && !noteEnabled) {
            return;
        }

        DatabaseManager.ApiStatus status = statusCache.get(DatabaseManager.statusKey(method, host, path));
        if (status == null) {
            return; // API mới: mọi cờ sẽ là 0, không có gì để đánh dấu.
        }

        boolean hasNewParams = !status.knownParams.containsAll(requestParams);
        boolean isScanned = !hasNewParams && status.scanned;
        boolean isBypassed = !hasNewParams && status.bypassed;
        boolean isRejected = status.rejected;

        if (highlightEnabled && (isScanned || isBypassed)) {
            response.annotations().setHighlightColor(HighlightColor.YELLOW);
        }
        if (noteEnabled) {
            if (isScanned) {
                response.annotations().setNotes("Scanned");
            } else if (isBypassed) {
                response.annotations().setNotes("Bypassed");
            } else if (isRejected) {
                response.annotations().setNotes("Rejected");
            }
        }
    }

    /**
     * Request có cần ghi xuống CSDL không: chỉ khi API chưa có trong cache hoặc mang param mới.
     * Request lặp lại của API đã biết đủ param thì bỏ qua ngay trên luồng HTTP, không tốn
     * câu SQL nào. Cache được cập nhật trên luồng CSDL sau mỗi lần ghi nên luôn theo kịp.
     */
    boolean hasUnknownParams(String method, String host, String path, Set<String> requestParams) {
        DatabaseManager.ApiStatus status = statusCache.get(DatabaseManager.statusKey(method, host, path));
        return status == null || !status.knownParams.containsAll(requestParams);
    }

    /**
     * Auto-bypass chỉ cần ghi khi API chưa có, hoặc chưa mang cờ nào. Đã bypass/scan/reject thì
     * câu upsert không đổi gì, nên bỏ qua. Trường hợp còn lại (API có cờ tắt nhưng từng có param)
     * vẫn gửi xuống, CSDL tự quyết định và không ghi nếu không cần.
     */
    boolean needsAutoBypassWrite(String method, String host, String path) {
        DatabaseManager.ApiStatus status = statusCache.get(DatabaseManager.statusKey(method, host, path));
        return status == null || !(status.bypassed || status.scanned || status.rejected);
    }

    /**
     * Đẩy một thao tác ghi CSDL sang luồng nền, rồi đồng bộ kết quả lên cache và giao diện.
     * Chỉ dòng thực sự thay đổi được cập nhật, thay cho việc tải lại toàn bộ bảng.
     *
     * @param task Thao tác trả về dòng đã thay đổi, hoặc null nếu CSDL không đổi.
     */
    private void submitDbTask(Supplier<DatabaseManager.ApiUpdate> task) {
        runOnDbThread(() -> {
            DatabaseManager.ApiUpdate update = task.get();
            if (update == null) {
                return;
            }
            // Cập nhật cache ngay trên luồng CSDL để response kế tiếp thấy trạng thái mới nhất.
            cacheStatus(update);
            SwingUtilities.invokeLater(() -> updateOrInsertTableRow(update.row));
        });
    }

    /**
     * Đẩy một tác vụ sang luồng CSDL, bỏ qua im lặng nếu extension đang được gỡ bỏ.
     * Burp có thể còn vài response dang dở sau khi executor đã shutdown; khi đó không
     * được để RejectedExecutionException thoát ra luồng HTTP của Burp.
     */
    private void runOnDbThread(Runnable task) {
        try {
            dbExecutor.execute(task);
        } catch (RejectedExecutionException e) {
            // Extension đang unload, không còn gì để ghi nữa.
        }
    }

    private void cacheStatus(DatabaseManager.ApiUpdate update) {
        Object[] row = update.row;
        String key = DatabaseManager.statusKey((String) row[0], (String) row[1], (String) row[2]);
        DatabaseManager.ApiStatus previous = statusCache.put(key, update.status);
        if (flagsChanged(previous, update.status)) {
            queueAnnotationUpdate(key);
        }
    }

    /**
     * Annotation trong history chỉ phụ thuộc 3 cờ scanned/rejected/bypassed, nên chỉ khi một
     * trong ba cờ thực sự đổi mới cần sửa lại history. Request lặp lại của API đã biết (ví dụ
     * bypass -> bypass) không được xếp hàng. API chưa có trong cache coi như mọi cờ đều tắt.
     */
    static boolean flagsChanged(DatabaseManager.ApiStatus previous, DatabaseManager.ApiStatus current) {
        boolean wasScanned = previous != null && previous.scanned;
        boolean wasRejected = previous != null && previous.rejected;
        boolean wasBypassed = previous != null && previous.bypassed;
        return wasScanned != current.scanned || wasRejected != current.rejected || wasBypassed != current.bypassed;
    }

    /**
     * Đồng bộ cờ trạng thái của một dòng trên bảng vào cache, sau khi người dùng tự tick
     * checkbox. Tập tham số đã biết giữ nguyên vì thao tác này không đụng tới tham số.
     * Chỉ được gọi trên EDT.
     */
    private void syncStatusCacheFromRow(int modelRow) {
        String key = DatabaseManager.statusKey(
                (String) tableModel.getValueAt(modelRow, 0),
                (String) tableModel.getValueAt(modelRow, 1),
                (String) tableModel.getValueAt(modelRow, 2));
        DatabaseManager.ApiStatus previous = statusCache.get(key);
        DatabaseManager.ApiStatus current = new DatabaseManager.ApiStatus(
                Boolean.TRUE.equals(tableModel.getValueAt(modelRow, 4)),
                Boolean.TRUE.equals(tableModel.getValueAt(modelRow, 5)),
                Boolean.TRUE.equals(tableModel.getValueAt(modelRow, 6)),
                previous == null ? Set.of() : previous.knownParams);
        statusCache.put(key, current);
        if (flagsChanged(previous, current)) {
            queueAnnotationUpdate(key);
        }
    }

    /**
     * Xếp một API vừa đổi trạng thái vào hàng chờ sửa annotation trong Proxy history.
     * Chỉ ghi nhận key (rẻ), việc quét history do {@link #sweepPendingAnnotations()} làm theo lô.
     */
    private void queueAnnotationUpdate(String statusKey) {
        if (statusKey == null || !isHistoryAnnotationEnabled()) {
            return;
        }
        pendingAnnotationKeys.add(statusKey);
    }

    /**
     * Chạy mỗi {@link #ANNOTATION_SWEEP_INTERVAL_SECONDS} giây trên luồng nền.
     * Hàng chờ dưới {@link #annotationSweepMinBatch} API thì bỏ qua, đợi lượt sau: một lượt quét
     * phải duyệt toàn bộ history nên quét cho vài API là quá đắt so với việc chờ gom thêm.
     */
    private void sweepPendingAnnotations() {
        try {
            if (!isHistoryAnnotationEnabled()) {
                pendingAnnotationKeys.clear();
                return;
            }
            if (pendingAnnotationKeys.size() < annotationSweepMinBatch) {
                return;
            }
            // Tách lô ra khỏi hàng chờ để thay đổi mới phát sinh trong lúc quét không bị mất.
            Set<String> batch = new HashSet<>(pendingAnnotationKeys);
            pendingAnnotationKeys.removeAll(batch);
            runAnnotationSweep(batch);
        } catch (Throwable t) {
            // Một exception thoát ra sẽ làm scheduler dừng hẳn, nên phải nuốt tại đây.
            api.logging().logToError("Annotation sweep failed: " + t.getMessage());
        }
    }

    /** Đẩy tác vụ sang luồng quét history, bỏ qua im lặng nếu extension đang được gỡ. */
    private void runOnSweeperThread(Runnable task) {
        if (annotationSweeper == null) {
            return;
        }
        try {
            annotationSweeper.execute(task);
        } catch (RejectedExecutionException e) {
            // Extension đang unload.
        }
    }

    /**
     * Quét Proxy history và sửa lại annotation theo trạng thái mới nhất.
     *
     * @param targetKeys Chỉ xử lý các API này; null = quét toàn bộ (dùng khi bấm Apply).
     * @return Số item history đã cập nhật, hoặc -1 nếu lượt quét không chạy được.
     */
    private int runAnnotationSweep(Set<String> targetKeys) {
        if (!isHistoryAnnotationEnabled()) {
            return -1;
        }
        if (!annotationSweepRunning.compareAndSet(false, true)) {
            // Lượt trước chưa xong -> trả key về hàng chờ, bỏ qua nhịp này.
            if (targetKeys != null) {
                pendingAnnotationKeys.addAll(targetKeys);
            }
            return -1;
        }
        try {
            long startedAt = System.currentTimeMillis();
            int annotated = annotateHistory(targetKeys);
            api.logging().logToOutput(String.format(
                    "Re-annotated %d proxy history entries for %s in %d ms.",
                    annotated,
                    targetKeys == null ? "all APIs" : targetKeys.size() + " changed API(s)",
                    System.currentTimeMillis() - startedAt));
            return annotated;
        } catch (Throwable t) {
            if (targetKeys != null) {
                pendingAnnotationKeys.addAll(targetKeys); // thử lại ở lượt sau
            }
            api.logging().logToError("Failed to re-annotate proxy history: " + t.getMessage());
            return -1;
        } finally {
            annotationSweepRunning.set(false);
        }
    }

    /**
     * Duyệt Proxy history MỘT lượt và cập nhật highlight/note cho các item khớp.
     * Trạng thái lấy từ {@link #statusCache} nên không chạm tới CSDL.
     *
     * @param targetKeys Chỉ xử lý các API này; null = mọi API đã biết.
     * @return Số item trong history đã được cập nhật.
     */
    private int annotateHistory(Set<String> targetKeys) {
        if ((targetKeys != null && targetKeys.isEmpty()) || statusCache.isEmpty()) {
            return 0;
        }

        int annotated = 0;
        for (ProxyHttpRequestResponse item : api.proxy().history()) {
            // item.method()/host()/path() đã deprecated for removal; dùng request() cũng khớp
            // đúng cách tính key của HttpHandler.
            HttpRequest request = item.request();
            if (request == null) {
                continue;
            }
            String rawPath = request.pathWithoutQuery();
            if (rawPath == null || rawPath.isEmpty()) {
                continue;
            }
            String key = DatabaseManager.statusKey(
                    request.method(), request.httpService().host(), normalizePath(rawPath));
            if (targetKeys != null && !targetKeys.contains(key)) {
                continue;
            }
            DatabaseManager.ApiStatus status = statusCache.get(key);
            if (status == null) {
                continue; // API chưa từng được ghi nhận (ngoài scope, bị loại trừ...).
            }
            if (applyHistoryAnnotations(item.annotations(), status)) {
                annotated++;
            }
        }
        return annotated;
    }

    /**
     * Ghi highlight/note cho một item history theo trạng thái của API.
     * <p>
     * Chỉ ghi đè những gì extension tự đặt: màu YELLOW và các note trong {@link #MANAGED_NOTES}.
     * Highlight màu khác hoặc note do người dùng tự viết luôn được giữ nguyên. API quay về
     * trạng thái chưa xác định thì annotation cũ của extension được xoá để không hiển thị sai.
     *
     * @return true nếu có thay đổi.
     */
    private boolean applyHistoryAnnotations(Annotations annotations, DatabaseManager.ApiStatus status) {
        boolean changed = false;

        if (highlightEnabled) {
            HighlightColor wanted = (status.scanned || status.bypassed) ? HighlightColor.YELLOW : HighlightColor.NONE;
            HighlightColor current = annotations.highlightColor();
            boolean writable = current == null || current == HighlightColor.NONE || current == HighlightColor.YELLOW;
            if (writable && current != wanted) {
                annotations.setHighlightColor(wanted);
                changed = true;
            }
        }

        if (noteEnabled) {
            String wanted = status.scanned ? "Scanned" : status.bypassed ? "Bypassed" : status.rejected ? "Rejected" : "";
            String current = annotations.notes();
            boolean writable = current == null || current.isBlank() || MANAGED_NOTES.contains(current);
            if (writable && !wanted.equals(current == null ? "" : current)) {
                annotations.setNotes(wanted);
                changed = true;
            }
        }
        return changed;
    }

    /** Sửa history chỉ có ý nghĩa khi option được bật VÀ có thứ để ghi (highlight hoặc note). */
    private boolean isHistoryAnnotationEnabled() {
        return autoAnnotateHistory && (highlightEnabled || noteEnabled);
    }

    /**
     * Đọc ngưỡng hàng chờ do người dùng nhập. Giá trị không hợp lệ hoặc nhỏ hơn 1
     * quay về mặc định thay vì làm hỏng lịch quét.
     */
    private int parseSweepBatchSize(String rawValue) {
        if (rawValue != null && !rawValue.isBlank()) {
            try {
                int parsed = Integer.parseInt(rawValue.trim());
                if (parsed >= 1) {
                    return parsed;
                }
                api.logging().logToError("History sweep batch size must be >= 1, falling back to "
                        + ANNOTATION_SWEEP_DEFAULT_MIN_BATCH + ": " + rawValue);
                return ANNOTATION_SWEEP_DEFAULT_MIN_BATCH;
            } catch (NumberFormatException e) {
                api.logging().logToError("Invalid history sweep batch size, falling back to "
                        + ANNOTATION_SWEEP_DEFAULT_MIN_BATCH + ": " + rawValue);
            }
        }
        return ANNOTATION_SWEEP_DEFAULT_MIN_BATCH;
    }

    /**
     * Popup tiến trình cho lượt quét history khi bấm Apply.
     * Nút OK bị vô hiệu cho tới khi lượt quét kết thúc.
     */
    private static class HistoryProgressDialog extends JDialog {
        private final JLabel messageLabel = new JLabel("Đang xử lý Proxy history, vui lòng đợi...");
        private final JButton okButton = new JButton("OK");

        HistoryProgressDialog(Window owner) {
            super(owner, "Recheck Scan", ModalityType.APPLICATION_MODAL);
            okButton.setEnabled(false);
            okButton.addActionListener(e -> dispose());

            JPanel content = new JPanel(new BorderLayout(10, 15));
            content.setBorder(BorderFactory.createEmptyBorder(20, 20, 15, 20));
            content.add(messageLabel, BorderLayout.CENTER);

            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 0));
            buttonPanel.add(okButton);
            content.add(buttonPanel, BorderLayout.SOUTH);

            setContentPane(content);
            setDefaultCloseOperation(DISPOSE_ON_CLOSE);
            pack();
            setLocationRelativeTo(owner);
        }

        /** Gọi trên EDT khi lượt quét đã xong: đổi thông báo và bật nút OK. */
        void markDone(String message) {
            messageLabel.setText(message);
            okButton.setEnabled(true);
            pack();
            setLocationRelativeTo(getOwner());
        }
    }

    /**
     * Cập nhật một dòng đã có hoặc chèn một dòng mới vào JTable. Chỉ được gọi trên EDT.
     */
    private void updateOrInsertTableRow(Object[] rowData) {
        Integer dbId = (Integer) rowData[8]; // Index của ID
        Integer modelRowIndex = dbIdToModelRow.get(dbId);

        // Những thay đổi dưới đây đến từ CSDL, không được ghi ngược trở lại CSDL.
        suppressDbWrite = true;
        try {
            if (modelRowIndex != null) { // API đã có trên bảng -> cập nhật tại chỗ.
                // Cột 3..7: Unscanned Params, Scanned, Rejected, Bypass, Repeater.
                for (int column = 3; column <= 7; column++) {
                    tableModel.setValueAt(rowData[column], modelRowIndex, column);
                }
            } else { // API mới -> chèn vào đầu bảng.
                tableModel.insertRow(0, rowData);
                // insertRow(0) đẩy mọi dòng cũ xuống một bậc, nên chỉ cần dịch map
                // thay vì quét lại toàn bộ bảng.
                dbIdToModelRow.replaceAll((id, modelRow) -> modelRow + 1);
                dbIdToModelRow.put(dbId, 0);
            }
        } finally {
            suppressDbWrite = false;
        }
        scheduleStatsUpdate();
    }

    /**
     * Đọc toàn bộ dữ liệu từ CSDL trên luồng nền rồi đổ lên bảng.
     * Chỉ dùng cho các mốc cần nạp lại toàn bộ: khởi động, Refresh, Apply, hoặc sau khi xoá.
     */
    private void reloadDataAsync() {
        runOnDbThread(() -> {
            List<Object[]> rows = databaseManager.loadApiData();
            Map<String, DatabaseManager.ApiStatus> statuses = databaseManager.loadStatusIndex();
            statusCache.clear();
            statusCache.putAll(statuses);
            SwingUtilities.invokeLater(() -> populateTable(rows));
        });
    }

    /**
     * Hẹn giờ tính lại thống kê, gom các thay đổi liên tiếp thành một lần chạy.
     * <p>
     * {@link #updateStats()} phải quét toàn bộ bảng, nên gọi trực tiếp sau mỗi ô bị đổi
     * sẽ biến thao tác hàng loạt thành O(n²). Chỉ được gọi trên EDT.
     */
    private void scheduleStatsUpdate() {
        if (statsRefreshTimer == null) {
            statsRefreshTimer = new javax.swing.Timer(300, e -> updateStats());
            statsRefreshTimer.setRepeats(false);
        }
        statsRefreshTimer.restart();
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

        return filterIgnoredParameters(allParamNames);
    }

    private Set<String> filterIgnoredParameters(Set<String> parameterNames) {
        if (parameterNames == null || parameterNames.isEmpty() || compiledIgnoredParameterRules.isEmpty()) {
            return parameterNames;
        }

        return parameterNames.stream()
                .filter(paramName -> !isIgnoredParameter(paramName))
                .collect(Collectors.toCollection(HashSet::new));
    }

    private boolean isIgnoredParameter(String parameterName) {
        if (parameterName == null || compiledIgnoredParameterRules.isEmpty()) {
            return false;
        }

        for (Pattern pattern : compiledIgnoredParameterRules) {
            if (pattern.matcher(parameterName).matches()) {
                return true;
            }
        }
        return false;
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
                super.setValueAt(aValue, row, col); // Cập nhật giá trị trên UI trước.

                // Bỏ qua khi thay đổi đến từ việc đồng bộ CSDL lên bảng, để không ghi
                // ngược xuống CSDL đúng những gì vừa đọc ra.
                if (suppressDbWrite) {
                    return;
                }

                // Chỉ xử lý các cột checkbox trạng thái "Rejected" (5) và "Bypass" (6).
                if (col == 5 || col == 6) {
                    Integer id = (Integer) getValueAt(row, 8); // Lấy ID của dòng từ cột ẩn.
                    if (id != null) {
                        boolean isChecked = Boolean.TRUE.equals(aValue);
                        int otherCol = (col == 5) ? 6 : 5;
                        String dbColumn = (col == 5) ? "is_rejected" : "is_bypassed";
                        String otherDbColumn = (col == 5) ? "is_bypassed" : "is_rejected";

                        // Hai trạng thái loại trừ nhau: tick ô này thì bỏ tick ô kia.
                        if (isChecked && Boolean.TRUE.equals(getValueAt(row, otherCol))) {
                            super.setValueAt(false, row, otherCol);
                            runOnDbThread(() -> databaseManager.updateApiStatus(id, otherDbColumn, false));
                        }
                        runOnDbThread(() -> databaseManager.updateApiStatus(id, dbColumn, isChecked));

                        // Giữ cache trạng thái khớp với bảng để highlight/note dùng đúng giá trị.
                        syncStatusCacheFromRow(row);
                    }
                }
                scheduleStatsUpdate(); // Cập nhật các nhãn thống kê (gom lại, tránh quét bảng mỗi ô).
            }
        };

        // Bố cục chính của tab extension.
        JTabbedPane tabs = new JTabbedPane();
        java.util.function.Supplier<TableRowSorter<DefaultTableModel>> sorterFactory = () -> {
            TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel) {
                @Override
                public void toggleSortOrder(int column) {
                    List<? extends SortKey> sortKeys = getSortKeys();
                    if (!sortKeys.isEmpty()) {
                        SortKey primaryKey = sortKeys.get(0);
                        if (primaryKey.getColumn() == column && primaryKey.getSortOrder() == SortOrder.DESCENDING) {
                            setSortKeys(Collections.emptyList());
                            return;
                        }
                    }
                    super.toggleSortOrder(column);
                }
            };
            sorter.setMaxSortKeys(1);
            return sorter;
        };

        // --- Cài đặt Tab "Unscanned" ---
        JTable unscannedTable = createCommonTable();
        setupHiddenColumns(unscannedTable); // Ẩn các cột cần thiết (Repeater, id)
        final TableRowSorter<DefaultTableModel> unscannedSorter = sorterFactory.get();
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
            RowFilter<Object, Object> textFilter = createPathSearchFilter(keyword);
            sorter.setRowFilter(textFilter != null ? RowFilter.andFilter(Arrays.asList(unscannedStatusFilter, textFilter)) : unscannedStatusFilter);
        });
        tabs.addTab("Unscanned", unscannedPanel);

        // --- Cài đặt Tab "Logs" ---
        JTable logsTable = createCommonTable();
        setupHiddenColumns(logsTable); // Ẩn các cột cần thiết (Repeater, id)
        final TableRowSorter<DefaultTableModel> logsSorter = sorterFactory.get();
        logsTable.setRowSorter(logsSorter);
        JButton logsRefreshButton = new JButton("Refresh");
        logsRefreshButton.addActionListener(e -> logsSorter.setRowFilter(logsSorter.getRowFilter()));
        JPanel logsPanel = createApiPanel("Search all paths:", logsTable, logsRefreshButton, (keyword, sorter) -> {
            sorter.setRowFilter(createPathSearchFilter(keyword));
        });
        tabs.addTab("Logs", logsPanel);

        // --- Cài đặt Tab "Settings" ---
        JTextArea extensionArea = new JTextArea(exclude_extensions != null ? exclude_extensions : DEFAULT_EXCLUDE_EXTENSIONS);
        JTextField outputPathField = new JTextField(savedOutputPath != null ? savedOutputPath : "");
        JTextField excludeStatusCodesField = new JTextField(exclude_status_code != null ? exclude_status_code : DEFAULT_EXCLUDE_STATUS_CODES);
        JTextArea pathParameterRulesArea = new JTextArea(path_parameter_rules != null ? path_parameter_rules : "");
        JTextArea ignoredParameterRulesArea = new JTextArea(ignored_parameter_rules != null ? ignored_parameter_rules : "");
        JButton browseButton = new JButton("Browse");
        browseButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
            if (fileChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
                String chosenPath = fileChooser.getSelectedFile().getAbsolutePath();
                outputPathField.setText(chosenPath);
                switchDatabase(chosenPath);
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
        JCheckBox autoAnnotateHistoryCheckBox = new JCheckBox(
                "Auto-fix Highlight/Note in Proxy history when API status changes", autoAnnotateHistory);
        autoAnnotateHistoryCheckBox.setToolTipText("Quét lại Proxy history mỗi "
                + ANNOTATION_SWEEP_INTERVAL_SECONDS + "s cho các API vừa đổi trạng thái, và quét toàn bộ khi bấm Apply.");
        autoAnnotateHistoryCheckBox.addActionListener(e -> {
            autoAnnotateHistory = autoAnnotateHistoryCheckBox.isSelected();
            saveSettings();
        });
        JTextField annotationBatchField = new JTextField(String.valueOf(annotationSweepMinBatch), 4);
        annotationBatchField.setToolTipText("Hàng chờ ít hơn số này thì bỏ qua lượt quét (mỗi lượt phải duyệt toàn bộ history). Mặc định "
                + ANNOTATION_SWEEP_DEFAULT_MIN_BATCH + ", nhỏ nhất 1. Đọc lại khi bấm Apply.");
        JButton applyButton = new JButton("Apply");
        applyButton.addActionListener(e -> {
            String requestedPath = outputPathField.getText().trim();
            if (!databaseManager.resolveDbPath(requestedPath).equals(databaseManager.currentDbPath())) {
                // Đường dẫn DB đổi: cấu hình phải đến từ file mới, không phải từ những gì đang gõ trên form.
                switchDatabase(requestedPath);
                return;
            }
            exclude_extensions = extensionArea.getText().trim();
            savedOutputPath = requestedPath;
            exclude_status_code = excludeStatusCodesField.getText().trim();
            path_parameter_rules = pathParameterRulesArea.getText().trim();
            ignored_parameter_rules = ignoredParameterRulesArea.getText().trim();
            compiledPathParameterRules = compilePathParameterRules(path_parameter_rules);
            compiledIgnoredParameterRules = compileIgnoredParameterRules(ignored_parameter_rules);
            excludedStatusCodes = parseStatusCodes(exclude_status_code);
            autoBypassNoParam = autoBypassCheckBox.isSelected();
            annotationSweepMinBatch = parseSweepBatchSize(annotationBatchField.getText());
            annotationBatchField.setText(String.valueOf(annotationSweepMinBatch)); // phản hồi giá trị thực dùng
            saveSettings();

            // Toàn bộ thao tác CSDL chạy trên dbExecutor: vừa không treo giao diện,
            // vừa không đụng độ với các tác vụ đang xử lý traffic.
            applyButton.setEnabled(false);
            // Sửa lại toàn bộ history có thể mất vài giây: hiện popup và chỉ cho OK khi xong.
            final HistoryProgressDialog progressDialog = isHistoryAnnotationEnabled()
                    ? new HistoryProgressDialog(SwingUtilities.getWindowAncestor(applyButton))
                    : null;
            final String dbPath = savedOutputPath;
            final boolean normalizePaths = !compiledPathParameterRules.isEmpty();
            final boolean cleanIgnoredParams = !compiledIgnoredParameterRules.isEmpty();
            final boolean bypassOldRecords = autoBypassNoParam;
            runOnDbThread(() -> {
                // Mở lại CSDL trước để đảm bảo đang làm việc với đúng file.
                databaseManager.reopen(dbPath);

                // *** Áp dụng chuẩn hoá path, loại tham số và bypass cho dữ liệu cũ ***
                if (normalizePaths) {
                    databaseManager.normalizeStoredPaths(this::normalizePath);
                }
                if (cleanIgnoredParams) {
                    databaseManager.removeIgnoredParameters(this::isIgnoredParameter);
                }
                if (bypassOldRecords) {
                    databaseManager.applyAutoBypassToOldRecords();
                }

                List<Object[]> rows = databaseManager.loadApiData();
                Map<String, DatabaseManager.ApiStatus> statuses = databaseManager.loadStatusIndex();
                statusCache.clear();
                statusCache.putAll(statuses);
                // Chỉ báo cho người dùng sau khi mọi thay đổi đã thực sự hoàn tất.
                SwingUtilities.invokeLater(() -> {
                    populateTable(rows);
                    applyButton.setEnabled(true);
                    if (progressDialog == null) {
                        JOptionPane.showMessageDialog(null, "Settings applied and project reloaded from database.");
                    }
                });

                // Quét history sau khi cache đã đồng bộ, trên luồng riêng để không giữ luồng CSDL.
                if (progressDialog != null) {
                    pendingAnnotationKeys.clear(); // lượt quét toàn bộ đã bao trùm hàng chờ
                    runOnSweeperThread(() -> {
                        int annotated = runAnnotationSweep(null);
                        String message = annotated < 0
                                ? "Không quét được history (một lượt quét khác đang chạy). Sẽ thử lại ở lượt định kỳ."
                                : "Đã xử lý xong: " + annotated + " request trong Proxy history được cập nhật.";
                        SwingUtilities.invokeLater(() -> progressDialog.markDone(message));
                    });
                }
            });
            if (progressDialog != null) {
                // Modal: chặn tại đây cho tới khi người dùng bấm OK (nút chỉ bật khi đã xử lý xong).
                progressDialog.setVisible(true);
            }
        });
        settingsForm = new SettingsForm(extensionArea, outputPathField, excludeStatusCodesField, pathParameterRulesArea,
                ignoredParameterRulesArea, annotationBatchField, highlightCheckBox, noteCheckBox, autoBypassCheckBox,
                autoAnnotateHistoryCheckBox);
        JButton resetDefaultButton = new JButton("Reset Default");
        resetDefaultButton.setToolTipText("Đưa mọi cấu hình về mặc định và lưu vào file DB đang mở. "
                + "Không đổi đường dẫn DB, không đụng dữ liệu API.");
        resetDefaultButton.addActionListener(e -> resetSettingsToDefault());
        tabs.addTab("Settings", SettingsPanel.create(extensionArea, outputPathField, browseButton, highlightCheckBox, noteCheckBox, autoBypassCheckBox, autoAnnotateHistoryCheckBox, annotationBatchField, applyButton, resetDefaultButton, totalLbl, scannedLbl, rejectedLbl, bypassLbl, unverifiedLbl, excludeStatusCodesField, pathParameterRulesArea, ignoredParameterRulesArea));
        
        // Đăng ký tab chính vào giao diện Burp.
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.add(tabs, BorderLayout.CENTER);
        api.userInterface().registerSuiteTab("Recheck Scan", mainPanel);
        
        // Tải dữ liệu lần đầu.
        reloadDataAsync();
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
     * Đồng thời dựng lại map `dbIdToModelRow`.
     */
    private void populateTable(List<Object[]> rows) {
        tableModel.setRowCount(0);
        dbIdToModelRow.clear();
        for (int i = 0; i < rows.size(); i++) {
            Object[] rowData = rows.get(i);
            tableModel.addRow(rowData);
            dbIdToModelRow.put((Integer) rowData[8], i); // Index của ID
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
     * Chuẩn hóa các segment động trong URL path theo rule người dùng cấu hình.
     * Ví dụ: /api/report/1684050854912458752/list -> /api/report/{id}/list.
     */
    private String normalizePath(String path) {
        if (path == null || path.isBlank() || compiledPathParameterRules.isEmpty()) {
            return path;
        }

        String normalizedPath = path;
        for (PathParameterRule rule : compiledPathParameterRules) {
            normalizedPath = rule.isPathAware()
                    ? applyPathAwareRule(normalizedPath, rule)
                    : applySegmentRule(normalizedPath, rule);
        }
        return normalizedPath;
    }

    private String applySegmentRule(String path, PathParameterRule rule) {
        String[] segments = path.split("/", -1);
        boolean changed = false;
        for (int i = 0; i < segments.length; i++) {
            String segment = segments[i];
            if (segment.isEmpty()) {
                continue;
            }
            if (rule.matches(segment)) {
                segments[i] = rule.placeholder();
                changed = true;
            }
        }
        return changed ? String.join("/", segments) : path;
    }

    private String applyPathAwareRule(String path, PathParameterRule rule) {
        Matcher matcher = rule.pattern().matcher(path);
        StringBuffer normalizedPath = new StringBuffer();
        boolean changed = false;
        while (matcher.find()) {
            String replacement = buildPathAwareReplacement(matcher, rule.placeholder());
            matcher.appendReplacement(normalizedPath, Matcher.quoteReplacement(replacement));
            changed = true;
        }
        matcher.appendTail(normalizedPath);
        return changed ? normalizedPath.toString() : path;
    }

    private String buildPathAwareReplacement(Matcher matcher, String placeholder) {
        String match = matcher.group();
        for (int groupIndex = 1; groupIndex <= matcher.groupCount(); groupIndex++) {
            if (matcher.start(groupIndex) >= 0) {
                int relativeStart = matcher.start(groupIndex) - matcher.start();
                int relativeEnd = matcher.end(groupIndex) - matcher.start();
                return match.substring(0, relativeStart) + placeholder + match.substring(relativeEnd);
            }
        }

        int lastSlashIndex = match.lastIndexOf('/');
        if (lastSlashIndex >= 0) {
            return match.substring(0, lastSlashIndex + 1) + placeholder;
        }
        return placeholder;
    }

    private List<PathParameterRule> compilePathParameterRules(String rulesText) {
        List<PathParameterRule> rules = new ArrayList<>();
        if (rulesText == null || rulesText.isBlank()) {
            return rules;
        }

        for (String rawLine : rulesText.split("\\R")) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            int separatorIndex = line.indexOf('=');
            if (separatorIndex <= 0 || separatorIndex == line.length() - 1) {
                api.logging().logToError("Invalid path parameter rule: " + line);
                continue;
            }

            String placeholder = normalizePlaceholder(line.substring(0, separatorIndex).trim());
            String spec = line.substring(separatorIndex + 1).trim();
            boolean pathAware = isPathAwareRegexSpec(spec);
            Pattern pattern = compilePathParameterPattern(spec);
            if (pattern != null) {
                rules.add(new PathParameterRule(placeholder, pattern, pathAware));
            }
        }
        return rules;
    }

    private boolean isPathAwareRegexSpec(String spec) {
        String lowerSpec = spec.toLowerCase(Locale.ROOT);
        return lowerSpec.startsWith("regex:") && spec.substring("regex:".length()).contains("/");
    }

    private String normalizePlaceholder(String placeholder) {
        if (placeholder.startsWith("{") && placeholder.endsWith("}")) {
            return placeholder;
        }
        return "{" + placeholder.replace("{", "").replace("}", "") + "}";
    }

    private Pattern compilePathParameterPattern(String spec) {
        String lowerSpec = spec.toLowerCase(Locale.ROOT);
        if (lowerSpec.startsWith("regex:")) {
            try {
                return Pattern.compile(spec.substring("regex:".length()));
            } catch (PatternSyntaxException e) {
                api.logging().logToError("Invalid path parameter regex rule: " + spec + " - " + e.getMessage());
                return null;
            }
        }

        String[] parts = lowerSpec.split(":", 2);
        String type = parts[0].trim();
        Integer length = null;
        if (parts.length == 2 && !parts[1].isBlank()) {
            try {
                length = Integer.parseInt(parts[1].trim());
            } catch (NumberFormatException e) {
                api.logging().logToError("Invalid path parameter length in rule: " + spec);
                return null;
            }
            if (length <= 0) {
                api.logging().logToError("Path parameter length must be positive in rule: " + spec);
                return null;
            }
        }

        String quantifier = length == null ? "+" : "{" + length + "}";
        return switch (type) {
            case "number", "numeric", "digits" -> Pattern.compile("[0-9]" + quantifier);
            case "hex" -> Pattern.compile("[0-9a-fA-F]" + quantifier);
            case "uuid" -> Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
            case "alnum", "alpha_numeric" -> Pattern.compile("[0-9a-zA-Z]" + quantifier);
            default -> {
                api.logging().logToError("Unsupported path parameter rule type: " + spec);
                yield null;
            }
        };
    }

    private List<Pattern> compileIgnoredParameterRules(String rulesText) {
        List<Pattern> rules = new ArrayList<>();
        if (rulesText == null || rulesText.isBlank()) {
            return rules;
        }

        for (String rawLine : rulesText.split("\\R")) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            Pattern pattern = compileIgnoredParameterPattern(line);
            if (pattern != null) {
                rules.add(pattern);
            }
        }
        return rules;
    }

    private Pattern compileIgnoredParameterPattern(String spec) {
        String lowerSpec = spec.toLowerCase(Locale.ROOT);
        if (lowerSpec.startsWith("regex:")) {
            try {
                return Pattern.compile(spec.substring("regex:".length()));
            } catch (PatternSyntaxException e) {
                api.logging().logToError("Invalid ignored parameter regex rule: " + spec + " - " + e.getMessage());
                return null;
            }
        }

        try {
            return Pattern.compile(wildcardToRegex(spec));
        } catch (PatternSyntaxException e) {
            api.logging().logToError("Invalid ignored parameter rule: " + spec + " - " + e.getMessage());
            return null;
        }
    }

    private String wildcardToRegex(String spec) {
        StringBuilder regex = new StringBuilder();
        for (int i = 0; i < spec.length(); i++) {
            char ch = spec.charAt(i);
            if (ch == '*') {
                regex.append(".*");
            } else if (ch == '?') {
                regex.append('.');
            } else {
                regex.append(Pattern.quote(String.valueOf(ch)));
            }
        }
        return regex.toString();
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
        attachStatusContextMenu(table);
        return table;
    }

    /**
     * Gắn menu chuột phải để đổi trạng thái hàng loạt cho các dòng đang chọn.
     */
    private void attachStatusContextMenu(JTable table) {
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem markBypassItem = new JMenuItem("Mark as Bypass");
        markBypassItem.addActionListener(e -> applyStatusToSelectedRows(table, 6));
        popupMenu.add(markBypassItem);

        JMenuItem markRejectItem = new JMenuItem("Mark as Reject");
        markRejectItem.addActionListener(e -> applyStatusToSelectedRows(table, 5));
        popupMenu.add(markRejectItem);

        popupMenu.addSeparator();

        JMenuItem deleteSelectedItem = new JMenuItem("Delete selected");
        deleteSelectedItem.addActionListener(e -> deleteSelectedRows(table));
        popupMenu.add(deleteSelectedItem);

        popupMenu.addSeparator();

        JMenuItem copyApiListItem = new JMenuItem("Copy Endpoint List");
        copyApiListItem.addActionListener(e -> copySitemap(table));
        popupMenu.add(copyApiListItem);

        popupMenu.addSeparator();

        // Dựng lại request chứa đủ param (đã quét + chưa quét), lấy request gốc
        // và giá trị param từ chính Proxy history.
        JMenuItem rebuildRequestItem = new JMenuItem("Rebuild request with all params (from history) ➜ Repeater");
        rebuildRequestItem.addActionListener(e -> startRebuild(table, false));
        popupMenu.add(rebuildRequestItem);

        // Bản thứ hai: thay cookie bằng giá trị mới nhất trong cookie jar, vì request
        // trong history có thể đã hết session.
        JMenuItem rebuildWithCookiesItem = new JMenuItem("Rebuild request + refresh cookies from cookie jar ➜ Repeater");
        rebuildWithCookiesItem.addActionListener(e -> startRebuild(table, true));
        popupMenu.add(rebuildWithCookiesItem);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                showPopupIfNeeded(e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                showPopupIfNeeded(e);
            }

            private void showPopupIfNeeded(MouseEvent e) {
                if (!e.isPopupTrigger()) {
                    return;
                }

                int viewRow = table.rowAtPoint(e.getPoint());
                if (viewRow >= 0 && !table.isRowSelected(viewRow)) {
                    table.setRowSelectionInterval(viewRow, viewRow);
                }

                if (table.getSelectedRowCount() > 0) {
                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
    }

    private void applyStatusToSelectedRows(JTable table, int statusColumn) {
        int[] selectedViewRows = table.getSelectedRows();
        if (selectedViewRows.length == 0) {
            return;
        }

        List<Integer> selectedModelRows = new ArrayList<>();
        for (int viewRow : selectedViewRows) {
            selectedModelRows.add(table.convertRowIndexToModel(viewRow));
        }

        int updated = 0;
        int skipped = 0;
        for (int modelRow : selectedModelRows) {
            if (canApplyStatus(modelRow, statusColumn)) {
                tableModel.setValueAt(true, modelRow, statusColumn);
                updated++;
            } else {
                skipped++;
            }
        }

        if (skipped > 0) {
            String statusName = statusColumn == 5 ? "Reject" : "Bypass";
            JOptionPane.showMessageDialog(null,
                    statusName + " applied to " + updated + " row(s). Skipped " + skipped + " row(s) because they are not eligible.");
        }
    }

    /**
     * Lấy dữ liệu các dòng đang chọn trên EDT rồi dựng request ở luồng nền.
     * Dùng chung luồng với bộ quét history để không bao giờ có hai lượt duyệt history song song.
     *
     * @param refreshCookies true để thay cookie bằng giá trị mới nhất trong cookie jar.
     */
    private void startRebuild(JTable table, boolean refreshCookies) {
        int[] selectedViewRows = table.getSelectedRows();
        if (selectedViewRows.length == 0) {
            return;
        }

        List<Integer> ids = new ArrayList<>(selectedViewRows.length);
        List<Object[]> targets = new ArrayList<>(selectedViewRows.length);
        for (int viewRow : selectedViewRows) {
            int modelRow = table.convertRowIndexToModel(viewRow);
            Object id = tableModel.getValueAt(modelRow, 8);
            if (id instanceof Integer dbId) {
                ids.add(dbId);
            }
            targets.add(new Object[]{
                    tableModel.getValueAt(modelRow, 0),
                    tableModel.getValueAt(modelRow, 1),
                    tableModel.getValueAt(modelRow, 2),
                    id});
        }

        // Một truy vấn cho tất cả dòng được chọn, thay vì một truy vấn mỗi dòng.
        runOnDbThread(() -> {
            Map<Integer, Set<String>> paramsById = databaseManager.getParamsByIds(ids);
            runOnSweeperThread(() -> {
                String report;
                try {
                    report = rebuildRequestsFromHistory(targets, paramsById, refreshCookies);
                } catch (Throwable t) {
                    report = "Rebuild thất bại: " + t.getMessage();
                    api.logging().logToError("Failed to rebuild request from history: " + t.getMessage());
                }
                final String message = report;
                api.logging().logToOutput(message);
                SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
                        null, message, "Rebuild request from history", JOptionPane.INFORMATION_MESSAGE));
            });
        });
    }

    /**
     * Dựng lại request cho các API được chọn, chứa đầy đủ param đã quét + chưa quét.
     * <p>
     * Toàn bộ dữ liệu đều lấy từ Proxy history thật: request gốc là một request đã đi qua Burp,
     * giá trị param cũng là giá trị đã quan sát được. Param chưa từng thấy trong history được
     * thêm với giá trị RỖNG - extension không tự sinh giá trị, và không mượn giá trị của API khác.
     * History chỉ được duyệt một lượt cho tất cả API được chọn.
     *
     * @param targets        Mỗi phần tử là {method, host, path, dbId} của một dòng trên bảng.
     * @param paramsById     Tham số đã biết của từng dòng, lấy sẵn bằng một truy vấn.
     * @param refreshCookies true để lấy cookie mới nhất từ cookie jar thay cho cookie trong history.
     * @return Báo cáo để hiển thị cho người dùng.
     */
    private String rebuildRequestsFromHistory(List<Object[]> targets, Map<Integer, Set<String>> paramsById,
                                              boolean refreshCookies) {
        Map<String, RebuildTarget> byKey = new LinkedHashMap<>();
        for (Object[] row : targets) {
            if (!(row[0] instanceof String method) || !(row[1] instanceof String host)
                    || !(row[2] instanceof String path) || !(row[3] instanceof Integer dbId)) {
                continue;
            }
            // Dòng ghi trước khi có rule vẫn lưu path thô: normalize lại để khớp key của history
            // (path đã normalize thì normalize thêm lần nữa không đổi). Chiều ngược lại - dòng đã
            // có {placeholder} mà rule hiện tại không tái tạo được - do findByPlaceholder xử lý.
            String storedPath = normalizePath(path);
            byKey.put(DatabaseManager.statusKey(method, host, storedPath),
                    new RebuildTarget(method, host, storedPath, paramsById.getOrDefault(dbId, Set.of()), refreshCookies));
        }
        if (byKey.isEmpty()) {
            return "Không có dòng hợp lệ nào được chọn.";
        }

        observeHistory(byKey);

        StringBuilder report = new StringBuilder();
        for (RebuildTarget target : byKey.values()) {
            report.append(target.rebuildAndSend()).append('\n');
        }
        return report.toString().trim();
    }

    /**
     * Duyệt Proxy history MỘT lượt, đưa mỗi request khớp vào target tương ứng.
     */
    private void observeHistory(Map<String, RebuildTarget> byKey) {
        for (ProxyHttpRequestResponse item : api.proxy().history()) {
            HttpRequest request = item.request();
            if (request == null) {
                continue;
            }
            String rawPath = request.pathWithoutQuery();
            if (rawPath == null || rawPath.isEmpty()) {
                continue;
            }
            String method = request.method();
            String host = request.httpService().host();
            RebuildTarget target = byKey.get(DatabaseManager.statusKey(method, host, normalizePath(rawPath)));
            if (target == null) {
                // Rule hiện tại có thể không cho ra đúng dạng đã lưu trong DB (rule đổi, hoặc
                // rỗng): khớp path thô với path đã lưu, coi mỗi {placeholder} là một segment.
                target = findByPlaceholder(byKey.values(), method, host, rawPath);
            }
            if (target != null) {
                target.observe(request);
            }
        }
    }

    /**
     * Chọn target cho một path thô: mỗi {placeholder} chỉ nhận segment thoả regex của rule
     * cùng tên ({uuid}=uuid thì "Pentest1" không khớp - với rule đang nạp, path đó là một
     * endpoint khác và được lưu thành dòng riêng). Placeholder không có rule cùng tên (rule đã
     * xoá/đổi tên) thì nhận segment bất kỳ. Nhiều target cùng khớp thì lấy target cụ thể nhất.
     */
    private static RebuildTarget findByPlaceholder(Collection<RebuildTarget> targets, String method, String host, String rawPath) {
        RebuildTarget best = null;
        for (RebuildTarget target : targets) {
            if (!target.method.equals(method) || !target.host.equals(host) || !target.matchesRawPath(rawPath)) {
                continue;
            }
            if (best == null || moreSpecific(target.path, target.literalLength, best.path, best.literalLength)) {
                best = target;
            }
        }
        return best;
    }

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{[^/{}]*\\}");

    /**
     * Regex segment của các rule KHÔNG path-aware, khoá theo placeholder ({id} -> [0-9]+).
     * Nhiều rule cùng placeholder thì ghép bằng |. Rule path-aware không có regex cho riêng
     * một segment nên không đưa vào; với chúng, "thoả rule" nghĩa là key normalize khớp,
     * tầng đó đã được thử trước khi tới đây.
     */
    private Map<String, String> segmentRuleRegexByPlaceholder() {
        Map<String, String> byPlaceholder = new HashMap<>();
        for (PathParameterRule rule : compiledPathParameterRules) {
            if (rule.isPathAware()) {
                continue;
            }
            byPlaceholder.merge(rule.placeholder(), rule.pattern().pattern(), (a, b) -> a + "|" + b);
        }
        return byPlaceholder;
    }

    /**
     * Biến một path đã normalize thành pattern khớp path thô. Mỗi {placeholder} khớp regex
     * của rule cùng tên nếu có trong {@code segmentRegexByPlaceholder}, không thì khớp một
     * segment bất kỳ; phần còn lại khớp nguyên văn. Trả về null nếu không có placeholder nào.
     */
    static Pattern placeholderPattern(String normalizedPath, Map<String, String> segmentRegexByPlaceholder) {
        if (normalizedPath == null || normalizedPath.indexOf('{') < 0) {
            return null;
        }
        Matcher matcher = PLACEHOLDER.matcher(normalizedPath);
        StringBuilder regex = new StringBuilder("^");
        int last = 0;
        while (matcher.find()) {
            String segmentRegex = segmentRegexByPlaceholder.get(matcher.group());
            regex.append(Pattern.quote(normalizedPath.substring(last, matcher.start())))
                    .append(segmentRegex == null ? "[^/]+" : "(?:" + segmentRegex + ")");
            last = matcher.end();
        }
        regex.append(Pattern.quote(normalizedPath.substring(last))).append("$");
        return Pattern.compile(regex.toString());
    }

    /**
     * Ứng viên cụ thể hơn: phần literal dài hơn; bằng nhau thì theo thứ tự chữ cái để kết quả
     * ổn định giữa các lần chạy (statusCache là ConcurrentHashMap, thứ tự duyệt không cố định).
     */
    private static boolean moreSpecific(String candidate, int candidateLiteral, String current, int currentLiteral) {
        if (candidateLiteral != currentLiteral) {
            return candidateLiteral > currentLiteral;
        }
        return candidate.compareTo(current) < 0;
    }

    /** Độ dài phần literal của path đã normalize: càng dài càng cụ thể. */
    static int literalLength(String normalizedPath) {
        return normalizedPath == null ? 0 : PLACEHOLDER.matcher(normalizedPath).replaceAll("").length();
    }

    /**
     * Điền các tham số còn thiếu vào request đang mở trong editor (Repeater/Intruder).
     * <p>
     * Khác với menu Rebuild: request nền ở đây là chính request người dùng đang sửa, nên
     * mọi thay đổi họ đã gõ được giữ nguyên; chỉ những tham số Recheck Scan biết mà request
     * chưa có mới được thêm vào. Giá trị lấy từ Proxy history, chưa từng thấy thì để rỗng.
     * Tham số đã biết lấy từ {@link #statusCache} nên không cần chạm CSDL.
     */
    private void fillMissingParamsInEditor(MessageEditorHttpRequestResponse editor, boolean refreshCookies) {
        HttpRequest current = editor.requestResponse().request();
        if (current == null) {
            return;
        }
        String method = current.method();
        String host = current.httpService().host();
        String rawPath = current.pathWithoutQuery();
        String label = method + " " + host + rawPath;

        Map.Entry<String, DatabaseManager.ApiStatus> match = findStatusForRawPath(method, host, rawPath);
        if (match == null) {
            showInfoDialog(label + ":\nAPI này chưa có trong Recheck Scan.");
            return;
        }
        // Dùng đúng path đã lưu trong DB làm định danh, để history cũng khớp theo dạng đó.
        final String path = match.getKey();
        final Set<String> knownParams = match.getValue().knownParams;
        if (knownParams.isEmpty()) {
            showInfoDialog(label + ":\nAPI có trong Recheck Scan (" + path
                    + ") nhưng không có tham số nào được ghi nhận - không có gì để điền.");
            return;
        }

        // Duyệt history trên luồng của sweeper để không bao giờ có hai lượt duyệt song song.
        runOnSweeperThread(() -> {
            try {
                RebuildTarget target = new RebuildTarget(method, host, path, knownParams, refreshCookies);
                observeHistory(Map.of(DatabaseManager.statusKey(method, host, path), target));

                FillReport report = new FillReport();
                HttpRequest filled = target.fillMissingParams(current, report);

                String summary = method + " " + host + path + ": thêm " + report.added + " param còn thiếu, "
                        + report.fromHistory + " lấy giá trị từ Proxy history"
                        + " (" + knownParams.size() + " param đã biết)." + report.details();
                api.logging().logToOutput(summary);

                boolean nothingChanged = report.added == 0 && report.fromHistory == 0
                        && report.cookieChanges.isEmpty();
                SwingUtilities.invokeLater(() -> {
                    if (!nothingChanged) {
                        editor.setRequest(filled);
                    }
                    // Chỉ làm phiền khi không có gì thay đổi hoặc có param Burp không chèn được;
                    // trường hợp bình thường, nội dung editor đổi ngay trước mắt là đủ.
                    if (nothingChanged) {
                        JOptionPane.showMessageDialog(null,
                                method + " " + host + path + ":\nRequest đã có đủ tham số Recheck Scan biết.",
                                "Recheck Scan", JOptionPane.INFORMATION_MESSAGE);
                    } else if (!report.failedParams.isEmpty()) {
                        JOptionPane.showMessageDialog(null, summary, "Recheck Scan", JOptionPane.WARNING_MESSAGE);
                    }
                });
            } catch (Throwable t) {
                api.logging().logToError("Failed to fill missing params: " + t.getMessage());
                showInfoDialog("Fill missing params thất bại: " + t.getMessage());
            }
        });
    }

    /**
     * Tìm trạng thái của API cho một path thô: thử key normalize theo rule hiện tại, rồi key
     * thô, cuối cùng quét các path đã lưu có placeholder và khớp theo từng segment. Nhờ vậy
     * request /api/users/123 vẫn tìm ra dòng /api/users/{id} kể cả khi rule đã đổi hoặc rỗng.
     *
     * @return Cặp (path đã lưu trong DB, trạng thái), hoặc null nếu không có.
     */
    private Map.Entry<String, DatabaseManager.ApiStatus> findStatusForRawPath(String method, String host, String rawPath) {
        for (String candidate : new String[]{normalizePath(rawPath), rawPath}) {
            DatabaseManager.ApiStatus status = statusCache.get(DatabaseManager.statusKey(method, host, candidate));
            if (status != null) {
                return Map.entry(candidate, status);
            }
        }
        String prefix = method + '\u0000' + host + '\u0000';
        Map<String, String> segmentRegex = segmentRuleRegexByPlaceholder();
        // Placeholder phải thoả rule cùng tên (không có rule thì nhận segment bất kỳ).
        // Nhiều dòng cùng khớp thì lấy dòng cụ thể nhất (phần literal dài nhất).
        Map.Entry<String, DatabaseManager.ApiStatus> best = null;
        for (Map.Entry<String, DatabaseManager.ApiStatus> entry : statusCache.entrySet()) {
            if (!entry.getKey().startsWith(prefix)) {
                continue;
            }
            String storedPath = entry.getKey().substring(prefix.length());
            Pattern pattern = placeholderPattern(storedPath, segmentRegex);
            if (pattern == null || !pattern.matcher(rawPath).matches()) {
                continue;
            }
            if (best == null || moreSpecific(storedPath, literalLength(storedPath), best.getKey(), literalLength(best.getKey()))) {
                best = Map.entry(storedPath, entry.getValue());
            }
        }
        return best;
    }

    private void showInfoDialog(String message) {
        SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(
                null, message, "Recheck Scan", JOptionPane.INFORMATION_MESSAGE));
    }

    /**
     * Thu thập dữ liệu thật từ history cho một API, rồi điền các tham số còn thiếu vào
     * một request: request gốc lấy từ history (menu Rebuild) hoặc chính request đang mở
     * trong Repeater (menu Fill missing params).
     */
    private class RebuildTarget {
        private final String method;
        private final String host;
        private final String path;
        private final Set<String> wantedParams;
        private final boolean refreshCookies;

        /** Request gốc: chọn request khớp có nhiều param nhất (bằng nhau thì lấy bản mới nhất). */
        private HttpRequest baseRequest;
        private int baseParamCount = -1;
        private int matchedItems = 0;
        /** Giá trị param đã quan sát được trong history, ưu tiên giá trị mới nhất khác rỗng. */
        private final Map<String, HttpParameter> observedParams = new HashMap<>();
        /** Pattern khớp path thô theo placeholder, null nếu path không có placeholder. */
        private final Pattern pathPattern;
        private final int literalLength;

        private RebuildTarget(String method, String host, String path, Set<String> wantedParams, boolean refreshCookies) {
            this.method = method;
            this.host = host;
            this.path = path;
            this.wantedParams = wantedParams == null ? Set.of() : wantedParams;
            this.refreshCookies = refreshCookies;
            this.pathPattern = placeholderPattern(path, segmentRuleRegexByPlaceholder());
            this.literalLength = literalLength(path);
        }

        private boolean matchesRawPath(String rawPath) {
            return pathPattern != null && rawPath != null && pathPattern.matcher(rawPath).matches();
        }

        private void observe(HttpRequest request) {
            matchedItems++;
            List<ParsedHttpParameter> params = request.parameters();
            int paramCount = params == null ? 0 : params.size();
            if (paramCount >= baseParamCount) {
                baseParamCount = paramCount;
                baseRequest = request;
            }
            if (params == null) {
                return;
            }
            for (ParsedHttpParameter param : params) {
                if (param.name() == null) {
                    continue;
                }
                HttpParameter known = observedParams.get(param.name());
                // Đã có giá trị thật thì không để giá trị rỗng ghi đè.
                if (known != null && !isBlankValue(known.value()) && isBlankValue(param.value())) {
                    continue;
                }
                observedParams.put(param.name(), HttpParameter.parameter(
                        param.name(), param.value() == null ? "" : param.value(), param.type()));
            }
        }

        /** Dựng lại request từ history rồi gửi sang Repeater. */
        private String rebuildAndSend() {
            String label = method + " " + host + path;
            if (baseRequest == null) {
                return label + ": KHÔNG tái tạo - không có request nào trong Proxy history khớp "
                        + path + (pathPattern == null ? "" : " (mỗi {..} = một segment thoả rule cùng tên)")
                        + " (dựng mới sẽ phải bịa toàn bộ header/giá trị).";
            }

            FillReport report = new FillReport();
            HttpRequest rebuilt = fillMissingParams(baseRequest, report);
            api.repeater().sendToRepeater(rebuilt, repeaterTabName());

            return label + ": đã gửi sang Repeater - " + wantedParams.size() + " param trong CSDL, "
                    + baseParamCount + " có sẵn trong request gốc, "
                    + report.fromHistory + " lấy giá trị từ request khác trong history"
                    + " (" + matchedItems + " request khớp)." + report.details();
        }

        /**
         * Điền các tham số còn thiếu vào {@code target}, giữ nguyên những gì đã có trong đó.
         * <p>
         * Giá trị chỉ lấy từ history; tham số chưa từng thấy được thêm với giá trị RỖNG.
         * Extension không tự sinh giá trị và không mượn giá trị của API khác.
         */
        private HttpRequest fillMissingParams(HttpRequest target, FillReport report) {
            Map<String, String> targetValues = new HashMap<>();
            for (ParsedHttpParameter param : target.parameters()) {
                targetValues.put(param.name(), param.value());
            }

            List<HttpParameter> toAdd = new ArrayList<>();
            List<HttpParameter> toUpdate = new ArrayList<>();
            HttpParameterType fallbackType = inferFallbackType(target);

            for (String name : new TreeSet<>(wantedParams)) {
                HttpParameter observed = observedParams.get(name);
                if (targetValues.containsKey(name)) {
                    // Đã có trong request: chỉ bù giá trị nếu đang rỗng mà history có giá trị thật.
                    if (observed != null && !isBlankValue(observed.value()) && isBlankValue(targetValues.get(name))) {
                        toUpdate.add(observed);
                        report.fromHistory++;
                    }
                    continue;
                }
                if (observed != null) {
                    toAdd.add(observed);
                    report.fromHistory++;
                    continue;
                }
                report.emptyParams.add(name);
                toAdd.add(HttpParameter.parameter(name, "", fallbackType));
            }
            report.fallbackType = fallbackType;
            report.added = toAdd.size();

            HttpRequest result = target;
            for (HttpParameter param : toAdd) {
                try {
                    result = result.withAddedParameters(param);
                } catch (RuntimeException e) {
                    report.failedParams.add(param.name() + " (" + param.type() + ")");
                }
            }
            for (HttpParameter param : toUpdate) {
                try {
                    result = result.withUpdatedParameters(param);
                } catch (RuntimeException e) {
                    report.failedParams.add(param.name() + " (" + param.type() + ")");
                }
            }

            if (refreshCookies) {
                result = applyCookieJar(result, target.pathWithoutQuery(), report);
            }
            return result;
        }

        /**
         * Thay cookie của request bằng giá trị mới nhất trong cookie jar của Burp.
         * Giá trị vẫn là giá trị thật Burp quan sát được từ `Set-Cookie`, chỉ mới hơn cookie
         * trong history. Giá trị cũ được ghi vào báo cáo để có thể tự trả lại.
         */
        private HttpRequest applyCookieJar(HttpRequest request, String realPath, FillReport report) {
            Map<String, String> currentCookies = new HashMap<>();
            for (ParsedHttpParameter param : request.parameters()) {
                if (param.type() == HttpParameterType.COOKIE) {
                    currentCookies.put(param.name(), param.value());
                }
            }

            HttpRequest result = request;
            for (Cookie cookie : matchingCookies(host, realPath)) {
                String currentValue = currentCookies.get(cookie.name());
                String newValue = cookie.value() == null ? "" : cookie.value();
                if (currentCookies.containsKey(cookie.name()) && Objects.equals(currentValue, newValue)) {
                    continue; // đã đúng giá trị mới nhất
                }
                HttpParameter replacement = HttpParameter.cookieParameter(cookie.name(), newValue);
                try {
                    result = currentCookies.containsKey(cookie.name())
                            ? result.withUpdatedParameters(replacement)
                            : result.withAddedParameters(replacement);
                } catch (RuntimeException e) {
                    report.failedParams.add(cookie.name() + " (COOKIE)");
                    continue;
                }
                report.cookieChanges.add(currentCookies.containsKey(cookie.name())
                        ? cookie.name() + " (cũ: " + shortenValue(currentValue) + ")"
                        : cookie.name() + " (mới)");
            }
            return result;
        }

        /**
         * Suy ra type cho param chưa từng thấy, dựa trên chính request đích
         * (suy ra type, không suy ra giá trị). Mặc định là URL.
         */
        private HttpParameterType inferFallbackType(HttpRequest request) {
            Map<HttpParameterType, Integer> counts = new EnumMap<>(HttpParameterType.class);
            for (ParsedHttpParameter param : request.parameters()) {
                if (param.type() == HttpParameterType.COOKIE) {
                    continue; // cookie không phải param của API
                }
                counts.merge(param.type(), 1, Integer::sum);
            }
            return counts.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .map(Map.Entry::getKey)
                    .orElse(HttpParameterType.URL);
        }

        private String repeaterTabName() {
            String name = method + " " + path;
            return name.length() <= 40 ? name : name.substring(0, 40);
        }
    }

    /** Kết quả của một lần điền tham số, dùng để báo lại cho người dùng. */
    private static class FillReport {
        private int fromHistory = 0;
        private int added = 0;
        private HttpParameterType fallbackType = HttpParameterType.URL;
        private final List<String> emptyParams = new ArrayList<>();
        private final List<String> failedParams = new ArrayList<>();
        private final List<String> cookieChanges = new ArrayList<>();

        private String details() {
            StringBuilder sb = new StringBuilder();
            if (!emptyParams.isEmpty()) {
                sb.append("\n  - ").append(emptyParams.size())
                        .append(" param không có trong history nên để giá trị RỖNG (type ")
                        .append(fallbackType).append(" suy từ request): ")
                        .append(String.join(", ", emptyParams));
            }
            if (!cookieChanges.isEmpty()) {
                sb.append("\n  - Cookie jar: ").append(cookieChanges.size()).append(" cookie được làm mới: ")
                        .append(String.join(", ", cookieChanges));
            }
            if (!failedParams.isEmpty()) {
                sb.append("\n  - Burp không chèn được: ").append(String.join(", ", failedParams));
            }
            return sb.toString();
        }
    }

    private static boolean isBlankValue(String value) {
        return value == null || value.isBlank();
    }

    /**
     * Cookie trong jar khớp với host + path của request và chưa hết hạn.
     * CookieJar không có API "lấy cookie cho URL này" nên phải tự khớp,
     * nếu không sẽ gửi cookie của site khác sang API này.
     */
    private List<Cookie> matchingCookies(String host, String requestPath) {
        List<Cookie> matched = new ArrayList<>();
        if (host == null) {
            return matched;
        }
        ZonedDateTime now = ZonedDateTime.now();
        for (Cookie cookie : api.http().cookieJar().cookies()) {
            if (cookie.name() == null || !cookieDomainMatches(host, cookie.domain())) {
                continue;
            }
            if (!cookiePathMatches(requestPath, cookie.path())) {
                continue;
            }
            // expiration() rỗng = session cookie (không hết hạn), không được coi là đã hết hạn.
            if (cookie.expiration().isPresent() && cookie.expiration().get().isBefore(now)) {
                continue;
            }
            matched.add(cookie);
        }
        return matched;
    }

    /** Khớp host với domain của cookie, hỗ trợ cả dạng ".example.com" cho subdomain. */
    static boolean cookieDomainMatches(String host, String cookieDomain) {
        if (host == null || cookieDomain == null) {
            return false;
        }
        String normalizedHost = host.toLowerCase(Locale.ROOT);
        String domain = cookieDomain.toLowerCase(Locale.ROOT);
        if (domain.startsWith(".")) {
            domain = domain.substring(1);
        }
        if (domain.isEmpty()) {
            return false;
        }
        return normalizedHost.equals(domain) || normalizedHost.endsWith("." + domain);
    }

    /** Khớp path theo RFC 6265: bằng nhau, cookie path kết thúc bằng "/", hoặc biên là "/". */
    static boolean cookiePathMatches(String requestPath, String cookiePath) {
        if (cookiePath == null || cookiePath.isEmpty() || cookiePath.equals("/")) {
            return true;
        }
        if (requestPath == null || !requestPath.startsWith(cookiePath)) {
            return false;
        }
        return requestPath.length() == cookiePath.length()
                || cookiePath.endsWith("/")
                || requestPath.charAt(cookiePath.length()) == '/';
    }

    /** Rút ngắn giá trị cookie khi đưa vào báo cáo. */
    private static String shortenValue(String value) {
        if (value == null) {
            return "";
        }
        return value.length() <= 12 ? value : value.substring(0, 12) + "...";
    }

    private void copySitemap(JTable table) {
        int[] selectedViewRows = table.getSelectedRows();
        if (selectedViewRows.length == 0) {
            return;
        }

        // Thu thập id trước, rồi lấy tham số của tất cả bằng MỘT truy vấn thay vì
        // một truy vấn cho mỗi dòng: với 5000 dòng chọn, cách cũ mất hơn một giây.
        List<Integer> ids = new ArrayList<>(selectedViewRows.length);
        for (int viewRow : selectedViewRows) {
            ids.add((Integer) tableModel.getValueAt(table.convertRowIndexToModel(viewRow), 8));
        }
        Map<Integer, Set<String>> paramsById = databaseManager.getParamsByIds(ids);

        StringBuilder sb = new StringBuilder();
        for (int viewRow : selectedViewRows) {
            int modelRow = table.convertRowIndexToModel(viewRow);
            String method = String.valueOf(tableModel.getValueAt(modelRow, 0));
            String path = String.valueOf(tableModel.getValueAt(modelRow, 2));
            Set<String> params = paramsById.getOrDefault(tableModel.getValueAt(modelRow, 8), Set.of());

            sb.append(method).append(" ").append(path);
            if (!params.isEmpty()) {
                sb.append(" - param: ").append(params.stream().sorted().collect(Collectors.joining(", ")));
            }
            sb.append("\n");
        }

        StringSelection selection = new StringSelection(sb.toString().trim());
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
    }

    private void deleteSelectedRows(JTable table) {
        int[] selectedViewRows = table.getSelectedRows();
        if (selectedViewRows.length == 0) {
            return;
        }

        List<Integer> idsToDelete = new ArrayList<>();
        for (int viewRow : selectedViewRows) {
            int modelRow = table.convertRowIndexToModel(viewRow);
            String host = String.valueOf(tableModel.getValueAt(modelRow, 1));
            String path = String.valueOf(tableModel.getValueAt(modelRow, 2));

            boolean inScope = api.scope().isInScope("http://" + host + path)
                    || api.scope().isInScope("https://" + host + path);
            if (inScope) {
                continue;
            }

            int id = (int) tableModel.getValueAt(modelRow, 8);
            idsToDelete.add(id);
        }

        if (idsToDelete.isEmpty()) {
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(
                null,
                "Are you sure you want to delete " + idsToDelete.size() + " selected API(s)?",
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) {
            return;
        }

        runOnDbThread(() -> {
            databaseManager.deleteApisByIds(idsToDelete);
            List<Object[]> rows = databaseManager.loadApiData();
            Map<String, DatabaseManager.ApiStatus> statuses = databaseManager.loadStatusIndex();
            statusCache.clear();
            statusCache.putAll(statuses);
            SwingUtilities.invokeLater(() -> populateTable(rows));
        });
    }

    private boolean canApplyStatus(int modelRow, int statusColumn) {
        boolean isScanned = Boolean.TRUE.equals(tableModel.getValueAt(modelRow, 4));
        if (isScanned) {
            return false;
        }

        if (statusColumn == 5) {
            return Boolean.TRUE.equals(tableModel.getValueAt(modelRow, 7));
        }

        return statusColumn == 6;
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

    private RowFilter<Object, Object> createPathSearchFilter(String keyword) {
        if (keyword == null || keyword.isEmpty()) {
            return null;
        }

        List<RowFilter<Object, Object>> filters = new ArrayList<>();
        filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(keyword), 2));

        String normalizedKeyword = normalizePath(keyword);
        if (normalizedKeyword != null && !normalizedKeyword.equals(keyword)) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(normalizedKeyword), 2));
        }

        return filters.size() == 1 ? filters.get(0) : RowFilter.orFilter(filters);
    }
    
    /**
     * Lưu các cài đặt hiện tại vào persistence extension data (đi theo project).
     */
    /** Mặc định khi cả Burp lẫn DB đều chưa có giá trị. */
    static final String DEFAULT_EXCLUDE_EXTENSIONS =
            ".js,.svg,.css,.png,.jpg,.ttf,.ico,.html,.map,.gif,.woff2,.bcmap,.jpeg,.woff";
    static final String DEFAULT_EXCLUDE_STATUS_CODES = "404,405";

    /** Các key cấu hình lưu trong DB (Burp chỉ giữ đường dẫn DB). */
    private static final List<String> DB_SETTING_KEYS = List.of(
            "exclude_extensions", "exclude_status_code", "path_parameter_rules", "ignored_parameter_rules",
            "highlightEnabled", "noteEnabled", "autoBypassNoParam", "autoAnnotateHistory", "annotationSweepMinBatch");

    /** Lưu: đường dẫn DB vào Burp (đồng bộ, rẻ), phần còn lại vào DB trên luồng CSDL. */
    private void saveSettings() {
        saveOutputPathToBurp();
        runOnDbThread(this::persistSettingsNow);
    }

    /** Ghi cấu hình hiện tại vào DB ngay trên luồng gọi; dùng khi đã ở luồng CSDL hoặc lúc khởi động. */
    private void persistSettingsNow() {
        databaseManager.saveSettings(settingsSnapshot());
    }

    /** Chụp cấu hình trong bộ nhớ thành map key -> value để ghi vào DB. */
    private Map<String, String> settingsSnapshot() {
        Map<String, String> snapshot = new LinkedHashMap<>();
        snapshot.put("exclude_extensions", valueOrEmpty(exclude_extensions));
        snapshot.put("exclude_status_code", valueOrEmpty(exclude_status_code));
        snapshot.put("path_parameter_rules", valueOrEmpty(path_parameter_rules));
        snapshot.put("ignored_parameter_rules", valueOrEmpty(ignored_parameter_rules));
        snapshot.put("highlightEnabled", String.valueOf(highlightEnabled));
        snapshot.put("noteEnabled", String.valueOf(noteEnabled));
        snapshot.put("autoBypassNoParam", String.valueOf(autoBypassNoParam));
        snapshot.put("autoAnnotateHistory", String.valueOf(autoAnnotateHistory));
        snapshot.put("annotationSweepMinBatch", String.valueOf(annotationSweepMinBatch));
        return snapshot;
    }

    /** Nạp map key -> value (từ DB hoặc từ Burp cũ) vào bộ nhớ và biên dịch lại rule. */
    private void applySettings(Map<String, String> settings) {
        exclude_extensions = settings.getOrDefault("exclude_extensions", DEFAULT_EXCLUDE_EXTENSIONS);
        exclude_status_code = settings.getOrDefault("exclude_status_code", DEFAULT_EXCLUDE_STATUS_CODES);
        path_parameter_rules = settings.getOrDefault("path_parameter_rules", "");
        ignored_parameter_rules = settings.getOrDefault("ignored_parameter_rules", "");
        highlightEnabled = Boolean.parseBoolean(settings.getOrDefault("highlightEnabled", "false"));
        noteEnabled = Boolean.parseBoolean(settings.getOrDefault("noteEnabled", "false"));
        autoBypassNoParam = Boolean.parseBoolean(settings.getOrDefault("autoBypassNoParam", "false"));
        autoAnnotateHistory = Boolean.parseBoolean(settings.getOrDefault("autoAnnotateHistory", "false"));
        annotationSweepMinBatch = parseSweepBatchSize(settings.get("annotationSweepMinBatch"));
        compiledPathParameterRules = compilePathParameterRules(path_parameter_rules);
        compiledIgnoredParameterRules = compileIgnoredParameterRules(ignored_parameter_rules);
        excludedStatusCodes = parseStatusCodes(exclude_status_code);
    }

    /**
     * Nạp cấu hình từ file DB đang mở. DB chưa có cấu hình (file mới, hoặc tạo bởi bản cũ
     * còn lưu mọi thứ trong Burp) thì lấy từ {@code legacyBurpSettings} rồi ghi vào DB -
     * đây là bước chuyển một lần cho người dùng cũ, không mất cấu hình đang có.
     */
    private void loadSettingsFromDatabase(Properties legacyBurpSettings) {
        loadOrSeedSettings(legacyBurpSettings);
    }

    /** Nguồn cấu hình đã nạp sau {@link #loadOrSeedSettings}. */
    enum SettingsSource { DATABASE, BURP_LEGACY, DEFAULTS }

    /**
     * Luồng nạp cấu hình dùng chung cho lúc khởi động và lúc đổi file DB:
     * 1. DB có cấu hình -> dùng DB.
     * 2. DB trống, project Burp còn key cũ (nâng cấp từ bản lưu mọi thứ trong Burp) -> lấy từ Burp.
     * 3. Cả hai đều trống (project và DB mới) -> giá trị mặc định.
     * Ở (2) và (3), kết quả được ghi vào DB để lần sau đi thẳng nhánh (1).
     * Key nào Burp cũ không có cũng nhận mặc định, qua {@link #applySettings}.
     */
    private SettingsSource loadOrSeedSettings(Properties burpProperties) {
        Map<String, String> fromDb = databaseManager.loadSettings();
        if (!fromDb.isEmpty()) {
            applySettings(fromDb);
            return SettingsSource.DATABASE;
        }
        Map<String, String> legacy = legacySettingsFromBurp(burpProperties);
        applySettings(legacy);
        persistSettingsNow();
        if (legacy.isEmpty()) {
            return SettingsSource.DEFAULTS;
        }
        api.logging().logToOutput("Migrated " + legacy.size() + " setting(s) from the Burp project into "
                + databaseManager.currentDbPath());
        return SettingsSource.BURP_LEGACY;
    }

    /** Các key cấu hình (không phải đường dẫn) mà project Burp còn giữ từ bản cũ. */
    private Map<String, String> legacySettingsFromBurp(Properties burpProperties) {
        Map<String, String> legacy = new LinkedHashMap<>();
        if (burpProperties == null) {
            return legacy;
        }
        for (String key : DB_SETTING_KEYS) {
            String value = burpProperties.getProperty(key);
            if (value != null) {
                legacy.put(key, value);
            }
        }
        return legacy;
    }

    /** Đọc nguyên Properties đang lưu trong project Burp (đường dẫn + key cũ nếu còn). */
    private Properties readBurpProperties() {
        Properties props = new Properties();
        try {
            String settingsStr = api.persistence().extensionData().getString("settings");
            if (settingsStr != null && !settingsStr.isEmpty()) {
                props.load(new StringReader(settingsStr));
            }
        } catch (Exception e) {
            api.logging().logToError("Failed to read settings from the Burp project: " + e.getMessage());
        }
        return props;
    }

    /**
     * Đưa cấu hình về mặc định: hỏi xác nhận, nạp mặc định vào bộ nhớ, lưu vào file DB đang mở
     * và hiện lên form. Đường dẫn DB và dữ liệu API giữ nguyên. Gọi từ EDT.
     */
    private void resetSettingsToDefault() {
        int answer = JOptionPane.showConfirmDialog(null,
                "Đưa toàn bộ cấu hình về mặc định và lưu vào file DB đang mở?\n"
                        + "Đường dẫn DB và dữ liệu API không bị ảnh hưởng.",
                "Reset Default", JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (answer != JOptionPane.OK_OPTION) {
            return;
        }
        // Map rỗng -> mọi key vắng mặt -> applySettings() dùng giá trị mặc định.
        applySettings(Map.of());
        pendingAnnotationKeys.clear();
        if (settingsForm != null) {
            settingsForm.showCurrentValues();
        }
        runOnDbThread(this::persistSettingsNow);
    }

    /** Ghi duy nhất đường dẫn DB vào Burp; các key cấu hình cũ (nếu còn) được dọn đi. */
    private void saveOutputPathToBurp() {
        try {
            Properties props = new Properties();
            props.setProperty(currentOutputPathKey(), valueOrEmpty(savedOutputPath));
            StringWriter writer = new StringWriter();
            props.store(writer, null);
            api.persistence().extensionData().setString("settings", writer.toString());
        } catch (Exception ex) {
            api.logging().logToError("Failed to save database path to the Burp project: " + ex.getMessage());
        }
    }

    /**
     * Đổi sang file DB khác: mở file, nạp cấu hình của file đó lên bộ nhớ và form, tải lại bảng.
     * File chưa có cấu hình thì được gieo bằng cấu hình đang dùng. Gọi từ EDT.
     */
    private void switchDatabase(String requestedPath) {
        // Đọc Burp TRƯỚC khi ghi lại path: ngay sau nâng cấp Burp vẫn còn key cũ để gieo cho file mới.
        Properties burpProperties = readBurpProperties();
        savedOutputPath = requestedPath;
        saveOutputPathToBurp();
        runOnDbThread(() -> {
            databaseManager.reopen(requestedPath);
            SettingsSource source = loadOrSeedSettings(burpProperties);
            pendingAnnotationKeys.clear();
            List<Object[]> rows = databaseManager.loadApiData();
            Map<String, DatabaseManager.ApiStatus> statuses = databaseManager.loadStatusIndex();
            statusCache.clear();
            statusCache.putAll(statuses);
            String dbPath = databaseManager.currentDbPath();
            SwingUtilities.invokeLater(() -> {
                if (settingsForm != null) {
                    settingsForm.showCurrentValues();
                }
                populateTable(rows);
                JOptionPane.showMessageDialog(null, "Đã mở " + dbPath + "\n" + switch (source) {
                    case DATABASE -> "Đã nạp cấu hình lưu trong file này lên form.";
                    case BURP_LEGACY -> "File chưa có cấu hình, đã chuyển cấu hình cũ từ project Burp vào file.";
                    case DEFAULTS -> "File chưa có cấu hình, đã dùng giá trị mặc định.";
                });
            });
        });
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

    /**
     * Tải các cài đặt từ persistence extension data khi khởi động.
     */
    /**
     * Đọc đường dẫn DB từ Burp. Trả về toàn bộ Properties đã lưu để còn chuyển các key cấu
     * hình cũ (bản trước lưu mọi thứ ở đây) sang DB một lần.
     */
    private Properties loadOutputPathFromBurp() {
        Properties props = readBurpProperties();
        savedOutputPath = props.getProperty(currentOutputPathKey(), "");
        return props;
    }
    /**
     * Kiểm tra xem một mã trạng thái HTTP nhất định có nên bị loại trừ dựa trên cài đặt của người dùng hay không.
     * @param statusCode Mã trạng thái HTTP cần kiểm tra.
     * @return true nếu mã trạng thái nằm trong danh sách bị loại trừ, ngược lại là false.
     */
    private boolean isExcludedStatusCode(int statusCode) {
        return excludedStatusCodes.contains(statusCode);
    }

    /**
     * Phân tích chuỗi status code người dùng nhập thành tập hợp sẵn sàng tra cứu.
     * Biên dịch một lần tại thời điểm Apply thay vì parse lại cho từng response.
     */
    private Set<Integer> parseStatusCodes(String rawStatusCodes) {
        if (rawStatusCodes == null || rawStatusCodes.isBlank()) {
            return Set.of();
        }

        Set<Integer> codes = new HashSet<>();
        for (String rawCode : rawStatusCodes.split(",")) {
            String code = rawCode.trim();
            if (code.isEmpty()) {
                continue;
            }
            try {
                codes.add(Integer.parseInt(code));
            } catch (NumberFormatException e) {
                api.logging().logToError("Invalid status code in exclude list: " + code);
            }
        }
        return Set.copyOf(codes);
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
        if (annotationSweeper != null) {
            annotationSweeper.shutdownNow();
        }
        // Chờ các thao tác ghi đang dở hoàn tất để không mất dữ liệu, nhưng không chờ vô hạn.
        dbExecutor.shutdown();
        try {
            if (!dbExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                dbExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            dbExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        databaseManager.close();
    }
}
