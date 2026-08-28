package com.example.graphql;

import burp.api.montoya.MontoyaApi;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Quản lý toàn bộ thao tác SQLite cho phiên bản GraphQL của Recheck Scan.
 * <p>
 * Điểm khác biệt cốt lõi so với bản REST là "định danh" của một đơn vị theo dõi. Với GraphQL,
 * mọi request thường tới cùng một endpoint nên ta không dùng path để phân biệt. Thay vào đó ràng
 * buộc duy nhất là <b>(host, endpoint, operation_type, root_field)</b>. Các "tham số" được theo dõi
 * chính là tên argument của root field – tương đương query/body param trong REST.
 */
public class GraphQLDatabaseManager {

    private final MontoyaApi api;
    private Connection connection;
    private String dbPath;

    public GraphQLDatabaseManager(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Khởi tạo kết nối tới file SQLite và đảm bảo bảng đã sẵn sàng.
     *
     * @param savedOutputPath đường dẫn file DB do người dùng cấu hình (có thể rỗng -> dùng mặc định).
     */
    public void initialize(String savedOutputPath) {
        this.dbPath = getDbPath(savedOutputPath);
        try {
            Class.forName("org.sqlite.JDBC");
            File dbFile = new File(dbPath);
            File parentDir = dbFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }
            connection = DriverManager.getConnection("jdbc:sqlite:" + this.dbPath);
            api.logging().logToOutput("GraphQL Recheck Scan connected to SQLite database: " + this.dbPath);
            createTableIfNotExists();
        } catch (SQLException | ClassNotFoundException e) {
            api.logging().logToError("Failed to initialize GraphQL SQLite database: " + e.getMessage(), e);
        }
    }

    /**
     * Chuẩn hóa đường dẫn DB. Ưu tiên đường dẫn người dùng, đảm bảo đuôi ".db".
     */
    private String getDbPath(String savedOutputPath) {
        if (savedOutputPath != null && !savedOutputPath.isBlank()) {
            String path = savedOutputPath.toLowerCase().endsWith(".csv")
                    ? savedOutputPath.substring(0, savedOutputPath.length() - 4)
                    : savedOutputPath;
            return path.toLowerCase().endsWith(".db") ? path : path + ".db";
        }
        return new File(System.getProperty("java.io.tmpdir"), "RecheckScan/scan_graphql.db").getAbsolutePath();
    }

    /**
     * Bảng {@code graphql_log} – trung tâm lưu trạng thái scan của từng root field.
     */
    private void createTableIfNotExists() throws SQLException {
        String sql = """
            CREATE TABLE IF NOT EXISTS graphql_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,      -- Khóa chính tự tăng.
                host TEXT NOT NULL,                        -- Host của endpoint GraphQL.
                endpoint TEXT NOT NULL,                    -- Đường dẫn endpoint (vd: /graphql).
                operation_type TEXT NOT NULL,              -- query / mutation / subscription.
                operation_name TEXT,                       -- Tên operation gần nhất quan sát được (để hiển thị).
                root_field TEXT NOT NULL,                  -- Tên root field - "API" GraphQL.
                unscanned_args TEXT,                       -- Argument CHƯA scan, ngăn cách bởi '|'.
                scanned_args TEXT,                         -- Argument ĐÃ scan, ngăn cách bởi '|'.
                is_scanned BOOLEAN DEFAULT 0,              -- Đã scan hết argument.
                is_rejected BOOLEAN DEFAULT 0,             -- Người dùng từ chối scan.
                is_bypassed BOOLEAN DEFAULT 0,             -- Bỏ qua (vd: field không có argument).
                is_from_repeater BOOLEAN DEFAULT 0,        -- Đã gửi qua Repeater.
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(host, endpoint, operation_type, root_field)
            );
            """;
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
        }
    }

    /**
     * Tải toàn bộ dữ liệu để hiển thị trên bảng UI. Mỗi Object[] khớp thứ tự cột của TableModel:
     * {OperationType, OperationName, RootField, Host, Endpoint, UnscannedArgs, Scanned, Rejected,
     * Bypass, Repeater(hidden), id(hidden)}.
     */
    public synchronized List<Object[]> loadData() {
        List<Object[]> rows = new ArrayList<>();
        String sql = "SELECT id, host, endpoint, operation_type, operation_name, root_field, "
                + "unscanned_args, scanned_args, is_scanned, is_rejected, is_bypassed, is_from_repeater "
                + "FROM graphql_log ORDER BY id DESC";
        try (Statement stmt = connection.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                String unscanned = rs.getString("unscanned_args");
                String display = (unscanned == null || unscanned.isEmpty()) ? "" : unscanned.replace("|", ", ");
                rows.add(new Object[]{
                        rs.getString("operation_type"),
                        rs.getString("operation_name"),
                        rs.getString("root_field"),
                        rs.getString("host"),
                        rs.getString("endpoint"),
                        display,
                        rs.getBoolean("is_scanned"),
                        rs.getBoolean("is_rejected"),
                        rs.getBoolean("is_bypassed"),
                        rs.getBoolean("is_from_repeater"),
                        rs.getInt("id")
                });
            }
        } catch (SQLException e) {
            api.logging().logToError("Failed to load GraphQL data: " + e.getMessage(), e);
        }
        return rows;
    }

    /**
     * Chèn mới hoặc cập nhật một root field. Nếu phát hiện argument mới thì thêm vào unscanned và
     * reset is_scanned/is_bypassed để buộc scan lại.
     */
    public synchronized void insertOrUpdate(String host, String endpoint, String opType, String opName,
                                            String rootField, Set<String> args) {
        String selectSql = "SELECT unscanned_args, scanned_args FROM graphql_log "
                + "WHERE host = ? AND endpoint = ? AND operation_type = ? AND root_field = ?";
        try (PreparedStatement selectStmt = connection.prepareStatement(selectSql)) {
            selectStmt.setString(1, host);
            selectStmt.setString(2, endpoint);
            selectStmt.setString(3, opType);
            selectStmt.setString(4, rootField);
            ResultSet rs = selectStmt.executeQuery();

            if (rs.next()) {
                Set<String> unscannedSet = stringToSet(rs.getString("unscanned_args"));
                Set<String> scannedSet = stringToSet(rs.getString("scanned_args"));

                Set<String> known = new HashSet<>(unscannedSet);
                known.addAll(scannedSet);

                Set<String> newArgs = new HashSet<>(args);
                newArgs.removeAll(known);

                if (!newArgs.isEmpty()) {
                    unscannedSet.addAll(newArgs);
                    String updateSql = "UPDATE graphql_log SET unscanned_args = ?, is_scanned = 0, is_bypassed = 0, "
                            + "operation_name = ?, last_seen = CURRENT_TIMESTAMP "
                            + "WHERE host = ? AND endpoint = ? AND operation_type = ? AND root_field = ?";
                    try (PreparedStatement updateStmt = connection.prepareStatement(updateSql)) {
                        updateStmt.setString(1, setToString(unscannedSet));
                        updateStmt.setString(2, opName);
                        updateStmt.setString(3, host);
                        updateStmt.setString(4, endpoint);
                        updateStmt.setString(5, opType);
                        updateStmt.setString(6, rootField);
                        updateStmt.executeUpdate();
                    }
                }
            } else {
                String insertSql = "INSERT INTO graphql_log (host, endpoint, operation_type, operation_name, "
                        + "root_field, unscanned_args) VALUES (?, ?, ?, ?, ?, ?)";
                try (PreparedStatement insertStmt = connection.prepareStatement(insertSql)) {
                    insertStmt.setString(1, host);
                    insertStmt.setString(2, endpoint);
                    insertStmt.setString(3, opType);
                    insertStmt.setString(4, opName);
                    insertStmt.setString(5, rootField);
                    insertStmt.setString(6, setToString(args));
                    insertStmt.executeUpdate();
                }
            }
        } catch (SQLException e) {
            api.logging().logToError("Error during GraphQL insert/update: " + e.getMessage(), e);
        }
    }

    /**
     * Xử lý argument đã được Burp Scanner kiểm thử: những argument giao với danh sách chưa-scan sẽ
     * được chuyển sang danh sách đã-scan. Nếu hết argument chưa-scan thì đánh dấu is_scanned = 1.
     *
     * @return true nếu có thay đổi trong DB.
     */
    public synchronized boolean processScannedArgs(String host, String endpoint, String opType,
                                                   String rootField, Set<String> scannerArgs) {
        String selectSql = "SELECT unscanned_args, scanned_args FROM graphql_log "
                + "WHERE host = ? AND endpoint = ? AND operation_type = ? AND root_field = ?";
        try (PreparedStatement selectStmt = connection.prepareStatement(selectSql)) {
            selectStmt.setString(1, host);
            selectStmt.setString(2, endpoint);
            selectStmt.setString(3, opType);
            selectStmt.setString(4, rootField);
            ResultSet rs = selectStmt.executeQuery();

            if (rs.next()) {
                Set<String> unscannedDb = stringToSet(rs.getString("unscanned_args"));
                if (unscannedDb.isEmpty()) {
                    return false;
                }
                Set<String> newlyScanned = new HashSet<>(scannerArgs);
                newlyScanned.retainAll(unscannedDb);
                if (newlyScanned.isEmpty()) {
                    return false;
                }
                Set<String> scannedDb = stringToSet(rs.getString("scanned_args"));
                unscannedDb.removeAll(newlyScanned);
                scannedDb.addAll(newlyScanned);

                String updateSql = "UPDATE graphql_log SET unscanned_args = ?, scanned_args = ?, is_scanned = ?, "
                        + "last_seen = CURRENT_TIMESTAMP "
                        + "WHERE host = ? AND endpoint = ? AND operation_type = ? AND root_field = ?";
                try (PreparedStatement updateStmt = connection.prepareStatement(updateSql)) {
                    updateStmt.setString(1, setToString(unscannedDb));
                    updateStmt.setString(2, setToString(scannedDb));
                    updateStmt.setBoolean(3, unscannedDb.isEmpty());
                    updateStmt.setString(4, host);
                    updateStmt.setString(5, endpoint);
                    updateStmt.setString(6, opType);
                    updateStmt.setString(7, rootField);
                    updateStmt.executeUpdate();
                    return true;
                }
            }
        } catch (SQLException e) {
            api.logging().logToError("Error during GraphQL processScannedArgs: " + e.getMessage(), e);
        }
        return false;
    }

    /**
     * Đánh dấu CẢ operation là đã scan (gom hết unscanned_args sang scanned_args, is_scanned=1).
     * Chỉ áp dụng khi operation đã tồn tại và chưa scan hết — KHÔNG tạo dòng mới từ request Scanner
     * (vì request Scanner thường đã bị biến đổi). Dùng cho luồng: có request từ Scanner chạm tới
     * operation này => coi như operation đã được audit.
     *
     * @return true nếu có thay đổi.
     */
    public synchronized boolean markOperationScanned(String host, String endpoint, String opType, String rootField) {
        String selectSql = "SELECT unscanned_args, scanned_args FROM graphql_log "
                + "WHERE host = ? AND endpoint = ? AND operation_type = ? AND root_field = ?";
        try (PreparedStatement sel = connection.prepareStatement(selectSql)) {
            sel.setString(1, host);
            sel.setString(2, endpoint);
            sel.setString(3, opType);
            sel.setString(4, rootField);
            ResultSet rs = sel.executeQuery();
            if (!rs.next()) {
                return false; // operation chưa từng thấy qua Proxy/Repeater -> không tạo mới.
            }
            Set<String> unscanned = stringToSet(rs.getString("unscanned_args"));
            Set<String> scanned = stringToSet(rs.getString("scanned_args"));
            if (unscanned.isEmpty()) {
                return false; // đã scan hết.
            }
            scanned.addAll(unscanned);
            String upd = "UPDATE graphql_log SET unscanned_args = '', scanned_args = ?, is_scanned = 1, "
                    + "last_seen = CURRENT_TIMESTAMP "
                    + "WHERE host = ? AND endpoint = ? AND operation_type = ? AND root_field = ?";
            try (PreparedStatement u = connection.prepareStatement(upd)) {
                u.setString(1, setToString(scanned));
                u.setString(2, host);
                u.setString(3, endpoint);
                u.setString(4, opType);
                u.setString(5, rootField);
                u.executeUpdate();
                return true;
            }
        } catch (SQLException e) {
            api.logging().logToError("Error during markOperationScanned: " + e.getMessage(), e);
        }
        return false;
    }

    /**
     * Đánh dấu đã scan theo id (dùng cho menu "Mark as scanned" thủ công): gom unscanned sang
     * scanned và bật is_scanned=1.
     */
    public synchronized void markScannedById(int id) {
        String sel = "SELECT unscanned_args, scanned_args FROM graphql_log WHERE id = ?";
        try (PreparedStatement s = connection.prepareStatement(sel)) {
            s.setInt(1, id);
            ResultSet rs = s.executeQuery();
            if (!rs.next()) {
                return;
            }
            Set<String> unscanned = stringToSet(rs.getString("unscanned_args"));
            Set<String> scanned = stringToSet(rs.getString("scanned_args"));
            scanned.addAll(unscanned);
            String upd = "UPDATE graphql_log SET unscanned_args = '', scanned_args = ?, is_scanned = 1, "
                    + "is_rejected = 0, is_bypassed = 0, last_seen = CURRENT_TIMESTAMP WHERE id = ?";
            try (PreparedStatement u = connection.prepareStatement(upd)) {
                u.setString(1, setToString(scanned));
                u.setInt(2, id);
                u.executeUpdate();
            }
        } catch (SQLException e) {
            api.logging().logToError("Error during markScannedById: " + e.getMessage(), e);
        }
    }

    /**
     * Auto-bypass cho root field không có argument (không tồn tại injection point qua argument).
     * Chỉ bypass khi chưa scanned/rejected và không còn argument chưa-scan.
     */
    public synchronized boolean autoBypass(String host, String endpoint, String opType, String opName, String rootField) {
        String upsertSql = """
            INSERT INTO graphql_log (host, endpoint, operation_type, operation_name, root_field,
                                     unscanned_args, scanned_args, is_bypassed)
            VALUES (?, ?, ?, ?, ?, '', '', 1)
            ON CONFLICT(host, endpoint, operation_type, root_field) DO UPDATE SET
                is_bypassed = CASE
                    WHEN graphql_log.is_scanned = 0 AND graphql_log.is_rejected = 0 AND graphql_log.unscanned_args = ''
                    THEN 1
                    ELSE graphql_log.is_bypassed
                END,
                operation_name = excluded.operation_name,
                last_seen = CURRENT_TIMESTAMP
            """;
        try (PreparedStatement stmt = connection.prepareStatement(upsertSql)) {
            stmt.setString(1, host);
            stmt.setString(2, endpoint);
            stmt.setString(3, opType);
            stmt.setString(4, opName);
            stmt.setString(5, rootField);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            api.logging().logToError("Error during GraphQL autoBypass: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Đánh dấu một root field đã được gửi qua Repeater (chỉ khi trước đó chưa được đánh dấu).
     */
    public synchronized boolean updateRepeaterStatus(String host, String endpoint, String opType, String rootField) {
        String sql = "UPDATE graphql_log SET is_from_repeater = 1, last_seen = CURRENT_TIMESTAMP "
                + "WHERE host = ? AND endpoint = ? AND operation_type = ? AND root_field = ? AND is_from_repeater = 0";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, host);
            stmt.setString(2, endpoint);
            stmt.setString(3, opType);
            stmt.setString(4, rootField);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            api.logging().logToError("Error during GraphQL updateRepeaterStatus: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Lấy trạng thái (is_scanned, is_rejected, is_bypassed) để quyết định highlight/note.
     */
    public synchronized Object[] getStatus(String host, String endpoint, String opType, String rootField) {
        String sql = "SELECT is_scanned, is_rejected, is_bypassed FROM graphql_log "
                + "WHERE host = ? AND endpoint = ? AND operation_type = ? AND root_field = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, host);
            stmt.setString(2, endpoint);
            stmt.setString(3, opType);
            stmt.setString(4, rootField);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return new Object[]{rs.getBoolean("is_scanned"), rs.getBoolean("is_rejected"), rs.getBoolean("is_bypassed")};
            }
        } catch (SQLException e) {
            api.logging().logToError("Failed to get GraphQL status: " + e.getMessage(), e);
        }
        return null;
    }

    /**
     * Lấy toàn bộ argument (unscanned + scanned) của một dòng theo id (dùng cho context menu copy).
     */
    public synchronized Set<String> getAllArgsById(int id) {
        String sql = "SELECT unscanned_args, scanned_args FROM graphql_log WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, id);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                Set<String> all = new HashSet<>();
                all.addAll(stringToSet(rs.getString("unscanned_args")));
                all.addAll(stringToSet(rs.getString("scanned_args")));
                return all;
            }
        } catch (SQLException e) {
            api.logging().logToError("Failed to get GraphQL args by id: " + e.getMessage(), e);
        }
        return new HashSet<>();
    }

    /**
     * Áp dụng auto-bypass hồi tố cho các root field cũ không có argument.
     */
    public synchronized int applyAutoBypassToOldRecords() {
        String sql = """
            UPDATE graphql_log
            SET is_bypassed = 1, last_seen = CURRENT_TIMESTAMP
            WHERE (unscanned_args IS NULL OR unscanned_args = '')
              AND is_scanned = 0 AND is_rejected = 0 AND is_bypassed = 0
            """;
        try (Statement stmt = connection.createStatement()) {
            int affected = stmt.executeUpdate(sql);
            if (affected > 0) {
                api.logging().logToOutput("Retroactively bypassed " + affected + " GraphQL fields without arguments.");
            }
            return affected;
        } catch (SQLException e) {
            api.logging().logToError("Error during GraphQL retroactive auto-bypass: " + e.getMessage(), e);
            return 0;
        }
    }

    /**
     * Cập nhật một cột trạng thái boolean (is_scanned/is_rejected/is_bypassed) theo id.
     */
    public void updateStatus(int id, String columnName, boolean value) {
        if (!Arrays.asList("is_scanned", "is_rejected", "is_bypassed").contains(columnName)) {
            api.logging().logToError("Invalid column name for GraphQL status update.");
            return;
        }
        String sql = String.format("UPDATE graphql_log SET %s = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?", columnName);
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setBoolean(1, value);
            stmt.setInt(2, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            api.logging().logToError("Failed to update GraphQL status: " + e.getMessage(), e);
        }
    }

    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                api.logging().logToOutput("GraphQL database connection closed.");
            }
        } catch (SQLException e) {
            api.logging().logToError("Error closing GraphQL database connection: " + e.getMessage(), e);
        }
    }

    // ===================================================================================
    // Helpers
    // ===================================================================================

    static Set<String> stringToSet(String str) {
        if (str == null || str.isBlank()) {
            return new HashSet<>();
        }
        return new HashSet<>(Arrays.asList(str.split("\\|")));
    }

    private String setToString(Set<String> set) {
        if (set == null || set.isEmpty()) {
            return "";
        }
        return set.stream().sorted().collect(Collectors.joining("|"));
    }
}
