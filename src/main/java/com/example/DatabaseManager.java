package com.example;

import burp.api.montoya.MontoyaApi;

import java.io.File;
import java.sql.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Quản lý tất cả các hoạt động liên quan đến cơ sở dữ liệu SQLite của extension.
 * <p>
 * Lớp này đóng gói toàn bộ logic kết nối, khởi tạo bảng, truy vấn và cập nhật dữ liệu.
 * Việc tách biệt logic xử lý dữ liệu ra khỏi logic nghiệp vụ (trong RecheckScanApiExtension)
 * và giao diện người dùng giúp mã nguồn trở nên sạch sẽ, dễ quản lý và bảo trì hơn.
 */
public class DatabaseManager {
    /**
     * Đối tượng API của Montoya, cần thiết để ghi log lỗi và thông báo.
     */
    private final MontoyaApi api;
    /**
     * Đối tượng kết nối đến cơ sở dữ liệu SQLite. Được quản lý trong suốt vòng đời của extension.
     */
    private Connection connection;
    /**
     * Đường dẫn đến tệp cơ sở dữ liệu SQLite trên đĩa.
     */
    private String dbPath;

    /**
     * Hàm khởi tạo cho DatabaseManager.
     *
     * @param api Đối tượng MontoyaApi được cung cấp bởi Burp.
     */
    public DatabaseManager(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Khởi tạo kết nối đến cơ sở dữ liệu và đảm bảo bảng dữ liệu đã sẵn sàng.
     *
     * @param savedOutputPath Đường dẫn đến tệp CSDL do người dùng cấu hình. Nếu rỗng, một đường dẫn mặc định sẽ được sử dụng.
     */
    public void initialize(String savedOutputPath) {
        this.dbPath = getDbPath(savedOutputPath);
        try {
            // Nạp driver JDBC cho SQLite.
            Class.forName("org.sqlite.JDBC");
            
            // Đảm bảo thư mục cha tồn tại trước khi tạo tệp CSDL.
            File dbFile = new File(dbPath);
            File parentDir = dbFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }
            
            // Tạo kết nối đến tệp SQLite.
            connection = DriverManager.getConnection("jdbc:sqlite:" + this.dbPath);
            api.logging().logToOutput("Successfully connected to SQLite database: " + this.dbPath);
            
            // Tạo bảng nếu nó chưa tồn tại.
            createTableIfNotExists();
        } catch (SQLException | ClassNotFoundException e) {
            api.logging().logToError("Failed to initialize SQLite database: " + e.getMessage(), e);
        }
    }

    /**
     * Xác định đường dẫn cuối cùng cho tệp cơ sở dữ liệu.
     * Ưu tiên đường dẫn do người dùng chỉ định. Nếu không, sử dụng đường dẫn mặc định.
     * Đảm bảo rằng tên tệp luôn kết thúc bằng ".db".
     *
     * @param savedOutputPath Đường dẫn thô từ cài đặt.
     * @return Đường dẫn tuyệt đối đã được chuẩn hóa.
     */
    private String getDbPath(String savedOutputPath) {
        if (savedOutputPath != null && !savedOutputPath.isBlank()) {
            // Hỗ trợ chuyển đổi từ định dạng .csv cũ sang .db mới
            String path = savedOutputPath.toLowerCase().endsWith(".csv")
                    ? savedOutputPath.substring(0, savedOutputPath.length() - 4)
                    : savedOutputPath;
            return path.toLowerCase().endsWith(".db") ? path : path + ".db";
        }
        // Đường dẫn mặc định trong thư mục Temp của Windows.
        return new File(System.getProperty("java.io.tmpdir"), "RecheckScan/scan_api.db").getAbsolutePath();
    }

    /**
     * Tạo bảng `api_log` nếu nó chưa tồn tại.
     * Đây là cấu trúc trung tâm để lưu trữ tất cả thông tin về các API.
     * Ràng buộc UNIQUE trên (host, path, method) là cốt lõi để phân biệt các API.
     *
     * @throws SQLException Nếu có lỗi khi thực thi câu lệnh SQL.
     */
    private void createTableIfNotExists() throws SQLException {
        String sql = """
            CREATE TABLE IF NOT EXISTS api_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,      -- Khóa chính tự tăng, định danh duy nhất cho mỗi dòng.
                method TEXT NOT NULL,                      -- Phương thức HTTP (GET, POST, etc.)
                host TEXT NOT NULL,                        -- Host của API (e.g., api.example.com)
                path TEXT NOT NULL,                        -- Đường dẫn của API (e.g., /v1/users)
                unscanned_params TEXT,                     -- Danh sách các tham số CHƯA được quét, cách nhau bởi dấu '|'.
                scanned_params TEXT,                       -- Danh sách các tham số ĐÃ được quét, cách nhau bởi dấu '|'.
                is_scanned BOOLEAN DEFAULT 0,              -- Trạng thái: đã quét hết các param (1) hay chưa (0).
                is_rejected BOOLEAN DEFAULT 0,             -- Trạng thái: người dùng đã từ chối quét (1) hay chưa (0).
                is_bypassed BOOLEAN DEFAULT 0,             -- Trạng thái: được tự động bỏ qua (1) hay chưa (0).
                is_from_repeater BOOLEAN DEFAULT 0,        -- Trạng thái: đã được gửi từ Repeater (1) hay chưa (0).
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Dấu thời gian lần cuối thấy API này.
                UNIQUE(host, path, method)                 -- Ràng buộc duy nhất: không thể có hai dòng trùng cả host, path và method.
            );
            """;
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
        }
    }

    /**
     * Tải tất cả dữ liệu API từ cơ sở dữ liệu để hiển thị trên JTable.
     * Sắp xếp theo ID giảm dần để các API mới nhất hiện lên đầu.
     *
     * @return Một danh sách các mảng Object, mỗi mảng đại diện cho một dòng trong bảng UI.
     */
    public List<Object[]> loadApiData() {
        List<Object[]> rows = new ArrayList<>();
        String sql = "SELECT id, method, host, path, unscanned_params, scanned_params, is_scanned, is_rejected, is_bypassed, is_from_repeater FROM api_log ORDER BY id DESC";
        try (Statement stmt = connection.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                String unscanned = rs.getString("unscanned_params");
                
                // Xây dựng chuỗi "unscanned_params" để hiển thị cho người dùng.
                StringBuilder unscanned_params = new StringBuilder();
                if (unscanned != null && !unscanned.isEmpty()) {
                    unscanned_params.append(unscanned.replace("|", ", "));
                }

                rows.add(new Object[]{
                        rs.getString("method"),
                        rs.getString("host"),
                        rs.getString("path"),
                        unscanned_params.toString().trim(),
                        rs.getBoolean("is_scanned"),
                        rs.getBoolean("is_rejected"),
                        rs.getBoolean("is_bypassed"),
                        rs.getBoolean("is_from_repeater"),
                        rs.getInt("id")
                });
            }
        } catch (SQLException e) {
            api.logging().logToError("Failed to load API data from database: " + e.getMessage(), e);
        }
        return rows;
    }

    /**
     * Chèn một API mới hoặc cập nhật các tham số của một API đã tồn tại.
     * Được gọi bởi các request thông thường (không phải từ Scanner).
     * Nếu phát hiện tham số mới, chúng sẽ được thêm vào `unscanned_params` và reset `is_scanned` về false.
     *
     * @param method        Phương thức HTTP của request.
     * @param host          Host của request.
     * @param path          Path của request.
     * @param requestParams Tập hợp các tham số từ request hiện tại.
     */
    public synchronized void insertOrUpdateApi(String method, String host, String path, Set<String> requestParams) {
        String selectSql = "SELECT unscanned_params, scanned_params FROM api_log WHERE host = ? AND path = ? AND method = ?";
        try (PreparedStatement selectStmt = connection.prepareStatement(selectSql)) {
            selectStmt.setString(1, host);
            selectStmt.setString(2, path);
            selectStmt.setString(3, method);
            ResultSet rs = selectStmt.executeQuery();

            if (rs.next()) { // API đã tồn tại -> Cập nhật
                Set<String> unscannedSet = stringToSet(rs.getString("unscanned_params"));
                Set<String> scannedSet = stringToSet(rs.getString("scanned_params"));
                
                // Gộp tất cả các param đã biết để so sánh.
                Set<String> knownParams = new HashSet<>(unscannedSet);
                knownParams.addAll(scannedSet);

                // Tìm các param thực sự mới.
                Set<String> newDiscoveredParams = new HashSet<>(requestParams);
                newDiscoveredParams.removeAll(knownParams);

                // Nếu có param mới, thêm vào danh sách unscanned và reset trạng thái is_scanned.
                if (!newDiscoveredParams.isEmpty()) {
                    unscannedSet.addAll(newDiscoveredParams);
                    String updatedUnscannedParams = setToString(unscannedSet);
                    String updateSql = "UPDATE api_log SET unscanned_params = ?, is_scanned = 0, is_bypassed = 0, last_seen = CURRENT_TIMESTAMP WHERE host = ? AND path = ? AND method = ?";
                    try (PreparedStatement updateStmt = connection.prepareStatement(updateSql)) {
                        updateStmt.setString(1, updatedUnscannedParams);
                        updateStmt.setString(2, host);
                        updateStmt.setString(3, path);
                        updateStmt.setString(4, method);
                        updateStmt.executeUpdate();
                    }
                }
            } else { // API mới -> Chèn dòng mới
                String paramsStr = setToString(requestParams);
                String insertSql = "INSERT INTO api_log (method, host, path, unscanned_params) VALUES (?, ?, ?, ?)";
                try (PreparedStatement insertStmt = connection.prepareStatement(insertSql)) {
                    insertStmt.setString(1, method);
                    insertStmt.setString(2, host);
                    insertStmt.setString(3, path);
                    insertStmt.setString(4, paramsStr);
                    insertStmt.executeUpdate();
                }
            }
        } catch (SQLException e) {
            api.logging().logToError("Error during insert/update API: " + e.getMessage(), e);
        }
    }

    /**
     * Xử lý các tham số được quét từ một request của Burp Scanner.
     * Các tham số nào khớp với danh sách `unscanned_params` sẽ được chuyển sang `scanned_params`.
     * Nếu `unscanned_params` trở nên rỗng, API sẽ được đánh dấu là `is_scanned = true`.
     *
     * @param method        Phương thức HTTP của request từ Scanner.
     * @param host          Host của request.
     * @param path          Path của request.
     * @param scannerParams Các tham số có trong request của Scanner.
     * @return true nếu có sự thay đổi trong CSDL, ngược lại false.
     */
    public synchronized boolean processScannedParameters(String method, String host, String path, Set<String> scannerParams) {
        String selectSql = "SELECT unscanned_params, scanned_params FROM api_log WHERE host = ? AND path = ? AND method = ?";
        try (PreparedStatement selectStmt = connection.prepareStatement(selectSql)) {
            selectStmt.setString(1, host);
            selectStmt.setString(2, path);
            selectStmt.setString(3, method);
            ResultSet rs = selectStmt.executeQuery();

            if (rs.next()) {
                Set<String> unscannedDbSet = stringToSet(rs.getString("unscanned_params"));
                if (unscannedDbSet.isEmpty()) return false; // Không có gì để quét.

                // Tìm các tham số vừa được quét (phần giao giữa param của scanner và param chưa quét).
                Set<String> newlyScannedParams = new HashSet<>(scannerParams);
                newlyScannedParams.retainAll(unscannedDbSet);
                if (newlyScannedParams.isEmpty()) return false; // Scanner không quét trúng param nào cần thiết.

                // Cập nhật lại các tập hợp param.
                Set<String> scannedDbSet = stringToSet(rs.getString("scanned_params"));
                unscannedDbSet.removeAll(newlyScannedParams);
                scannedDbSet.addAll(newlyScannedParams);

                // Cập nhật CSDL với trạng thái mới.
                String updateSql = "UPDATE api_log SET unscanned_params = ?, scanned_params = ?, is_scanned = ?, last_seen = CURRENT_TIMESTAMP WHERE host = ? AND path = ? AND method = ?";
                try (PreparedStatement updateStmt = connection.prepareStatement(updateSql)) {
                    updateStmt.setString(1, setToString(unscannedDbSet));
                    updateStmt.setString(2, setToString(scannedDbSet));
                    updateStmt.setBoolean(3, unscannedDbSet.isEmpty()); // is_scanned = true chỉ khi không còn gì để quét.
                    updateStmt.setString(4, host);
                    updateStmt.setString(5, path);
                    updateStmt.setString(6, method);
                    updateStmt.executeUpdate();
                    return true;
                }
            }
        } catch (SQLException e) {
            api.logging().logToError("Error during processScannedParameters: " + e.getMessage(), e);
        }
        return false;
    }
    
    /**
     * Xử lý tính năng auto-bypass cho API GET không có tham số.
     * Sử dụng ON CONFLICT để tránh ghi đè các API đã được đánh dấu `scanned` hoặc `rejected`
     * Đồng thời đảm bảo không đánh dấu bypass nếu API đó còn param chưa được scan
     *
     * @param method Phương thức HTTP (luôn là GET).
     * @param host   Host của API.
     * @param path   Path của API.
     * @return true nếu có sự thay đổi trong CSDL.
     */
    public synchronized boolean autoBypassApi(String method, String host, String path) {
        String upsertSql = """
            INSERT INTO api_log (method, host, path, unscanned_params, scanned_params, is_bypassed)
            VALUES (?, ?, ?, '', '', 1)
            ON CONFLICT(host, path, method) DO UPDATE SET
                is_bypassed = CASE
                    WHEN api_log.is_scanned = 0 AND api_log.is_rejected = 0 AND api_log.unscanned_params = ''
                    THEN 1
                    ELSE api_log.is_bypassed
                END,
                last_seen = CURRENT_TIMESTAMP
            """;
        try (PreparedStatement stmt = connection.prepareStatement(upsertSql)) {
            stmt.setString(1, method);
            stmt.setString(2, host);
            stmt.setString(3, path);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            api.logging().logToError("Error during autoBypassApi: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Đánh dấu một API đã được gửi từ Repeater.
     * Chỉ cập nhật nếu trạng thái hiện tại là chưa được đánh dấu để tránh reload UI không cần thiết.
     *
     * @param method Phương thức HTTP.
     * @param host   Host của API.
     * @param path   Path của API.
     * @return true nếu có sự thay đổi trong CSDL, ngược lại false.
     */
    public synchronized boolean updateRepeaterStatus(String method, String host, String path) {
        String sql = "UPDATE api_log SET is_from_repeater = 1, last_seen = CURRENT_TIMESTAMP WHERE host = ? AND path = ? AND method = ? AND is_from_repeater = 0";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, host);
            stmt.setString(2, path);
            stmt.setString(3, method);
            int affectedRows = stmt.executeUpdate();
            return affectedRows > 0;
        } catch (SQLException e) {
            api.logging().logToError("Error during updateRepeaterStatus: " + e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * Chuyển đổi một chuỗi (dữ liệu từ DB) thành một Set các chuỗi.
     *
     * @param str Chuỗi được phân tách bởi '|'.
     * @return Một Set các tham số.
     */
    private Set<String> stringToSet(String str) {
        if (str == null || str.isBlank()) return new HashSet<>();
        return new HashSet<>(Arrays.asList(str.split("\\|")));
    }

    /**
     * Chuyển đổi một Set các chuỗi thành một chuỗi duy nhất để lưu vào DB.
     * Các tham số được sắp xếp theo bảng chữ cái để đảm bảo tính nhất quán.
     *
     * @param set Tập hợp các tham số.
     * @return Một chuỗi được phân tách bởi '|'.
     */
    private String setToString(Set<String> set) {
        if (set == null || set.isEmpty()) return "";
        return set.stream().sorted().collect(Collectors.joining("|"));
    }

    /**
     * Áp dụng quy tắc auto-bypass cho tất cả các bản ghi cũ phù hợp trong CSDL.
     * Được gọi khi người dùng nhấn Apply trong Settings với tùy chọn auto-bypass được bật.
     *
     * @return Số lượng dòng đã được cập nhật.
     */
    public synchronized int applyAutoBypassToOldRecords() {
        String sql = """
            UPDATE api_log
            SET
                is_bypassed = 1,
                last_seen = CURRENT_TIMESTAMP
            WHERE
                (unscanned_params IS NULL OR unscanned_params = '')
                AND is_scanned = 0
                AND is_rejected = 0
                AND is_bypassed = 0
            """;
        try (Statement stmt = connection.createStatement()) {
            int affectedRows = stmt.executeUpdate(sql);
            if (affectedRows > 0) {
                api.logging().logToOutput("Retroactively bypassed " + affectedRows + " old GET APIs without parameters.");
            }
            return affectedRows;
        } catch (SQLException e) {
            api.logging().logToError("Error during retroactive auto-bypass: " + e.getMessage(), e);
            return 0;
        }
    }
    
    /**
     * Cập nhật một cột trạng thái boolean (is_scanned, is_rejected, is_bypassed) cho một API.
     * Được sử dụng khi người dùng tick vào các checkbox trên giao diện.
     *
     * @param id         ID của dòng trong CSDL.
     * @param columnName Tên của cột cần cập nhật.
     * @param value      Giá trị boolean mới.
     */
    public void updateApiStatus(int id, String columnName, boolean value) {
        if (!Arrays.asList("is_scanned", "is_rejected", "is_bypassed").contains(columnName)) {
            api.logging().logToError("Invalid column name for status update.");
            return;
        }
        String sql = String.format("UPDATE api_log SET %s = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?", columnName);
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setBoolean(1, value);
            pstmt.setInt(2, id);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            api.logging().logToError("Failed to update API status: " + e.getMessage(), e);
        }
    }

    /**
     * Đóng kết nối cơ sở dữ liệu khi extension được gỡ bỏ.
     * Rất quan trọng để giải phóng tài nguyên.
     */
    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                api.logging().logToOutput("Database connection closed.");
            }
        } catch (SQLException e) {
            api.logging().logToError("Error closing database connection: " + e.getMessage(), e);
        }
    }
    
    /**
     * Lấy các cờ trạng thái (scanned, rejected, bypassed) của một API cụ thể.
     * Được sử dụng để quyết định việc highlight và thêm note.
     *
     * @param method Phương thức HTTP.
     * @param host   Host của API.
     * @param path   Path của API.
     * @return Một mảng Object chứa 3 giá trị boolean, hoặc null nếu không tìm thấy.
     */
    public Object[] getApiStatus(String method, String host, String path) {
        String sql = "SELECT is_scanned, is_rejected, is_bypassed FROM api_log WHERE host = ? AND path = ? AND method = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, host);
            stmt.setString(2, path);
            stmt.setString(3, method);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return new Object[]{rs.getBoolean("is_scanned"), rs.getBoolean("is_rejected"), rs.getBoolean("is_bypassed")};
            }
        } catch (SQLException e) {
            api.logging().logToError("Failed to get API status for " + host + path + ": " + e.getMessage(), e);
        }
        return null;
    }
}