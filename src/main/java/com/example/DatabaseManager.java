package com.example;

import burp.api.montoya.MontoyaApi;

import java.sql.*;
import java.util.*;
import java.util.stream.Collectors;

public class DatabaseManager {
    private final MontoyaApi api;
    private Connection connection;

    public DatabaseManager(MontoyaApi api) {
        this.api = api;
    }

    public static boolean testConnection(String host, String port, String dbName, String user, String pass) {
        String url = String.format("jdbc:mysql://%s:%s?useSSL=false", host, port);
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            DriverManager.getConnection(url, user, pass).close();
            return true;
        } catch (SQLException | ClassNotFoundException e) {
            return false;
        }
    }

    public void initialize(String host, String port, String dbName, String user, String pass) {
        try {
            close(); // Đóng kết nối cũ nếu có
            Class.forName("com.mysql.cj.jdbc.Driver");

            // Bước 1: Kết nối đến server mà không chọn database cụ thể
            String serverUrl = String.format("jdbc:mysql://%s:%s?useSSL=false", host, port);
            try (Connection serverConnection = DriverManager.getConnection(serverUrl, user, pass);
                 Statement stmt = serverConnection.createStatement()) {
                
                // Bước 2: Dùng lệnh SQL để tạo database nếu nó chưa có
                // Dùng dấu backtick (`) để bao quanh tên database, tránh lỗi với các tên đặc biệt
                stmt.executeUpdate("CREATE DATABASE IF NOT EXISTS `" + dbName + "`");
                api.logging().logToOutput("Database '" + dbName + "' checked/created successfully.");
            }

            // Bước 3: Bây giờ, kết nối vào database vừa được tạo
            String dbUrl = String.format("jdbc:mysql://%s:%s/%s?useSSL=false", host, port, dbName);
            this.connection = DriverManager.getConnection(dbUrl, user, pass);
            api.logging().logToOutput("Successfully connected to MySQL database: " + dbName);

            // Bước 4: Tạo bảng trong database đó
            createTableIfNotExists();

        } catch (SQLException | ClassNotFoundException e) {
            api.logging().logToError("Failed to initialize MySQL database: " + e.getMessage(), e);
            this.connection = null; // Đảm bảo connection là null nếu thất bại
        }
    }

    public boolean isConnected() {
        try {
            return connection != null && !connection.isClosed();
        } catch (SQLException e) {
            return false;
        }
    }

    private void createTableIfNotExists() throws SQLException {
        // Sửa lại SQL để tương thích hoàn toàn với MySQL
        String sql = """
            CREATE TABLE IF NOT EXISTS api_log (
                id INT PRIMARY KEY AUTO_INCREMENT,
                method VARCHAR(10) NOT NULL,
                host VARCHAR(255) NOT NULL,
                path VARCHAR(2048) NOT NULL,
                unscanned_params TEXT,
                scanned_params TEXT,
                is_scanned BOOLEAN DEFAULT 0,
                is_rejected BOOLEAN DEFAULT 0,
                is_bypassed BOOLEAN DEFAULT 0,
                is_from_repeater BOOLEAN DEFAULT 0,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY unique_api (host, path(767), method)
            );
            """;
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
        }
    }

    public List<Object[]> loadApiData() {
        List<Object[]> rows = new ArrayList<>();
        if (!isConnected()) return rows;
        String sql = "SELECT id, method, host, path, unscanned_params, is_scanned, is_rejected, is_bypassed, is_from_repeater FROM api_log ORDER BY id DESC";
        try (Statement stmt = connection.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                String unscanned = rs.getString("unscanned_params");
                String unscanned_params = (unscanned != null && !unscanned.isEmpty()) ? unscanned.replace("|", ", ") : "";

                rows.add(new Object[]{
                        rs.getString("method"),
                        rs.getString("host"),
                        rs.getString("path"),
                        unscanned_params.trim(),
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

    public synchronized void insertOrUpdateApi(String method, String host, String path, Set<String> requestParams) {
        if (!isConnected()) return;
        String selectSql = "SELECT unscanned_params, scanned_params FROM api_log WHERE host = ? AND path = ? AND method = ?";
        try (PreparedStatement selectStmt = connection.prepareStatement(selectSql)) {
            selectStmt.setString(1, host);
            selectStmt.setString(2, path);
            selectStmt.setString(3, method);
            ResultSet rs = selectStmt.executeQuery();

            if (rs.next()) {
                Set<String> unscannedSet = stringToSet(rs.getString("unscanned_params"));
                Set<String> scannedSet = stringToSet(rs.getString("scanned_params"));
                Set<String> knownParams = new HashSet<>(unscannedSet);
                knownParams.addAll(scannedSet);

                Set<String> newDiscoveredParams = new HashSet<>(requestParams);
                newDiscoveredParams.removeAll(knownParams);

                if (!newDiscoveredParams.isEmpty()) {
                    unscannedSet.addAll(newDiscoveredParams);
                    String updatedUnscannedParams = setToString(unscannedSet);
                    String updateSql = "UPDATE api_log SET unscanned_params = ?, is_scanned = 0, is_bypassed = 0 WHERE host = ? AND path = ? AND method = ?";
                    try (PreparedStatement updateStmt = connection.prepareStatement(updateSql)) {
                        updateStmt.setString(1, updatedUnscannedParams);
                        updateStmt.setString(2, host);
                        updateStmt.setString(3, path);
                        updateStmt.setString(4, method);
                        updateStmt.executeUpdate();
                    }
                }
            } else {
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

    public synchronized boolean processScannedParameters(String method, String host, String path, Set<String> scannerParams) {
        if (!isConnected()) return false;
        String selectSql = "SELECT unscanned_params, scanned_params FROM api_log WHERE host = ? AND path = ? AND method = ?";
        try (PreparedStatement selectStmt = connection.prepareStatement(selectSql)) {
            selectStmt.setString(1, host);
            selectStmt.setString(2, path);
            selectStmt.setString(3, method);
            ResultSet rs = selectStmt.executeQuery();

            if (rs.next()) {
                Set<String> unscannedDbSet = stringToSet(rs.getString("unscanned_params"));
                if (unscannedDbSet.isEmpty()) return false;

                Set<String> newlyScannedParams = new HashSet<>(scannerParams);
                newlyScannedParams.retainAll(unscannedDbSet);
                if (newlyScannedParams.isEmpty()) return false;

                Set<String> scannedDbSet = stringToSet(rs.getString("scanned_params"));
                unscannedDbSet.removeAll(newlyScannedParams);
                scannedDbSet.addAll(newlyScannedParams);

                String updateSql = "UPDATE api_log SET unscanned_params = ?, scanned_params = ?, is_scanned = ? WHERE host = ? AND path = ? AND method = ?";
                try (PreparedStatement updateStmt = connection.prepareStatement(updateSql)) {
                    updateStmt.setString(1, setToString(unscannedDbSet));
                    updateStmt.setString(2, setToString(scannedDbSet));
                    updateStmt.setBoolean(3, unscannedDbSet.isEmpty());
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

    public synchronized boolean autoBypassApi(String method, String host, String path) {
        if (!isConnected()) return false;
        String upsertSql = """
            INSERT INTO api_log (method, host, path, unscanned_params, scanned_params, is_bypassed)
            VALUES (?, ?, ?, '', '', 1)
            ON DUPLICATE KEY UPDATE
                is_bypassed = CASE
                    WHEN is_scanned = 0 AND is_rejected = 0 AND (unscanned_params IS NULL OR unscanned_params = '')
                    THEN 1
                    ELSE is_bypassed
                END
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

    public synchronized boolean updateRepeaterStatus(String method, String host, String path) {
        if (!isConnected()) return false;
        String sql = "UPDATE api_log SET is_from_repeater = 1 WHERE host = ? AND path = ? AND method = ? AND is_from_repeater = 0";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, host);
            stmt.setString(2, path);
            stmt.setString(3, method);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            api.logging().logToError("Error during updateRepeaterStatus: " + e.getMessage(), e);
            return false;
        }
    }

    private Set<String> stringToSet(String str) {
        if (str == null || str.isBlank()) return new HashSet<>();
        return new HashSet<>(Arrays.asList(str.split("\\|")));
    }

    private String setToString(Set<String> set) {
        if (set == null || set.isEmpty()) return "";
        return set.stream().sorted().collect(Collectors.joining("|"));
    }

    public void updateApiStatus(int id, String columnName, boolean value) {
        if (!isConnected()) return;
        if (!Arrays.asList("is_rejected", "is_bypassed").contains(columnName)) {
            api.logging().logToError("Invalid column name for status update.");
            return;
        }
        String sql = String.format("UPDATE api_log SET %s = ? WHERE id = ?", columnName);
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setBoolean(1, value);
            pstmt.setInt(2, id);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            api.logging().logToError("Failed to update API status: " + e.getMessage(), e);
        }
    }

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

    public Object[] getApiStatus(String method, String host, String path) {
        if (!isConnected()) return null;
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