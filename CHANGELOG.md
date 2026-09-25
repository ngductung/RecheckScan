# Changelog

## [2026.9.3] - 2026-09-25

Bản tổng hợp nội dung v2026.9.2 và các thay đổi vừa merge, đến commit `c4325e4`. Phần bổ sung tập trung vào cấu hình theo file SQLite, tìm API khi rebuild/fill và giảm xử lý dư thừa khi có nhiều request.

### Mới: Cấu hình đi theo file SQLite

Các rule, danh sách loại trừ, tuỳ chọn highlight/note, auto-bypass và đồng bộ Proxy history được lưu cùng dữ liệu API trong file SQLite. Project Burp chỉ cần giữ đường dẫn tới file DB; mang DB sang project khác sẽ mang theo cả cấu hình đã lưu.

Thứ tự nạp cấu hình:

1. Nếu DB đã có cấu hình, dùng cấu hình trong DB.
2. Nếu DB chưa có cấu hình, chuyển cấu hình cũ còn lưu trong project Burp sang DB.
3. Nếu cả hai đều chưa có, dùng mặc định và lưu vào DB.

Khi chọn file qua **Browse**, extension mở DB đó và nạp lại form Settings cùng bảng API. Nếu sửa đường dẫn bằng tay rồi bấm **Apply**, lần bấm đó cũng chuyển DB và nạp cấu hình từ file mới.

**Reset Default** nằm cạnh Apply. Sau khi xác nhận, cấu hình được đưa về mặc định và lưu vào DB đang mở; đường dẫn DB và dữ liệu API được giữ nguyên.

Danh sách loại trừ mặc định được khôi phục khi chưa có cấu hình: các đuôi file tĩnh thông dụng và mã trạng thái `404,405`. Giá trị rỗng đã được lưu có chủ ý vẫn được giữ.

### Tái tạo request và điền tham số còn thiếu

Hai lối vào dùng dữ liệu Recheck Scan đã thu thập.

**Từ bảng Recheck Scan**, chuột phải vào các dòng đang chọn:

- `Rebuild request with all params (from history) ➜ Repeater`
- `Rebuild request + refresh cookies from cookie jar ➜ Repeater`

Extension lấy một request khớp API trong Proxy history làm khung, bổ sung tham số mà CSDL biết nhưng request gốc thiếu, rồi gửi sang tab Repeater. Báo cáo cho biết số tham số đã biết, đã có sẵn và lấy được giá trị từ history.

**Từ request editor**, chuột phải trong Repeater hoặc Proxy:

- `Fill missing params (from Recheck Scan)`
- `Fill missing params + refresh cookies`

Giá trị tham số được lấy từ history; tham số chưa tìm được giá trị được thêm với giá trị rỗng. Rebuild từ bảng sẽ từ chối nếu không tìm được request khớp trong history. Tuỳ chọn refresh cookies lấy cookie phù hợp từ cookie jar.

**Bổ sung trong bản này: tìm lại API đã lưu dưới dạng placeholder.** Khi chuẩn hoá bằng rule hiện tại không tìm thấy API, rebuild/fill có thêm bước khớp raw path với path đã lưu. Ví dụ `/api/users/123` vẫn có thể tìm ra `/api/users/{id}` sau khi rule cũ bị xoá.

- Giữ điều kiện cùng HTTP method và host.
- Ở bước khớp dự phòng, placeholder có rule theo segment cùng tên phải thoả regex của rule đó; ví dụ `{uuid}=uuid` không nhận `Pentest1`.
- Nếu không còn rule theo segment cùng tên, placeholder khớp một segment bất kỳ. Các trường hợp path-aware cần lưu ý ở phần Hạn chế đã biết.
- Khi nhiều mẫu dự phòng cùng khớp, ưu tiên path có phần literal dài hơn; nếu bằng nhau, dùng thứ tự tên path để kết quả ổn định.
- Thông báo phân biệt API chưa được ghi nhận với API đã có nhưng không có tham số để điền.

### Tự đồng bộ highlight/note trong Proxy history

Khi trạng thái Scanned, Bypassed hoặc Rejected của API đổi, API được đưa vào hàng chờ để luồng nền cập nhật lại các bản ghi đã nằm trong Proxy history. Bật/tắt tại Settings; **queue threshold** đặt số API tối thiểu trong hàng chờ trước một lượt quét.

Luồng đồng bộ history chỉ ghi đè highlight đang là NONE hoặc YELLOW, và note đang rỗng hoặc là một trong `Scanned` / `Bypassed` / `Rejected`. Note tự viết và highlight màu khác được giữ nguyên.

**Bổ sung trong bản này:** chỉ xếp hàng khi một trong ba cờ trạng thái thực sự thay đổi. Request lặp lại với cùng trạng thái không còn kích hoạt việc quét lại history chỉ vì cache được cập nhật.

### Giảm xử lý dư thừa trên request

Các tối ưu từ v2026.9.2 được giữ lại:

- Thao tác CSDL khi xử lý response được chuyển sang một luồng nền; ghi xong chỉ cập nhật dòng thay đổi trên bảng.
- Highlight/note trên luồng HTTP đọc từ cache trong bộ nhớ.
- Gom cập nhật thống kê khi đánh dấu hàng loạt.
- **Copy Endpoint List** lấy tham số của các dòng được chọn bằng một truy vấn.
- Các trường cài đặt dùng `volatile`, truy cập CSDL được đồng bộ.

**Bổ sung từ các PR vừa merge:**

- Kiểm tra Burp scope trước khi chuẩn hoá path và trích xuất tham số, tránh parse body JSON/XML của request ngoài scope.
- Với traffic không phải Scanner, kiểm tra đuôi file bị loại trừ trước khi parse tham số. Scanner vẫn bỏ qua bộ lọc đuôi file, nhưng hiện cũng phải nằm trong scope.
- Request thông thường của API đã biết, không có tham số mới, bỏ qua tác vụ insert/update ngay từ cache. Nhánh đánh dấu request từ Repeater vẫn được xử lý riêng.
- Auto-bypass bỏ qua tác vụ ghi nếu cache cho biết API đã Bypassed, Scanned hoặc Rejected.
- Tầng CSDL không đọc lại dòng hay cập nhật UI khi insert/update hoặc auto-bypass không làm thay đổi dữ liệu.

Các số đo hiệu năng trong note v2026.9.2 là số liệu của bản trước; chưa có benchmark mới cho các tối ưu lần này.

### JAR theo nền tảng

Mỗi bản build chỉ giữ native SQLite cần thiết cho nền tảng đích. Code extension giống nhau trong cả bốn file.

| File | Dùng cho | Dung lượng xấp xỉ |
|---|---|---|
| `RecheckScan.jar` | Các nền tảng Burp thông dụng; chọn file này nếu không chắc | 3.73 MiB |
| `RecheckScan-win-x64.jar` | Windows x86_64 | 0.83 MiB |
| `RecheckScan-linux-x64.jar` | Linux x86_64 | 0.85 MiB |
| `RecheckScan-mac-arm64.jar` | macOS Apple Silicon | 0.87 MiB |

Dung lượng đo từ `mvn clean package` tại commit `c4325e4`; 1 MiB = 1.048.576 byte. Các bản theo nền tảng vẫn dưới 1 MB.

### Rule và thao tác trên bảng

**URL Path Parameter Rules nhận diện vị trí.** Rule `regex:` chứa `/` khớp trên toàn bộ path; rule không chứa `/` tiếp tục hoạt động theo segment:

```text
{id}=regex:/api/users/([0-9]+)

/api/users/12345/posts/678 -> /api/users/{id}/posts/678
```

**Ignored Parameter Rules** loại tham số không cần theo dõi khỏi dữ liệu thu thập; Scanner dùng cùng tập tham số đã lọc. Ba cú pháp đều khớp trọn tên tham số:

```text
utm_*            wildcard
_ga              tên chính xác
regex:^__.*$     regex tự viết
```

Bấm **Apply** dọn các tham số khớp rule khỏi dữ liệu đã lưu. **Bổ sung trong bản này:** toàn bộ lô cập nhật của bước dọn ignored parameters nằm trong một transaction; lỗi SQL sẽ rollback cả lô. Hạn chế cập nhật dở dang của bước này trong note cũ đã được xử lý.

Context menu trên bảng tiếp tục hỗ trợ `Mark as Bypass`, `Mark as Reject`, `Delete selected` và `Copy Endpoint List`. Khi xoá, API còn trong scope được giữ lại. Sắp xếp cột có ba trạng thái: tăng dần, giảm dần, bỏ sắp xếp.

### Sửa lỗi

- Sửa rebuild/fill không tìm được API đã lưu dưới dạng placeholder khi rule hiện tại không tái tạo đúng path đó; bổ sung ràng buộc rule theo segment và chọn mẫu dự phòng cụ thể hơn.
- Khôi phục danh sách loại trừ mặc định cho DB/project chưa có cấu hình; thống nhất thứ tự ưu tiên DB, cấu hình Burp cũ, rồi mặc định.
- Bọc lô dọn ignored parameters trong transaction để tránh ghi thành công một phần khi có lỗi.
- Giữ các sửa lỗi từ v2026.9.2: checkbox **Auto-bypass APIs without params** được áp dụng cho mọi HTTP method; tìm kiếm escape ký tự regex và hỗ trợ dạng path đã chuẩn hoá.

### Thay đổi khi nâng cấp

**Cấu hình chuyển sang SQLite.** DB có cấu hình được ưu tiên hơn project Burp. DB chưa có cấu hình được bổ sung từ project cũ hoặc mặc định. Khi chuyển DB, các giá trị đang sửa trên form không tự ghi đè cấu hình của file mới. Reset Default cũng lưu vào DB đang mở, nên lần nạp sau từ cùng DB sẽ nhận cấu hình mặc định.

**Scope áp dụng cả cho Scanner.** Response từ Scanner ngoài Burp scope hiện bị bỏ qua, không cập nhật trạng thái quét trong Recheck Scan.

Các thay đổi từ v2026.9.2 vẫn áp dụng:

- Ô **Ignore URL Path Parameter Rules** đã bị gỡ; dùng rule path-aware để mô tả vị trí cần chuẩn hoá. Khoá cũ `ignore_path_parameter_rules` không còn được đọc; việc ghi lại cấu hình vào project Burp có thể xoá khoá này.
- Tên JAR đổi từ `burp-recheck-scan-2.0-SQLITE.jar` thành `RecheckScan.jar` cùng các bản theo nền tảng.

### Hạn chế đã biết

- Nếu ignored rules loại hết tham số của một API, `is_scanned` vẫn bị reset về 0; API đã quét có thể trở lại Unverified.
- Nhánh khớp placeholder dự phòng chưa kiểm tra lại rule path-aware. Với `{id}=regex:/api/users/([0-9]+)`, mẫu `/api/users/{id}` có thể nhận nhầm `/api/users/admin`, dẫn tới rebuild/fill lấy nhầm request hoặc giá trị từ history. Không nên coi việc khớp này là bảo đảm tuyệt đối không lẫn API.
- Trong nhánh dự phòng, regex theo segment có anchor `^`/`$` được ghép vào regex của cả path; vì vậy có thể không khớp request hợp lệ khi bước tìm bằng path chuẩn hoá không thành công.
- Rule phân biệt hoa thường theo pattern được dùng; regex tự viết có thể thay đổi điều này bằng flag. Lỗi cú pháp rule chỉ hiện ở log tab Extensions.
- Các bản JAR theo nền tảng không hỗ trợ Alpine/musl, FreeBSD hoặc JVM 32-bit.

### Kiểm tra và cài đặt

`mvn clean package` thành công và tạo đủ bốn JAR. Repo hiện không có test sources; build thành công chưa xác nhận các luồng tương tác trong Burp. Hai hạn chế về placeholder ở trên đã được tái hiện bằng JShell trên class vừa build.

Tải JAR phù hợp ở Assets, rồi vào Burp: `Extensions` → `Installed` → `Add` → `Java` → chọn file.

## [2.0-SQLITE] - 2025-05-16

### Added
- ✅ SQLite database integration replacing CSV files
- ✅ Auto-bypass functionality for APIs without parameters
- ✅ Enhanced UI with separate tabs (Unscanned, Logs, Settings)
- ✅ Real-time search and filtering capabilities
- ✅ Statistics dashboard with live counters
- ✅ Thread-safe database operations
- ✅ Comprehensive error handling and logging
- ✅ Status code exclusion configuration
- ✅ Highlight and note features for Proxy history
- ✅ Copy functionality with Ctrl+C shortcut
- ✅ Retroactive auto-bypass for existing data

### Changed
- 🔄 Migrated from CSV file storage to SQLite database
- 🔄 Completely redesigned user interface
- 🔄 Improved parameter extraction logic
- 🔄 Enhanced configuration management
- 🔄 Better resource management and cleanup

### Technical Improvements
- Thread-safe database operations with synchronized methods
- Proper resource management using try-with-resources
- Background processing to prevent UI blocking
- Optimized database schema with proper indices
- Maven build configuration with shade plugin
- Comprehensive Javadoc documentation

### Database Schema
```sql
CREATE TABLE api_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    method TEXT NOT NULL,
    host TEXT NOT NULL,  
    path TEXT NOT NULL,
    unscanned_params TEXT,
    scanned_params TEXT,
    is_scanned BOOLEAN DEFAULT 0,
    is_rejected BOOLEAN DEFAULT 0,
    is_bypassed BOOLEAN DEFAULT 0,
    is_from_repeater BOOLEAN DEFAULT 0,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host, path, method)
);
```

### Fixed
- 🐛 Race conditions in table updates
- 🐛 Memory leaks from unclosed database connections
- 🐛 UI freezing during large data operations
- 🐛 Inconsistent parameter detection across content types

## [1.0] - 2025-05-13

### Added
- ✅ Basic API endpoint detection
- ✅ Parameter extraction from URL and body
- ✅ CSV export functionality  
- ✅ Manual scan status management
- ✅ Simple table-based interface
- ✅ Extension loading/unloading support

### Features
- HTTP request/response monitoring
- Parameter tracking for GET/POST requests
- Basic filtering by file extensions
- Export scan results to CSV format
- Manual marking of scanned/rejected APIs

### Technical Details
- Built on Montoya API 2025.6
- Java 17 compatibility
- Maven build system
- Single-threaded operations
- File-based persistence

### Known Limitations
- CSV format limitations for complex data
- Manual refresh required for UI updates
- No auto-bypass functionality
- Limited filtering and search capabilities
- Basic error handling

---

## Migration Guide

### From v1.0 to v2.0

**Automatic Migration:**
- Extension automatically detects old CSV files
- Data is migrated to SQLite format on first run
- Original CSV files are preserved as backup

**Configuration Changes:**
- Database path replaces CSV export path
- New auto-bypass settings available
- Enhanced exclusion filters

**UI Changes:**
- New tab-based interface
- Separate views for Unscanned and All logs
- Enhanced Settings panel with statistics
- Real-time search functionality

**Performance Improvements:**
- Significantly faster data operations
- Better memory usage
- Thread-safe concurrent access
- Optimized for large datasets

### Breaking Changes
- Configuration file format updated
- API for programmatic access changed
- Minimum Java version increased to 17

### Recommendations
- Backup existing data before upgrading
- Review and update configuration settings
- Test extension functionality after migration
- Clear browser cache if using web-based targets

---

## Future Roadmap

### Planned Features
- [ ] API endpoint clustering and grouping
- [ ] Advanced filtering with multiple criteria
- [ ] Export/import functionality for sharing datasets
- [ ] Integration with other Burp tools
- [ ] Custom scan templates
- [ ] Automated reporting features
- [ ] REST API for external integration

### Performance Enhancements  
- [ ] Connection pooling implementation
- [ ] Lazy loading for large datasets
- [ ] Background data synchronization
- [ ] Memory usage optimization
- [ ] Query performance improvements

### UI/UX Improvements
- [ ] Dark theme support
- [ ] Customizable column layouts
- [ ] Advanced search with regex support
- [ ] Bulk operations for multiple APIs
- [ ] Keyboard shortcuts for common actions
- [ ] Context menu enhancements

---

For detailed technical changes and code improvements, see the [commit history](https://github.com/vn-ncvinh/RecheckScan/commits/main) on GitHub.
