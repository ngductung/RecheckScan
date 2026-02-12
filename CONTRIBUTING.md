# Contributing to Recheck Scan API Extension

Cảm ơn bạn đã quan tâm đến việc đóng góp cho dự án! Chúng tôi hoan nghênh mọi đóng góp từ cộng đồng.

## 🚀 Cách đóng góp

### Báo cáo lỗi (Bug Reports)

Khi báo cáo lỗi, vui lòng bao gồm:

1. **Mô tả ngắn gọn về lỗi**
2. **Các bước tái tạo lỗi**
3. **Kết quả mong đợi và kết quả thực tế**
4. **Môi trường**:
   - Phiên bản Burp Suite
   - Phiên bản Java
   - Hệ điều hành
5. **Screenshots hoặc logs** (nếu có)

### Đề xuất tính năng (Feature Requests)

Khi đề xuất tính năng mới:

1. **Mô tả chi tiết tính năng**
2. **Lý do tại sao tính năng này hữu ích**
3. **Ví dụ sử dụng**
4. **Mockup hoặc wireframe** (nếu có)

### Code Contributions

#### Quy trình

1. **Fork repository**
2. **Tạo branch mới**:
   ```bash
   git checkout -b feature/ten-tinh-nang
   # hoặc
   git checkout -b bugfix/mo-ta-loi
   ```

3. **Implement changes**:
   - Tuân thủ coding standards
   - Viết tests cho code mới
   - Cập nhật documentation

4. **Commit changes**:
   ```bash
   git commit -m "feat: thêm tính năng auto-refresh"
   # hoặc  
   git commit -m "fix: sửa lỗi database connection timeout"
   ```

5. **Push và tạo Pull Request**:
   ```bash
   git push origin feature/ten-tinh-nang
   ```

#### Coding Standards

**Java Code Style:**
- Sử dụng 4 spaces cho indentation
- Tên class: PascalCase
- Tên method/variable: camelCase
- Tên constant: UPPER_SNAKE_CASE
- Luôn sử dụng `{}` cho if/for/while blocks

**Javadoc Comments:**
```java
/**
 * Mô tả ngắn gọn về method.
 * <p>
 * Mô tả chi tiết hơn nếu cần thiết.
 *
 * @param parameter Mô tả tham số
 * @return Mô tả giá trị trả về
 * @throws Exception Mô tả exception có thể xảy ra
 */
public ReturnType methodName(ParameterType parameter) throws Exception {
    // Implementation
}
```

**Database Operations:**
- Luôn sử dụng PreparedStatement
- Proper resource management với try-with-resources
- Synchronized methods cho thread safety
- Proper error handling và logging

**UI Components:**
- Sử dụng SwingUtilities.invokeLater() cho UI updates
- Proper disposal của resources
- Consistent spacing và alignment

#### Testing

Trước khi submit Pull Request:

1. **Build thành công**:
   ```bash
   mvn clean compile
   ```

2. **Test extension manually**:
   - Load vào Burp Suite
   - Test các chức năng chính
   - Verify không có memory leaks

3. **Kiểm tra lỗi**:
   - Không có compiler warnings
   - Proper exception handling
   - No resource leaks

## 📋 Development Setup

### Prerequisites

```bash
# Java 17+
java -version

# Maven 3.6+
mvn -version

# Burp Suite Professional
```

### Setup Environment

```bash
# Clone repo
git clone https://github.com/vn-ncvinh/RecheckScan.git
cd RecheckScan

# Build
mvn clean compile

# Package
mvn package

# Load target/burp-recheck-scan-2.0-SQLITE.jar vào Burp
```

### Project Structure

```
src/main/java/com/example/
├── DatabaseManager.java          # Database operations
├── RecheckScanApiExtension.java   # Main extension logic  
└── SettingsPanel.java            # UI configuration
```

## 🔍 Code Review Process

### Pull Request Requirements

- [ ] Clear description of changes
- [ ] No breaking changes (unless major version)
- [ ] Documentation updates
- [ ] Manual testing completed
- [ ] Clean commit history

### Review Criteria

1. **Code Quality**:
   - Readable và maintainable
   - Proper error handling
   - Consistent với existing code style

2. **Functionality**:
   - Features work as described
   - No regression bugs
   - Performance impact acceptable

3. **Security**:
   - No SQL injection vulnerabilities
   - Proper input validation
   - Safe file operations

## 📝 Commit Message Guidelines

Sử dụng format:

```
type(scope): description

body (optional)

footer (optional)
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(database): add connection pooling support

Implement connection pooling to improve performance
when handling multiple concurrent requests.

Closes #123
```

```
fix(ui): resolve table not updating after database changes

The table model wasn't properly refreshing after database
operations completed on background threads.

Fixes #456
```

## 🏷️ Versioning

Dự án tuân thủ [Semantic Versioning](https://semver.org/):

- **MAJOR.MINOR.PATCH**
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes

## 📞 Liên hệ

Nếu có câu hỏi về contributing:

- Tạo Discussion trong GitHub repo
- Open Issue với label "question"
- Email trực tiếp cho maintainers

---

**Cảm ơn bạn đã quan tâm đến dự án! 🙏**
