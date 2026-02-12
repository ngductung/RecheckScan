# Build và Deployment Instructions

## 🔧 Build Requirements

### System Requirements
- **Java Development Kit (JDK) 17+**
- **Apache Maven 3.6+**
- **Git** (for cloning repository)
- **Burp Suite Professional 2023.1.2+** (for testing)

### Verification Commands
```bash
# Verify Java version
java -version
javac -version

# Verify Maven
mvn -version

# Verify Git
git --version
```

## 📦 Build Process

### 1. Clone Repository
```bash
git clone https://github.com/vn-ncvinh/RecheckScan.git
cd RecheckScan
```

### 2. Clean Build
```bash
# Clean previous builds
mvn clean

# Compile source code
mvn compile

# Run tests (if available)
mvn test

# Package with dependencies
mvn package
```

### 3. Build Output
```bash
target/
├── classes/                          # Compiled .class files
├── burp-recheck-scan-2.0-SQLITE.jar # Main JAR file
├── original-burp-recheck-scan-2.0-SQLITE.jar # JAR without dependencies
└── maven-archiver/
```

## 🚀 Deployment to Burp Suite

### Method 1: Load from JAR file

1. **Open Burp Suite Professional**
2. **Go to Extensions tab**
3. **Click "Add" button**
4. **Select "Java" as extension type**
5. **Browse to select**: `target/burp-recheck-scan-2.0-SQLITE.jar`
6. **Click "Next" to load**

### Method 2: Development Mode

1. **Add to classpath**:
   ```bash
   # Add target/classes to Burp's classpath
   -classpath "target/classes:lib/*"
   ```

2. **Set main class**: `com.example.RecheckScanApiExtension`

## 🔍 Verification Steps

### After Loading Extension

1. **Check Extension Output**:
   - Go to Extensions → Installed
   - Verify "Recheck Scan API (v2)" is loaded
   - Check "Output" tab for initialization messages

2. **Verify UI Elements**:
   - New tab "Recheck Scan" should appear
   - Three sub-tabs: Unscanned, Logs, Settings
   - Settings should load saved configuration

3. **Test Basic Functionality**:
   ```bash
   # Expected log messages:
   Successfully connected to SQLite database: [path]
   Extension loaded successfully
   ```

### Database Initialization

```bash
# Default database location
%USERPROFILE%\AppData\Local\RecheckScan\scan_api.db

# Verify database creation
sqlite3 scan_api.db ".tables"
# Should show: api_log
```

## 🛠️ Development Build

### IDE Setup (IntelliJ IDEA)

```xml
<!-- Add to IntelliJ project configuration -->
<module>
  <component name="NewModuleRootManager">
    <orderEntry type="library" name="Burp Suite Professional" level="project" />
  </component>
</module>
```

### Maven Development Profile

```bash
# Development build with debug info
mvn clean compile -Pdevelopment

# Quick build (skip tests)
mvn clean package -DskipTests

# Debug build
mvn clean package -X
```

### Hot Reload During Development

1. **Enable auto-compile** in IDE
2. **Use Burp's extension reload**:
   - Extensions → Installed → Select extension → Reload
3. **Monitor Extension Output** for errors

## 📋 Build Troubleshooting

### Common Issues

**1. Java Version Mismatch**
```bash
Error: Unsupported major.minor version
```
**Solution**: Verify Java 17+ is being used
```bash
export JAVA_HOME=/path/to/java17
mvn clean package
```

**2. Missing Dependencies**
```bash
Error: Could not resolve dependencies
```
**Solution**: Force dependency download
```bash
mvn dependency:resolve
mvn clean package
```

**3. Shade Plugin Issues**
```bash
Error: Failed to execute goal shade
```
**Solution**: Clear Maven cache
```bash
rm -rf ~/.m2/repository/org/apache/maven/plugins/maven-shade-plugin
mvn clean package
```

**4. SQLite Driver Not Found**
```bash
ClassNotFoundException: org.sqlite.JDBC
```
**Solution**: Verify shade plugin includes SQLite dependency
```bash
# Check JAR contents
jar -tf target/burp-recheck-scan-2.0-SQLITE.jar | grep sqlite
```

### Build Verification

```bash
# Verify JAR structure
jar -tf target/burp-recheck-scan-2.0-SQLITE.jar

# Should contain:
# com/example/RecheckScanApiExtension.class
# com/example/DatabaseManager.class  
# com/example/SettingsPanel.class
# org/sqlite/ (SQLite driver classes)
# META-INF/MANIFEST.MF (with Main-Class)
```

### Performance Testing

```bash
# Memory usage test
jps | grep -i burp
jstat -gc [PID] 5s

# Extension load time
tail -f ~/.BurpSuite/logs/extensions.log
```

## 🔧 Build Customization

### Custom Build Properties

```xml
<!-- Add to pom.xml for custom builds -->
<properties>
    <extension.version>2.0-CUSTOM</extension.version>
    <sqlite.version>3.50.1.0</sqlite.version>
    <burp.api.version>2025.6</burp.api.version>
</properties>
```

### Environment-Specific Builds

```bash
# Production build
mvn clean package -Pproduction

# Debug build  
mvn clean package -Pdebug -Dmaven.compiler.debug=true

# Minimal build (no debug info)
mvn clean package -Dminimal=true
```

### Custom JAR Name

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-shade-plugin</artifactId>
    <configuration>
        <finalName>RecheckScan-${project.version}-custom</finalName>
    </configuration>
</plugin>
```

## 📊 Build Metrics

### Typical Build Times
- **Clean compile**: ~10-15 seconds
- **Full package**: ~20-30 seconds  
- **With tests**: ~45-60 seconds

### JAR Size Expectations
- **With dependencies**: ~3-5 MB
- **Classes only**: ~100-200 KB
- **SQLite driver**: ~2-3 MB

### Resource Usage
- **Build memory**: 512MB - 1GB heap
- **Runtime memory**: 50-100MB
- **Database size**: 1-10MB (depending on data)

---

**For CI/CD pipeline integration, see `.github/workflows/` directory for GitHub Actions configuration.**
