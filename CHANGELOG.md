# Changelog

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
