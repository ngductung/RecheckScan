package com.example;

import burp.api.montoya.MontoyaApi;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DatabaseManagerRecoveryTest {
    @TempDir Path tempDir;

    @Test
    void invalidProjectPathFallsBackAndCanSwitchToValidDatabase() throws Exception {
        Path blocker = Files.createFile(tempDir.resolve("blocker"));
        Path invalid = blocker.resolve("scan.db");
        DatabaseManager manager = new DatabaseManager(apiWithNoopLogging());
        String temporaryDbPath = null;
        try {
            assertNotNull(manager.initialize(invalid.toString()));
            temporaryDbPath = manager.currentDbPath();
            assertTrue(temporaryDbPath.startsWith(Path.of(System.getProperty("java.io.tmpdir")).toString()));
            assertTrue(Files.exists(Path.of(temporaryDbPath)));
            manager.saveSettings(Map.of("highlightEnabled", "true"));
            assertEquals("true", manager.loadSettings().get("highlightEnabled"));

            assertThrows(SQLException.class, () -> manager.reopen(invalid.toString()));
            assertEquals(temporaryDbPath, manager.currentDbPath());
            assertEquals("true", manager.loadSettings().get("highlightEnabled"));

            Path valid = tempDir.resolve("new").resolve("scan.db");
            manager.reopen(valid.toString());
            assertEquals(valid.toString(), manager.currentDbPath());
            assertTrue(Files.exists(valid));
            assertTrue(manager.loadSettings().isEmpty());
            manager.saveSettings(Map.of("highlightEnabled", "false"));
            assertThrows(SQLException.class, () -> manager.reopen(invalid.toString()));
            assertEquals(valid.toString(), manager.currentDbPath());
            assertEquals("false", manager.loadSettings().get("highlightEnabled"));
            manager.reopen(valid.toString());
            assertEquals("false", manager.loadSettings().get("highlightEnabled"));
        } finally {
            manager.close();
            if (temporaryDbPath != null) {
                Files.deleteIfExists(Path.of(temporaryDbPath));
            }
        }
    }

    private static MontoyaApi apiWithNoopLogging() {
        Class<?> loggingType;
        try {
            loggingType = MontoyaApi.class.getMethod("logging").getReturnType();
        } catch (NoSuchMethodException e) {
            throw new AssertionError(e);
        }
        Object logging = Proxy.newProxyInstance(loggingType.getClassLoader(), new Class<?>[]{loggingType},
                (proxy, method, args) -> null);
        return (MontoyaApi) Proxy.newProxyInstance(MontoyaApi.class.getClassLoader(),
                new Class<?>[]{MontoyaApi.class},
                (proxy, method, args) -> method.getName().equals("logging") ? logging : null);
    }
}
