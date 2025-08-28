package com.airis.burp.ai.config;

import java.io.File;

public class ConfigManagerTest {
    private ConfigManager configManager;
    private String testConfigPath = "test_manager_config.json";

    public static void main(String[] args) {
        ConfigManagerTest test = new ConfigManagerTest();
        test.runAllTests();
    }

    public void runAllTests() {
        testLoadDefaultConfig();
        testSaveAndLoadConfig();
        testEncryptApiKey();
        testDecryptApiKey();
        testValidateConfig();
        testGetDefaultSystemPrompt();
        cleanupTestFiles();
        System.out.println("All tests passed!");
    }

    private void setUp() {
        configManager = new ConfigManager(testConfigPath);
        cleanupTestFiles();
    }

    private void testLoadDefaultConfig() {
        setUp();
        ConfigModel config = configManager.loadConfig();
        assertNotNull(config);
        assertEquals("", config.getProvider());
        assertEquals("", config.getEndpoint());
        assertEquals("", config.getEncryptedApiKey());
        assertNotEquals("", config.getSystemPrompt()); // Should have default prompt
        System.out.println("✓ testLoadDefaultConfig");
    }

    private void testSaveAndLoadConfig() {
        setUp();
        ConfigModel config = new ConfigModel();
        config.setProvider("openai");
        config.setEndpoint("https://api.openai.com/v1/chat/completions");
        config.setEncryptedApiKey("encrypted-key");
        config.setSystemPrompt("Custom prompt");

        configManager.saveConfig(config);
        
        ConfigModel loaded = configManager.loadConfig();
        assertEquals(config.getProvider(), loaded.getProvider());
        assertEquals(config.getEndpoint(), loaded.getEndpoint());
        assertEquals(config.getEncryptedApiKey(), loaded.getEncryptedApiKey());
        assertEquals(config.getSystemPrompt(), loaded.getSystemPrompt());
        System.out.println("✓ testSaveAndLoadConfig");
    }

    private void testEncryptApiKey() {
        setUp();
        String plainKey = "sk-1234567890abcdef";
        String encrypted = configManager.encryptApiKey(plainKey);
        
        assertNotNull(encrypted);
        assertNotEquals("", encrypted);
        assertNotEquals(plainKey, encrypted);
        System.out.println("✓ testEncryptApiKey");
    }

    private void testDecryptApiKey() {
        setUp();
        String plainKey = "sk-1234567890abcdef";
        String encrypted = configManager.encryptApiKey(plainKey);
        String decrypted = configManager.decryptApiKey(encrypted);
        
        assertEquals(plainKey, decrypted);
        System.out.println("✓ testDecryptApiKey");
    }

    private void testValidateConfig() {
        setUp();
        ConfigModel config = new ConfigModel();
        
        assertFalse(configManager.validateConfig(config));
        
        config.setProvider("openai");
        assertFalse(configManager.validateConfig(config));
        
        config.setEndpoint("https://api.openai.com/v1/chat/completions");
        assertFalse(configManager.validateConfig(config));
        
        config.setEncryptedApiKey("encrypted-key");
        assertFalse(configManager.validateConfig(config));
        
        config.setSystemPrompt("Test prompt");
        assertTrue(configManager.validateConfig(config));
        
        // Test invalid provider
        config.setProvider("invalid");
        assertFalse(configManager.validateConfig(config));
        
        // Test invalid endpoint
        config.setProvider("openai");
        config.setEndpoint("http://insecure.com");
        assertFalse(configManager.validateConfig(config));
        System.out.println("✓ testValidateConfig");
    }

    private void testGetDefaultSystemPrompt() {
        setUp();
        String defaultPrompt = configManager.getDefaultSystemPrompt();
        assertNotNull(defaultPrompt);
        assertNotEquals("", defaultPrompt);
        assertTrue(defaultPrompt.contains("HTTP"));
        System.out.println("✓ testGetDefaultSystemPrompt");
    }

    private void cleanupTestFiles() {
        File testFile = new File(testConfigPath);
        if (testFile.exists()) {
            testFile.delete();
        }
    }

    // Simple assertions
    private void assertEquals(String expected, String actual) {
        if (!expected.equals(actual)) {
            throw new AssertionError("Expected: " + expected + ", but was: " + actual);
        }
    }

    private void assertNotNull(Object obj) {
        if (obj == null) {
            throw new AssertionError("Expected non-null value");
        }
    }

    private void assertNotEquals(String expected, String actual) {
        if (expected.equals(actual)) {
            throw new AssertionError("Expected different values, but both were: " + expected);
        }
    }

    private void assertTrue(boolean condition) {
        if (!condition) {
            throw new AssertionError("Expected true, but was false");
        }
    }

    private void assertFalse(boolean condition) {
        if (condition) {
            throw new AssertionError("Expected false, but was true");
        }
    }
}