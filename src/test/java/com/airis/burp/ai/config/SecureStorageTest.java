package com.airis.burp.ai.config;

import java.io.File;

public class SecureStorageTest {
    private SecureStorage secureStorage;
    private String testConfigPath = "test_config.json";

    public static void main(String[] args) {
        SecureStorageTest test = new SecureStorageTest();
        test.runAllTests();
    }

    public void runAllTests() {
        testEncryptDecrypt();
        testSaveAndLoad();
        testLoadNonExistentFile();
        testInvalidData();
        cleanupTestFiles();
        System.out.println("All tests passed!");
    }

    private void setUp() {
        secureStorage = new SecureStorage();
        cleanupTestFiles();
    }

    private void testEncryptDecrypt() {
        setUp();
        String plaintext = "test-api-key-12345";
        String encrypted = secureStorage.encrypt(plaintext);
        
        assertNotNull(encrypted);
        assertNotEquals(plaintext, encrypted);
        
        String decrypted = secureStorage.decrypt(encrypted);
        assertEquals(plaintext, decrypted);
        System.out.println("✓ testEncryptDecrypt");
    }

    private void testSaveAndLoad() {
        setUp();
        ConfigModel config = new ConfigModel();
        config.setProvider("openai");
        config.setEndpoint("https://api.openai.com/v1/chat/completions");
        config.setEncryptedApiKey("test-encrypted-key");
        config.setSystemPrompt("Test system prompt");
        
        secureStorage.save(config, testConfigPath);
        
        ConfigModel loaded = secureStorage.load(testConfigPath);
        assertEquals(config.getProvider(), loaded.getProvider());
        assertEquals(config.getEndpoint(), loaded.getEndpoint());
        assertEquals(config.getEncryptedApiKey(), loaded.getEncryptedApiKey());
        assertEquals(config.getSystemPrompt(), loaded.getSystemPrompt());
        System.out.println("✓ testSaveAndLoad");
    }

    private void testLoadNonExistentFile() {
        setUp();
        ConfigModel config = secureStorage.load("non_existent_file.json");
        assertNotNull(config);
        assertEquals("", config.getProvider());
        System.out.println("✓ testLoadNonExistentFile");
    }

    private void testInvalidData() {
        setUp();
        // Test null encryption
        String encrypted = secureStorage.encrypt(null);
        assertEquals("", encrypted);
        
        // Test null decryption
        String decrypted = secureStorage.decrypt(null);
        assertEquals("", decrypted);
        
        // Test empty string encryption
        encrypted = secureStorage.encrypt("");
        assertEquals("", encrypted);
        System.out.println("✓ testInvalidData");
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
}