package com.airis.burp.ai.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.*;
import java.io.File;

public class SecureStorageTest {
    private SecureStorage secureStorage;
    private String testConfigPath = "test_config.json";

    @BeforeEach
    public void setUp() {
        secureStorage = new SecureStorage();
        cleanupTestFiles();
    }

    @AfterEach
    public void tearDown() {
        cleanupTestFiles();
    }

    @Test
    public void testEncryptDecrypt() {
        String plaintext = "test-api-key-12345";
        String encrypted = secureStorage.encrypt(plaintext);
        
        assertNotNull(encrypted);
        assertNotEquals(plaintext, encrypted);
        
        String decrypted = secureStorage.decrypt(encrypted);
        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testSaveAndLoad() {
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
    }

    @Test
    public void testLoadNonExistentFile() {
        ConfigModel config = secureStorage.load("non_existent_file.json");
        assertNotNull(config);
        assertEquals("", config.getProvider());
    }

    @Test
    public void testInvalidData() {
        // Test null encryption
        String encrypted = secureStorage.encrypt(null);
        assertEquals("", encrypted);
        
        // Test null decryption
        String decrypted = secureStorage.decrypt(null);
        assertEquals("", decrypted);
        
        // Test empty string encryption
        encrypted = secureStorage.encrypt("");
        assertEquals("", encrypted);
    }

    private void cleanupTestFiles() {
        File testFile = new File(testConfigPath);
        if (testFile.exists()) {
            testFile.delete();
        }
    }
}