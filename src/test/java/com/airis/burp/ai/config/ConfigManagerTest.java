package com.airis.burp.ai.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import static org.junit.jupiter.api.Assertions.*;
import java.io.File;

public class ConfigManagerTest {
    private ConfigManager configManager;
    private String testConfigPath = "test_manager_config.json";

    @BeforeEach
    public void setUp() {
        configManager = new ConfigManager(testConfigPath);
        cleanupTestFiles();
    }

    @AfterEach
    public void tearDown() {
        cleanupTestFiles();
    }

    @Test
    public void testLoadDefaultConfig() {
        ConfigModel config = configManager.loadConfig();
        assertNotNull(config);
        assertEquals("", config.getProvider());
        assertEquals("", config.getEndpoint());
        assertEquals("", config.getEncryptedApiKey());
        assertNotEquals("", config.getSystemPrompt()); // Should have default prompt
    }

    @Test
    public void testSaveAndLoadConfig() {
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
    }

    @Test
    public void testEncryptApiKey() {
        String plainKey = "sk-1234567890abcdef";
        String encrypted = configManager.encryptApiKey(plainKey);
        
        assertNotNull(encrypted);
        assertNotEquals("", encrypted);
        assertNotEquals(plainKey, encrypted);
    }

    @Test
    public void testDecryptApiKey() {
        String plainKey = "sk-1234567890abcdef";
        String encrypted = configManager.encryptApiKey(plainKey);
        String decrypted = configManager.decryptApiKey(encrypted);
        
        assertEquals(plainKey, decrypted);
    }

    @Test
    public void testValidateConfig() {
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
    }

    @Test
    public void testGetDefaultSystemPrompt() {
        String defaultPrompt = configManager.getDefaultSystemPrompt();
        assertNotNull(defaultPrompt);
        assertNotEquals("", defaultPrompt);
        assertTrue(defaultPrompt.contains("HTTP"));
    }

    private void cleanupTestFiles() {
        File testFile = new File(testConfigPath);
        if (testFile.exists()) {
            testFile.delete();
        }
    }
}