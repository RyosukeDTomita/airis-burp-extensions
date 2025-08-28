package com.airis.burp.ai.config;

package com.airis.burp.ai.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class ConfigModelTest {
    private ConfigModel configModel;

    @BeforeEach
    public void setUp() {
        configModel = new ConfigModel();
    }

    @Test
    public void testDefaultValues() {
        assertEquals("", configModel.getProvider());
        assertEquals("", configModel.getEndpoint());
        assertEquals("", configModel.getEncryptedApiKey());
        assertEquals("", configModel.getSystemPrompt());
    }

    @Test
    public void testSetAndGetProvider() {
        String provider = "openai";
        configModel.setProvider(provider);
        assertEquals(provider, configModel.getProvider());
    }

    @Test
    public void testSetAndGetEndpoint() {
        String endpoint = "https://api.openai.com/v1/chat/completions";
        configModel.setEndpoint(endpoint);
        assertEquals(endpoint, configModel.getEndpoint());
    }

    @Test
    public void testSetAndGetEncryptedApiKey() {
        String encryptedKey = "encrypted_api_key_here";
        configModel.setEncryptedApiKey(encryptedKey);
        assertEquals(encryptedKey, configModel.getEncryptedApiKey());
    }

    @Test
    public void testSetAndGetSystemPrompt() {
        String prompt = "Analyze HTTP requests for security vulnerabilities";
        configModel.setSystemPrompt(prompt);
        assertEquals(prompt, configModel.getSystemPrompt());
    }

    @Test
    public void testValidateProvider() {
        assertTrue(configModel.isValidProvider("openai"));
        assertTrue(configModel.isValidProvider("anthropic"));
        assertFalse(configModel.isValidProvider("invalid"));
        assertFalse(configModel.isValidProvider(""));
        assertFalse(configModel.isValidProvider(null));
    }

    @Test
    public void testValidateEndpoint() {
        assertTrue(configModel.isValidEndpoint("https://api.openai.com/v1/chat/completions"));
        assertTrue(configModel.isValidEndpoint("https://api.anthropic.com/v1/messages"));
        assertFalse(configModel.isValidEndpoint("http://insecure.com"));
        assertFalse(configModel.isValidEndpoint("not_a_url"));
        assertFalse(configModel.isValidEndpoint(""));
        assertFalse(configModel.isValidEndpoint(null));
    }

    @Test
    public void testIsComplete() {
        assertFalse(configModel.isComplete());
        
        configModel.setProvider("openai");
        assertFalse(configModel.isComplete());
        
        configModel.setEndpoint("https://api.openai.com/v1/chat/completions");
        assertFalse(configModel.isComplete());
        
        configModel.setEncryptedApiKey("encrypted_key");
        assertFalse(configModel.isComplete());
        
        configModel.setSystemPrompt("Test prompt");
        assertTrue(configModel.isComplete());
    }
}