package com.airis.burp.ai.config;

public class ConfigModelTest {
    private ConfigModel configModel;

    public static void main(String[] args) {
        ConfigModelTest test = new ConfigModelTest();
        test.runAllTests();
    }

    public void runAllTests() {
        testDefaultValues();
        testSetAndGetProvider();
        testSetAndGetEndpoint();
        testSetAndGetEncryptedApiKey();
        testSetAndGetSystemPrompt();
        testValidateProvider();
        testValidateEndpoint();
        testIsComplete();
        System.out.println("All tests passed!");
    }

    private void setUp() {
        configModel = new ConfigModel();
    }

    private void testDefaultValues() {
        setUp();
        assertEquals("", configModel.getProvider());
        assertEquals("", configModel.getEndpoint());
        assertEquals("", configModel.getEncryptedApiKey());
        assertEquals("", configModel.getSystemPrompt());
        System.out.println("✓ testDefaultValues");
    }

    private void testSetAndGetProvider() {
        setUp();
        String provider = "openai";
        configModel.setProvider(provider);
        assertEquals(provider, configModel.getProvider());
        System.out.println("✓ testSetAndGetProvider");
    }

    private void testSetAndGetEndpoint() {
        setUp();
        String endpoint = "https://api.openai.com/v1/chat/completions";
        configModel.setEndpoint(endpoint);
        assertEquals(endpoint, configModel.getEndpoint());
        System.out.println("✓ testSetAndGetEndpoint");
    }

    private void testSetAndGetEncryptedApiKey() {
        setUp();
        String encryptedKey = "encrypted_api_key_here";
        configModel.setEncryptedApiKey(encryptedKey);
        assertEquals(encryptedKey, configModel.getEncryptedApiKey());
        System.out.println("✓ testSetAndGetEncryptedApiKey");
    }

    private void testSetAndGetSystemPrompt() {
        setUp();
        String prompt = "Analyze HTTP requests for security vulnerabilities";
        configModel.setSystemPrompt(prompt);
        assertEquals(prompt, configModel.getSystemPrompt());
        System.out.println("✓ testSetAndGetSystemPrompt");
    }

    private void testValidateProvider() {
        setUp();
        assertTrue(configModel.isValidProvider("openai"));
        assertTrue(configModel.isValidProvider("anthropic"));
        assertFalse(configModel.isValidProvider("invalid"));
        assertFalse(configModel.isValidProvider(""));
        assertFalse(configModel.isValidProvider(null));
        System.out.println("✓ testValidateProvider");
    }

    private void testValidateEndpoint() {
        setUp();
        assertTrue(configModel.isValidEndpoint("https://api.openai.com/v1/chat/completions"));
        assertTrue(configModel.isValidEndpoint("https://api.anthropic.com/v1/messages"));
        assertFalse(configModel.isValidEndpoint("http://insecure.com"));
        assertFalse(configModel.isValidEndpoint("not_a_url"));
        assertFalse(configModel.isValidEndpoint(""));
        assertFalse(configModel.isValidEndpoint(null));
        System.out.println("✓ testValidateEndpoint");
    }

    private void testIsComplete() {
        setUp();
        assertFalse(configModel.isComplete());
        
        configModel.setProvider("openai");
        assertFalse(configModel.isComplete());
        
        configModel.setEndpoint("https://api.openai.com/v1/chat/completions");
        assertFalse(configModel.isComplete());
        
        configModel.setEncryptedApiKey("encrypted_key");
        assertFalse(configModel.isComplete());
        
        configModel.setSystemPrompt("Test prompt");
        assertTrue(configModel.isComplete());
        System.out.println("✓ testIsComplete");
    }

    private void assertEquals(String expected, String actual) {
        if (!expected.equals(actual)) {
            throw new AssertionError("Expected: " + expected + ", but was: " + actual);
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