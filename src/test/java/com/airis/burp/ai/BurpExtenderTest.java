package com.airis.burp.ai;

import com.airis.burp.ai.config.ConfigManager;

public class BurpExtenderTest {
    private BurpExtender burpExtender;
    private MockBurpExtenderCallbacks mockCallbacks;

    public static void main(String[] args) {
        BurpExtenderTest test = new BurpExtenderTest();
        test.runAllTests();
    }

    public void runAllTests() {
        testRegisterExtension();
        testInitialization();
        testGetConfigManager();
        testGetExtensionName();
        System.out.println("All tests passed!");
    }

    private void setUp() {
        burpExtender = new BurpExtender();
        mockCallbacks = new MockBurpExtenderCallbacks();
    }

    private void testRegisterExtension() {
        setUp();
        burpExtender.registerExtenderCallbacks(mockCallbacks);
        
        // Verify that the extension was properly registered
        assertTrue(mockCallbacks.isExtensionRegistered());
        assertEquals("AI Security Analyzer", mockCallbacks.getRegisteredExtensionName());
        System.out.println("✓ testRegisterExtension");
    }

    private void testInitialization() {
        setUp();
        burpExtender.registerExtenderCallbacks(mockCallbacks);
        
        // Verify that components were initialized
        assertNotNull(burpExtender.getConfigManager());
        System.out.println("✓ testInitialization");
    }

    private void testGetConfigManager() {
        setUp();
        burpExtender.registerExtenderCallbacks(mockCallbacks);
        
        ConfigManager configManager = burpExtender.getConfigManager();
        assertNotNull(configManager);
        
        // Should return the same instance on subsequent calls
        ConfigManager configManager2 = burpExtender.getConfigManager();
        assertTrue(configManager == configManager2);
        System.out.println("✓ testGetConfigManager");
    }

    private void testGetExtensionName() {
        setUp();
        String extensionName = burpExtender.getExtensionName();
        assertEquals("AI Security Analyzer", extensionName);
        System.out.println("✓ testGetExtensionName");
    }

    // Mock implementation of IBurpExtenderCallbacks
    private class MockBurpExtenderCallbacks {
        private boolean extensionRegistered = false;
        private String registeredExtensionName = "";

        public void setExtensionName(String name) {
            this.registeredExtensionName = name;
            this.extensionRegistered = true;
        }

        public void printOutput(String output) {
            System.out.println("Burp Output: " + output);
        }

        public void printError(String error) {
            System.err.println("Burp Error: " + error);
        }

        public boolean isExtensionRegistered() {
            return extensionRegistered;
        }

        public String getRegisteredExtensionName() {
            return registeredExtensionName;
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

    private void assertTrue(boolean condition) {
        if (!condition) {
            throw new AssertionError("Expected true, but was false");
        }
    }
}