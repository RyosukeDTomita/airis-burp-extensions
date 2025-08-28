package com.airis.burp.ai;

import com.airis.burp.ai.config.ConfigManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class BurpExtenderTest {
    private BurpExtender burpExtender;
    private MockBurpExtenderCallbacks mockCallbacks;

    @BeforeEach
    public void setUp() {
        burpExtender = new BurpExtender();
        mockCallbacks = new MockBurpExtenderCallbacks();
    }

    @Test
    public void testRegisterExtension() {
        burpExtender.registerExtenderCallbacks(mockCallbacks);
        
        // Verify that the extension was properly registered
        assertTrue(mockCallbacks.isExtensionRegistered());
        assertEquals("AI Security Analyzer", mockCallbacks.getRegisteredExtensionName());
    }

    @Test
    public void testInitialization() {
        burpExtender.registerExtenderCallbacks(mockCallbacks);
        
        // Verify that components were initialized
        assertNotNull(burpExtender.getConfigManager());
    }

    @Test
    public void testGetConfigManager() {
        burpExtender.registerExtenderCallbacks(mockCallbacks);
        
        ConfigManager configManager = burpExtender.getConfigManager();
        assertNotNull(configManager);
        
        // Should return the same instance on subsequent calls
        ConfigManager configManager2 = burpExtender.getConfigManager();
        assertTrue(configManager == configManager2);
    }

    @Test
    public void testGetExtensionName() {
        String extensionName = burpExtender.getExtensionName();
        assertEquals("AI Security Analyzer", extensionName);
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
}