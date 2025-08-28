package com.airis.burp.ai.config;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Secure storage for configuration data with encryption support.
 */
public class SecureStorage {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES";
    private SecretKey secretKey;

    public SecureStorage() {
        initializeKey();
    }

    private void initializeKey() {
        try {
            // In a real implementation, this key should be derived from user-specific data
            // For now, using a simple fixed key for testing
            byte[] keyBytes = "MySecretKey12345".getBytes(); // 16 bytes for AES-128
            this.secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize encryption key", e);
        }
    }

    public String encrypt(String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) {
            return "";
        }
        
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String decrypt(String encryptedText) {
        if (encryptedText == null || encryptedText.isEmpty()) {
            return "";
        }
        
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] encrypted = Base64.getDecoder().decode(encryptedText);
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    public void save(ConfigModel config, String filePath) {
        try {
            // Simple JSON-like format for saving
            StringBuilder json = new StringBuilder();
            json.append("{\n");
            json.append("  \"provider\": \"").append(config.getProvider()).append("\",\n");
            json.append("  \"endpoint\": \"").append(config.getEndpoint()).append("\",\n");
            json.append("  \"encryptedApiKey\": \"").append(config.getEncryptedApiKey()).append("\",\n");
            json.append("  \"systemPrompt\": \"").append(config.getSystemPrompt().replace("\"", "\\\"")).append("\"\n");
            json.append("}");
            
            Files.write(Paths.get(filePath), json.toString().getBytes());
        } catch (Exception e) {
            throw new RuntimeException("Failed to save configuration", e);
        }
    }

    public ConfigModel load(String filePath) {
        ConfigModel config = new ConfigModel();
        
        try {
            if (!Files.exists(Paths.get(filePath))) {
                return config; // Return empty config if file doesn't exist
            }
            
            String content = new String(Files.readAllBytes(Paths.get(filePath)));
            
            // Simple JSON parsing (not production-ready, but sufficient for testing)
            config.setProvider(extractValue(content, "provider"));
            config.setEndpoint(extractValue(content, "endpoint"));
            config.setEncryptedApiKey(extractValue(content, "encryptedApiKey"));
            config.setSystemPrompt(extractValue(content, "systemPrompt"));
            
        } catch (Exception e) {
            // Return empty config on error
        }
        
        return config;
    }

    private String extractValue(String json, String key) {
        String searchKey = "\"" + key + "\": \"";
        int startIndex = json.indexOf(searchKey);
        if (startIndex == -1) {
            return "";
        }
        startIndex += searchKey.length();
        int endIndex = json.indexOf("\"", startIndex);
        if (endIndex == -1) {
            return "";
        }
        return json.substring(startIndex, endIndex).replace("\\\"", "\"");
    }
}