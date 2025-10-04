package com.airis.burp.ai.config;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Provides secure storage for {@link ConfigModel} using Burp's persistence API with AES-GCM
 * encryption for sensitive values such as API keys.
 */
public final class SecureConfigStorage {
  private static final String ENCRYPTION_ALGORITHM = "AES";
  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int KEY_LENGTH = 256;
  private static final int GCM_IV_LENGTH = 12; // 96 bits per NIST recommendation
  private static final int GCM_TAG_LENGTH = 16; // 128-bit authentication tag

  private static final String MASTER_KEY_SETTING = "airis.master.key";
  private static final String PROVIDER_SETTING = "airis.config.provider";
  private static final String ENDPOINT_SETTING = "airis.config.endpoint";
  private static final String API_KEY_SETTING = "airis.config.apiKey";
  private static final String USER_PROMPT_SETTING = "airis.config.userPrompt";

  private final Logging logger;
  private final PersistedObject storage;
  private final SecureRandom secureRandom = new SecureRandom();

  private SecretKey masterKey;

  /**
   * Initializes secure storage, generating or loading the master encryption key.
   *
   * @param api
   */
  public SecureConfigStorage(MontoyaApi api) {
    this.logger = api.logging();
    this.storage = api.persistence().extensionData();
    this.initializeMasterKey();
  }

  /**
   * If no master key exists, generate and store a new one. If a key exists, it is loaded into
   * memory for encryption/decryption operations.
   * @throws IllegalStateException if key generation or loading fails.
   */
  private void initializeMasterKey() {
    String encodedKey = this.storage.getString(MASTER_KEY_SETTING);
    // If no master key exists, generate and store a new one.
    if (encodedKey == null || encodedKey.isEmpty()) {
      try {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ENCRYPTION_ALGORITHM);
        keyGenerator.init(KEY_LENGTH);
        this.masterKey = keyGenerator.generateKey();
        this.storage.setString(
            MASTER_KEY_SETTING, Base64.getEncoder().encodeToString(this.masterKey.getEncoded()));
        this.logger.logToOutput("Generated new encryption master key.");
      } catch (GeneralSecurityException e) {
        this.logger.logToError("Failed to generate master key: " + e.getMessage());
        throw new IllegalStateException("Unable to initialize secure storage", e);
      }
      // Load existing key
    } else {
      byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
      this.masterKey = new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
      this.logger.logToOutput("Loaded existing encryption master key.");
    }
  }

  /**
   * Loads configuration from Burp MontoyaApi.persistence().extensionData() if present.
   *
   * @return Optional<ConfigModel>
   */
  public Optional<ConfigModel> load() {
    final String provider = this.storage.getString(PROVIDER_SETTING);
    final String endpoint = this.storage.getString(ENDPOINT_SETTING);
    final String encryptedApiKey = this.storage.getString(API_KEY_SETTING);
    final String userPrompt = this.storage.getString(USER_PROMPT_SETTING);

    if (provider == null || endpoint == null || encryptedApiKey == null || userPrompt == null) {
      return Optional.empty();
    }

    try {
      String apiKey = this.decryptToString(encryptedApiKey);
      return Optional.of(new ConfigModel(provider, endpoint, apiKey, userPrompt));
    } catch (GeneralSecurityException e) {
      this.logger.logToError("Failed to decrypt stored configuration: " + e.getMessage());
      return Optional.empty();
    }
  }

  /** Saves the provided configuration to the Burp MontoyaApi.persistence().extensionData().
   * @param config The configuration model to save.
   * @throws IllegalStateException if encryption fails.
  */
  public void save(ConfigModel config) {
    String apiKey = config.getApiKey();
    try {
      String encryptedKey = this.encryptString(apiKey);

      this.storage.setString(PROVIDER_SETTING, config.getProvider());
      this.storage.setString(ENDPOINT_SETTING, config.getEndpoint());
      this.storage.setString(USER_PROMPT_SETTING, config.getUserPrompt());
      this.storage.setString(API_KEY_SETTING, encryptedKey);

      this.logger.logToOutput("Configuration stored securely.");
    } catch (GeneralSecurityException e) {
      this.logger.logToError("Failed to encrypt configuration: " + e.getMessage());
      throw new IllegalStateException("Unable to save configuration securely", e);
    }
  }

  /** Returns true if all configuration properties exist in storage.
   *
   * @return Boolean true if all configuration properties are present, false otherwise.
   **/
  public boolean hasConfig() {
    return this.storage.getString(PROVIDER_SETTING) != null
        && this.storage.getString(ENDPOINT_SETTING) != null
        && this.storage.getString(API_KEY_SETTING) != null
        && this.storage.getString(USER_PROMPT_SETTING) != null;
  }


  /** Deletes the master key and configuration data, reinitializing a fresh key. */
  public void reset() {
    this.storage.deleteString(MASTER_KEY_SETTING);
    this.storage.deleteString(PROVIDER_SETTING);
    this.storage.deleteString(ENDPOINT_SETTING);
    this.storage.deleteString(API_KEY_SETTING);
    this.storage.deleteString(USER_PROMPT_SETTING);
    this.initializeMasterKey();
    this.logger.logToOutput("Configuration cleared from storage.");
  }

  /**
   * Encrypts a plaintext string using AES-GCM with the master key.
   * @param plaintext
   * @return
   * @throws GeneralSecurityException
   */
  private String encryptString(String plaintext) throws GeneralSecurityException {
    if (plaintext == null || plaintext.isEmpty()) {
      return "";
    }

    byte[] plainBytes = plaintext.getBytes(StandardCharsets.UTF_8);
    try {
      byte[] iv = new byte[GCM_IV_LENGTH];
      this.secureRandom.nextBytes(iv);

      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(
          Cipher.ENCRYPT_MODE, this.masterKey, new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv));

      byte[] ciphertext = cipher.doFinal(plainBytes);
      byte[] combined = new byte[iv.length + ciphertext.length];
      System.arraycopy(iv, 0, combined, 0, iv.length);
      System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);

      return Base64.getEncoder().encodeToString(combined);
    } catch (GeneralSecurityException e) {
      throw e;
    } finally {
      Arrays.fill(plainBytes, (byte) 0);
    }
  }

  private String decryptToString(String encrypted) throws GeneralSecurityException {
    if (encrypted == null || encrypted.isEmpty()) {
      return "";
    }

    byte[] combined = Base64.getDecoder().decode(encrypted);
    if (combined.length <= GCM_IV_LENGTH) {
      throw new GeneralSecurityException("Invalid encrypted payload");
    }

    byte[] iv = Arrays.copyOfRange(combined, 0, GCM_IV_LENGTH);
    byte[] ciphertext = Arrays.copyOfRange(combined, GCM_IV_LENGTH, combined.length);

    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.DECRYPT_MODE, this.masterKey, new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv));

    byte[] plainBytes = cipher.doFinal(ciphertext);
    try {
      return new String(plainBytes, StandardCharsets.UTF_8);
    } finally {
      Arrays.fill(plainBytes, (byte) 0);
    }
  }
}
