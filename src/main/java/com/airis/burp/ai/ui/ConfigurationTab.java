package com.airis.burp.ai.ui;

import burp.ITab;
import com.airis.burp.ai.config.ConfigManager;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.core.AnalysisEngine;
import burp.api.montoya.logging.Logging;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Configuration tab for the AI Security Analyzer extension.
 */
public class ConfigurationTab implements ITab {
    
    private final ConfigManager configManager;
    private final AnalysisEngine analysisEngine;
    private final Logging logging; // For Montoya API logging (optional)
    private JPanel mainPanel;
    private JComboBox<String> providerCombo;
    private JTextField endpointField;
    private JPasswordField apiKeyField;
    private JTextArea systemPromptArea;
    private JButton saveButton;
    private JButton testButton;
    private JLabel statusLabel;

    // Constructor for legacy API
    public ConfigurationTab(ConfigManager configManager, AnalysisEngine analysisEngine) {
        this(configManager, analysisEngine, null);
    }
    
    // Constructor for Montoya API
    public ConfigurationTab(ConfigManager configManager, Logging logging) {
        this(configManager, null, logging);
    }
    
    // Common constructor
    public ConfigurationTab(ConfigManager configManager, AnalysisEngine analysisEngine, Logging logging) {
        this.configManager = configManager;
        this.analysisEngine = analysisEngine;
        this.logging = logging;
        initializeUI();
        loadConfiguration();
    }

    @Override
    public String getTabCaption() {
        return "AI Security Analyzer";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
    
    /**
     * Get the component for Montoya API registration
     */
    public Component getComponent() {
        return mainPanel;
    }

    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout());
        
        // Create configuration panel
        JPanel configPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Title
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        JLabel titleLabel = new JLabel("AI Security Analyzer Configuration");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 16f));
        configPanel.add(titleLabel, gbc);
        
        // Provider selection
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        configPanel.add(new JLabel("LLM Provider:"), gbc);
        
        gbc.gridx = 1;
        providerCombo = new JComboBox<>(new String[]{"openai", "anthropic"});
        configPanel.add(providerCombo, gbc);
        
        // Endpoint URL
        gbc.gridx = 0;
        gbc.gridy = 2;
        configPanel.add(new JLabel("Endpoint URL:"), gbc);
        
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        endpointField = new JTextField(40);
        endpointField.setText("https://api.openai.com/v1/chat/completions");
        configPanel.add(endpointField, gbc);
        
        // API Key
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        configPanel.add(new JLabel("API Key:"), gbc);
        
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        apiKeyField = new JPasswordField(40);
        configPanel.add(apiKeyField, gbc);
        
        // System Prompt
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        configPanel.add(new JLabel("System Prompt:"), gbc);
        
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        systemPromptArea = new JTextArea(8, 40);
        systemPromptArea.setLineWrap(true);
        systemPromptArea.setWrapStyleWord(true);
        systemPromptArea.setText(configManager.getDefaultSystemPrompt());
        JScrollPane scrollPane = new JScrollPane(systemPromptArea);
        configPanel.add(scrollPane, gbc);
        
        // Buttons
        gbc.gridx = 0;
        gbc.gridy = 5;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0;
        gbc.weighty = 0;
        gbc.anchor = GridBagConstraints.CENTER;
        
        JPanel buttonPanel = new JPanel(new FlowLayout());
        
        saveButton = new JButton("Save Configuration");
        saveButton.addActionListener(new SaveAction());
        buttonPanel.add(saveButton);
        
        testButton = new JButton("Test Connection");
        testButton.addActionListener(new TestAction());
        buttonPanel.add(testButton);
        
        configPanel.add(buttonPanel, gbc);
        
        // Status label
        gbc.gridy = 6;
        statusLabel = new JLabel("Ready");
        statusLabel.setForeground(Color.BLUE);
        configPanel.add(statusLabel, gbc);
        
        mainPanel.add(configPanel, BorderLayout.CENTER);
        
        // Add provider change listener
        providerCombo.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                updateEndpointForProvider();
            }
        });
    }

    private void loadConfiguration() {
        ConfigModel config = configManager.loadConfig();
        if (config != null) {
            if (!config.getProvider().isEmpty()) {
                providerCombo.setSelectedItem(config.getProvider());
            }
            if (!config.getEndpoint().isEmpty()) {
                endpointField.setText(config.getEndpoint());
            }
            if (!config.getSystemPrompt().isEmpty()) {
                systemPromptArea.setText(config.getSystemPrompt());
            }
        }
    }

    private void updateEndpointForProvider() {
        String provider = (String) providerCombo.getSelectedItem();
        if ("openai".equals(provider)) {
            endpointField.setText("https://api.openai.com/v1/chat/completions");
        } else if ("anthropic".equals(provider)) {
            endpointField.setText("https://api.anthropic.com/v1/messages");
        }
    }

    private class SaveAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            try {
                ConfigModel config = new ConfigModel();
                config.setProvider((String) providerCombo.getSelectedItem());
                config.setEndpoint(endpointField.getText().trim());
                
                // Encrypt API key
                String apiKey = new String(apiKeyField.getPassword());
                if (!apiKey.isEmpty()) {
                    String encryptedKey = configManager.encryptApiKey(apiKey);
                    config.setEncryptedApiKey(encryptedKey);
                }
                
                config.setSystemPrompt(systemPromptArea.getText().trim());
                
                // Validate configuration
                if (configManager.validateConfig(config)) {
                    configManager.saveConfig(config);
                    if (analysisEngine != null) {
                        analysisEngine.setConfiguration(config);
                    }
                    statusLabel.setText("Configuration saved successfully");
                    statusLabel.setForeground(Color.GREEN);
                    
                    // Log using appropriate API
                    if (logging != null) {
                        logging.logToOutput("Configuration saved successfully");
                    }
                } else {
                    statusLabel.setText("Invalid configuration - please check all fields");
                    statusLabel.setForeground(Color.RED);
                    
                    // Log using appropriate API  
                    if (logging != null) {
                        logging.logToError("Invalid configuration - please check all fields");
                    }
                }
                
            } catch (Exception ex) {
                statusLabel.setText("Error saving configuration: " + ex.getMessage());
                statusLabel.setForeground(Color.RED);
            }
        }
    }

    private class TestAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            statusLabel.setText("Testing connection... (Note: Actual API test not implemented in this version)");
            statusLabel.setForeground(Color.ORANGE);
            
            // In a real implementation, this would test the API connection
            Timer timer = new Timer(2000, new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    statusLabel.setText("Connection test completed (mock)");
                    statusLabel.setForeground(Color.BLUE);
                    ((Timer) e.getSource()).stop();
                }
            });
            timer.start();
        }
    }
}