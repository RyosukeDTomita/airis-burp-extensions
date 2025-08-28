package com.airis.burp.ai.ui;

import burp.*;
import com.airis.burp.ai.core.AnalysisEngine;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * Context menu factory that adds "AI Security Analyzer" option to context menus.
 */
public class RepeaterContextMenuFactory implements IContextMenuFactory {
    
    private final IBurpExtenderCallbacks callbacks;
    private final AnalysisEngine analysisEngine;
    
    public RepeaterContextMenuFactory(IBurpExtenderCallbacks callbacks, AnalysisEngine analysisEngine) {
        this.callbacks = callbacks;
        this.analysisEngine = analysisEngine;
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        try {
            // Only show menu for message editor/viewer contexts
            byte context = invocation.getInvocationContext();
            
            if (context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || 
                context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                
                IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
                
                if (selectedMessages != null && selectedMessages.length > 0) {
                    JMenuItem analyzeMenuItem = new JMenuItem("AI Security Analyzer");
                    analyzeMenuItem.addActionListener(new AnalyzeActionListener(selectedMessages[0]));
                    menuItems.add(analyzeMenuItem);
                }
            }
            
        } catch (Exception e) {
            callbacks.printError("Error in createMenuItems: " + e.getMessage());
            e.printStackTrace();
        }
        
        return menuItems;
    }
    
    /**
     * Action listener for the "AI Security Analyzer" menu item.
     */
    private class AnalyzeActionListener implements ActionListener {
        private final IHttpRequestResponse message;
        
        public AnalyzeActionListener(IHttpRequestResponse message) {
            this.message = message;
        }
        
        @Override
        public void actionPerformed(ActionEvent e) {
            // Execute analysis in background thread to avoid blocking UI
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    try {
                        callbacks.printOutput("Starting AI analysis...");
                        
                        // Extract request and response
                        String requestString = "";
                        String responseString = "";
                        
                        if (message.getRequest() != null) {
                            requestString = new String(message.getRequest());
                        }
                        
                        if (message.getResponse() != null) {
                            responseString = new String(message.getResponse());
                        }
                        
                        // Perform analysis
                        String result = analysisEngine.analyzeRequestResponse(requestString, responseString);
                        
                        // Check if we have a meaningful result
                        if (result == null || result.trim().isEmpty()) {
                            result = "AI analysis returned no result. Please check your API configuration and ensure the endpoint and API key are correctly set.";
                        }
                        
                        callbacks.printOutput("Analysis result: " + result);
                        
                        // Show result in dialog
                        showAnalysisResult(result);
                        
                    } catch (Exception ex) {
                        callbacks.printError("Error during AI analysis: " + ex.getMessage());
                        JOptionPane.showMessageDialog(
                            null, 
                            "分析中にエラーが発生しました: " + ex.getMessage(), 
                            "AI分析エラー", 
                            JOptionPane.ERROR_MESSAGE
                        );
                    }
                }
            });
        }
        
        private void showAnalysisResult(String result) {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    // Create dialog to show analysis result
                    JDialog resultDialog = new JDialog();
                    resultDialog.setTitle("AI Security Analysis Results");
                    resultDialog.setSize(1000, 700);
                    resultDialog.setLocationRelativeTo(null);
                    resultDialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
                    
                    // Create main panel with border layout
                    JPanel mainPanel = new JPanel(new java.awt.BorderLayout());
                    
                    // Add header
                    JLabel headerLabel = new JLabel("AI Security Analysis Results");
                    headerLabel.setFont(headerLabel.getFont().deriveFont(16.0f));
                    headerLabel.setBorder(javax.swing.BorderFactory.createEmptyBorder(10, 10, 10, 10));
                    mainPanel.add(headerLabel, java.awt.BorderLayout.NORTH);
                    
                    // Create text area with better formatting
                    JTextArea resultArea = new JTextArea(result);
                    resultArea.setEditable(false);
                    resultArea.setWrapStyleWord(true);
                    resultArea.setLineWrap(true);
                    resultArea.setFont(new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12));
                    resultArea.setMargin(new java.awt.Insets(10, 10, 10, 10));
                    
                    // Add scroll pane
                    JScrollPane scrollPane = new JScrollPane(resultArea);
                    scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                    scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                    mainPanel.add(scrollPane, java.awt.BorderLayout.CENTER);
                    
                    // Create button panel
                    JPanel buttonPanel = new JPanel(new java.awt.FlowLayout());
                    
                    JButton copyButton = new JButton("Copy to Clipboard");
                    copyButton.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            java.awt.datatransfer.StringSelection selection = 
                                new java.awt.datatransfer.StringSelection(result);
                            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                                .setContents(selection, null);
                            JOptionPane.showMessageDialog(resultDialog, 
                                "Analysis results copied to clipboard", 
                                "Copied", JOptionPane.INFORMATION_MESSAGE);
                        }
                    });
                    
                    JButton closeButton = new JButton("Close");
                    closeButton.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            resultDialog.dispose();
                        }
                    });
                    
                    buttonPanel.add(copyButton);
                    buttonPanel.add(closeButton);
                    mainPanel.add(buttonPanel, java.awt.BorderLayout.SOUTH);
                    
                    resultDialog.add(mainPanel);
                    resultDialog.setVisible(true);
                    
                    // Log the result as well
                    callbacks.printOutput("AI Analysis completed. Result length: " + result.length() + " characters");
                }
            });
        }
    }
}