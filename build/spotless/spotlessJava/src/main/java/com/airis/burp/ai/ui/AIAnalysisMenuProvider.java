package com.airis.burp.ai.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.airis.burp.ai.config.ConfigManager;
import com.airis.burp.ai.core.AnalysisEngine;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;

/**
 * This Class provides the result view for the LLM analysis. To add an item to Burp's right-click
 * context menu, register a ContextMenuItemsProvider and implement the provideMenuItems() method.
 */
public class AIAnalysisMenuProvider implements ContextMenuItemsProvider {

  private final AnalysisEngine analysisEngine;
  private final MontoyaApi montoyaApi;

  public AIAnalysisMenuProvider(
      AnalysisEngine analysisEngine, ConfigManager configManager, MontoyaApi montoyaApi) {
    this.analysisEngine = analysisEngine;
    this.montoyaApi = montoyaApi;
  }

  /**
   * Invoked by Burp Suite when the user requests a context menu with WebSocket information in the
   * user interface.
   *
   * @param ContextMenuEvent
   */
  @Override
  public List<Component> provideMenuItems(ContextMenuEvent event) {
    List<Component> menuItems = new ArrayList<>();

    try {
      List<HttpRequestResponse> selectedMessages = event.selectedRequestResponses();
      if (selectedMessages.isEmpty()) {
        return menuItems;
      }
      JMenuItem analyzeMenuItem = new JMenuItem("AI Security Analyzer");
      // TODO: 選択された通信履歴のうち、最初の1つのみ扱っている
      HttpRequestResponse message = selectedMessages.get(0);

      // handler of click Event
      analyzeMenuItem.addActionListener(
          new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
              analyzeWithMontoya(message);
            }
          });
      menuItems.add(analyzeMenuItem);
    } catch (Exception e) {
      if (montoyaApi != null) {
        montoyaApi.logging().logToError("Error in provideMenuItems: " + e.getMessage());
      }
      e.printStackTrace();
    }
    return menuItems;
  }

  /** callback functions Analyze request/response using Montoya API */
  private void analyzeWithMontoya(HttpRequestResponse message) {
    SwingUtilities.invokeLater(
        new Runnable() {
          @Override
          public void run() {
            try {
              // Null check for analysisEngine
              if (analysisEngine == null) {
                montoyaApi.logging().logToError("AnalysisEngine is not initialized");
                JOptionPane.showMessageDialog(
                    null,
                    "Analysis engine is not initialized. Please check your configuration.",
                    "Initialization Error",
                    JOptionPane.ERROR_MESSAGE);
                return;
              }

              montoyaApi.logging().logToOutput("Starting AI analysis...");
              String requestString = "";
              String responseString = "";

              HttpRequest request = message.request();
              // NOTE: message.hasRequest is not exist.
              if (request == null) {
                montoyaApi.logging().logToError("Request is null");
              }
              requestString = request.toString();
              if (message.hasResponse()) {
                HttpResponse response = message.response();
                if (response != null) {
                  responseString = response.toString();
                }
              }

              // Perform analysis
              String result = analysisEngine.analyzeRequestResponse(requestString, responseString);

              // Check if we have a meaningful result
              if (result == null || result.trim().isEmpty()) {
                result =
                    "AI analysis returned no result. Please check your API configuration and ensure the endpoint and API key are correctly set.";
              }
              montoyaApi.logging().logToOutput("Analysis result: " + result);
              showAnalysisResultMontoya(result);
            } catch (Exception ex) {
              montoyaApi.logging().logToError("Error during AI analysis: " + ex.getMessage());
              ex.printStackTrace();
              JOptionPane.showMessageDialog(
                  null,
                  "Error occurred during analysis: " + ex.getMessage(),
                  "AI Analysis Error",
                  JOptionPane.ERROR_MESSAGE);
            }
          }
        });
  }

  /** Show analysis result dialog */
  private void showAnalysisResultMontoya(String result) {
    SwingUtilities.invokeLater(
        new Runnable() {
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
            resultArea.setFont(
                new java.awt.Font(java.awt.Font.MONOSPACED, java.awt.Font.PLAIN, 12));
            resultArea.setMargin(new java.awt.Insets(10, 10, 10, 10));

            // Add scroll pane
            JScrollPane scrollPane = new JScrollPane(resultArea);
            scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
            scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
            mainPanel.add(scrollPane, java.awt.BorderLayout.CENTER);

            // Create button panel
            JPanel buttonPanel = new JPanel(new java.awt.FlowLayout());

            JButton copyButton = new JButton("Copy to Clipboard");
            copyButton.addActionListener(
                new ActionListener() {
                  @Override
                  public void actionPerformed(ActionEvent e) {
                    java.awt.datatransfer.StringSelection selection =
                        new java.awt.datatransfer.StringSelection(result);
                    java.awt.Toolkit.getDefaultToolkit()
                        .getSystemClipboard()
                        .setContents(selection, null);
                    JOptionPane.showMessageDialog(
                        resultDialog,
                        "Analysis results copied to clipboard",
                        "Copied",
                        JOptionPane.INFORMATION_MESSAGE);
                  }
                });

            JButton closeButton = new JButton("Close");
            closeButton.addActionListener(
                new ActionListener() {
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

            montoyaApi
                .logging()
                .logToOutput(
                    "AI Analysis completed. Result length: " + result.length() + " characters");
          }
        });
  }
}
