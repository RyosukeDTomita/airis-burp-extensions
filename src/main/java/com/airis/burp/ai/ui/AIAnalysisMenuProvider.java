package com.airis.burp.ai.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.airis.burp.ai.config.ConfigModel;
import com.airis.burp.ai.core.AnalysisEngine;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;

/**
 * Context menu provider for Burp Suite that allows AI analysis of HTTP requests/responses. Displays
 * analysis results in a custom dialog window.
 */
public class AIAnalysisMenuProvider implements ContextMenuItemsProvider {
  /** Core analysis engine for processing requests */
  private final AnalysisEngine analysisEngine;

  private final MontoyaApi montoyaApi;

  public AIAnalysisMenuProvider(
      AnalysisEngine analysisEngine, ConfigModel configModel, MontoyaApi montoyaApi) {
    this.analysisEngine = analysisEngine;
    this.montoyaApi = montoyaApi;
  }

  /**
   * Provides menu items for the context menu when right-clicking in Burp
   *
   * @param event Context menu event containing selected HTTP items
   * @return List of menu items to display
   */
  @Override
  public List<Component> provideMenuItems(ContextMenuEvent event) {
    List<Component> menuItemList = new ArrayList<>();

    // Check if valid HTTP request/response is selected
    if (event.selectedRequestResponses() != null && !event.selectedRequestResponses().isEmpty()) {
      JMenuItem analyzeMenuItem = new JMenuItem("Analyze with AI");

      // Add action listener for menu click
      analyzeMenuItem.addActionListener(
          e -> {
            // Get first selected item
            HttpRequestResponse item = event.selectedRequestResponses().get(0);
            analyzeWithMontoya(item);
          });

      menuItemList.add(analyzeMenuItem);
    }

    return menuItemList;
  }

  /**
   * Analyzes HTTP request/response using Montoya API
   *
   * @param requestResponse The HTTP request and response to analyze
   */
  private void analyzeWithMontoya(HttpRequestResponse requestResponse) {

    try {
      // Extract request as string
      String request = requestResponse.request().toString();

      // Extract response if available
      final String response;
      if (requestResponse.response() != null) {
        response = requestResponse.response().toString();
      } else {
        response = "";
      }
      // montoyaApi.logging().logToOutput(String.format("[DEBUG]: request=%s, response=%s", request,
      // response));

      // Perform analysis in background thread
      SwingUtilities.invokeLater(
          () -> {
            try {
              // Show loading dialog
              JDialog loadingDialog = new JDialog();
              loadingDialog.setTitle("AI Analysis");
              loadingDialog.setModal(false);
              loadingDialog.setSize(300, 100);
              loadingDialog.setLocationRelativeTo(null);
              JPanel panel = new JPanel(new BorderLayout());
              panel.add(new JLabel("Analyzing... Please wait.", SwingConstants.CENTER));
              loadingDialog.add(panel);
              loadingDialog.setVisible(true);

              // Perform analysis
              new Thread(
                      () -> {
                        String result = analysisEngine.analyze(request, response);

                        SwingUtilities.invokeLater(
                            () -> {
                              loadingDialog.dispose();
                              showAnalysisResultMontoya(result);
                            });
                      })
                  .start();

            } catch (Exception ex) {
              montoyaApi.logging().logToError("Analysis failed: " + ex.getMessage());
              JOptionPane.showMessageDialog(
                  null, "Analysis failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
          });

    } catch (Exception e) {
      montoyaApi.logging().logToError("Failed to analyze request: " + e.getMessage());
    }
  }

  /**
   * Shows analysis result in a dialog.
   *
   * @param result
   */
  private void showAnalysisResultMontoya(String result) {
    JDialog resultDialog = new JDialog();
    resultDialog.setTitle("AI Analysis Result");
    resultDialog.setModal(true);
    resultDialog.setSize(800, 600);
    resultDialog.setLocationRelativeTo(null);

    // Create text area for result
    JTextArea resultArea = new JTextArea(result);
    resultArea.setEditable(false);
    resultArea.setWrapStyleWord(true);
    resultArea.setLineWrap(true);
    resultArea.setCaretPosition(0);

    // Add scroll pane
    JScrollPane scrollPane = new JScrollPane(resultArea);
    scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

    // Create button panel
    JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

    // Copy button
    JButton copyButton = new JButton("Copy to Clipboard");
    copyButton.addActionListener(
        e -> {
          StringSelection selection = new StringSelection(result);
          Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
          clipboard.setContents(selection, null);
          JOptionPane.showMessageDialog(
              resultDialog, "Copied to clipboard!", "Success", JOptionPane.INFORMATION_MESSAGE);
        });

    // Close button
    JButton closeButton = new JButton("Close");
    closeButton.addActionListener(e -> resultDialog.dispose());

    buttonPanel.add(copyButton);
    buttonPanel.add(closeButton);

    // Add components to dialog
    resultDialog.setLayout(new BorderLayout());
    resultDialog.add(scrollPane, BorderLayout.CENTER);
    resultDialog.add(buttonPanel, BorderLayout.SOUTH);

    resultDialog.setVisible(true);
  }
}
