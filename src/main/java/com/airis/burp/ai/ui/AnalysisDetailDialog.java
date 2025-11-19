package com.airis.burp.ai.ui;

import com.airis.burp.ai.core.AnalysisResult;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import javax.swing.*;

/**
 * Dialog for displaying detailed information about an analysis result. Shows the full prompt and
 * result with copy functionality.
 */
public class AnalysisDetailDialog extends JDialog {
  private final AnalysisResult analysisResult;
  private final BiConsumer<AnalysisResult, Consumer<AnalysisResult>> sendRequestHandler;
  private JEditorPane resultPane;
  private JButton sendRequestButton;

  /**
   * Creates a new detail dialog
   *
   * @param parent Parent frame
   * @param analysisResult The result to display
   * @param api Montoya API instance
   * @param analysisEngine Analysis engine for re-running analysis
   */
  public AnalysisDetailDialog(
      Frame parent,
      AnalysisResult analysisResult,
      BiConsumer<AnalysisResult, Consumer<AnalysisResult>> sendRequestHandler) {
    super(parent, "Analysis Details", true);
    this.analysisResult = analysisResult;
    this.sendRequestHandler = sendRequestHandler;
    initializeUI();
  }

  private void initializeUI() {
    setSize(900, 700);
    setLocationRelativeTo(getParent());
    setLayout(new BorderLayout(10, 10));

    // Header panel with basic info
    JPanel headerPanel = createHeaderPanel();
    add(headerPanel, BorderLayout.NORTH);

    // Main content with prompt and result
    JPanel contentPanel = createContentPanel();
    add(contentPanel, BorderLayout.CENTER);

    // Button panel
    JPanel buttonPanel = createButtonPanel();
    add(buttonPanel, BorderLayout.SOUTH);
  }

  private JPanel createHeaderPanel() {
    JPanel panel = new JPanel(new GridLayout(3, 2, 10, 5));
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

    panel.add(new JLabel("URL:"));
    panel.add(new JLabel(analysisResult.getUrl()));

    panel.add(new JLabel("Timestamp:"));
    panel.add(new JLabel(analysisResult.getTimestamp()));

    panel.add(new JLabel("Status:"));
    JLabel statusLabel = new JLabel(analysisResult.getStatus());
    statusLabel.setOpaque(true);
    statusLabel.setBackground(getStatusColor(analysisResult.getStatus()));
    statusLabel.setForeground(Color.WHITE);
    statusLabel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
    panel.add(statusLabel);

    return panel;
  }

  private JPanel createContentPanel() {
    JPanel panel = new JPanel(new GridLayout(2, 2, 10, 10));
    panel.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));

    // Request section
    JPanel requestPanel = new JPanel(new BorderLayout());
    requestPanel.setBorder(BorderFactory.createTitledBorder("HTTP Request"));
    JTextArea requestArea =
        new JTextArea(analysisResult.getHttpHistoryItem().getRequest());
    requestArea.setEditable(false);
    requestArea.setLineWrap(true);
    requestArea.setWrapStyleWord(true);
    requestArea.setCaretPosition(0);
    requestArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
    JScrollPane requestScrollPane = new JScrollPane(requestArea);
    requestPanel.add(requestScrollPane, BorderLayout.CENTER);

    // Response section
    JPanel responsePanel = new JPanel(new BorderLayout());
    responsePanel.setBorder(BorderFactory.createTitledBorder("HTTP Response"));
    JTextArea responseArea =
        new JTextArea(analysisResult.getHttpHistoryItem().getResponse());
    responseArea.setEditable(false);
    responseArea.setLineWrap(true);
    responseArea.setWrapStyleWord(true);
    responseArea.setCaretPosition(0);
    responseArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
    JScrollPane responseScrollPane = new JScrollPane(responseArea);
    responsePanel.add(responseScrollPane, BorderLayout.CENTER);

    // Prompt section
    JPanel promptPanel = new JPanel(new BorderLayout());
    promptPanel.setBorder(BorderFactory.createTitledBorder("Prompt"));
    JTextArea promptArea = new JTextArea(analysisResult.getPrompt());
    promptArea.setEditable(false);
    promptArea.setLineWrap(true);
    promptArea.setWrapStyleWord(true);
    promptArea.setCaretPosition(0);
    JScrollPane promptScrollPane = new JScrollPane(promptArea);
    promptPanel.add(promptScrollPane, BorderLayout.CENTER);

    // Result section
    JPanel resultPanel = new JPanel(new BorderLayout());
    resultPanel.setBorder(BorderFactory.createTitledBorder("Analysis Result"));
    resultPane = new JEditorPane();
    resultPane.setContentType("text/html");
    resultPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
    resultPane.setEditable(false);
    updateResultPane(analysisResult.getResult());
    JScrollPane resultScrollPane = new JScrollPane(resultPane);
    resultPanel.add(resultScrollPane, BorderLayout.CENTER);

    panel.add(requestPanel);
    panel.add(responsePanel);
    panel.add(promptPanel);
    panel.add(resultPanel);

    return panel;
  }

  private JPanel createButtonPanel() {
    JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
    panel.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));

    // Copy Request button
    JButton copyRequestButton = new JButton("Copy Request");
    copyRequestButton.addActionListener(
        e -> copyToClipboard(analysisResult.getHttpHistoryItem().getRequest(), "Request"));

    // Copy Response button
    JButton copyResponseButton = new JButton("Copy Response");
    copyResponseButton.addActionListener(
        e -> copyToClipboard(analysisResult.getHttpHistoryItem().getResponse(), "Response"));

    // Copy Prompt button
    JButton copyPromptButton = new JButton("Copy Prompt");
    copyPromptButton.addActionListener(e -> copyToClipboard(analysisResult.getPrompt(), "Prompt"));

    // Copy Result button
    JButton copyResultButton = new JButton("Copy Result");
    copyResultButton.addActionListener(e -> copyToClipboard(analysisResult.getResult(), "Result"));

    // Copy All button
    JButton copyAllButton = new JButton("Copy All");
    copyAllButton.addActionListener(
        e -> {
          String all =
              "URL: "
                  + analysisResult.getUrl()
                  + "\n"
                  + "Timestamp: "
                  + analysisResult.getTimestamp()
                  + "\n"
                  + "Status: "
                  + analysisResult.getStatus()
                  + "\n\n"
                  + "=== HTTP Request ===\n"
                  + analysisResult.getHttpHistoryItem().getRequest()
                  + "\n\n"
                  + "=== HTTP Response ===\n"
                  + analysisResult.getHttpHistoryItem().getResponse()
                  + "\n\n"
                  + "=== Prompt ===\n"
                  + analysisResult.getPrompt()
                  + "\n\n"
                  + "=== Analysis Result ===\n"
                  + analysisResult.getResult();
          copyToClipboard(all, "All information");
        });

    // Send Request button - sends the request that was used for this analysis to LLM
    sendRequestButton = new JButton("Send Request");
    sendRequestButton.setToolTipText("Send the HTTP request to LLM API");
    sendRequestButton.addActionListener(e -> sendRequest());

    // Close button
    JButton closeButton = new JButton("Close");
    closeButton.addActionListener(e -> dispose());

    panel.add(copyRequestButton);
    panel.add(copyResponseButton);
    panel.add(copyPromptButton);
    panel.add(copyResultButton);
    panel.add(copyAllButton);
    panel.add(sendRequestButton);
    panel.add(closeButton);

    return panel;
  }

  private void sendRequest() {
    if (sendRequestHandler == null) {
      return;
    }

    sendRequestButton.setEnabled(false);
    updateResultPane("_Sending request to LLM API..._");

    sendRequestHandler.accept(
        analysisResult,
        updatedResult ->
            SwingUtilities.invokeLater(
                () -> {
                  updateResultPane(updatedResult.getResult());
                  sendRequestButton.setEnabled(true);
                }));
  }

  private void updateResultPane(String markdownText) {
    resultPane.setText(MarkdownRenderer.toHtml(markdownText));
    resultPane.setCaretPosition(0);
  }

  private void copyToClipboard(String text, String contentName) {
    StringSelection selection = new StringSelection(text);
    Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
    clipboard.setContents(selection, null);
    JOptionPane.showMessageDialog(
        this, contentName + " copied to clipboard!", "Success", JOptionPane.INFORMATION_MESSAGE);
  }

  private Color getStatusColor(String status) {
    switch (status) {
      case AnalysisResult.STATUS_COMPLETE:
        return new Color(46, 125, 50); // Green
      case AnalysisResult.STATUS_RUNNING:
        return new Color(25, 118, 210); // Blue
      case AnalysisResult.STATUS_ERROR:
        return new Color(211, 47, 47); // Red
      case AnalysisResult.STATUS_PENDING:
        return new Color(158, 158, 158); // Gray
      default:
        return Color.GRAY;
    }
  }
}
