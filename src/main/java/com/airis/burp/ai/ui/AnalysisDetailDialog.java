package com.airis.burp.ai.ui;

import com.airis.burp.ai.core.AnalysisResult;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import javax.swing.*;

/**
 * Dialog for displaying detailed information about an analysis result. Shows the full prompt and
 * result with copy functionality.
 */
public class AnalysisDetailDialog extends JDialog {
  private final AnalysisResult analysisResult;

  /**
   * Creates a new detail dialog
   *
   * @param parent Parent frame
   * @param analysisResult The result to display
   */
  public AnalysisDetailDialog(Frame parent, AnalysisResult analysisResult) {
    super(parent, "Analysis Details", true);
    this.analysisResult = analysisResult;
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
    JPanel panel = new JPanel(new GridLayout(2, 1, 10, 10));
    panel.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));

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
    resultPanel.setBorder(BorderFactory.createTitledBorder("Result"));
    JTextArea resultArea = new JTextArea(analysisResult.getResult());
    resultArea.setEditable(false);
    resultArea.setLineWrap(true);
    resultArea.setWrapStyleWord(true);
    resultArea.setCaretPosition(0);
    JScrollPane resultScrollPane = new JScrollPane(resultArea);
    resultPanel.add(resultScrollPane, BorderLayout.CENTER);

    panel.add(promptPanel);
    panel.add(resultPanel);

    return panel;
  }

  private JPanel createButtonPanel() {
    JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
    panel.setBorder(BorderFactory.createEmptyBorder(0, 10, 10, 10));

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
                  + "Prompt:\n"
                  + analysisResult.getPrompt()
                  + "\n\n"
                  + "Result:\n"
                  + analysisResult.getResult();
          copyToClipboard(all, "All information");
        });

    // Close button
    JButton closeButton = new JButton("Close");
    closeButton.addActionListener(e -> dispose());

    panel.add(copyPromptButton);
    panel.add(copyResultButton);
    panel.add(copyAllButton);
    panel.add(closeButton);

    return panel;
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
