package com.airis.burp.ai.ui;

import burp.api.montoya.MontoyaApi;
import com.airis.burp.ai.core.AnalysisEngine;
import com.airis.burp.ai.core.AnalysisResult;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.ExecutorService;
import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;

/**
 * Main tab for displaying and managing analysis results.
 * Provides a table view with operation buttons.
 */
public class AnalysisResultsTab extends JPanel {
  private final AnalysisResultTableModel tableModel;
  private final JTable resultsTable;
  private final AnalysisEngine analysisEngine;
  private final MontoyaApi api;
  private final ExecutorService executorService;

  /**
   * Creates a new analysis results tab
   * 
   * @param analysisEngine The analysis engine for running analyses
   * @param api Montoya API instance
   * @param executorService Executor for background tasks
   */
  public AnalysisResultsTab(AnalysisEngine analysisEngine, MontoyaApi api, ExecutorService executorService) {
    this.analysisEngine = analysisEngine;
    this.api = api;
    this.executorService = executorService;
    this.tableModel = new AnalysisResultTableModel();
    this.resultsTable = new JTable(tableModel);

    initializeUI();
  }

  private void initializeUI() {
    setLayout(new BorderLayout(10, 10));
    setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

    // Configure table
    configureTable();

    // Add table in scroll pane
    JScrollPane scrollPane = new JScrollPane(resultsTable);
    add(scrollPane, BorderLayout.CENTER);

    // Add button panel
    JPanel buttonPanel = createButtonPanel();
    add(buttonPanel, BorderLayout.SOUTH);
  }

  private void configureTable() {
    // Set column widths
    resultsTable.getColumnModel().getColumn(0).setPreferredWidth(300); // URL
    resultsTable.getColumnModel().getColumn(1).setPreferredWidth(100); // Timestamp
    resultsTable.getColumnModel().getColumn(2).setPreferredWidth(100); // Status
    resultsTable.getColumnModel().getColumn(3).setPreferredWidth(300); // Prompt

    // Center align status column
    DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
    centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
    resultsTable.getColumnModel().getColumn(2).setCellRenderer(centerRenderer);

    // Set row height
    resultsTable.setRowHeight(25);

    // Set selection mode
    resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

    // Add mouse listener for double-click and right-click
    resultsTable.addMouseListener(new MouseAdapter() {
      @Override
      public void mouseClicked(MouseEvent e) {
        if (e.getClickCount() == 2) {
          int row = resultsTable.getSelectedRow();
          if (row >= 0) {
            showDetails(row);
          }
        }
      }

      @Override
      public void mousePressed(MouseEvent e) {
        if (e.isPopupTrigger()) {
          showContextMenu(e);
        }
      }

      @Override
      public void mouseReleased(MouseEvent e) {
        if (e.isPopupTrigger()) {
          showContextMenu(e);
        }
      }

      private void showContextMenu(MouseEvent e) {
        int row = resultsTable.rowAtPoint(e.getPoint());
        if (row >= 0) {
          resultsTable.setRowSelectionInterval(row, row);
          JPopupMenu contextMenu = createContextMenu(row);
          contextMenu.show(e.getComponent(), e.getX(), e.getY());
        }
      }
    });
  }

  private JPanel createButtonPanel() {
    JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));

    // View Details button
    JButton viewDetailsButton = new JButton("View Details");
    viewDetailsButton.addActionListener(e -> {
      int selectedRow = resultsTable.getSelectedRow();
      if (selectedRow >= 0) {
        showDetails(selectedRow);
      } else {
        JOptionPane.showMessageDialog(
            this,
            "Please select a row first.",
            "No Selection",
            JOptionPane.INFORMATION_MESSAGE);
      }
    });

    // Edit Prompt button
    JButton editPromptButton = new JButton("Edit Prompt");
    editPromptButton.addActionListener(e -> editPrompt());

    // Send Request button
    JButton sendRequestButton = new JButton("Send Request");
    sendRequestButton.addActionListener(e -> sendRequest());

    // Copy button
    JButton copyButton = new JButton("Copy");
    copyButton.addActionListener(e -> copySelectedResult());

    // Export button
    JButton exportButton = new JButton("Export");
    exportButton.addActionListener(e -> exportResults());

    // Delete button
    JButton deleteButton = new JButton("Delete");
    deleteButton.addActionListener(e -> deleteSelectedResult());

    // Clear All button
    JButton clearAllButton = new JButton("Clear All");
    clearAllButton.addActionListener(e -> clearAllResults());

    panel.add(viewDetailsButton);
    panel.add(editPromptButton);
    panel.add(sendRequestButton);
    panel.add(copyButton);
    panel.add(exportButton);
    panel.add(deleteButton);
    panel.add(clearAllButton);

    return panel;
  }

  /**
   * Creates a context menu for a table row
   * 
   * @param row The row index
   * @return The context menu
   */
  private JPopupMenu createContextMenu(int row) {
    JPopupMenu menu = new JPopupMenu();

    JMenuItem viewDetailsItem = new JMenuItem("View Details");
    viewDetailsItem.addActionListener(e -> showDetails(row));

    JMenuItem editPromptItem = new JMenuItem("Edit Prompt");
    editPromptItem.addActionListener(e -> editPrompt());

    JMenuItem sendRequestItem = new JMenuItem("Send Request");
    sendRequestItem.addActionListener(e -> sendRequest());

    JMenuItem copyItem = new JMenuItem("Copy");
    copyItem.addActionListener(e -> copySelectedResult());

    JMenuItem deleteItem = new JMenuItem("Delete");
    deleteItem.addActionListener(e -> deleteSelectedResult());

    menu.add(viewDetailsItem);
    menu.add(editPromptItem);
    menu.add(sendRequestItem);
    menu.addSeparator();
    menu.add(copyItem);
    menu.add(deleteItem);

    return menu;
  }

  /**
   * Adds a new result to the table
   * 
   * @param result The analysis result to add
   */
  public void addResult(AnalysisResult result) {
    SwingUtilities.invokeLater(() -> {
      tableModel.addResult(result);
      // Scroll to the new row
      int newRow = tableModel.getRowCount() - 1;
      resultsTable.scrollRectToVisible(resultsTable.getCellRect(newRow, 0, true));
    });
  }

  private void showDetails(int row) {
    AnalysisResult result = tableModel.getResultAt(row);
    if (result != null) {
      AnalysisDetailDialog dialog = new AnalysisDetailDialog((Frame) SwingUtilities.getWindowAncestor(this), result);
      dialog.setVisible(true);
    }
  }

  private void editPrompt() {
    int selectedRow = resultsTable.getSelectedRow();
    if (selectedRow < 0) {
      JOptionPane.showMessageDialog(
          this,
          "Please select a row first.",
          "No Selection",
          JOptionPane.INFORMATION_MESSAGE);
      return;
    }

    AnalysisResult result = tableModel.getResultAt(selectedRow);
    if (result == null) {
      return;
    }

    String newPrompt = JOptionPane.showInputDialog(
        this,
        "Edit prompt:",
        result.getPrompt());

    if (newPrompt != null && !newPrompt.trim().isEmpty()) {
      result.setPrompt(newPrompt);
      result.setStatus(AnalysisResult.STATUS_PENDING);
      result.setResult("");
      tableModel.updateResult(selectedRow);
      api.logging().logToOutput("Prompt updated for: " + result.getUrl());
    }
  }

  private void sendRequest() {
    int selectedRow = resultsTable.getSelectedRow();
    if (selectedRow < 0) {
      JOptionPane.showMessageDialog(
          this,
          "Please select a row first.",
          "No Selection",
          JOptionPane.INFORMATION_MESSAGE);
      return;
    }

    AnalysisResult result = tableModel.getResultAt(selectedRow);
    if (result == null) {
      return;
    }

    // Check if prompt is empty
    if (result.getPrompt() == null || result.getPrompt().trim().isEmpty()) {
      JOptionPane.showMessageDialog(
          this,
          "Please set a prompt before sending request.",
          "Empty Prompt",
          JOptionPane.WARNING_MESSAGE);
      return;
    }

    // Update status to running
    result.setStatus(AnalysisResult.STATUS_RUNNING);
    tableModel.updateResult(selectedRow);

    // Execute analysis asynchronously
    executorService.submit(() -> {
      try {
        String request = result.getHttpHistoryItem().getRequest();
        String response = result.getHttpHistoryItem().getResponse();
        String customPrompt = result.getPrompt();
        
        // Perform analysis with the custom prompt
        String analysisResult = analysisEngine.analyze(request, response, customPrompt);
        
        SwingUtilities.invokeLater(() -> {
          result.setResult(analysisResult);
          result.setStatus(AnalysisResult.STATUS_COMPLETE);
          tableModel.updateResult(selectedRow);
        });
      } catch (Exception e) {
        SwingUtilities.invokeLater(() -> {
          result.setResult("Error: " + e.getMessage());
          result.setStatus(AnalysisResult.STATUS_ERROR);
          tableModel.updateResult(selectedRow);
        });
        api.logging().logToError("Analysis failed: " + e.getMessage());
      }
    });
  }

  private void copySelectedResult() {
    int selectedRow = resultsTable.getSelectedRow();
    if (selectedRow < 0) {
      JOptionPane.showMessageDialog(
          this,
          "Please select a row first.",
          "No Selection",
          JOptionPane.INFORMATION_MESSAGE);
      return;
    }

    AnalysisResult result = tableModel.getResultAt(selectedRow);
    if (result != null) {
      String text = "URL: " + result.getUrl() + "\n"
          + "Timestamp: " + result.getTimestamp() + "\n"
          + "Status: " + result.getStatus() + "\n"
          + "Prompt: " + result.getPrompt() + "\n"
          + "Result: " + result.getResult();

      java.awt.datatransfer.StringSelection selection = new java.awt.datatransfer.StringSelection(text);
      java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);

      JOptionPane.showMessageDialog(
          this,
          "Result copied to clipboard!",
          "Success",
          JOptionPane.INFORMATION_MESSAGE);
    }
  }

  private void exportResults() {
    List<AnalysisResult> results = tableModel.getAllResults();
    if (results.isEmpty()) {
      JOptionPane.showMessageDialog(
          this,
          "No results to export.",
          "Empty Results",
          JOptionPane.INFORMATION_MESSAGE);
      return;
    }

    JFileChooser fileChooser = new JFileChooser();
    fileChooser.setDialogTitle("Export Results");
    fileChooser.setSelectedFile(new java.io.File("analysis_results.txt"));

    int userSelection = fileChooser.showSaveDialog(this);
    if (userSelection == JFileChooser.APPROVE_OPTION) {
      try (FileWriter writer = new FileWriter(fileChooser.getSelectedFile())) {
        for (AnalysisResult result : results) {
          writer.write("=====================================\n");
          writer.write("URL: " + result.getUrl() + "\n");
          writer.write("Timestamp: " + result.getTimestamp() + "\n");
          writer.write("Status: " + result.getStatus() + "\n");
          writer.write("Prompt: " + result.getPrompt() + "\n");
          writer.write("Result:\n" + result.getResult() + "\n");
          writer.write("=====================================\n\n");
        }
        JOptionPane.showMessageDialog(
            this,
            "Results exported successfully!",
            "Success",
            JOptionPane.INFORMATION_MESSAGE);
      } catch (IOException e) {
        api.logging().logToError("Export failed: " + e.getMessage());
        JOptionPane.showMessageDialog(
            this,
            "Export failed: " + e.getMessage(),
            "Error",
            JOptionPane.ERROR_MESSAGE);
      }
    }
  }

  private void deleteSelectedResult() {
    int selectedRow = resultsTable.getSelectedRow();
    if (selectedRow < 0) {
      JOptionPane.showMessageDialog(
          this,
          "Please select a row first.",
          "No Selection",
          JOptionPane.INFORMATION_MESSAGE);
      return;
    }

    int confirm = JOptionPane.showConfirmDialog(
        this,
        "Are you sure you want to delete this result?",
        "Confirm Delete",
        JOptionPane.YES_NO_OPTION);

    if (confirm == JOptionPane.YES_OPTION) {
      tableModel.removeResult(selectedRow);
      api.logging().logToOutput("Result deleted");
    }
  }

  private void clearAllResults() {
    if (tableModel.getRowCount() == 0) {
      return;
    }

    int confirm = JOptionPane.showConfirmDialog(
        this,
        "Are you sure you want to clear all results?",
        "Confirm Clear All",
        JOptionPane.YES_NO_OPTION);

    if (confirm == JOptionPane.YES_OPTION) {
      tableModel.clearAll();
      api.logging().logToOutput("All results cleared");
    }
  }

  /**
   * Gets the main panel component
   * 
   * @return The main panel
   */
  public JPanel getMainPanel() {
    return this;
  }
}
