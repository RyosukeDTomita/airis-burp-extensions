package com.airis.burp.ai.ui;

import com.airis.burp.ai.core.AnalysisResult;
import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;

/**
 * Table model for managing analysis results in the results tab.
 * Provides data for the JTable displaying analysis entries.
 */
public class AnalysisResultTableModel extends AbstractTableModel {
  private static final String[] COLUMN_NAMES = {"URL", "Timestamp", "Status", "Prompt"};
  private final List<AnalysisResult> results;

  public AnalysisResultTableModel() {
    this.results = new ArrayList<>();
  }

  @Override
  public int getRowCount() {
    return results.size();
  }

  @Override
  public int getColumnCount() {
    return COLUMN_NAMES.length;
  }

  @Override
  public String getColumnName(int column) {
    return COLUMN_NAMES[column];
  }

  @Override
  public Object getValueAt(int rowIndex, int columnIndex) {
    AnalysisResult result = results.get(rowIndex);
    switch (columnIndex) {
      case 0:
        return result.getUrl();
      case 1:
        return result.getTimestamp();
      case 2:
        return result.getStatus();
      case 3:
        return result.getPrompt();
      default:
        return null;
    }
  }

  /**
   * Adds a new analysis result to the table
   * 
   * @param result The analysis result to add
   */
  public void addResult(AnalysisResult result) {
    int newRow = results.size();
    results.add(result);
    fireTableRowsInserted(newRow, newRow);
  }

  /**
   * Updates an existing result in the table
   * 
   * @param rowIndex The row to update
   */
  public void updateResult(int rowIndex) {
    if (rowIndex >= 0 && rowIndex < results.size()) {
      fireTableRowsUpdated(rowIndex, rowIndex);
    }
  }

  /**
   * Gets the result at the specified row
   * 
   * @param rowIndex The row index
   * @return The analysis result
   */
  public AnalysisResult getResultAt(int rowIndex) {
    if (rowIndex >= 0 && rowIndex < results.size()) {
      return results.get(rowIndex);
    }
    return null;
  }

  /**
   * Removes a result from the table
   * 
   * @param rowIndex The row to remove
   */
  public void removeResult(int rowIndex) {
    if (rowIndex >= 0 && rowIndex < results.size()) {
      results.remove(rowIndex);
      fireTableRowsDeleted(rowIndex, rowIndex);
    }
  }

  /**
   * Clears all results from the table
   */
  public void clearAll() {
    int rowCount = results.size();
    if (rowCount > 0) {
      results.clear();
      fireTableRowsDeleted(0, rowCount - 1);
    }
  }

  /**
   * Gets all results
   * 
   * @return List of all analysis results
   */
  public List<AnalysisResult> getAllResults() {
    return new ArrayList<>(results);
  }
}
