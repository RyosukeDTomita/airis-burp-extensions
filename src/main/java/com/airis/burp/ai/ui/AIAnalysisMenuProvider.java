package com.airis.burp.ai.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.airis.burp.ai.core.AnalysisResult;
import com.airis.burp.ai.core.HttpHistoryItem;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

/** Context menu provider for Burp Suite that allows adding HTTP requests to the analysis tab. */
public class AIAnalysisMenuProvider implements ContextMenuItemsProvider {
  private final MontoyaApi montoyaApi;
  private AnalysisResultsTab analysisResultsTab;

  public AIAnalysisMenuProvider(MontoyaApi montoyaApi) {
    this.montoyaApi = montoyaApi;
  }

  /**
   * Sets the analysis results tab reference for adding results
   *
   * @param analysisResultsTab The results tab
   */
  public void setAnalysisResultsTab(AnalysisResultsTab analysisResultsTab) {
    this.analysisResultsTab = analysisResultsTab;
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
      // Create submenu
      JMenu airisMenu = new JMenu("AIris");

      // Add to analysis tab menu item
      JMenuItem addToTabMenuItem = new JMenuItem("Add to analysis tab");
      addToTabMenuItem.addActionListener(
          e -> {
            // Get first selected item
            HttpRequestResponse item = event.selectedRequestResponses().get(0);
            addToAnalysisTab(item);
          });

      airisMenu.add(addToTabMenuItem);
      menuItemList.add(airisMenu);
    }

    return menuItemList;
  }

  /**
   * Adds a request to the analysis tab for later processing
   *
   * @param requestResponse The HTTP request and response to add
   */
  private void addToAnalysisTab(HttpRequestResponse requestResponse) {
    if (analysisResultsTab == null) {
      JOptionPane.showMessageDialog(
          null, "Analysis Results tab is not available.", "Error", JOptionPane.ERROR_MESSAGE);
      return;
    }

    try {
      // Extract request as string
      String request = requestResponse.request().toString();

      // Extract response if available
      String response = "";
      if (requestResponse.response() != null) {
        response = requestResponse.response().toString();
      }

      // Extract URL for display
      String url = requestResponse.request().url();

      // Create HttpHistoryItem
      HttpHistoryItem httpHistoryItem = HttpHistoryItem.fromHttpRequestResponse(request, response);

      // Prompt user for custom prompt
      String prompt =
          JOptionPane.showInputDialog(
              null,
              "Enter analysis prompt (optional):",
              "Add to Analysis Tab",
              JOptionPane.QUESTION_MESSAGE);

      // Use default prompt if empty
      if (prompt == null) {
        return; // User cancelled
      }
      if (prompt.trim().isEmpty()) {
        prompt = "Analyze this HTTP request and response for security vulnerabilities.";
      }

      // Create analysis result
      AnalysisResult result = new AnalysisResult(url, prompt, httpHistoryItem);

      // Add to tab
      analysisResultsTab.addResult(result);

      montoyaApi.logging().logToOutput("Added to analysis tab: " + url);

    } catch (Exception e) {
      montoyaApi.logging().logToError("Failed to add to analysis tab: " + e.getMessage());
      JOptionPane.showMessageDialog(
          null,
          "Failed to add to analysis tab: " + e.getMessage(),
          "Error",
          JOptionPane.ERROR_MESSAGE);
    }
  }
}
