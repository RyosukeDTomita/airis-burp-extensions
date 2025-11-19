package com.airis.burp.ai.ui;

/** Utility class retained for compatibility; now just returns plain text for markdown. */
public final class MarkdownRenderer {

  private MarkdownRenderer() {}

  public static String toPlainText(String text) {
    if (text == null || text.trim().isEmpty()) {
      return "No analysis result yet.";
    }
    return text;
  }
}
