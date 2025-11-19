package com.airis.burp.ai.ui;

import org.commonmark.node.Node;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;

/** Utility to convert Markdown returned by LLMs into HTML suitable for Swing components. */
public final class MarkdownRenderer {
  private static final Parser PARSER = Parser.builder().build();
  private static final HtmlRenderer HTML_RENDERER = HtmlRenderer.builder().build();
  private static final String HTML_PREFIX =
      "<html><head><style>"
          + "body{font-family:'Segoe UI',sans-serif;font-size:13px;color:#1f1f1f;margin:8px;}"
          + "h1,h2,h3,h4{margin-top:16px;margin-bottom:8px;}"
          + "pre{background:#f4f4f4;border:1px solid #ddd;padding:8px;overflow:auto;}"
          + "code{font-family:'JetBrains Mono','Consolas','Courier New',monospace;}"
          + "ul,ol{margin-left:18px;}"
          + "table{border-collapse:collapse;}"
          + "th,td{border:1px solid #ddd;padding:4px;}"
          + "</style></head><body>";
  private static final String HTML_SUFFIX = "</body></html>";

  private MarkdownRenderer() {
    // utility class
  }

  /**
   * Converts Markdown text into an HTML snippet. Ensures a helpful placeholder when content is
   * empty and wraps the HTML with minimal styling for Swing rendering.
   */
  public static String toHtml(String markdown) {
    if (markdown == null || markdown.trim().isEmpty()) {
      return HTML_PREFIX + "<i>No analysis result yet.</i>" + HTML_SUFFIX;
    }

    Node document = PARSER.parse(markdown);
    String rendered = HTML_RENDERER.render(document);
    return HTML_PREFIX + rendered + HTML_SUFFIX;
  }
}
