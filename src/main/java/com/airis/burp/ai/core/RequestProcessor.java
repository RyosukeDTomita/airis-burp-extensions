package com.airis.burp.ai.core;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import com.airis.burp.ai.llm.LLMClient;

/**
 * Processes HTTP requests and responses for analysis.
 */
public class RequestProcessor {
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("(password|pwd|pass)[\"\\s]*[=:][\"\\s]*([^&\\s,}]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern API_KEY_PATTERN = Pattern.compile("(api[_-]?key|token|secret)[\"\\s]*[=:][\"\\s]*([^&\\s,}]+)", Pattern.CASE_INSENSITIVE);
    private static final String REDACTED = "[REDACTED]";
    
    private final LLMClient llmClient;
    
    public RequestProcessor(LLMClient llmClient) {
        this.llmClient = llmClient;
    }

    public AnalysisRequest parseHttpRequest(String httpRequest) {
        AnalysisRequest request = new AnalysisRequest();
        
        if (httpRequest == null || httpRequest.trim().isEmpty()) {
            return request;
        }

        String[] parts = httpRequest.split("\\r\\n\\r\\n", 2);
        String headerSection = parts[0];
        String body = parts.length > 1 ? parts[1] : "";

        String[] lines = headerSection.split("\\r\\n");
        if (lines.length > 0) {
            // Parse request line (GET /path HTTP/1.1)
            String requestLine = lines[0];
            String[] requestParts = requestLine.split(" ");
            if (requestParts.length >= 2) {
                request.setMethod(requestParts[0]);
                request.setUrl(requestParts[1]);
            }

            // Parse headers
            if (lines.length > 1) {
                StringBuilder headerLines = new StringBuilder();
                for (int i = 1; i < lines.length; i++) {
                    headerLines.append(lines[i]);
                    if (i < lines.length - 1) {
                        headerLines.append("\r\n");
                    }
                }
                Map<String, String> headers = extractHeaders(headerLines.toString());
                request.setHeaders(headers);
            }
        }

        request.setBody(body);
        return request;
    }

    public void parseHttpResponse(AnalysisRequest request, String httpResponse) {
        if (httpResponse == null || httpResponse.trim().isEmpty()) {
            return;
        }

        String[] parts = httpResponse.split("\\r\\n\\r\\n", 2);
        String headerSection = parts[0];
        String responseBody = parts.length > 1 ? parts[1] : "";

        String[] lines = headerSection.split("\\r\\n");
        if (lines.length > 0) {
            // Parse status line (HTTP/1.1 200 OK)
            String statusLine = lines[0];
            String[] statusParts = statusLine.split(" ");
            if (statusParts.length >= 2) {
                try {
                    int statusCode = Integer.parseInt(statusParts[1]);
                    request.setStatusCode(statusCode);
                } catch (NumberFormatException e) {
                    request.setStatusCode(0);
                }
            }
        }

        request.setResponseBody(responseBody);
    }

    public AnalysisRequest createAnalysisRequest(String httpRequest, String httpResponse) {
        AnalysisRequest request = parseHttpRequest(httpRequest);
        parseHttpResponse(request, httpResponse);
        return request;
    }

    public String sanitizeData(String data) {
        if (data == null) {
            return "";
        }

        String sanitized = data;
        
        // Redact passwords
        sanitized = PASSWORD_PATTERN.matcher(sanitized).replaceAll("$1\": \"" + REDACTED + "\"");
        
        // Redact API keys and tokens  
        sanitized = API_KEY_PATTERN.matcher(sanitized).replaceAll("$1\": \"" + REDACTED + "\"");
        
        return sanitized;
    }

    public Map<String, String> extractHeaders(String headerLines) {
        Map<String, String> headers = new HashMap<String, String>();
        
        if (headerLines == null || headerLines.trim().isEmpty()) {
            return headers;
        }

        String[] lines = headerLines.split("\\r\\n");
        for (String line : lines) {
            if (line.trim().isEmpty()) {
                continue;
            }
            
            int colonIndex = line.indexOf(':');
            if (colonIndex > 0 && colonIndex < line.length() - 1) {
                String name = line.substring(0, colonIndex).trim();
                String value = line.substring(colonIndex + 1).trim();
                headers.put(name, value);
            }
        }
        
        return headers;
    }
}