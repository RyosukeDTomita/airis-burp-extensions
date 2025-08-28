package com.airis.burp.ai.core;

import java.util.HashMap;
import java.util.Map;

/**
 * Request data model for AI analysis.
 */
public class AnalysisRequest {
    private String method = "";
    private String url = "";
    private Map<String, String> headers = new HashMap<String, String>();
    private String body = "";
    private int statusCode = 0;
    private String responseBody = "";

    // Getters
    public String getMethod() {
        return method;
    }

    public String getUrl() {
        return url;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public String getBody() {
        return body;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getResponseBody() {
        return responseBody;
    }

    // Setters
    public void setMethod(String method) {
        this.method = method != null ? method : "";
    }

    public void setUrl(String url) {
        this.url = url != null ? url : "";
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers != null ? headers : new HashMap<String, String>();
    }

    public void setBody(String body) {
        this.body = body != null ? body : "";
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public void setResponseBody(String responseBody) {
        this.responseBody = responseBody != null ? responseBody : "";
    }
}