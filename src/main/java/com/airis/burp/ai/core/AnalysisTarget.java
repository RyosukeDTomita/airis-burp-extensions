package com.airis.burp.ai.core;

import java.util.HashMap;
import java.util.Map;

public class AnalysisTarget {
    private String method = "";
    private String url = "";
    private Map<String, String> headers = new HashMap<>();
    private String body = "";
    private int statusCode = 0;
    private String responseBody = "";
    private Map<String, String> responseHeaders = new HashMap<>();
    
    public String getMethod() {
        return method;
    }
    
    public void setMethod(String method) {
        this.method = method != null ? method : "";
    }
    
    public String getUrl() {
        return url;
    }
    
    public void setUrl(String url) {
        this.url = url != null ? url : "";
    }
    
    public Map<String, String> getHeaders() {
        return headers;
    }
    
    public void setHeaders(Map<String, String> headers) {
        this.headers = headers != null ? headers : new HashMap<>();
    }
    
    public String getBody() {
        return body;
    }
    
    public void setBody(String body) {
        this.body = body != null ? body : "";
    }
    
    public int getStatusCode() {
        return statusCode;
    }
    
    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }
    
    public String getResponseBody() {
        return responseBody;
    }
    
    public void setResponseBody(String responseBody) {
        this.responseBody = responseBody != null ? responseBody : "";
    }
    
    public Map<String, String> getResponseHeaders() {
        return responseHeaders;
    }
    
    public void setResponseHeaders(Map<String, String> responseHeaders) {
        this.responseHeaders = responseHeaders != null ? responseHeaders : new HashMap<>();
    }
}