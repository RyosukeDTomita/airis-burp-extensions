package com.airis.burp.ai.core;

import java.util.ArrayList;
import java.util.List;

public class AnalysisResult {
    
    private String analysis = "";
    private List<Finding> findings = new ArrayList<Finding>();
    private long responseTime = 0;
    
    public String getAnalysis() {
        return analysis;
    }
    
    public List<Finding> getFindings() {
        return findings;
    }
    
    public long getResponseTime() {
        return responseTime;
    }
    
    public void setAnalysis(String analysis) {
        this.analysis = analysis != null ? analysis : "";
    }
    
    public void setFindings(List<Finding> findings) {
        this.findings = findings != null ? findings : new ArrayList<Finding>();
    }
    
    public void setResponseTime(long responseTime) {
        this.responseTime = responseTime;
    }
}