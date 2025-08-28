package com.airis.burp.ai.core;

/**
 * Individual security finding from AI analysis.
 */
public class Finding {
    private String title = "";
    private String description = "";
    private String severity = "";
    private String recommendation = "";

    public Finding() {}

    public Finding(String title, String description, String severity, String recommendation) {
        setTitle(title);
        setDescription(description);
        setSeverity(severity);
        setRecommendation(recommendation);
    }

    // Getters
    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public String getSeverity() {
        return severity;
    }

    public String getRecommendation() {
        return recommendation;
    }

    // Setters
    public void setTitle(String title) {
        this.title = title != null ? title : "";
    }

    public void setDescription(String description) {
        this.description = description != null ? description : "";
    }

    public void setSeverity(String severity) {
        this.severity = severity != null ? severity : "";
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation != null ? recommendation : "";
    }
}