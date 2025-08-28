# Multi-stage Dockerfile for AIRIS Burp Suite Extension
FROM gradle:9.0.0-jdk21-noble AS builder

# Set working directory
WORKDIR /app

# Copy source code and build files
COPY . .

# After test Build JAR
RUN gradle clean jar --no-daemon -x test

