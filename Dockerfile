FROM gradle:9.0.0-jdk21-noble AS builder

WORKDIR /app
COPY . .
# After test Build JAR
RUN gradle clean jar --no-daemon -x test

