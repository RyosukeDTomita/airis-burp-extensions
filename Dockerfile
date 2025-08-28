FROM gradle:9.0.0-jdk21-noble AS builder

WORKDIR /app
COPY . .

# After test Build JAR
#RUN /app/gradlew clean jar --no-daemon -x test
RUN gradle clean jar --no-daemon -x test

