# Multi-stage build for GraalVM native image
FROM ghcr.io/graalvm/native-image-community:25 AS builder

WORKDIR /app

# Copy Maven wrapper and pom.xml
COPY mvnw pom.xml ./
COPY .mvn .mvn/

# Copy source code
COPY src src/

# Build native image
RUN ./mvnw -Pnative -DskipTests clean package

# Final stage - Alpine Linux with native executable
FROM alpine:latest

# Install required libraries for native image
RUN apk add --no-cache \
    gcompat \
    libstdc++

WORKDIR /app

# Copy the native executable from builder stage
COPY --from=builder /app/target/timestamp-server /app/timestamp-server

# Create non-root user
RUN adduser -D -s /bin/sh appuser && \
    chown -R appuser:appuser /app

# Create external config directory for mounting (after user creation)
RUN mkdir -p /app/config && \
    chown appuser:appuser /app/config

USER appuser

# Expose port
EXPOSE 8080

# Set Spring profile for Docker
ENV SPRING_PROFILES_ACTIVE=docker

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/actuator/health || exit 1

# Run the native executable with config directory in classpath
ENTRYPOINT ["/app/timestamp-server", "--spring.config.location=classpath:/,classpath:/config/,file:/app/config/"]
