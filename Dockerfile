# Build stage
FROM eclipse-temurin:25-jdk as builder

WORKDIR /workspace/app

COPY . .
RUN ./mvnw clean package -Pnative -DskipTests

# Final stage
FROM eclipse-temurin:25-jre

WORKDIR /app

COPY --from=builder /workspace/app/target/timestamp-server /app/timestamp-server

EXPOSE 8080

ENTRYPOINT ["/app/timestamp-server"]