> **Attention:** This project is specifically for testing purposes, for example, for running automated tests. It is not recommended for use in a production environment.

# Timestamp Server for Digital Signatures

A high-performance timestamp server built with Spring Boot, Maven, and GraalVM Native Image support for digital signature applications.

## Features

- **RFC 3161 Timestamp Support**: Generates timestamps in ASN.1 format for digital signatures
- **Multiple Timestamp Formats**: Supports RFC 3161, ISO 8601, and Unix epoch formats
- **Native Image Optimization**: Compiled to native executable for superior performance
- **Security**: Built-in Spring Security with configurable authentication
- **Health Monitoring**: Actuator endpoints for monitoring and metrics
- **CORS Support**: Cross-origin resource sharing enabled
- **Comprehensive Testing**: JUnit 5 and AssertJ integration tests

## Prerequisites

- Java 25 (GraalVM CE)
- Maven 3.8+
- Git

## Setup

### 1. Install GraalVM

```bash
# Set JAVA_HOME to GraalVM
export JAVA_HOME=~/.jdks/graalvm-ce-25.0.2/
export PATH=$JAVA_HOME/bin:$PATH
```

### 2. Build the Application

```bash
# Regular build (JVM)
./mvnw clean install

# Native build (GraalVM)
./mvnw clean package -Pnative
```

### 3. Run the Server

#### JVM Mode:
```bash
java -jar target/timestamp-server-1.0-SNAPSHOT.jar
```

#### Native Mode:
```bash
./target/timestamp-server
```

## API Endpoints

| Endpoint | Method | Description | Content-Type | Response Format |
|----------|--------|-------------|----------------|----------------|
| `/api/timestamp` | POST | RFC 3161 timestamp | `application/timestamp-query` | `application/timestamp-reply` |
| `/api/timestamp/simple` | GET | Simple ISO 8601 timestamp | - | String |
| `/api/timestamp/unix` | GET | Unix epoch timestamp | - | Long |
| `/api/timestamp/health` | GET | Health check | - | String |

## Docker Support

### Build Docker Image:
```bash
docker build -t timestamp-server .
```

### Run with Docker:
```bash
docker run -p 8080:8080 timestamp-server
```

## Configuration

Edit `src/main/resources/application.yml` to customize:
- Server port
- Security settings
- Logging levels
- Actuator endpoints

## Testing

Run all tests:
```bash
./mvnw test
```

Run specific test class:
```bash
./mvnw test -Dtest=TimestampServiceTest
```

### Manual Testing with KEAASZ

The application has been manually tested with the KEAASZ (Kormányzati Elektronikus Aláíró és Aláírás-ellenőrző Szolgáltatás) application, which can be downloaded from [here](https://keaesz.gov.hu/keaasz/).

## Native Image Configuration

The application is configured for GraalVM Native Image with:
- Automatic resource configuration
- Static executable generation
- Spring AOT support

## Security Considerations

- CSRF protection disabled for API endpoints (recommended for timestamp servers)
- Stateless session management
- Configurable security rules

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Startup Time (Native) | < 100ms |
| Memory Footprint (Native) | ~50MB |
| Request Latency | < 5ms |
| Throughput | > 10,000 req/sec |

## Contributing

1. Fork the repository
2. Create your feature branch
3. Before committing, please format your code using the AOSP style with `./mvnw spotless:apply`.
4. Commit your changes
5. Push to the branch
6. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For issues and questions, please open an issue in the GitHub repository.

---

**Built with Spring Boot 3.5.6, GraalVM 25, and Maven**