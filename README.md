> **Attention:** This project is specifically for testing purposes, for example, for running automated tests. It is not
> recommended for use in a production environment.

# Timestamp Server for Digital Signatures

A high-performance timestamp server built with Spring Boot, Maven, and GraalVM Native Image support for digital
signature applications.

## Features

- **RFC 3161 Timestamp Support**: Generates timestamps in ASN.1 format for digital signatures
- **Multiple Timestamp Formats**: Supports RFC 3161, ISO 8601, and Unix epoch formats
- **PKCS12 Key Management**: REST API endpoint for updating signing keys with PKCS12 keystores
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

| Endpoint                | Method | Description                                               | Content-Type                  | Response Format               |
|-------------------------|--------|-----------------------------------------------------------|-------------------------------|-------------------------------|
| `/api/timestamp`        | POST   | RFC 3161 timestamp query                                  | `application/timestamp-query` | `application/timestamp-reply` |
| `/api/timestamp/simple` | GET    | Get current timestamp in ISO 8601 format                  | -                             | String (ISO 8601)             |
| `/api/timestamp/unix`   | GET    | Get current timestamp as Unix epoch (seconds since epoch) | -                             | Long                          |
| `/api/timestamp/health` | GET    | Health check endpoint                                     | -                             | String                        |
| `/api/timestamp/update-key` | POST | Update signing key with PKCS12 keystore (multipart/form-data) | `multipart/form-data` | String (success/error) |

### Actuator Endpoints

The following actuator endpoints are exposed:

- `/actuator/health` - Application health status
- `/actuator/info` - Application information
- `/actuator/metrics` - Application metrics
- `/actuator/prometheus` - Prometheus metrics endpoint

## Docker Support

### Build Docker Image:

```bash
docker build -t timestamp-server .
```

### Run with Docker:

```bash
docker run -p 8080:8080 timestamp-server
```

### Docker Configuration Options

The Docker image supports the following configuration options:

#### Environment Variables

- `SPRING_PROFILES_ACTIVE` - Set to `docker` to activate Docker-specific configuration (default: `docker`)
- Standard Spring Boot environment variables for all `application.yml` properties

#### External Configuration

Mount a custom configuration file to `/app/config/` to override default settings:

```bash
docker run -p 8080:8080 \
  -v /path/to/your/config:/app/config \
  timestamp-server
```

Configuration files in `/app/config/` take precedence over classpath settings.

#### Using Docker Compose

```bash
# Start the service
docker compose up -d

# View logs
docker compose logs -f

# Stop the service
docker compose down
```

#### Resource Limits (docker-compose.yml)

The default configuration includes:
- **Memory**: 256MB limit, 128MB reserved
- **CPU**: 1.0 limit, 0.25 reserved
- **Security**: Read-only filesystem, no-new-privileges
- **Health Check**: 30s interval with 3 retries

#### Custom Configuration Example

Create a custom `application-override.yml`:

```yaml
server:
  port: 8080

timestamp:
  certificate-subject: "CN=Production Timestamp Authority, O=My Company, C=HU"
  validity-days: 730
```

Mount and activate:

```bash
docker run -p 8080:8080 \
  -v $(pwd)/application-override.yml:/app/config/application-override.yml \
  -e SPRING_CONFIG_IMPORT=optional:file:/app/config/application-override.yml \
  timestamp-server
```

## Configuration

Edit `src/main/resources/application.yml` to customize:

- Server port and graceful shutdown settings
- Spring application name
- Actuator endpoints (health, info, metrics, prometheus)
- Logging levels (root: INFO, com.digital.signature: DEBUG)
- Timestamp server configuration:
    - Key algorithm (RSA) and size (2048)
    - Signature algorithm (SHA256WithRSA)
    - Certificate subject details
    - Policy ID for timestamping
    - Validity period in days
    - PKCS12 keystore path, password, key alias, and key password (for production use)

### Security Configuration

The application uses Spring Security with the following settings:

- Stateless session management (SessionCreationPolicy.STATELESS)
- CSRF protection disabled for API endpoints (recommended for timestamp servers)
- Public access to all endpoints including actuator endpoints
- No authentication required by default
- Global exception handling via `@RestControllerAdvice` for consistent error responses
  To customize security, modify the `SecurityFilterChain` bean in `TimestampServerApplication.java`.

## Testing

Run all tests:

```bash
./mvnw test
```

Run specific test class:

```bash
./mvnw test -Dtest=TimestampServiceTest
```

Run PKCS12 key update tests:

```bash
./mvnw test -Dtest=TimestampServiceUpdateKeyTest
./mvnw test -Dtest=TimestampControllerUpdateKeyTest
```

### Manual Testing with KEAASZ

The application has been manually tested with the KEAASZ (Kormányzati Elektronikus Aláíró és Aláírás-ellenőrző
Szolgáltatás) application, which can be downloaded from [here](https://keaasz.gov.hu/keaasz/).

### PKCS12 Key Update Testing

To manually test the key update functionality:

```bash
# Generate a test keystore
export JAVA_HOME=~/.jdks/graalvm-ce-25.0.2/
./mvnw exec:java -Dexec.mainClass="com.digital.signature.util.TestKeystoreGenerator" \
  -Dexec.args="test-keystore.p12 testPassword testKey keyPassword"

# Update signing key via REST API
curl -X POST "http://localhost:8080/api/timestamp/update-key" \
  -F "file=@test-keystore.p12" \
  -F "keystorePassword=testPassword" \
  -F "keyPassword=keyPassword" \
  -F "keyAlias=testKey"
```

## Native Image Configuration

The application is configured for GraalVM Native Image with:

- Automatic resource configuration
- Static executable generation
- Spring AOT support

## PKCS12 Key Management

The timestamp server now supports dynamic key updates via REST API. This feature allows you to:

- Update signing keys without restarting the server
- Use PKCS12 keystores with separate keystore and key passwords
- Auto-detect key aliases if not specified
- Validate certificates for proper timestamping extensions

### REST API Endpoint

```
POST /api/timestamp/update-key
```

**Parameters:**
- `file`: PKCS12 file (multipart/form-data)
- `keystorePassword`: Keystore password (required)
- `keyPassword`: Key password (optional, defaults to keystorePassword)
- `keyAlias`: Key alias (optional, auto-detects first private key)

**Responses:**
- `200 OK`: Success - key updated
- `500 Internal Server Error`: Error with ProblemDetail response

### Security

The key update endpoint uses the global `ErrorHandlerController` for exception handling, providing consistent RFC 7807 (Problem Details) error responses. All exceptions are logged with appropriate severity levels.

## Security Considerations

- CSRF protection disabled for API endpoints (recommended for timestamp servers)
- Stateless session management
- Configurable security rules

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
**Built with Spring Boot 3.5.6, GraalVM 25, and Maven**"