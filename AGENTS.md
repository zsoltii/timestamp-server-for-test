# Agent Guidelines for Timestamp Server Project

## Build System

### Maven Commands
- Use the Maven wrapper: `./mvnw`
- Build project: `./mvnw clean package`
- Run tests: `./mvnw test`
- Run specific test: `./mvnw test -Dtest=TestClassName`
- Run specific test method: `./mvnw test -Dtest=TestClassName#testMethod`
- Verify build: `./mvnw clean verify`
- Format code: `./mvnw spotless:apply`
- Check formatting: `./mvnw spotless:check`

### Spring Boot Commands
- Run application: `./mvnw spring-boot:run`
- Build native image: `./mvnw -Pnative package`

### GraalVM Native Image
- Set JAVA_HOME to GraalVM CE 25 before native builds
- Native image builds require GraalVM native-image tool

## Code Style Guidelines

### Java Conventions
- Follow Google Java Format Style (AOSP) as configured in Spotless
- Use 4-space indentation
- Maximum line length: 100 characters
- Class names: PascalCase (e.g., `TimestampService`)
- Method names: camelCase (e.g., `generateTimestampResponse`)
- Variable names: camelCase (e.g., `privateKey`)
- Constants: UPPER_SNAKE_CASE (e.g., `MAX_RETRIES`)
- Package names: lowercase with dots (e.g., `com.digital.signature.service`)

### Import Organization
- Group imports by package (Spring, Java, BouncyCastle, etc.)
- Use specific imports, not wildcard imports
- Static imports for constants and assertion methods
- Organize imports alphabetically within groups

### Error Handling
- Use specific exception types (IllegalArgumentException, IllegalStateException)
- Wrap low-level exceptions with meaningful messages
- Use SLF4J for logging with appropriate log levels:
  - DEBUG: Detailed debugging information
  - INFO: Important application events
  - WARN: Potential issues or unexpected conditions
  - ERROR: Serious problems that affect functionality
- Include context in error messages
- Use @PostConstruct for initialization that may throw exceptions

### Method Design
- Keep methods focused on single responsibility
- Limit method length to ~30 lines where possible
- Use meaningful parameter names
- Document public methods with JavaDoc
- Include @throws documentation for exceptions
- Use synchronized for thread-safe operations

### Testing Guidelines
- Write JUnit 5 tests using @Test annotation
- Use AssertJ assertions (assertThat)
- Test both positive and negative cases
- Create integration tests for Spring components
- Use @SpringBootTest for integration tests
- Test error conditions and edge cases
- Include test method names that describe behavior

### Constructor Injection

- Prefer constructor injection over field injection
- Use `@Autowired` on constructors (optional in Spring Boot 3.x)
- Mark constructors as `public` for testability
- Keep constructors focused on dependency initialization

### Cryptographic Operations
- Use BouncyCastle for cryptographic operations
- Handle private keys securely
- Validate certificates before use
- Use appropriate algorithm identifiers
- Follow RFC 3161 for timestamp protocol
- Use SHA-256 or stronger for hashing

### Documentation
- Include JavaDoc for public classes and methods
- Document parameters and return values
- Include @throws for exceptions
- Document thread-safety requirements
- Include examples where helpful
- Keep documentation up-to-date

### Code Organization
- Group related methods together
- Place test classes in same package as production code
- Use meaningful package names
- Separate controller, service, and config layers
- Keep configuration in separate classes

### Version Control
- Follow semantic versioning
- Include meaningful commit messages
- Reference issues in commit messages
- Keep commits focused on single changes
- Update README.md when controllers change

### Security
- Validate all inputs
- Use secure random number generation
- Handle secrets carefully
- Validate certificates
- Use appropriate key sizes
- Follow security best practices

### Performance
- Avoid unnecessary object creation
- Use appropriate data structures
- Consider synchronization overhead
- Optimize cryptographic operations
- Use efficient algorithms

### Dependency Management
- Specify exact versions for critical dependencies
- Use Spring Boot parent POM for version management
- Keep dependencies up-to-date
- Document why each dependency is needed

### Logging
- Use SLF4J LoggerFactory
- Log important application events
- Include context in log messages
- Use appropriate log levels
- Avoid logging sensitive information
- Use structured logging where possible

### Code Reviews
- Review for adherence to style guidelines
- Check for proper error handling
- Verify test coverage
- Ensure security best practices
- Validate documentation
- Check for performance issues

### Continuous Integration
- Run all tests on every commit
- Check code formatting
- Verify build succeeds
- Run static analysis tools
- Check for dependency vulnerabilities

### Release Process
- Update version in pom.xml
- Run `./mvnw clean package` for build
- Create release notes
- Tag release in Git
- Build and test release artifacts
- Publish to repository if applicable

### JDK

- Always use GraalVM CE 25: ~/.jdks/graalvm-ce-25.0.2
- Set JAVA_HOME to GraalVM for native builds

### README.md

- Update README.md when controllers or API endpoints change
- Document new endpoints in the API table
- Update configuration examples when config changes
- Include changes to build instructions or prerequisites
