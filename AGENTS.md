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
- Set JAVA_HOME to GraalVM CE 25 before native builds: `export JAVA_HOME=~/.jdks/graalvm-ce-25.0.2`
- Native image builds require GraalVM native-image tool

## Code Style Guidelines

### Java Conventions
- Follow Google Java Format Style (AOSP) via Spotless
- 4-space indentation, max line length: 100 characters
- Class names: PascalCase (`TimestampService`)
- Method/variable names: camelCase (`generateTimestampResponse`, `privateKey`)
- Constants: UPPER_SNAKE_CASE (`MAX_RETRIES`)
- Package names: lowercase with dots (`com.digital.signature.service`)

### Import Organization
- Group imports by package (Spring, Java, BouncyCastle)
- Use specific imports, not wildcards
- Static imports for constants and assertions
- Alphabetical order within groups

### Error Handling
- Use specific exceptions: `IllegalArgumentException`, `IllegalStateException`
- Wrap low-level exceptions with meaningful messages
- Use SLF4J logging: DEBUG (detailed), INFO (events), WARN (issues), ERROR (problems)
- Include context in error messages
- Use `@PostConstruct` for initialization that may throw

### Method Design
- Single responsibility, limit to ~30 lines
- Use meaningful parameter names
- Document public methods with JavaDoc including `@throws`
- Use `synchronized` for thread-safe operations

### Testing
- JUnit 5 with `@Test` annotation
- AssertJ assertions (`assertThat`)
- Test positive and negative cases
- Use `@SpringBootTest` for integration tests
- Test error conditions and edge cases
- Descriptive test method names

### Constructor Injection
- Prefer constructor injection over field injection
- Use `@Autowired` on constructors (optional in Spring Boot 3.x)
- Mark constructors `public` for testability

### Cryptographic Operations
- Use BouncyCastle for crypto operations
- Handle private keys securely, validate certificates
- Follow RFC 3161 for timestamp protocol
- Use SHA-256 or stronger for hashing

### Documentation
- JavaDoc for public classes/methods
- Document parameters, return values, `@throws`
- Document thread-safety requirements
- Keep documentation up-to-date

### Code Organization
- Group related methods together
- Test classes in same package as production code
- Separate controller, service, and config layers
- Keep configuration in separate classes

### Security
- Validate all inputs
- Use secure random number generation
- Handle secrets carefully, validate certificates
- Use appropriate key sizes

### Performance
- Avoid unnecessary object creation
- Consider synchronization overhead
- Optimize cryptographic operations

### Logging
- Use `SLF4J LoggerFactory`
- Log important events with context
- Avoid logging sensitive information

### Version Control
- Follow semantic versioning
- Meaningful commit messages referencing issues
- Keep commits focused on single changes
- Update README.md when controllers/APIs change

### README.md
- Update when controllers or API endpoints change
- Document new endpoints in the API table
- Update configuration examples when changed
- Include changes to build instructions
