# Agent Guidelines for Timestamp Server Project

## Build System

### JDK for building (important)
- Always build with the IDE project JDK (Temurin 25, `.idea/misc.xml` `project-jdk-name=temurin-25`):
  `export JAVA_HOME=/home/zsoltii/.jdks/temurin-25.0.4.1`, or prefix every command with
  `JAVA_HOME=/home/zsoltii/.jdks/temurin-25.0.4.1`.
- Do not rely on the default `java` of the shell (a newer JDK): with it the PMD run fails with parser
  `StackOverflowError`s and bogus violations.

### Full build with tests, Spotless and PMD
```bash
JAVA_HOME=/home/zsoltii/.jdks/temurin-25.0.4.1 ./mvnw -q spotless:apply
JAVA_HOME=/home/zsoltii/.jdks/temurin-25.0.4.1 ./mvnw clean install
```
- `clean install` (or `clean verify`) compiles, runs all unit and Cucumber tests, checks Spotless and runs
  `pmd:check`. `clean package` stops before the `verify` phase and does **not** run PMD.
- Short result summary:
  `... ./mvnw clean install 2>&1 | grep -E "PMD Fail|Tests run: [0-9]+, F.*Skipped: [0-9]+$|<<< FAIL|BUILD"`
- Compile only (fast check): `JAVA_HOME=... ./mvnw -q compile` (add `test-compile` for the tests).

### PMD
- Ruleset: `pmd-custom-ruleset.xml` (almost all categories: final parameters/locals, OnlyOneReturn,
  no null assignment, guarded log statements, `/* default */` comment on package-private members,
  no literals in `if` conditions, short/long names, etc.). Test sources are excluded.
- Run PMD alone after compiling: `JAVA_HOME=... ./mvnw -q compile pmd:check`
  (report: `target/pmd.xml`; violations are printed as `PMD Failure: <class>:<line> Rule:<rule>`).
- The build fails on any violation; fix the code instead of suppressing rules. Use
  `@SuppressWarnings("PMD.<Rule>")` only for a justified case (e.g. `PMD.ShortVariable` on a record
  component named `id`).
- Typical fixes: guard logs with `if (LOGGER.isInfoEnabled())`, single exit variable instead of
  multiple `return`s, constants instead of literals in `if`, `final` on parameters and locals.
- Do not use `var` in Java code.

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
- **Always write both positive and negative JUnit unit tests** for every new or changed method
  (valid input and the expected result, plus invalid input, null/blank values and error paths)
- Unit tests are plain JUnit/Mockito tests that build the class under test directly
  (e.g. `new TimestampService(config)`), without a Spring context. `@SpringBootTest` tests are
  integration tests: they may be added on top, but never replace the unit tests
- Cucumber scenarios (`src/test/resources/features`) are additional usage examples, not a
  substitute for unit tests
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
