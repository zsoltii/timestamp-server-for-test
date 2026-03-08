# PKCS12 Key Update Feature Implementation Summary

## Overview
This implementation adds a new REST API endpoint to the timestamp server that allows updating the signing key with a new PKCS12 keystore file.

## Changes Made

### 1. New REST API Endpoint
**File**: `src/main/java/com/digital/signature/controller/TimestampController.java`

Added a new POST endpoint at `/api/timestamp/update-key` that:
- Accepts a PKCS12 file via multipart form data
- Requires `keystorePassword` parameter
- Optionally accepts `keyPassword` (defaults to `keystorePassword` if not provided)
- Optionally accepts `keyAlias` (auto-detects first private key if not provided)
- Returns success or error messages

### 2. Key Update Service Method
**File**: `src/main/java/com/digital/signature/service/TimestampService.java`

Added `updateSigningKey()` method that:
- Loads the new PKCS12 keystore
- Extracts private key and certificate
- Validates the certificate has proper extensions for timestamping
- Updates the `TimeStampResponseGenerator` with the new signing key
- Is thread-safe (synchronized)

### 3. Unit Tests
**File**: `src/test/java/com/digital/signature/service/TimestampServiceUpdateKeyTest.java`

Comprehensive unit tests covering:
- ✅ Successful key update with valid PKCS12
- ✅ Default key password usage when not provided
- ✅ Auto-detection of key alias when not provided
- ✅ Error handling for invalid keystore password
- ✅ Error handling for invalid key password
- ✅ Error handling for invalid key alias
- ✅ Error handling for PKCS12 files without private keys

### 4. Integration Tests
**File**: `src/test/java/com/digital/signature/controller/TimestampControllerUpdateKeyTest.java`

Integration tests covering:
- ✅ Successful key update via REST API
- ✅ Key password omission handling
- ✅ Key alias omission handling
- ✅ Error handling for invalid password
- ✅ Error handling for invalid key password
- ✅ Error handling for invalid key alias
- ✅ Error handling for non-PKCS12 files

## Test Results

All tests pass successfully:
- **Unit Tests**: 7/7 passed
- **Integration Tests**: 7/7 passed
- **Existing Tests**: All 42 existing tests continue to pass
- **Total**: 56/56 tests passed

## API Documentation

### Request
```
POST /api/timestamp/update-key
Content-Type: multipart/form-data

Parameters:
- file: PKCS12 file (required)
- keystorePassword: Keystore password (required)
- keyPassword: Key password (optional, defaults to keystorePassword)
- keyAlias: Key alias (optional, auto-detects first private key)
```

### Success Response
```
HTTP 200 OK
Content-Type: text/plain

"Signing key updated successfully"
```

### Error Response
The API uses Spring's `@RestControllerAdvice` for global exception handling. Error responses follow RFC 7807 (Problem Details) format:

```
HTTP 500 Internal Server Error
Content-Type: application/problem+json

{
  "type": "about:blank",
  "title": "Internal Server Error",
  "status": 500,
  "detail": "[error message]"
}
```

Common error scenarios:
- Invalid keystore password
- Invalid key password
- Invalid key alias
- Malformed PKCS12 file
- Missing private key in keystore

All exceptions are logged and handled by `ErrorHandlerController` which provides consistent error responses.

## Security Considerations

1. **Thread Safety**: The `updateSigningKey()` method is synchronized to prevent concurrent modifications
2. **Certificate Validation**: Ensures certificates have proper ExtendedKeyUsage for timestamping
3. **Error Handling**: Comprehensive error handling for invalid inputs and edge cases
4. **Password Management**: Supports separate keystore and key passwords for enhanced security

## Usage Example

```bash
# Generate a test keystore
./mvnw exec:java -Dexec.mainClass="com.digital.signature.util.TestKeystoreGenerator" \
  -Dexec.args="test-keystore.p12 testPassword testKey keyPassword"

# Update signing key via REST API
curl -X POST "http://localhost:8080/api/timestamp/update-key" \
  -F "file=@test-keystore.p12" \
  -F "keystorePassword=testPassword" \
  -F "keyPassword=keyPassword" \
  -F "keyAlias=testKey"
```

## Compatibility

- **Java Version**: Requires Java 25 (GraalVM CE 25.0.2)
- **Spring Boot**: 3.5.6
- **BouncyCastle**: Compatible with existing dependency
- **Backward Compatibility**: All existing functionality remains unchanged
