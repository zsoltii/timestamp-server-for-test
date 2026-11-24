> **Attention:** This project is specifically for testing purposes, for example, for running automated tests. It is not
> recommended for use in a production environment.

# Timestamp Server for Digital Signatures

A small [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) Time-Stamp Authority (TSA) built with Spring Boot, Maven and
BouncyCastle, with optional GraalVM Native Image support. It is meant for **testing applications that create or validate
signatures with timestamps** (for example PAdES-T / XAdES-T / CAdES-T signatures), and it can deliberately stamp
documents with a time **in the past or in the future**.

## Table of contents

1. [Features](#features)
2. [Quick start](#quick-start)
3. [How it works](#how-it-works)
4. [Web UI](#web-ui)
5. [REST API reference](#rest-api-reference)
6. [Controlling the time of the timestamps](#controlling-the-time-of-the-timestamps)
7. [Using the server from a signing application](#using-the-server-from-a-signing-application)
8. [Signing key and certificate](#signing-key-and-certificate)
   - [Create an uploadable PKCS12 keystore](#create-an-uploadable-pkcs12-keystore)
   - [Verify and upload the keystore](#verify-and-upload-the-keystore)
9. [Configuration reference](#configuration-reference)
10. [Error handling](#error-handling)
11. [Docker](#docker)
12. [Security considerations](#security-considerations)
13. [Native image](#native-image)
14. [Development and testing](#development-and-testing)
15. [Troubleshooting](#troubleshooting)
16. [Contributing](#contributing) · [License](#license)

## Features

- **RFC 3161 timestamp service**: answers standard `application/timestamp-query` requests with
  `application/timestamp-reply` responses, so any RFC 3161 client can use it.
- **Time control**: a fixed time that is written into *every* timestamp (set once on the server, clients send plain
  requests), or a one-off custom time per request. Times can be in the past or in the future.
- **Flexible time format**: `yyyy-MM-dd HH:mm:ssZ` with offsets (`+0200`), abbreviations (`CEST`) or region ids
  (`Europe/Budapest`); UTC when no zone is given.
- **Signing key management**: self-signed key generated on startup, a PKCS12 keystore from the configuration, or a
  PKCS12 file uploaded at runtime without restarting the server.
- **Web UI**: a single page for the status, the signing certificate, the fixed time, one-off `.tsr` files and the key
  update.
- **Other formats**: simple ISO 8601 and Unix epoch time endpoints.
- **Operations**: Actuator health/metrics endpoints, Docker images (native and JVM), graceful shutdown, CORS enabled.

## Quick start

Prerequisites: Java 25 (GraalVM CE is only needed for the native image), Git. Maven is provided by the wrapper
(`./mvnw`).

```bash
# Build (runs the tests and the static analysis); use -DskipTests to skip the tests
./mvnw clean package

# Run on the default port 8080 (add --server.port=8081 to change it)
java -jar target/timestamp-server.jar
```

Check that it runs and request a first timestamp with OpenSSL:

```bash
curl http://localhost:8080/api/timestamp/health            # Timestamp Server is running

# 1. create a timestamp query (a hash of the file + "give me the certificate")
openssl ts -query -data document.pdf -sha256 -cert -out request.tsq
# 2. send it
curl -X POST http://localhost:8080/api/timestamp \
  -H "Content-Type: application/timestamp-query" --data-binary @request.tsq -o response.tsr
# 3. inspect the answer
openssl ts -reply -in response.tsr -text
# 4. verify it against the server's signing certificate
curl -s http://localhost:8080/api/timestamp/certificate/pem -o tsa.pem
openssl ts -verify -in response.tsr -queryfile request.tsq -CAfile tsa.pem     # Verification: OK
```

Open `http://localhost:8080/` for the [web UI](#web-ui).

## How it works

```
 client (signing app, curl, ...)                          timestamp server
 ───────────────────────────────                          ─────────────────────────────────────────
  POST /api/timestamp                  ─────────────▶     TimestampController
  Content-Type: application/timestamp-query                  │  validates the media type
  body: DER TimeStampReq                                     ▼
                                                          TimestampService
                                                             │  1. picks the time:
                                                             │       fixed time (if set) or current time
                                                             │  2. BouncyCastle TimeStampResponseGenerator
                                                             │     builds the token and signs it with the
                                                             │     signing key (algorithm selected from the key by default)
  ◀─────────────  200 application/timestamp-reply            ▼
  body: DER TimeStampResp                                 signing key + certificate (in memory)
```

- **Layers**: `controller` (HTTP, status codes), `service` (timestamp logic, key handling), `config` (typed
  configuration, CORS). `ErrorHandlerController` turns exceptions into RFC 7807 problem details.
- **Accepted requests**: message imprints hashed with **SHA-1, SHA-256 or SHA-512**; other algorithms (for example MD5)
  get a *rejection* response (a well-formed `TimeStampResp` with a failure status), not an HTTP error. If a request names
  a policy, it must be the configured `timestamp.policy-id`.
- **Response content**: the token contains the message imprint of the request, the used time (`genTime`), the policy
  id, a serial number (derived from the system clock in milliseconds) and, when the request has `certReq = true`, the
  signing certificate. Accuracy is not set.
- **State**: the signing key and the fixed time live in memory only. A restart generates a new key (unless a keystore is
  configured) and clears the fixed time.
- **Thread safety**: the fixed time is an atomic reference; the signing key update is `synchronized`.

## Web UI

`http://localhost:8080/` serves a single static page (Hungarian labels) with these sections:

| Section                                    | What it does                                                                                            |
|--------------------------------------------|---------------------------------------------------------------------------------------------------------|
| **Állapot** (status)                       | Health check, current time as ISO 8601, current time as Unix epoch.                                     |
| **Aláíró tanúsítvány** (signing certificate)| Shows the PEM certificate, downloads it as DER (`.cer`).                                                |
| **Rögzített időbélyeg-időpont** (fixed time)| Sets, shows and clears the [fixed time](#fixed-time-for-every-timestamp). The current value is loaded when the page opens. |
| **Időbélyeg tetszőleges időponttal** (one-off) | Pick a file (its SHA-256 is computed in the browser, the file is not uploaded) or paste a SHA-256 hash, optionally enter a time, and the `.tsr` response is downloaded. |
| **Aláíró kulcs csere** (key update)        | Uploads a PKCS12 file and replaces the signing key (see [Signing key and certificate](#signing-key-and-certificate)). |

The page uses relative API URLs, so it also works under a context path behind a reverse proxy.
If the UI is published under `/timestamp`, open `/timestamp/` (with the trailing slash) and
proxy that whole path, including `/timestamp/api/timestamp/...`, to the application.
No separate proxy rules are needed for individual API endpoints.

Everything the page does can also be done with `curl`.

## REST API reference

Base path: `/api/timestamp`. All endpoints are public (no authentication).

| Endpoint                      | Method           | Purpose                                              | Request                       | Response                      |
|-------------------------------|------------------|------------------------------------------------------|-------------------------------|-------------------------------|
| `/api/timestamp`              | POST             | RFC 3161 timestamp (fixed time if set, else now)     | `application/timestamp-query` | `application/timestamp-reply` |
| `/api/timestamp/custom`       | POST             | RFC 3161 timestamp with a one-off custom time        | `application/timestamp-query` | `application/timestamp-reply` |
| `/api/timestamp/fixed-time`   | GET / PUT / DELETE | Read, set or clear the fixed time                  | query parameter `time`        | text (ISO 8601) or 204        |
| `/api/timestamp/simple`       | GET              | Current time as ISO 8601                             | -                             | text, e.g. `2026-11-18T06:40:05.215535083Z` |
| `/api/timestamp/unix`         | GET              | Current time as Unix epoch seconds                   | -                             | number                        |
| `/api/timestamp/health`       | GET              | Liveness check                                       | -                             | text                          |
| `/api/timestamp/certificate`  | GET              | Signing certificate, DER (`signing-certificate.cer`) | -                             | `application/pkix-cert`       |
| `/api/timestamp/certificate/pem` | GET           | Signing certificate, PEM                             | -                             | `application/x-pem-file`      |
| `/api/timestamp/update-key`   | POST             | Replace the signing key with a PKCS12 keystore       | `multipart/form-data`         | text                          |

`/simple` and `/unix` always return the real current time; the fixed time does not affect them.

### `POST /api/timestamp`

The standard RFC 3161 endpoint. Send a DER encoded `TimeStampReq`, get a DER encoded `TimeStampResp`.
No extra fields are needed, which is what makes it usable from any signing application.

| Status | When                                                                               |
|--------|------------------------------------------------------------------------------------|
| 200    | A response was produced. It may still be a *rejection* (see `status` inside the response, e.g. unsupported hash algorithm). |
| 415    | The `Content-Type` is not `application/timestamp-query`.                           |
| 500    | The body is not a valid `TimeStampReq`.                                            |

### `POST /api/timestamp/custom?time=<time>`

Same as above, but the time is taken from the optional `time` query parameter instead of the fixed time. An empty or
missing `time` means the current time. The time that was used is returned in the `X-Timestamp-Time` response header (ISO
8601, UTC). An invalid `time` gives `400 Bad Request`.

### `/api/timestamp/fixed-time`

| Call                         | Result                                                                                              |
|------------------------------|-----------------------------------------------------------------------------------------------------|
| `GET`                        | `200` with the fixed time as ISO 8601 UTC text, or `204 No Content` when none is set.               |
| `PUT ?time=<time>`           | Sets the fixed time. `200` with the stored time (UTC). An empty `time` clears it and returns `204`. |
| `DELETE`                     | Clears the fixed time, `204`. The current time is used again.                                       |

An invalid `time` gives `400 Bad Request` and the previous setting is kept.

### `POST /api/timestamp/update-key`

`multipart/form-data` with the fields:

| Field                | Required | Description                                                                            |
|----------------------|----------|----------------------------------------------------------------------------------------|
| `file`               | yes      | The PKCS12 file (`.p12` / `.pfx`).                                                     |
| `keystorePassword`   | yes      | Keystore password.                                                                     |
| `keyPassword`        | no       | Private key password, defaults to the keystore password.                               |
| `keyAlias`           | no       | Alias of the key entry, defaults to the first private key found.                       |
| `requireCriticalEku` | no       | Boolean; defaults to `true`. If `false`, both critical and noncritical EKUs are accepted. |

`200` with `Signing key updated successfully`, or `500` with a problem detail when the file, the password or the alias
is wrong. An invalid boolean gives `400`.

The web UI always sends this option explicitly: its checkbox is checked by default and sends `true`; clearing it
sends `false`. Setting it to `false` is a test-only,
non-RFC 3161 mode: strict timestamp validators may reject tokens made with a noncritical EKU. The certificate must
still have an EKU containing **only** `id-kp-timeStamping`; the uploaded certificate is not modified.

```bash
curl -X POST http://localhost:8080/api/timestamp/update-key \
  -F "file=@test-tsa.p12" -F "keystorePassword=changeit" -F "requireCriticalEku=false"
```

### Actuator endpoints

`/actuator/health` (with details), `/actuator/info`, `/actuator/metrics`, `/actuator/prometheus`.

## Controlling the time of the timestamps

### Fixed time for every timestamp

Set a time once on the server; from then on **every standard request** to `POST /api/timestamp` (no extra fields, so
any RFC 3161 client works unchanged) gets a timestamp carrying that time, until you change or clear it.

On the web UI use the section *Rögzített időbélyeg-időpont*, or with the API:

```bash
# set (URL-encode the + sign as %2B, or let curl encode it)
curl -X PUT -G "http://localhost:8080/api/timestamp/fixed-time" \
  --data-urlencode "time=2026-11-01 12:34:56+0100"          # -> 2026-11-01T11:34:56Z

# read (204 No Content when nothing is set)
curl "http://localhost:8080/api/timestamp/fixed-time"

# clear: the current time is used again (an empty time parameter does the same)
curl -X DELETE "http://localhost:8080/api/timestamp/fixed-time"
```

- An empty or cleared fixed time means the **current time** is used.
- The setting is **kept in memory only** and is lost when the server restarts.
- It applies to `POST /api/timestamp` only; `/custom` always uses its own `time` parameter.

### One-off custom time

```bash
# the time of this single response is 2020-01-31T12:30:00Z
curl -X POST -G "http://localhost:8080/api/timestamp/custom" --data-urlencode "time=2020-01-31 14:30:00+0200" \
  -H "Content-Type: application/timestamp-query" --data-binary @request.tsq -o response.tsr
```

The web UI has a matching form that builds the request from a file (or a SHA-256 hash) and downloads the `.tsr`.

### Time format

`yyyy-MM-dd HH:mm:ssZ`, 24-hour clock, followed by an optional zone:

| Zone kind     | Accepted values                                                                  | Notes                                                                 |
|---------------|----------------------------------------------------------------------------------|-----------------------------------------------------------------------|
| none          | `2026-11-01 12:34:56`                                                            | UTC                                                                   |
| offset        | `Z`, `+0200`, `+02:00`, `+02`, `-0530`                                           | Range ±18:00                                                          |
| abbreviation  | `UTC`, `UT`, `GMT`, `WET`, `WEST`, `CET`, `CEST`, `EET`, `EEST` (case-insensitive) | Always the fixed offset (`CET` = +01:00, `CEST` = +02:00), even outside the season. Ambiguous abbreviations such as `CST` or `PST` are **rejected**. |
| region id     | `Europe/Budapest`, `America/New_York`, `UTC+02:00`, ...                          | Uses the daylight saving rules of the date. Case-sensitive.           |

More rules:

- A `T` may replace the space between the date and the time: `2026-11-01T12:34:56CEST`.
- Spaces are allowed before the zone: `2026-11-01 12:34:56 CEST`.
- Leading and trailing whitespace is ignored. Seconds are required.
- In a URL, an unencoded `+` arrives as a space. A space followed by digits (`12:34:56 0200`) is therefore read as
  `+0200`. Prefer `%2B` or `curl --data-urlencode`.
- For a region id, a local time that does not exist (the hour skipped when the clocks go forward) is moved forward, and a
  time that occurs twice (when the clocks go back) gets the earlier offset.
- Examples: `2026-11-01 12:34:56+0100`, `2026-11-01T12:34:56CET`, `2026-11-01 12:34:56 Europe/Budapest`,
  `2099-12-31 23:59:59Z`.
- Invalid values (wrong shape, impossible date such as `2023-02-29`, hour `25`, unknown zone, ...) return
  `400 Bad Request` with a message that starts with `Invalid time`.

Past times such as `1999-12-31` and far future times are accepted; the time is not checked against the validity period
of the signing certificate.

## Using the server from a signing application

1. **Point the application to the TSA URL**: `http://<host>:<port>/api/timestamp`. Plain HTTP and no authentication are
   used. Do **not** add `/custom` unless you want the application to always send the same `time` parameter.
2. **Make the application ask for a timestamp.** Many applications sign *without* a timestamp by default. For example, a
   PAdES signature in the `PAdES_BASELINE_B` profile contains no timestamp at all, and the application then shows its
   own local signing time. Choose the **`-T` level** (e.g. `PAdES_BASELINE_T`) or higher. When it works, the signature
   contains a content/signature timestamp created by `Test Timestamp Authority`.
3. **Optionally fix the time** (see above) before signing, to get a past or future timestamp in the document.
4. **Trust the certificate if you want a clean validation.** The default signing certificate is self-signed and
   regenerated at every start, so validators report the timestamp as *indeterminate* ("not verifiable against the trusted
   list"). Either import `GET /api/timestamp/certificate` into the trust store of the validator, or use a long-lived key
   from a PKCS12 file so the certificate stays the same (see [Signing key and certificate](#signing-key-and-certificate)).
5. **Verify from the command line** with `openssl ts -verify` as in the [quick start](#quick-start).

The server was manually tested with the KEAASZ application (Kormányzati Elektronikus Aláíró és Aláírás-ellenőrző
Szolgáltatás), which can be downloaded from [here](https://keaasz.gov.hu/keaasz/). Its report shows the timestamp time
of a document stamped with a fixed time, for example `2026.11.01 13:34:56 CET` for the fixed time
`2026-11-01T12:34:56Z`.

> The time shown in a signature as "signing time" ("nem hitelesített időpont" in KEAASZ) comes from the signer's own
> clock. Only the *timestamp* time is controlled by this server.

## Signing key and certificate

Three ways to provide the signing key:

1. **Generated on startup (default).** When no keystore is configured, an RSA key pair (`timestamp.key-size`, default
   2048 bits) and a self-signed certificate (subject `timestamp.certificate-subject`, valid for
   `timestamp.validity-days` days) are generated. The certificate is a non-CA certificate with the key usages
   `digitalSignature` and `nonRepudiation` and the critical extended key usage `id-kp-timeStamping`. It is new at every
   start.
2. **PKCS12 keystore in the configuration.** Set `timestamp.keystore-path`, `timestamp.keystore-password` and
   `timestamp.key-alias` (and optionally `timestamp.key-password`). The server fails to start when the file, the
   password or the alias is wrong. Use this to keep the same certificate across restarts.
3. **PKCS12 upload at runtime.** `POST /api/timestamp/update-key` (or the web UI) replaces the key and the certificate
   without a restart. The update is in memory only; after a restart the configured or generated key is used again.

With `timestamp.signature-algorithm=auto` (the default), the server selects the timestamp signature algorithm
from the private key at startup and after each upload. PKCS12 signing keys supported on JDK 25 include RSA,
RSA-PSS, EC (ECDSA), DSA, Ed25519, Ed448 and ML-DSA-44/65/87. An RSA key still defaults to `SHA256withRSA`.
The uploaded certificate needs the `id-kp-timeStamping` EKU, critical by default. Timestamp verifiers must support
the selected signature algorithm. PKCS11 and key-agreement-only keys are not supported by this upload.
If an existing deployment explicitly sets a signature algorithm, remove that override or change it to `auto`
to allow switching between key types without restarting.

### Create an uploadable PKCS12 keystore

The `.p12` or `.pfx` must contain a **private-key entry** and its matching X.509 v3 signer certificate.
The certificate's **Extended Key Usage (EKU)** must contain **only** Time Stamping
(`1.3.6.1.5.5.7.3.8`) and must be **critical** unless the upload explicitly enables the nonstandard
test-only mode described above. This is separate from **Key Usage (KU)**. To match the server's generated test
certificate, use `digitalSignature` and `nonRepudiation` for KU and set Basic Constraints to non-CA.
The following examples create self-signed certificates for local testing.

#### KeyStore Explorer 5.7

1. Select **File > New**, choose **PKCS #12**, then select **Tools > Generate Key Pair**. Choose RSA
   (2048 bits or more) or EC (for example P-256).
2. In **Generate Key Pair Certificate**, select **Version 3**, fill in the certificate details, and
   click **Add Extensions**.
3. Click **Add**. In **Add Extension Type**, select **Extended Key Usage** and check **Critical
   Extension** before clicking **OK**. In the **Extended Key Usage Extension (EKU)** dialog, select
   only **Time Stamping** and click **OK**.
4. If **Extended Key Usage** is missing from the **Add Extension Type** list, it has already been
   added. Click **Cancel**, select the existing **Extended Key Usage** row in **Add Certificate
   Extensions**, and use **Toggle Criticality** if the row is not already critical. Use **Edit** on
   that row to confirm that **Time Stamping** is its only value.
5. To match the built-in certificate, add critical **Key Usage** with **Digital Signature** and
   **Non-repudiation**, and critical **Basic Constraints** with **Subject is a CA** unchecked.
6. Finish generating the entry, give it the alias `tsa`, and save the keystore as `test-tsa.p12`.
   To export just one entry from an existing keystore, right-click it and select **Export > Export
   Key Pair**, then supply the PKCS #12 export password.

If you need to keep an existing private key, right-click its entry and choose **Generate CSR**.
Have the issuer create a **new** certificate with the critical, Time Stamping-only EKU, then use
**Import CA Reply** on the original entry and save or export it. If you have your own test CA in
KeyStore Explorer, use **Sign > Sign CSR** on the CA entry and set the EKU under **Add Extensions**
when issuing the certificate. Changing the EKU in an already signed certificate is not possible
without reissuing it; exporting it again does not change the flag.

#### OpenSSL

Generate a password-protected RSA private key and self-signed test certificate, then package them
under alias `tsa`. OpenSSL prompts for the private-key passphrase and the PKCS12 export password.

```bash
openssl req -new -x509 -newkey rsa:2048 -sha256 -days 365 \
  -subj '/CN=Test Timestamp Authority' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature,nonRepudiation' \
  -addext 'extendedKeyUsage=critical,timeStamping' \
  -keyout tsa-key.pem -out tsa-cert.pem

openssl pkcs12 -export -name tsa \
  -inkey tsa-key.pem -in tsa-cert.pem -out test-tsa.p12
```

For EC, replace `-newkey rsa:2048` with `-newkey ec -pkeyopt ec_paramgen_curve:prime256v1`.
Keep the private-key file and the PKCS12 file out of version control.

#### Java `keytool`

Generate the key and self-signed certificate directly into the keystore. `keytool` prompts for the
keystore password.

```bash
keytool -genkeypair -storetype PKCS12 -keystore test-tsa.p12 -alias tsa \
  -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -validity 365 \
  -dname 'CN=Test Timestamp Authority' \
  -ext 'BC:critical=ca:false' \
  -ext 'KU:critical=digitalSignature,nonRepudiation' \
  -ext 'EKU:critical=timeStamping'
```

### Verify and upload the keystore

```bash
keytool -list -v -storetype PKCS12 -keystore test-tsa.p12 -alias tsa
```

For RFC 3161-compliant use, check that the entry is a `PrivateKeyEntry` and that the signer certificate has
`Criticality=true` on the **ExtendedKeyUsages** extension (OID `2.5.29.37`), with only `timeStamping`.
If the server reports `Certificate must have an ExtendedKeyUsage extension marked as critical`,
check this flag on the signer certificate for the exact alias you uploaded, not on the KU or CA
certificate. Reissue the signer certificate if the flag is missing, or explicitly disable the criticality
requirement for test-only use as described in the upload API section.

In the web UI, use **Aláíró kulcs csere** and supply the file, its password and the alias `tsa`.
Alternatively, send the same fields to the [key update endpoint](#post-apitimestampupdate-key):

```bash
read -rs -p 'PKCS12 password: ' tsa_password
printf '\n'
printf '%s' "$tsa_password" | curl --fail-with-body \
  -F 'file=@test-tsa.p12' \
  -F 'keystorePassword=<-' \
  -F 'keyAlias=tsa' \
  http://localhost:8080/api/timestamp/update-key
unset tsa_password
```

Supply `keyPassword` only if the private-key password differs from the keystore password.

Download the current certificate:

```bash
curl -o signing-certificate.cer http://localhost:8080/api/timestamp/certificate      # DER
curl -o signing-certificate.pem http://localhost:8080/api/timestamp/certificate/pem  # PEM
```

The certificate endpoints always return the **current** certificate, also after a key update.

## Configuration reference

Configuration is read from `src/main/resources/application.yml` and, like any Spring Boot application, can be
overridden with environment variables, command line arguments (`--timestamp.key-size=3072`) or an external file.

| Property                          | Default                                                  | Description                                              |
|-----------------------------------|----------------------------------------------------------|----------------------------------------------------------|
| `server.port`                     | `8080`                                                   | HTTP port (`SERVER_PORT`, or `--server.port=8081`).      |
| `server.shutdown`                 | `graceful`                                               | Graceful shutdown.                                       |
| `timestamp.key-algorithm`         | `RSA`                                                    | Algorithm of the generated key pair.                     |
| `timestamp.key-size`              | `2048`                                                   | Size of the generated key.                               |
| `timestamp.signature-algorithm`   | `auto`                                                   | Select from the private key, or explicitly pin a compatible signature algorithm. |
| `timestamp.certificate-subject`   | `CN=Test Timestamp Authority, O=Digital Signature, C=HU` | Subject of the generated certificate.                    |
| `timestamp.policy-id`             | `1.3.6.1.4.1.13762.3`                                    | Policy OID written into the tokens.                      |
| `timestamp.validity-days`         | `365`                                                    | Validity of the generated certificate.                   |
| `timestamp.keystore-path`         | *(unset)*                                                | PKCS12 file; when set, no key is generated.              |
| `timestamp.keystore-password`     | *(unset)*                                                | Required with `keystore-path`.                           |
| `timestamp.key-alias`             | *(unset)*                                                | Required with `keystore-path`.                           |
| `timestamp.key-password`          | keystore password                                        | Password of the key entry.                               |
| `management.endpoints.web.exposure.include` | `health,info,metrics,prometheus`               | Exposed Actuator endpoints.                              |

Environment variable form (Spring relaxed binding): `TIMESTAMP_KEYSTORE_PATH`, `TIMESTAMP_KEY_ALIAS`,
`TIMESTAMP_VALIDITY_DAYS`, ... The fixed time is **not** a configuration property; it is set at runtime.

Logging uses the Spring Boot defaults (`INFO`). Each generated timestamp logs
`Generating timestamp with time: <instant>`. To see every HTTP request (also unknown URLs and wrong methods) while
diagnosing a client, start with `--logging.level.org.springframework.web.servlet.DispatcherServlet=DEBUG`.

## Error handling

Errors are returned as RFC 7807 problem details (`application/problem+json`):

```json
{"detail":"Invalid time 'nonsense', expected format: yyyy-MM-dd HH:mm:ssZ","instance":"/api/timestamp/fixed-time","status":400,"title":"Bad Request"}
```

| Status | Meaning                                                                                              |
|--------|------------------------------------------------------------------------------------------------------|
| 400    | Invalid `time` value on `/custom` and `/fixed-time`.                                                 |
| 415    | Wrong `Content-Type` on the timestamp endpoints.                                                     |
| 500    | Anything else: invalid `TimeStampReq`, invalid PKCS12 file/password/alias on `update-key`, missing certificate. |

A timestamp *rejection* (for example an unsupported hash algorithm) is **not** an HTTP error: the server answers `200`
and the `TimeStampResp` carries the failure status.

## Docker

Two image flavors are available:

- **`Dockerfile`** (default): builds a GraalVM **native image**. Smaller, faster-starting container, but the build is slow
  and needs more memory.
- **`Dockerfile.jvm`**: builds a regular **JVM image** with a layered jar. Builds much faster and needs no GraalVM, at the
  cost of a slightly larger image and JVM startup time.

```bash
docker build -t timestamp-server .                         # native
docker build -f Dockerfile.jvm -t timestamp-server:jvm .   # JVM

docker run -p 8080:8080 timestamp-server
docker run -p 8080:8080 timestamp-server:jvm
```

The images run as a non-root user with the Spring profile `docker` (`SPRING_PROFILES_ACTIVE=docker`, which sets the
certificate subject to `CN=Docker Timestamp Authority, ...`) and a health check on `/actuator/health`.

### External configuration

Files in `/app/config/` take precedence over the classpath settings:

```bash
docker run -p 8080:8080 -v /path/to/your/config:/app/config timestamp-server
```

Custom `application-override.yml`:

```yaml
timestamp:
  certificate-subject: "CN=Production Timestamp Authority, O=My Company, C=HU"
  validity-days: 730
```

```bash
docker run -p 8080:8080 \
  -v $(pwd)/application-override.yml:/app/config/application-override.yml \
  -e SPRING_CONFIG_IMPORT=optional:file:/app/config/application-override.yml \
  timestamp-server
```

To keep the same signing certificate across container restarts, mount a PKCS12 file and set `TIMESTAMP_KEYSTORE_PATH`,
`TIMESTAMP_KEYSTORE_PASSWORD` and `TIMESTAMP_KEY_ALIAS`.

### Docker Compose

```bash
docker compose up -d                                       # native image (default)
docker compose --profile jvm up -d timestamp-server-jvm    # JVM image
docker compose logs -f
docker compose down
```

Defaults in `docker-compose.yml`: native image 256 MB memory limit (128 MB reserved), JVM image 512 MB (256 MB reserved),
1.0 CPU limit (0.25 reserved), read-only filesystem, `no-new-privileges`, health check every 30 s with 3 retries.

## Security considerations

This server is a **test tool**, so its defaults are open on purpose:

- No authentication: every endpoint, including `update-key` (which replaces the signing key) and the fixed time setter,
  is public. Do not expose it on an untrusted network.
- CSRF protection is disabled, sessions are stateless, CORS allows all origins and methods.
- The default signing certificate is self-signed and not trusted by anything; a fixed time makes the timestamps
  deliberately untrue. Timestamps from this server must never be used as evidence.
- Private keys and passwords are not logged. Spring Security logs a generated development password at startup that has
  no effect because all requests are permitted.

To add authentication, change the `SecurityFilterChain` bean in `TimestampServerApplication.java`.

## Native image

```bash
export JAVA_HOME=~/.jdks/graalvm-ce-25.0.2/     # GraalVM CE 25 with the native-image tool
export PATH=$JAVA_HOME/bin:$PATH
./mvnw -Pnative clean package
./target/timestamp-server
```

The native build uses resource auto-detection, a static executable and Spring AOT. Time-zone region ids
(`Europe/Budapest`) rely on the time-zone data of the runtime; verify them in the native image if you depend on them.

## Development and testing

### Project layout

```
src/main/java/com/digital/signature
├── TimestampServerApplication.java        entry point, security filter chain
├── config/       TimeStampConfig, WebConfig (CORS)
├── controller/   TimestampController, ErrorHandlerController
└── service/      TimestampService         timestamps, time parsing, fixed time, key handling
src/main/resources/static/index.html       the web UI
src/test/...                               unit, integration and Cucumber tests
```

### Build and quality commands

```bash
./mvnw clean verify          # compile, tests, Checkstyle, PMD
./mvnw test                  # tests only
./mvnw spotless:apply        # format (Google Java Format, AOSP style)
./mvnw spotless:check
```

SpotBugs, JaCoCo (report in `target/site/jacoco`) and PIT mutation testing are configured in `pom.xml` as well.

### Test types and rules

- **Unit tests** are plain JUnit 5 / Mockito / AssertJ tests that create the class directly
  (for example `new TimestampService(new TimeStampConfig())`), without a Spring context.
  `TimestampServiceCustomTimeTest` (time parsing, fixed time, custom time) and `TimestampControllerTest` are examples.
- **Always write both positive and negative unit tests** for every new or changed method: valid input and the expected
  result, plus invalid input, null/blank values and error paths. (This rule is also in `AGENTS.md`.)
- **Integration tests** use `@SpringBootTest`. They may be added on top of the unit tests but never replace them.
- **Cucumber (BDD) scenarios** in `src/test/resources/features/*.feature` start the application on a random port and
  call the real HTTP endpoints with genuine RFC 3161 requests. They are written as usage examples:
  - `timestamp.feature` – health, simple/unix time, certificate, standard timestamp request
  - `fixed-time-timestamp.feature` – set / read / clear the fixed time and stamp with it
  - `custom-time-timestamp.feature` – one-off custom time, time zones, errors

```bash
./mvnw test -Dtest=RunCucumberTest                          # only the Cucumber scenarios
./mvnw test -Dtest=TimestampServiceCustomTimeTest           # a single class
./mvnw test -Dtest=TimestampServiceUpdateKeyTest#testMethod  # a single method
```

The Cucumber HTML report is written to `target/cucumber-reports/cucumber.html`.

## Troubleshooting

| Symptom                                                                 | Likely cause and fix                                                                                         |
|-------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| The document shows the current time instead of the fixed time           | The application did not request a timestamp (signature level without timestamp, e.g. `PAdES_BASELINE_B`), or it calls another URL. Use the `-T` level and `http://host:port/api/timestamp`. Check the server log for `POST "/api/timestamp"` (with the `DispatcherServlet` DEBUG option). |
| The fixed time is gone                                                  | The server was restarted; the fixed time is kept in memory only. Set it again.                              |
| `400` on `fixed-time` or `custom`                                       | Invalid time. Use `yyyy-MM-dd HH:mm:ssZ`; abbreviations such as `CST` are ambiguous and rejected (use `+0800`-style offsets or a region id). |
| `+0200` becomes ` 0200` in a URL                                        | Encode `+` as `%2B` or use `curl --data-urlencode`.                                                          |
| Validator says the timestamp is "indeterminate" / "not verifiable"      | The self-signed TSA certificate is not trusted. Import it from `/api/timestamp/certificate` or use a fixed keystore. |
| Timestamp certificate changes at every restart                          | Expected with the generated key. Configure `timestamp.keystore-*` to keep one certificate.                   |
| `415 Unsupported Media Type`                                            | Send `Content-Type: application/timestamp-query`.                                                            |
| Response status is not `granted` although HTTP is `200`                 | The request was rejected as an RFC 3161 failure, e.g. an unsupported hash algorithm (allowed: SHA-1, SHA-256, SHA-512) or a different policy OID. |
| Server does not start after configuring a keystore                      | Wrong path, password or alias; the log shows the cause (`Failed to initialize TimestampService`).            |

## Contributing

1. Fork the repository
2. Create your feature branch
3. Add positive and negative unit tests, update this README when endpoints or behaviour change
4. Format your code with `./mvnw spotless:apply` and run `./mvnw clean verify`
5. Commit your changes
6. Push to the branch
7. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For issues and questions, please open an issue in the GitHub repository.

---
**Built with Spring Boot 4.1, Java 25 (GraalVM optional), BouncyCastle and Maven**
