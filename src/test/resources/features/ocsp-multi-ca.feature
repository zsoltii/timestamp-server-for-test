Feature: OCSP responder serving multiple CAs

  One OCSP responder URL serves every configured CA:
    POST /api/ocsp/responder                    (Content-Type: application/ocsp-request)
    GET  /api/ocsp/responder/{url-encoded base64 request}

  The CertID of the request (issuer name hash and issuer key hash) selects the CA profile, so
  the AIA OCSP URL of every test CA can point to the same address. A CA is identified by its
  subject name and public key: a renewed CA certificate with the same name and key is the same
  CA, while two CAs with the same name but different keys are separate CAs. One request may
  ask about several certificates of the same CA; a request mixing CAs is unauthorized.

  Background:
    Given the timestamp server is running
    And the OCSP simulated time is "2029-01-01T00:00:00Z"

  Scenario Outline: Two CAs with the same name keep separate statuses
    Given OCSP CA "ca-a" with subject "CN=Test CA" is uploaded as profile "a"
    And OCSP CA "ca-b" with subject "CN=Test CA" is uploaded as profile "b"
    And certificate serial "1A" of OCSP profile "a" is GOOD
    And certificate serial "1A" of OCSP profile "b" is REVOKED at "2028-06-01T00:00:00Z" with reason 1
    When I send an OCSP <method> request for serial "1A" issued by OCSP CA "ca-a"
    Then the OCSP response status is "successful"
    And the OCSP certificate status is "GOOD"
    And the OCSP response is signed by the signer of OCSP CA "ca-a"
    When I send an OCSP <method> request for serial "1A" issued by OCSP CA "ca-b"
    Then the OCSP response status is "successful"
    And the OCSP certificate status is "REVOKED"
    And the OCSP response is signed by the signer of OCSP CA "ca-b"

    Examples:
      | method |
      | POST   |
      | GET    |

  Scenario Outline: Any supported CertID hash selects the right profile
    Given OCSP CA "ca-a" with subject "CN=Hash CA A" is uploaded as profile "a"
    And OCSP CA "ca-b" with subject "CN=Hash CA B" is uploaded as profile "b"
    When I send an OCSP POST request for serial "01" issued by OCSP CA "ca-b" using "<hash>"
    Then the OCSP response status is "successful"
    And the OCSP response is signed by the signer of OCSP CA "ca-b"

    Examples:
      | hash    |
      | SHA-1   |
      | SHA-256 |
      | SHA-512 |

  Scenario: Several certificates of the same CA in one request
    Given OCSP CA "ca-a" with subject "CN=Batch CA" is uploaded as profile "a"
    When I send an OCSP POST request for serials "01" and "02" issued by OCSP CA "ca-a"
    Then the OCSP response status is "successful"
    And the OCSP response contains 2 certificate statuses

  Scenario: Mixed and unknown issuers are unauthorized
    Given OCSP CA "ca-a" with subject "CN=Mixed CA A" is uploaded as profile "a"
    And OCSP CA "ca-b" with subject "CN=Mixed CA B" is uploaded as profile "b"
    When I send an OCSP POST request for serial "01" issued by OCSP CA "ca-a" and serial "02" issued by OCSP CA "ca-b"
    Then the OCSP response status is "unauthorized"
    When I send an OCSP POST request for serial "01" issued by an unknown CA
    Then the OCSP response status is "unauthorized"

  Scenario: The same CA identity cannot be uploaded under a second profile ID
    Given OCSP CA "ca-a" with subject "CN=Renewed CA" is uploaded as profile "a"
    When OCSP CA "ca-a" renewed with the same name and key is uploaded as profile "a2"
    Then the OCSP admin response status is 400
    And the OCSP admin response body contains "Issuer already has a profile: a"
    And the OCSP profile list contains only "a"

  Scenario: Renewing a CA under the same profile ID keeps its statuses
    Given OCSP CA "ca-a" with subject "CN=Renewed CA" is uploaded as profile "a"
    And certificate serial "1A" of OCSP profile "a" is GOOD
    When OCSP CA "ca-a" renewed with the same name and key is uploaded as profile "a"
    Then the OCSP admin response status is 204
    And OCSP profile "a" has 1 configured statuses
    When I send an OCSP POST request for serial "1A" issued by OCSP CA "ca-a"
    Then the OCSP certificate status is "GOOD"

  Scenario: Replacing a profile with a different CA clears its statuses
    Given OCSP CA "ca-a" with subject "CN=First CA" is uploaded as profile "a"
    And certificate serial "1A" of OCSP profile "a" is GOOD
    When OCSP CA "ca-b" with subject "CN=Second CA" is uploaded as profile "a"
    Then OCSP profile "a" has 0 configured statuses

  Scenario: A CA already served by another profile cannot replace a profile
    Given OCSP CA "ca-a" with subject "CN=First CA" is uploaded as profile "a"
    And OCSP CA "ca-b" with subject "CN=Second CA" is uploaded as profile "b"
    When OCSP CA "ca-b" is uploaded as profile "a"
    Then the OCSP admin response status is 400
    And the OCSP admin response body contains "Issuer already has a profile: b"

  Scenario: A failed renewal keeps the previous profile working
    Given OCSP CA "ca-a" with subject "CN=Direct CA" signing directly is uploaded as profile "a"
    When OCSP CA "ca-a" renewed with the old CA certificate in the PKCS12 is uploaded as profile "a"
    Then the OCSP admin response status is 400
    And the OCSP admin response body contains "PKCS12 certificate does not match"
    When I send an OCSP POST request for serial "01" issued by OCSP CA "ca-a"
    Then the OCSP response status is "successful"
    And the OCSP response is signed by the signer of OCSP CA "ca-a"

  Scenario: An expired CA does not affect the other CA
    Given OCSP CA "ca-a" with subject "CN=Expired CA" valid until "2028-12-31T00:00:00Z" is uploaded as profile "a"
    And OCSP CA "ca-b" with subject "CN=Valid CA" is uploaded as profile "b"
    When I send an OCSP POST request for serial "01" issued by OCSP CA "ca-a"
    Then the OCSP response status is "internalError"
    When I send an OCSP POST request for serial "01" issued by OCSP CA "ca-b"
    Then the OCSP response status is "successful"
