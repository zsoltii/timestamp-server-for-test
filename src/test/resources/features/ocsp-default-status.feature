Feature: OCSP responder default status (blacklist)

  The OCSP responder works as a blacklist. A certificate of a configured issuer is GOOD unless
  it is explicitly listed otherwise, so nothing has to be configured to get GOOD answers.
  Only the certificates that should fail are configured:
    PUT /api/ocsp/profiles/{id}/statuses/{serial}   {"status":"REVOKED", ...}
  An explicit UNKNOWN status is still available for testing the "unknown" answer, and removing a
  configured status brings back the GOOD default. Requests for an unconfigured issuer stay
  unauthorized.

  Background:
    Given the timestamp server is running
    And the OCSP simulated time is "2029-01-01T00:00:00Z"

  Scenario: Without any configured status every certificate is GOOD
    Given OCSP CA "ca-a" with subject "CN=Blacklist CA" is uploaded as profile "a"
    When I send an OCSP POST request for serial "7F" issued by OCSP CA "ca-a"
    Then the OCSP response status is "successful"
    And the OCSP certificate status is "GOOD"
    And OCSP profile "a" has 0 configured statuses

  Scenario: Only the listed certificate is revoked
    Given OCSP CA "ca-a" with subject "CN=Blacklist CA" is uploaded as profile "a"
    And certificate serial "11" of OCSP profile "a" is REVOKED at "2028-06-01T00:00:00Z" with reason 1
    When I send an OCSP POST request for serials "11" and "12" issued by OCSP CA "ca-a"
    Then the OCSP response status is "successful"
    And the OCSP certificate status of response 1 is "REVOKED"
    And the OCSP certificate status of response 2 is "GOOD"

  Scenario: An explicit UNKNOWN status overrides the GOOD default
    Given OCSP CA "ca-a" with subject "CN=Blacklist CA" is uploaded as profile "a"
    And certificate serial "20" of OCSP profile "a" is UNKNOWN
    When I send an OCSP POST request for serial "20" issued by OCSP CA "ca-a"
    Then the OCSP certificate status is "UNKNOWN"

  Scenario: Removing a revoked status brings back the GOOD default
    Given OCSP CA "ca-a" with subject "CN=Blacklist CA" is uploaded as profile "a"
    And certificate serial "30" of OCSP profile "a" is REVOKED at "2028-06-01T00:00:00Z" with reason 1
    When the configured status of serial "30" of OCSP profile "a" is removed
    Then the OCSP admin response status is 204
    When I send an OCSP POST request for serial "30" issued by OCSP CA "ca-a"
    Then the OCSP certificate status is "GOOD"

  Scenario: The default is per issuer, an unconfigured CA is still unauthorized
    Given OCSP CA "ca-a" with subject "CN=Blacklist CA" is uploaded as profile "a"
    When I send an OCSP POST request for serial "01" issued by an unknown CA
    Then the OCSP response status is "unauthorized"
