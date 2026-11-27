Feature: OCSP responder on custom URL paths

  Certificates contain a fixed OCSP URL path. To simulate it, extra paths can be registered
  (admin UI or POST /api/ocsp/paths); the responder then answers on them like on
  /api/ocsp/responder, with both GET and POST.

  Background:
    Given the timestamp server is running
    And the OCSP simulated time is "2029-01-01T00:00:00Z"
    And OCSP CA "ca-a" with subject "CN=Path CA" is uploaded as profile "a"

  Scenario Outline: A registered custom path serves OCSP requests
    Given the OCSP custom path "/ca/ocsp" is registered
    When I send an OCSP <method> request for serial "7F" issued by OCSP CA "ca-a" on path "/ca/ocsp"
    Then the OCSP response status is "successful"
    And the OCSP certificate status is "GOOD"

    Examples:
      | method |
      | POST   |
      | GET    |

  Scenario: With overlapping paths the longest one serves GET requests
    Given the OCSP custom path "/ca" is registered
    And the OCSP custom path "/ca/ocsp" is registered
    When I send an OCSP GET request for serial "7F" issued by OCSP CA "ca-a" on path "/ca/ocsp"
    Then the OCSP response status is "successful"
    And the OCSP certificate status is "GOOD"

  Scenario: A custom path uses the profile statuses
    Given the OCSP custom path "/ocsp" is registered
    And certificate serial "11" of OCSP profile "a" is REVOKED at "2028-06-01T00:00:00Z" with reason 1
    When I send an OCSP POST request for serial "11" issued by OCSP CA "ca-a" on path "/ocsp"
    Then the OCSP certificate status is "REVOKED"

  Scenario Outline: Reserved or malformed paths are rejected
    When I register the OCSP custom path "<path>"
    Then the OCSP admin response status is 400

    Examples:
      | path        |
      | /api/ocsp   |
      | /actuator   |
      | /           |
      | no-slash    |
      | /with space |
