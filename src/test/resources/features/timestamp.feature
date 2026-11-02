Feature: Timestamp server API

  Background:
    Given the timestamp server is running

  Scenario: Health check reports that the server is up
    When I send a GET request to "/api/timestamp/health"
    Then the response status is 200
    And the response body is not empty

  Scenario: Simple timestamp is returned in ISO-8601 format
    When I send a GET request to "/api/timestamp/simple"
    Then the response status is 200
    And the response body is a valid ISO-8601 instant

  Scenario: Unix timestamp is close to the current time
    When I send a GET request to "/api/timestamp/unix"
    Then the response status is 200
    And the response body is a unix time within 60 seconds of now

  Scenario: Signing certificate is available in PEM format
    When I send a GET request to "/api/timestamp/certificate/pem"
    Then the response status is 200
    And the response body contains "BEGIN CERTIFICATE"

  Scenario Outline: RFC 3161 timestamp request is answered with a granted response
    When I send an RFC 3161 timestamp request for the text "<text>"
    Then the response status is 200
    And the timestamp response is granted
    And the timestamp token matches the digest of "<text>"

    Examples:
      | text                 |
      | hello world          |
      | árvíztűrő tükörfúrógép |
