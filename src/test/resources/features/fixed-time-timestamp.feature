Feature: Fixed time for every timestamp

  The server can be told to use one given time for all timestamps. After that a completely
  standard RFC 3161 request (POST /api/timestamp, Content-Type: application/timestamp-query,
  no extra fields) is answered with a timestamp carrying the configured time, which can be in
  the past or in the future.

  The time is configured with:
    PUT    /api/timestamp/fixed-time?time=yyyy-MM-dd HH:mm:ssZ    (also available on the web UI)
    GET    /api/timestamp/fixed-time                              (204 when not set)
    DELETE /api/timestamp/fixed-time                              (back to the current time)

  Time format: yyyy-MM-dd HH:mm:ssZ
    - Z is a zone: an offset (Z, +0200, +02:00), an abbreviation (UTC, GMT, CET, CEST, EET, EEST,
      WET, WEST) or a region id (Europe/Budapest)
    - without a zone the time is UTC
    - an empty time clears the setting, the current time is used

  Background:
    Given the timestamp server is running

  Scenario Outline: A standard timestamp request gets the configured time
    When I set the fixed time to "<time>"
    Then the response status is 200
    And the response body is "<time in UTC>"
    When I send an RFC 3161 timestamp request for the text "hello world"
    Then the response status is 200
    And the timestamp response is granted
    And the timestamp token matches the digest of "hello world"
    And the timestamp token time is "<time in UTC>"

    Examples: past, future and zones
      | time                      | time in UTC          |
      | 2001-09-09 01:46:40       | 2001-09-09T01:46:40Z |
      | 2099-12-31 23:59:59       | 2099-12-31T23:59:59Z |
      | 2020-01-31 14:30:00+0200  | 2020-01-31T12:30:00Z |
      | 2020-01-31 14:30:00-05:30 | 2020-01-31T20:00:00Z |
      | 2026-11-01T12:34:56CEST   | 2026-11-01T10:34:56Z |
      | 2026-11-01 12:34:56 CET   | 2026-11-01T11:34:56Z |
      | 2026-07-15 12:00:00Europe/Budapest | 2026-07-15T10:00:00Z |

  Scenario: Every timestamp gets the same configured time
    Given I set the fixed time to "2001-09-09 01:46:40"
    When I send an RFC 3161 timestamp request for the text "first"
    Then the timestamp token time is "2001-09-09T01:46:40Z"
    When I send an RFC 3161 timestamp request for the text "second"
    Then the timestamp token time is "2001-09-09T01:46:40Z"

  Scenario: The configured time can be read back
    Given I set the fixed time to "2001-09-09 01:46:40"
    When I send a GET request to "/api/timestamp/fixed-time"
    Then the response status is 200
    And the response body is "2001-09-09T01:46:40Z"

  Scenario: Without a configured time the current time is used
    When I send a GET request to "/api/timestamp/fixed-time"
    Then the response status is 204
    When I send an RFC 3161 timestamp request for the text "hello world"
    Then the timestamp token time is within 60 seconds of now

  Scenario Outline: Clearing the fixed time brings back the current time
    Given I set the fixed time to "2001-09-09 01:46:40"
    When I <clear action>
    Then the response status is 204
    When I send an RFC 3161 timestamp request for the text "hello world"
    Then the timestamp token time is within 60 seconds of now

    Examples: ways to clear
      | clear action                |
      | set the fixed time to ""    |
      | clear the fixed time        |

  Scenario: An unknown time zone is rejected
    When I set the fixed time to "2026-11-01 12:34:56XYZ"
    Then the response status is 400

  Scenario: An invalid time is rejected and the previous setting is kept
    Given I set the fixed time to "2001-09-09 01:46:40"
    When I set the fixed time to "not a time"
    Then the response status is 400
    When I send an RFC 3161 timestamp request for the text "hello world"
    Then the timestamp token time is "2001-09-09T01:46:40Z"

  Scenario: The web UI offers the fixed time form
    When I send a GET request to "/"
    Then the response status is 200
    And the response body contains "fixed-time-form"
