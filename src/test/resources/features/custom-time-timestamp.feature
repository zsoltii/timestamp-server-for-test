Feature: Timestamp with a custom time

  A timestamp can be created for a time in the past or in the future, which is useful for testing
  how signature validators treat old or not yet valid timestamps.

  The client sends a normal RFC 3161 request (Content-Type: application/timestamp-query) to
  POST /api/timestamp/custom and passes the wanted time in the optional "time" query parameter.

  Time format: yyyy-MM-dd HH:mm:ssZ
    - Z is a zone: an offset (Z, +0200, +02:00), an abbreviation (UTC, GMT, CET, CEST, EET, EEST,
      WET, WEST) or a region id (Europe/Budapest)
    - without a zone the time is UTC
    - without the time parameter the current time is used

  Background:
    Given the timestamp server is running

  Scenario Outline: A time in the past or in the future is written into the timestamp
    When I send an RFC 3161 timestamp request for the text "hello world" with time "<time>"
    Then the response status is 200
    And the timestamp response is granted
    And the timestamp token matches the digest of "hello world"
    And the timestamp token time is "<token time in UTC>"

    Examples: past and future
      | time                | token time in UTC    |
      | 2001-09-09 01:46:40 | 2001-09-09T01:46:40Z |
      | 1999-12-31 23:59:59 | 1999-12-31T23:59:59Z |
      | 2099-12-31 23:59:59 | 2099-12-31T23:59:59Z |

  Scenario Outline: The zone of the time is taken into account, UTC is the default
    When I send an RFC 3161 timestamp request for the text "hello world" with time "<time>"
    Then the response status is 200
    And the timestamp token time is "<token time in UTC>"

    Examples: zones
      | time                       | token time in UTC    |
      | 2020-01-31 14:30:00        | 2020-01-31T14:30:00Z |
      | 2020-01-31 14:30:00Z       | 2020-01-31T14:30:00Z |
      | 2020-01-31 14:30:00+0200   | 2020-01-31T12:30:00Z |
      | 2020-01-31 14:30:00+02:00  | 2020-01-31T12:30:00Z |
      | 2020-01-31 14:30:00-0530   | 2020-01-31T20:00:00Z |
      | 2026-11-01T12:34:56CEST       | 2026-11-01T10:34:56Z |
      | 2026-11-01 12:34:56 CET       | 2026-11-01T11:34:56Z |
      | 2026-11-01 12:34:56UTC        | 2026-11-01T12:34:56Z |
      | 2026-01-15 12:00:00Europe/Budapest | 2026-01-15T11:00:00Z |
      | 2026-07-15 12:00:00Europe/Budapest | 2026-07-15T10:00:00Z |

  Scenario: The used time is returned in the X-Timestamp-Time header
    When I send an RFC 3161 timestamp request for the text "hello world" with time "2020-01-31 14:30:00+0200"
    Then the response status is 200
    And the response header "X-Timestamp-Time" is "2020-01-31T12:30:00Z"

  Scenario: Without the time parameter the current time is used
    When I send an RFC 3161 timestamp request for the text "hello world" with time ""
    Then the response status is 200
    And the timestamp response is granted
    And the timestamp token time is within 60 seconds of now

  Scenario Outline: An invalid time is rejected
    When I send an RFC 3161 timestamp request for the text "hello world" with time "<time>"
    Then the response status is 400

    Examples: invalid times
      | time                |
      | not a time          |
      | 2020-01-31          |
      | 2020-02-30 10:00:00 |
      | 2020-01-31 25:00:00 |
      | 2020-01-31 10:00:00XYZ |
      | 2020-01-31 10:00:00CST |

  Scenario: The web UI offers the custom time form
    When I send a GET request to "/"
    Then the response status is 200
    And the response body contains "custom-time-form"
