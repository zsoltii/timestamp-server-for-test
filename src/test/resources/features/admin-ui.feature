Feature: Admin web UI with separate tabs

  The admin page at "/" separates the settings of the two services into tabs, so each one is
  easy to manage on its own:
    - "Timestamp server": status, signing certificate, fixed time, custom time, signing key
    - "OCSP responder":   issuer profiles, simulated times, certificate statuses
  The selected tab can be opened directly with the URL fragment (#timestamp or #ocsp).

  Background:
    Given the timestamp server is running

  Scenario: The page offers a Timestamp server tab and an OCSP responder tab
    When I send a GET request to "/"
    Then the response status is 200
    And the response body contains "role=\"tablist\""
    And the response body contains "id=\"tab-btn-timestamp\""
    And the response body contains "id=\"tab-btn-ocsp\""

  Scenario Outline: Each service's settings are on its own tab
    When I send a GET request to "/"
    Then the response status is 200
    And the response body contains "id=\"<panel>\""
    And the response body contains "id=\"<form>\""

    Examples: panels and the forms they hold
      | panel         | form              |
      | tab-timestamp | fixed-time-form   |
      | tab-timestamp | update-key-form   |
      | tab-ocsp      | ocsp-profile-form |
      | tab-ocsp      | ocsp-status-form  |
