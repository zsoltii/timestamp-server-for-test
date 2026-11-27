Feature: Forwarding OCSP requests without issuer profile

  When forwarding is enabled (PUT /api/ocsp/forwarding or the OCSP tab of the web UI), a
  request whose certificates match none of the issuer profiles is sent to the configured
  OCSP responder URL and its answer is returned unchanged, as if this server had answered.
  Forwarding is off by default. Requests of a configured issuer are always answered locally.

  Background:
    Given the timestamp server is running
    And the OCSP simulated time is "2029-01-01T00:00:00Z"
    And OCSP CA "ca-a" with subject "CN=Local CA" is uploaded as profile "a"
    And an upstream OCSP responder answering "sigRequired"

  Scenario: By default a request without profile is unauthorized and not forwarded
    When I send an OCSP POST request for serial "01" issued by an unknown CA
    Then the OCSP response status is "unauthorized"
    And the upstream OCSP responder received 0 requests

  Scenario: An enabled forwarding returns the answer of the other responder
    Given OCSP forwarding is enabled to the upstream responder
    When I send an OCSP POST request for serial "01" issued by an unknown CA
    Then the OCSP response status is "sigRequired"
    And the upstream OCSP responder received 1 request

  Scenario: Certificates of a configured issuer are still answered locally
    Given OCSP forwarding is enabled to the upstream responder
    When I send an OCSP POST request for serial "7F" issued by OCSP CA "ca-a"
    Then the OCSP response status is "successful"
    And the upstream OCSP responder received 0 requests

  Scenario: A disabled forwarding keeps the URL but does not forward
    Given OCSP forwarding is disabled with the upstream URL kept
    When I send an OCSP POST request for serial "01" issued by an unknown CA
    Then the OCSP response status is "unauthorized"
    And the upstream OCSP responder received 0 requests

  Scenario: Forwarding to itself does not loop
    Given OCSP forwarding is enabled to this server's own responder
    When I send an OCSP POST request for serial "01" issued by an unknown CA
    Then the OCSP response status is "unauthorized"

  Scenario: Enabling forwarding requires a URL
    When I enable OCSP forwarding without URL
    Then the OCSP admin response status is 400
