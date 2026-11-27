package com.digital.signature.controller;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.digital.signature.service.OcspService;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.HttpMediaTypeNotSupportedException;

class OcspControllerLoggingTest {
    private final Logger logger = (Logger) LoggerFactory.getLogger(OcspController.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    private final OcspController controller = new OcspController(new OcspService());

    @BeforeEach
    void setUp() {
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        logger.detachAppender(appender);
    }

    private List<String> warnings() {
        return appender.list.stream()
                .filter(e -> e.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
    }

    @Test
    void rejectedAdminCallIsLoggedWithMethodUriAndReason() {
        final MockHttpServletRequest request =
                new MockHttpServletRequest("PUT", "/api/ocsp/profiles/a/statuses/zz");

        final ProblemDetail problem =
                controller.badRequest(
                        new IllegalArgumentException("Serial number must be hexadecimal"), request);

        assertThat(problem.getStatus()).isEqualTo(400);
        assertThat(warnings())
                .singleElement()
                .asString()
                .contains("PUT /api/ocsp/profiles/a/statuses/zz", "HTTP 400", "hexadecimal");
    }

    @Test
    void wrongContentTypeIsLoggedAs415() {
        final MockHttpServletRequest request =
                new MockHttpServletRequest("POST", "/api/ocsp/responder");

        final ProblemDetail problem =
                controller.unsupportedMediaType(
                        new HttpMediaTypeNotSupportedException(
                                MediaType.TEXT_PLAIN, List.of(MediaType.APPLICATION_JSON)),
                        request);

        assertThat(problem.getStatus()).isEqualTo(415);
        assertThat(warnings())
                .singleElement()
                .asString()
                .contains("POST /api/ocsp/responder", "HTTP 415");
    }

    @Test
    void invalidGetEncodingIsLogged() {
        assertThat(OcspController.decodeGetRequest("not-base64!")).isNull();
        assertThat(warnings()).singleElement().asString().contains("not URL-encoded base64");
    }

    @Test
    void validGetEncodingLogsNoWarning() {
        assertThat(OcspController.decodeGetRequest("AQID")).containsExactly(1, 2, 3);
        assertThat(warnings()).isEmpty();
    }
}
