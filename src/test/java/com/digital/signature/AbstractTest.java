package com.digital.signature;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import com.digital.signature.logging.MemoryAppender;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.LoggerFactory;

/**
 * Abstract base class for all tests that provides common test infrastructure. Automatically clears
 * the MemoryAppender before and after each test method.
 */
public abstract class AbstractTest {

    @BeforeEach
    void setUpAbstract() {
        clearMemoryAppender();
    }

    @AfterEach
    void tearDownAbstract() {
        clearMemoryAppender();
    }

    /**
     * Gets the MemoryAppender from the Logback configuration.
     *
     * @return the MemoryAppender instance, or null if not found
     */
    protected MemoryAppender getMemoryAppender() {
        LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
        Logger rootLogger = loggerContext.getLogger(Logger.ROOT_LOGGER_NAME);

        java.util.Iterator<Appender<ILoggingEvent>> it = rootLogger.iteratorForAppenders();
        while (it.hasNext()) {
            Appender<ILoggingEvent> appender = it.next();
            if (appender instanceof MemoryAppender) {
                return (MemoryAppender) appender;
            }
        }
        return null;
    }

    /** Clears the memory appender manually if needed during a test. */
    protected void clearMemoryAppender() {
        MemoryAppender appender = getMemoryAppender();
        if (appender != null) {
            appender.clear();
        }
    }

    /**
     * Gets the logged events from the memory appender.
     *
     * @return list of logged events
     */
    protected List<ILoggingEvent> getLoggedEvents() {
        MemoryAppender appender = getMemoryAppender();
        if (appender != null) {
            return appender.getLoggedEvents();
        }
        return Collections.emptyList();
    }
}
