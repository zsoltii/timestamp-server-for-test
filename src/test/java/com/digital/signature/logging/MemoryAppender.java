package com.digital.signature.logging;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** In-memory appender for testing purposes. */
public class MemoryAppender extends AppenderBase<ILoggingEvent> {

    private final List<ILoggingEvent> list = new ArrayList<>();

    @Override
    protected void append(ILoggingEvent eventObject) {
        list.add(eventObject);
    }

    public void clear() {
        list.clear();
    }

    public List<ILoggingEvent> getLoggedEvents() {
        return Collections.unmodifiableList(list);
    }
}
