package com.digital.signature;

import static org.assertj.core.api.Assertions.assertThat;

import com.digital.signature.service.TimestampService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.SecurityFilterChain;

@SpringBootTest
class TimestampServerApplicationTests extends AbstractTest {

    @Autowired private ApplicationContext context;

    @Autowired private SecurityFilterChain securityFilterChain;

    @Test
    void contextLoads() {
        assertThat(context.getBean(TimestampService.class)).isNotNull();
    }

    @Test
    void securityFilterChain_shouldBeConfigured() {
        assertThat(securityFilterChain).isNotNull();
    }

    @Test
    void securityFilterChain_shouldHaveFiltersConfigured() {
        // This test kills the NullReturnValsMutator by actually using the filter chain
        assertThat(securityFilterChain.getFilters()).isNotEmpty();
    }
}
