package com.digital.signature;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.web.SecurityFilterChain;

@SpringBootTest
class TimestampServerApplicationTests {

    @Autowired private SecurityFilterChain securityFilterChain;

    @Test
    void contextLoads() {
        assertThat(true).isTrue();
    }

    @Test
    void securityFilterChain_shouldBeConfigured() {
        assertThat(securityFilterChain).isNotNull();
    }
}
