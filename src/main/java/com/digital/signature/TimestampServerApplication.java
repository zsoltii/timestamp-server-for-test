package com.digital.signature;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@SpringBootApplication
public class TimestampServerApplication {

    public static void main(final String[] args) {
        SpringApplication.run(TimestampServerApplication.class, args);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http)
            throws java.io.IOException {
        http.sessionManagement(
                        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(
                        auth ->
                                auth.requestMatchers("/actuator/**")
                                        .permitAll()
                                        .anyRequest()
                                        .permitAll())
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }
}
