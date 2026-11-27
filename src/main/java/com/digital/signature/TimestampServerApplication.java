package com.digital.signature;

import com.digital.signature.service.OcspService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;

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

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> ocspEncodedSlash() {
        return factory ->
                factory.addConnectorCustomizers(
                        connector -> connector.setEncodedSolidusHandling("passthrough"));
    }

    @Bean
    public WebSecurityCustomizer ocspFirewall(
            final ObjectProvider<OcspService> ocspServiceProvider) {
        final StrictHttpFirewall standard = new StrictHttpFirewall();
        final StrictHttpFirewall ocsp = new StrictHttpFirewall();
        ocsp.setAllowUrlEncodedSlash(true);
        ocsp.setAllowUrlEncodedDoubleSlash(true);
        ocsp.setAllowUrlEncodedPercent(true);
        final HttpFirewall firewall =
                new HttpFirewall() {
                    @Override
                    public FirewalledRequest getFirewalledRequest(
                            final HttpServletRequest request) {
                        final String uri = request.getRequestURI();
                        final String prefix = request.getContextPath() + "/api/ocsp/responder/";
                        final OcspService ocspService = ocspServiceProvider.getIfAvailable();
                        final boolean customPath =
                                ocspService != null
                                        && ocspService.customPathRemainder(
                                                        uri.substring(
                                                                request.getContextPath().length()))
                                                != null;
                        final boolean ocspGet =
                                "GET".equals(request.getMethod())
                                        && (uri.startsWith(prefix) || customPath);
                        return (ocspGet ? ocsp : standard).getFirewalledRequest(request);
                    }

                    @Override
                    public HttpServletResponse getFirewalledResponse(
                            final HttpServletResponse response) {
                        return standard.getFirewalledResponse(response);
                    }
                };
        return web -> web.httpFirewall(firewall);
    }
}
