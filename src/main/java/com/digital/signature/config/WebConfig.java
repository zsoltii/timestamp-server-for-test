package com.digital.signature.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    public WebConfig() {
        // Default constructor
    }

    @Override
    public void addCorsMappings(final CorsRegistry registry) {
        registry.addMapping("/**").allowedOrigins("*").allowedMethods("*").maxAge(3600);
    }
}
