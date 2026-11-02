package com.digital.signature.cucumber.steps;

import com.digital.signature.TimestampServerApplication;
import io.cucumber.spring.CucumberContextConfiguration;
import org.springframework.boot.test.context.SpringBootTest;

/** Starts the application on a random port once and shares it with all step definitions. */
@CucumberContextConfiguration
@SpringBootTest(
        classes = TimestampServerApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class CucumberSpringConfiguration {}
