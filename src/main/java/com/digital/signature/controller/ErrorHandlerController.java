package com.digital.signature.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
public class ErrorHandlerController extends ResponseEntityExceptionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(ErrorHandlerController.class);

    public ErrorHandlerController() {
        // Default constructor
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleGlobalException(final Exception exception) {
        if (LOGGER.isErrorEnabled()) {
            LOGGER.error("An unexpected error occurred: {}", exception.getMessage());
        }
        return ProblemDetail.forStatusAndDetail(
                HttpStatus.INTERNAL_SERVER_ERROR, exception.getMessage());
    }
}
