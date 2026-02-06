package com.digital.signature.controller;

import com.digital.signature.service.TimestampService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(TimestampController.class)
class ErrorHandlerControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private TimestampService timestampService;

    @Test
    void handleTimestampQuery_shouldReturnInternalServerError_whenServiceThrowsException() throws Exception {
        // Arrange
        when(timestampService.generateTimestampResponse(any())).thenThrow(new RuntimeException("Test exception"));

        // Act & Assert
        mockMvc.perform(post("/api/timestamp")
                .contentType("application/timestamp-query")
                .content(new byte[]{1, 2, 3}))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.title").value("Internal Server Error"))
                .andExpect(jsonPath("$.detail").value("Test exception"));
    }
}
