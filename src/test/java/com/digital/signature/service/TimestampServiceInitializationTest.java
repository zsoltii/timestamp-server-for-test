package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.digital.signature.TimestampServerApplication;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.UnsatisfiedDependencyException;
import org.springframework.boot.SpringApplication;

class TimestampServiceInitializationTest {

    @Test
    void init_shouldThrowIllegalStateException_whenKeyPairGeneratorFails() {
        // Arrange: Mock the static KeyPairGenerator.getInstance to throw an exception
        try (MockedStatic<KeyPairGenerator> mocked = Mockito.mockStatic(KeyPairGenerator.class)) {
            mocked.when(() -> KeyPairGenerator.getInstance("RSA"))
                    .thenThrow(
                            new NoSuchAlgorithmException("Test failure: RSA algorithm not found"));

            // Act & Assert: Check if the Spring application context fails to load
            assertThatThrownBy(() -> SpringApplication.run(TimestampServerApplication.class))
                    // The top-level exception is UnsatisfiedDependencyException because
                    // TimestampController depends on TimestampService
                    .isInstanceOf(UnsatisfiedDependencyException.class)
                    // The cause is the failure to create the TimestampService bean
                    .getCause()
                    // This cause is our specific IllegalStateException from the init() method
                    .getCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Failed to initialize TimestampService")
                    // And the root cause is the mocked NoSuchAlgorithmException
                    .getCause()
                    .isInstanceOf(NoSuchAlgorithmException.class);
        }
    }
}
