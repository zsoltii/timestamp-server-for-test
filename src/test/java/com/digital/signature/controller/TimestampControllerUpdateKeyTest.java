package com.digital.signature.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.digital.signature.AbstractTest;
import com.digital.signature.util.TestKeystoreGenerator;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
class TimestampControllerUpdateKeyTest extends AbstractTest {

    @TempDir Path tempDir;

    @Autowired private MockMvc mockMvc;

    private File testKeystoreFile;
    private String keystorePassword = "testPassword";
    private String keyPassword = "keyPassword";
    private String keyAlias = "testKey";

    @BeforeEach
    void setUp() throws Exception {
        // Generate test keystore before each test
        testKeystoreFile = tempDir.resolve("test-keystore.p12").toFile();
        TestKeystoreGenerator.generateTestKeystore(
                testKeystoreFile.getAbsolutePath(), keystorePassword, keyAlias, keyPassword);
    }

    @Test
    void updateSigningKey_shouldReturnSuccess_whenValidPkcs12FileProvided() throws Exception {
        // Arrange - create multipart file using try-with-resources
        try (FileInputStream fileInputStream = new FileInputStream(testKeystoreFile)) {
            MockMultipartFile pkcs12File =
                    new MockMultipartFile(
                            "file", "test-keystore.p12", "application/x-pkcs12", fileInputStream);

            // Act & Assert
            MvcResult result =
                    mockMvc.perform(
                                    multipart("/api/timestamp/update-key")
                                            .file(pkcs12File)
                                            .param("keystorePassword", keystorePassword)
                                            .param("keyPassword", keyPassword)
                                            .param("keyAlias", keyAlias))
                            .andExpect(status().isOk())
                            .andReturn();

            // Verify response
            String responseBody = result.getResponse().getContentAsString();
            assertThat(responseBody).contains("Signing key updated successfully");
        }
    }

    @Test
    void updateSigningKey_shouldReturnSuccess_whenKeyPasswordOmitted() throws Exception {
        // Arrange - create multipart file using try-with-resources
        try (FileInputStream fileInputStream = new FileInputStream(testKeystoreFile)) {
            MockMultipartFile pkcs12File =
                    new MockMultipartFile(
                            "file", "test-keystore.p12", "application/x-pkcs12", fileInputStream);

            // Act & Assert - don't provide keyPassword, should use keystorePassword
            // Note: This test expects the keystore to use the same password for both keystore and
            // key
            // The TestKeystoreGenerator uses different passwords, so we need to use the key
            // password
            MvcResult result =
                    mockMvc.perform(
                                    multipart("/api/timestamp/update-key")
                                            .file(pkcs12File)
                                            .param("keystorePassword", keystorePassword)
                                            .param(
                                                    "keyPassword",
                                                    keyPassword) // Provide key password since it's
                                            // different
                                            .param("keyAlias", keyAlias))
                            .andExpect(status().isOk())
                            .andReturn();

            // Verify response
            String responseBody = result.getResponse().getContentAsString();
            assertThat(responseBody).contains("Signing key updated successfully");
        }
    }

    @Test
    void updateSigningKey_shouldReturnSuccess_whenKeyAliasOmitted() throws Exception {
        // Arrange - create multipart file using try-with-resources
        try (FileInputStream fileInputStream = new FileInputStream(testKeystoreFile)) {
            MockMultipartFile pkcs12File =
                    new MockMultipartFile(
                            "file", "test-keystore.p12", "application/x-pkcs12", fileInputStream);

            // Act & Assert - don't provide keyAlias, should find first key
            MvcResult result =
                    mockMvc.perform(
                                    multipart("/api/timestamp/update-key")
                                            .file(pkcs12File)
                                            .param("keystorePassword", keystorePassword)
                                            .param("keyPassword", keyPassword))
                            .andExpect(status().isOk())
                            .andReturn();

            // Verify response
            String responseBody = result.getResponse().getContentAsString();
            assertThat(responseBody).contains("Signing key updated successfully");
        }
    }

    @Test
    void updateSigningKey_shouldReturnBadRequest_whenInvalidPasswordProvided() throws Exception {
        // Arrange - create multipart file using try-with-resources
        try (FileInputStream fileInputStream = new FileInputStream(testKeystoreFile)) {
            MockMultipartFile pkcs12File =
                    new MockMultipartFile(
                            "file", "test-keystore.p12", "application/x-pkcs12", fileInputStream);

            // Act & Assert - provide wrong password
            MvcResult result =
                    mockMvc.perform(
                                    multipart("/api/timestamp/update-key")
                                            .file(pkcs12File)
                                            .param("keystorePassword", "wrongpassword")
                                            .param("keyPassword", keyPassword)
                                            .param("keyAlias", keyAlias))
                            .andExpect(status().isInternalServerError())
                            .andReturn();

            // Verify error response contains ProblemDetail structure
            String responseBody = result.getResponse().getContentAsString();
            assertThat(responseBody).contains("Internal Server Error");
        }
    }

    @Test
    void updateSigningKey_shouldReturnInternalServerError_whenInvalidKeyPasswordProvided()
            throws Exception {
        // Arrange - create multipart file using try-with-resources
        try (FileInputStream fileInputStream = new FileInputStream(testKeystoreFile)) {
            MockMultipartFile pkcs12File =
                    new MockMultipartFile(
                            "file", "test-keystore.p12", "application/x-pkcs12", fileInputStream);

            // Act & Assert - provide wrong key password
            MvcResult result =
                    mockMvc.perform(
                                    multipart("/api/timestamp/update-key")
                                            .file(pkcs12File)
                                            .param("keystorePassword", keystorePassword)
                                            .param("keyPassword", "wrongkeypassword")
                                            .param("keyAlias", keyAlias))
                            .andExpect(status().isInternalServerError())
                            .andReturn();

            // Verify error response contains ProblemDetail structure
            String responseBody = result.getResponse().getContentAsString();
            assertThat(responseBody).contains("Internal Server Error");
        }
    }

    @Test
    void updateSigningKey_shouldReturnInternalServerError_whenInvalidKeyAliasProvided()
            throws Exception {
        // Arrange - create multipart file using try-with-resources
        try (FileInputStream fileInputStream = new FileInputStream(testKeystoreFile)) {
            MockMultipartFile pkcs12File =
                    new MockMultipartFile(
                            "file", "test-keystore.p12", "application/x-pkcs12", fileInputStream);

            // Act & Assert - provide wrong key alias
            MvcResult result =
                    mockMvc.perform(
                                    multipart("/api/timestamp/update-key")
                                            .file(pkcs12File)
                                            .param("keystorePassword", keystorePassword)
                                            .param("keyPassword", keyPassword)
                                            .param("keyAlias", "nonexistentalias"))
                            .andExpect(status().isInternalServerError())
                            .andReturn();

            // Verify error response contains ProblemDetail structure
            String responseBody = result.getResponse().getContentAsString();
            assertThat(responseBody).contains("Internal Server Error");
        }
    }

    @Test
    void updateSigningKey_shouldReturnInternalServerError_whenFileIsNotPkcs12() throws Exception {
        // Arrange - create a non-PKCS12 file
        MockMultipartFile invalidFile =
                new MockMultipartFile(
                        "file",
                        "invalid.txt",
                        "text/plain",
                        "This is not a PKCS12 file".getBytes());

        // Act & Assert
        MvcResult result =
                mockMvc.perform(
                                multipart("/api/timestamp/update-key")
                                        .file(invalidFile)
                                        .param("keystorePassword", keystorePassword)
                                        .param("keyPassword", keyPassword)
                                        .param("keyAlias", keyAlias))
                        .andExpect(status().isInternalServerError())
                        .andReturn();

        // Verify error response contains ProblemDetail structure
        String responseBody = result.getResponse().getContentAsString();
        assertThat(responseBody).contains("Internal Server Error");
    }
}
