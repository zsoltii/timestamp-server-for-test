package com.digital.signature.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class OcspCustomPathTest {
    private final OcspService service = new OcspService();

    @Test
    void addsAndNormalizesPath() {
        assertThat(service.addCustomPath(" /ca/ocsp/ ")).isEqualTo("/ca/ocsp");
        assertThat(service.customPaths()).containsExactly("/ca/ocsp");
    }

    @Test
    void addingTheSamePathTwiceKeepsOneEntry() {
        service.addCustomPath("/ocsp");
        service.addCustomPath("/ocsp/");
        assertThat(service.customPaths()).containsExactly("/ocsp");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(
            strings = {
                " ",
                "/",
                "ocsp",
                "/a b",
                "/a//b",
                "/a/../b",
                "/a/./b",
                "/a?x=1",
                "/api",
                "/api/ocsp/responder",
                "/actuator/health",
                "/error"
            })
    void rejectsInvalidOrReservedPaths(final String path) {
        assertThatThrownBy(() -> service.addCustomPath(path))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(service.customPaths()).isEmpty();
    }

    @Test
    void removesRegisteredPathOnly() {
        service.addCustomPath("/ocsp");
        assertThat(service.removeCustomPath("/ocsp/")).isTrue();
        assertThat(service.removeCustomPath("/ocsp")).isFalse();
        assertThat(service.removeCustomPath(null)).isFalse();
    }

    @Test
    void matchesExactPathAndRemainder() {
        service.addCustomPath("/ca/ocsp");
        assertThat(service.customPathRemainder("/ca/ocsp")).isEmpty();
        assertThat(service.customPathRemainder("/ca/ocsp/")).isEmpty();
        assertThat(service.customPathRemainder("/ca/ocsp/MEUw%2F")).isEqualTo("MEUw%2F");
    }

    @Test
    void longestOverlappingPathWinsRegardlessOfRegistrationOrder() {
        service.addCustomPath("/ca");
        service.addCustomPath("/ca/ocsp");
        assertThat(service.customPathRemainder("/ca/ocsp/MEUw")).isEqualTo("MEUw");
        assertThat(service.customPathRemainder("/ca/ocsp")).isEmpty();
        assertThat(service.customPathRemainder("/ca/other")).isEqualTo("other");
    }

    @Test
    void shorterPathStillMatchesWhenLongerOneDoesNot() {
        service.addCustomPath("/ca/ocsp");
        service.addCustomPath("/ca");
        assertThat(service.customPathRemainder("/ca/ocspx")).isEqualTo("ocspx");
        assertThat(service.customPathRemainder("/cab")).isNull();
    }

    @Test
    void doesNotMatchOtherPaths() {
        service.addCustomPath("/ca/ocsp");
        assertThat(service.customPathRemainder("/ca/ocspx")).isNull();
        assertThat(service.customPathRemainder("/ca")).isNull();
        assertThat(service.customPathRemainder("/other")).isNull();
        assertThat(service.customPathRemainder(null)).isNull();
    }
}
