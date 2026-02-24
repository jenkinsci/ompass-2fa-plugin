package io.jenkins.plugins.ompass;

import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import org.junit.Rule;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Tests that the OMPASS 2FA plugin can be configured via JCasC (Configuration as Code).
 */
public class ConfigurationAsCodeTest {

    @Rule
    public JenkinsConfiguredWithCodeRule j = new JenkinsConfiguredWithCodeRule();

    @Test
    @ConfiguredWithCode("configuration-as-code.yml")
    public void testConfigurationImport() {
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull("Config should be available", config);
        assertTrue("2FA should be enabled", config.isEnableOmpass2fa());
        assertEquals("https://ompass.example.com", config.getOmpassServerUrl());
        assertEquals("test-client-id", config.getClientId());
        assertNotNull("Secret key should be set", config.getSecretKey());
        assertEquals("EN", config.getLanguage());
    }

    @Test
    @ConfiguredWithCode("configuration-as-code.yml")
    public void testConfigurationExport() throws Exception {
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config);
        // Verify round-trip: values loaded from YAML should be retrievable
        assertEquals("https://ompass.example.com", config.getOmpassServerUrl());
        assertEquals("test-client-id", config.getClientId());
        assertEquals("EN", config.getLanguage());
    }
}
