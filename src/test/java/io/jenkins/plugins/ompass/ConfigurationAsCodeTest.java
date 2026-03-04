package io.jenkins.plugins.ompass;

import io.jenkins.plugins.casc.ConfigurationAsCode;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that the OMPASS 2FA plugin can be configured via JCasC (Configuration as Code).
 */
@WithJenkins
public class ConfigurationAsCodeTest {

    private void applyJCascConfig() throws Exception {
        String resource = getClass().getResource("configuration-as-code.yml").toExternalForm();
        ConfigurationAsCode.get().configure(resource);
    }

    @Test
    public void testConfigurationImport(JenkinsRule j) throws Exception {
        applyJCascConfig();

        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config, "Config should be available");
        assertTrue(config.isEnableOmpass2fa(), "2FA should be enabled");
        assertEquals("https://ompass.example.com", config.getOmpassServerUrl());
        assertEquals("test-client-id", config.getClientId());
        assertNotNull(config.getSecretKey(), "Secret key should be set");
        assertEquals("EN", config.getLanguage());
    }

    @Test
    public void testConfigurationExport(JenkinsRule j) throws Exception {
        applyJCascConfig();

        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config);
        // Verify round-trip: values loaded from YAML should be retrievable
        assertEquals("https://ompass.example.com", config.getOmpassServerUrl());
        assertEquals("test-client-id", config.getClientId());
        assertEquals("EN", config.getLanguage());
    }
}
