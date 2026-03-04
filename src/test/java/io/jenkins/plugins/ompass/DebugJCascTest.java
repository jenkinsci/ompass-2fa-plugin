package io.jenkins.plugins.ompass;

import io.jenkins.plugins.casc.ConfigurationAsCode;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.*;

@WithJenkins
public class DebugJCascTest {

    @Test
    public void testApplyJCascConfig(JenkinsRule j) throws Exception {
        String resource = getClass().getResource("configuration-as-code.yml").toExternalForm();
        System.out.println("YAML resource: " + resource);
        ConfigurationAsCode.get().configure(resource);

        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config);
        assertTrue(config.isEnableOmpass2fa(), "2FA should be enabled");
        assertEquals("https://ompass.example.com", config.getOmpassServerUrl());
    }
}
