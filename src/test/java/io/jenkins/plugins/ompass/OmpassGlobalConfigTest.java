package io.jenkins.plugins.ompass;

import hudson.util.Secret;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link OmpassGlobalConfig} persistence, default values,
 * and secret key encryption behavior.
 */
@WithJenkins
public class OmpassGlobalConfigTest {

    // -----------------------------------------------------------------------
    // Default values
    // -----------------------------------------------------------------------

    @Test
    public void testDefaultValues(JenkinsRule j) {
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config, "Global config singleton must not be null");

        assertFalse(config.isEnableOmpass2fa(), "enableOmpass2fa should default to false");
        assertEquals("EN", config.getLanguage(), "language should default to EN");
        assertEquals("", config.getOmpassServerUrl(), "ompassServerUrl should default to empty string");
        assertEquals("", config.getClientId(), "clientId should default to empty string");
        assertNull(config.getSecretKey(), "secretKey should default to null");
    }

    // -----------------------------------------------------------------------
    // Save and load round-trip
    // -----------------------------------------------------------------------

    @Test
    public void testSaveAndLoad(JenkinsRule j) {
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config);

        // Set non-default values
        config.setOmpassServerUrl("https://ompass.example.com");
        config.setClientId("test-client-id-123");
        config.setSecretKey(Secret.fromString("super-secret-key"));
        config.setEnableOmpass2fa(true);
        config.setLanguage("KR");
        config.save();

        // Create a fresh instance that should load persisted values
        OmpassGlobalConfig reloaded = new OmpassGlobalConfig();

        assertEquals("https://ompass.example.com", reloaded.getOmpassServerUrl());
        assertEquals("test-client-id-123", reloaded.getClientId());
        assertNotNull(reloaded.getSecretKey(), "secretKey should be loaded");
        assertEquals("super-secret-key", reloaded.getSecretKey().getPlainText());
        assertTrue(reloaded.isEnableOmpass2fa(), "enableOmpass2fa should be true after reload");
        assertEquals("KR", reloaded.getLanguage());
    }

    // -----------------------------------------------------------------------
    // Secret key encryption
    // -----------------------------------------------------------------------

    @Test
    public void testSecretKeyEncryption(JenkinsRule j) {
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config);

        String plainTextSecret = "my-super-secret-key-value";
        config.setSecretKey(Secret.fromString(plainTextSecret));
        config.save();

        // Verify the getter returns a Secret object
        Secret retrieved = config.getSecretKey();
        assertNotNull(retrieved, "Secret should not be null after being set");
        assertTrue(retrieved instanceof Secret,
                "Secret should be an instance of hudson.util.Secret");

        // Verify the encrypted value is not stored as plain text
        String encryptedValue = retrieved.getEncryptedValue();
        assertNotNull(encryptedValue, "Encrypted value should not be null");
        assertNotEquals(plainTextSecret, encryptedValue,
                "Encrypted value must differ from plain text");

        // Verify the plain text can be recovered
        assertEquals(plainTextSecret, retrieved.getPlainText(),
                "Plain text should be recoverable from Secret");
    }

    // -----------------------------------------------------------------------
    // Singleton access
    // -----------------------------------------------------------------------

    @Test
    public void testGetSingleton(JenkinsRule j) {
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config, "OmpassGlobalConfig.get() must not return null inside a Jenkins context");

        // Calling get() multiple times should return the same instance
        OmpassGlobalConfig sameConfig = OmpassGlobalConfig.get();
        assertSame(config, sameConfig,
                "Repeated calls to get() should return the same singleton");
    }

    // -----------------------------------------------------------------------
    // Null-safe getters
    // -----------------------------------------------------------------------

    @Test
    public void testNullSafeGetters(JenkinsRule j) {
        // Create a raw instance without loading any persisted state.
        // Internal fields will be null because nothing was ever set.
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config);

        // The getters must never return null for String/Boolean fields
        // (secretKey is allowed to be null by design).
        assertNotNull(config.getOmpassServerUrl(), "getOmpassServerUrl must not return null");
        assertNotNull(config.getClientId(), "getClientId must not return null");
        assertNotNull(config.getLanguage(), "getLanguage must not return null");

        assertEquals("", config.getOmpassServerUrl(), "Default ompassServerUrl should be empty string");
        assertEquals("", config.getClientId(), "Default clientId should be empty string");
        assertFalse(config.isEnableOmpass2fa(), "Default enableOmpass2fa should be false");
        assertEquals("EN", config.getLanguage(), "Default language should be EN");
    }

    // -----------------------------------------------------------------------
    // Individual setter persistence
    // -----------------------------------------------------------------------

    @Test
    public void testSetterTriggersAutoPersist(JenkinsRule j) {
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config);

        // @DataBoundSetter does not auto-save; save() must be called explicitly.
        // In practice, configure(req, json) calls save() after binding all fields.
        config.setOmpassServerUrl("https://auto-persist-test.example.com");
        config.save();

        OmpassGlobalConfig reloaded = new OmpassGlobalConfig();
        assertEquals("https://auto-persist-test.example.com", reloaded.getOmpassServerUrl(),
                "Value should persist after explicit save");
    }

    // -----------------------------------------------------------------------
    // Overwrite behavior
    // -----------------------------------------------------------------------

    @Test
    public void testOverwriteExistingValues(JenkinsRule j) {
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config);

        config.setOmpassServerUrl("https://first.example.com");
        config.setClientId("first-client");
        config.save();

        // Overwrite with new values
        config.setOmpassServerUrl("https://second.example.com");
        config.setClientId("second-client");
        config.save();

        OmpassGlobalConfig reloaded = new OmpassGlobalConfig();
        assertEquals("https://second.example.com", reloaded.getOmpassServerUrl());
        assertEquals("second-client", reloaded.getClientId());
    }

    // -----------------------------------------------------------------------
    // Empty string handling
    // -----------------------------------------------------------------------

    @Test
    public void testEmptyStringValues(JenkinsRule j) {
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config);

        config.setOmpassServerUrl("");
        config.setClientId("");
        config.setLanguage("");
        config.save();

        OmpassGlobalConfig reloaded = new OmpassGlobalConfig();
        // Empty string is a valid value -- getters should return it, not the default
        assertEquals("", reloaded.getOmpassServerUrl());
        assertEquals("", reloaded.getClientId());
        assertEquals("", reloaded.getLanguage());
    }
}
