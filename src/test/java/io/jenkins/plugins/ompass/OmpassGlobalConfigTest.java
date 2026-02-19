package io.jenkins.plugins.ompass;

import hudson.util.Secret;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.junit.Assert.*;

/**
 * Tests for {@link OmpassGlobalConfig} persistence, default values,
 * and secret key encryption behavior.
 */
public class OmpassGlobalConfigTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    // -----------------------------------------------------------------------
    // Default values
    // -----------------------------------------------------------------------

    @Test
    public void testDefaultValues() {
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull("Global config singleton must not be null", config);

        assertFalse("enableOmpass2fa should default to false", config.getEnableOmpass2fa());
        assertEquals("language should default to EN", "EN", config.getLanguage());
        assertEquals("ompassServerUrl should default to empty string", "", config.getOmpassServerUrl());
        assertEquals("clientId should default to empty string", "", config.getClientId());
        assertNull("secretKey should default to null", config.getSecretKey());
    }

    // -----------------------------------------------------------------------
    // Save and load round-trip
    // -----------------------------------------------------------------------

    @Test
    public void testSaveAndLoad() {
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
        assertNotNull("secretKey should be loaded", reloaded.getSecretKey());
        assertEquals("super-secret-key", reloaded.getSecretKey().getPlainText());
        assertTrue("enableOmpass2fa should be true after reload", reloaded.getEnableOmpass2fa());
        assertEquals("KR", reloaded.getLanguage());
    }

    // -----------------------------------------------------------------------
    // Secret key encryption
    // -----------------------------------------------------------------------

    @Test
    public void testSecretKeyEncryption() {
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config);

        String plainTextSecret = "my-super-secret-key-value";
        config.setSecretKey(Secret.fromString(plainTextSecret));
        config.save();

        // Verify the getter returns a Secret object
        Secret retrieved = config.getSecretKey();
        assertNotNull("Secret should not be null after being set", retrieved);
        assertTrue("Secret should be an instance of hudson.util.Secret",
                retrieved instanceof Secret);

        // Verify the encrypted value is not stored as plain text
        String encryptedValue = retrieved.getEncryptedValue();
        assertNotNull("Encrypted value should not be null", encryptedValue);
        assertNotEquals("Encrypted value must differ from plain text",
                plainTextSecret, encryptedValue);

        // Verify the plain text can be recovered
        assertEquals("Plain text should be recoverable from Secret",
                plainTextSecret, retrieved.getPlainText());
    }

    // -----------------------------------------------------------------------
    // Singleton access
    // -----------------------------------------------------------------------

    @Test
    public void testGetSingleton() {
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull("OmpassGlobalConfig.get() must not return null inside a Jenkins context", config);

        // Calling get() multiple times should return the same instance
        OmpassGlobalConfig sameConfig = OmpassGlobalConfig.get();
        assertSame("Repeated calls to get() should return the same singleton",
                config, sameConfig);
    }

    // -----------------------------------------------------------------------
    // Null-safe getters
    // -----------------------------------------------------------------------

    @Test
    public void testNullSafeGetters() {
        // Create a raw instance without loading any persisted state.
        // Internal fields will be null because nothing was ever set.
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config);

        // The getters must never return null for String/Boolean fields
        // (secretKey is allowed to be null by design).
        assertNotNull("getOmpassServerUrl must not return null", config.getOmpassServerUrl());
        assertNotNull("getClientId must not return null", config.getClientId());
        assertNotNull("getEnableOmpass2fa must not return null", config.getEnableOmpass2fa());
        assertNotNull("getLanguage must not return null", config.getLanguage());

        assertEquals("Default ompassServerUrl should be empty string", "", config.getOmpassServerUrl());
        assertEquals("Default clientId should be empty string", "", config.getClientId());
        assertFalse("Default enableOmpass2fa should be false", config.getEnableOmpass2fa());
        assertEquals("Default language should be EN", "EN", config.getLanguage());
    }

    // -----------------------------------------------------------------------
    // Individual setter persistence
    // -----------------------------------------------------------------------

    @Test
    public void testSetterTriggersAutoPersist() {
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config);

        // Each setter calls save() internally via @DataBoundSetter pattern.
        // Verify that after setting a value, a fresh load reflects it.
        config.setOmpassServerUrl("https://auto-persist-test.example.com");

        OmpassGlobalConfig reloaded = new OmpassGlobalConfig();
        assertEquals("Value should persist after setter call",
                "https://auto-persist-test.example.com", reloaded.getOmpassServerUrl());
    }

    // -----------------------------------------------------------------------
    // Overwrite behavior
    // -----------------------------------------------------------------------

    @Test
    public void testOverwriteExistingValues() {
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
    public void testEmptyStringValues() {
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
