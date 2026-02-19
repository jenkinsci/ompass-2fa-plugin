package io.jenkins.plugins.ompass;

import com.ompasscloud.sdk.OmpassClient;
import com.ompasscloud.sdk.OmpassConfig;
import hudson.util.Secret;

import java.util.logging.Logger;

/**
 * Thread-safe factory for obtaining a shared OmpassClient instance.
 * The client is lazily created and cached. When the global configuration changes
 * (detected by a hash of server URL, client ID, and secret key),
 * the existing client is closed and a new one is created.
 *
 * This prevents creating a new HTTP client on every request while ensuring
 * configuration changes take effect without a restart.
 */
public final class OmpassClientFactory {

    private static final Logger LOGGER = Logger.getLogger(OmpassClientFactory.class.getName());

    private static volatile OmpassClient instance;
    private static volatile String configHash;

    private OmpassClientFactory() {
        // Utility class -- not instantiable
    }

    /**
     * Returns a shared OmpassClient instance configured with the current OmpassGlobalConfig.
     * Creates a new client if the configuration has changed since the last call.
     *
     * @return a configured OmpassClient instance
     * @throws IllegalStateException if the global configuration is missing or incomplete
     */
    public static synchronized OmpassClient getInstance() {
        OmpassGlobalConfig globalConfig = OmpassGlobalConfig.get();
        if (globalConfig == null) {
            throw new IllegalStateException("OMPASS global configuration is not available");
        }

        String serverUrl = globalConfig.getOmpassServerUrl();
        String clientId = globalConfig.getClientId();
        Secret secretKeySecret = globalConfig.getSecretKey();

        if (serverUrl == null || serverUrl.trim().isEmpty()) {
            throw new IllegalStateException("OMPASS server URL is not configured");
        }
        if (clientId == null || clientId.trim().isEmpty()) {
            throw new IllegalStateException("OMPASS client ID is not configured");
        }
        if (secretKeySecret == null || Secret.toString(secretKeySecret).trim().isEmpty()) {
            throw new IllegalStateException("OMPASS secret key is not configured");
        }

        String secretKeyPlain = secretKeySecret.getPlainText();
        String currentHash = computeHash(serverUrl, clientId, secretKeyPlain);

        if (instance == null || !currentHash.equals(configHash)) {
            if (instance != null) {
                LOGGER.info("OMPASS configuration changed, recreating client");
                try {
                    instance.close();
                } catch (Exception e) {
                    LOGGER.warning("Error closing previous OMPASS client: " + e.getMessage());
                }
            }

            OmpassConfig sdkConfig = OmpassConfig.builder()
                    .clientId(clientId)
                    .secretKey(secretKeyPlain)
                    .baseUrl(serverUrl)
                    .build();

            instance = new OmpassClient(sdkConfig);
            configHash = currentHash;
            LOGGER.info("OMPASS client created, server: " + serverUrl);
        }

        return instance;
    }

    /**
     * Clears the cached client instance. The next call to getInstance() will
     * create a new client. Useful for testing and configuration resets.
     */
    public static synchronized void reset() {
        if (instance != null) {
            try {
                instance.close();
            } catch (Exception e) {
                LOGGER.warning("Error closing OMPASS client during reset: " + e.getMessage());
            }
            instance = null;
        }
        configHash = null;
        LOGGER.info("OMPASS client factory reset");
    }

    /**
     * Computes a simple hash string from configuration values.
     * Used to detect configuration changes without storing actual secrets.
     */
    private static String computeHash(String serverUrl, String clientId, String secretKey) {
        int hash = 17;
        hash = 31 * hash + (serverUrl != null ? serverUrl.hashCode() : 0);
        hash = 31 * hash + (clientId != null ? clientId.hashCode() : 0);
        hash = 31 * hash + (secretKey != null ? secretKey.hashCode() : 0);
        return String.valueOf(hash);
    }
}
