package io.jenkins.plugins.ompass;

import hudson.Extension;
import hudson.XmlFile;
import hudson.util.Secret;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest2;

import java.io.File;
import java.util.logging.Logger;

/**
 * Global configuration for the OMPASS 2FA plugin.
 * Stores the OMPASS server URL, client credentials, and 2FA enabled state.
 * Configuration is persisted to a custom XML file under the Jenkins plugin directory.
 */
@Extension
public class OmpassGlobalConfig extends GlobalConfiguration {

    private static final Logger LOGGER = Logger.getLogger(OmpassGlobalConfig.class.getName());

    private String ompassServerUrl;
    private String clientId;
    private Secret secretKey;
    private Boolean enableOmpass2fa;
    private String language;

    public OmpassGlobalConfig() {
        load();
    }

    /**
     * Returns the singleton instance of this configuration.
     *
     * @return the global OMPASS configuration object, or null if not available
     */
    public static OmpassGlobalConfig get() {
        return GlobalConfiguration.all().get(OmpassGlobalConfig.class);
    }

    @Override
    protected XmlFile getConfigFile() {
        File configDir = new File(Jenkins.get().getRootDir(), "plugins/ompass2faConfig");
        if (!configDir.exists()) {
            boolean created = configDir.mkdirs();
            if (!created) {
                LOGGER.warning("Failed to create configuration directory: " + configDir.getAbsolutePath());
            }
        }
        return new XmlFile(new File(configDir, this.getId() + ".xml"));
    }

    @Override
    public boolean configure(StaplerRequest2 req, JSONObject json) throws FormException {
        req.bindJSON(this, json);
        save();
        return true;
    }

    // --- Getters with null-safe defaults ---

    public String getOmpassServerUrl() {
        return ompassServerUrl != null ? ompassServerUrl : "";
    }

    public String getClientId() {
        return clientId != null ? clientId : "";
    }

    public Secret getSecretKey() {
        return secretKey;
    }

    public Boolean getEnableOmpass2fa() {
        return enableOmpass2fa != null ? enableOmpass2fa : Boolean.FALSE;
    }

    public String getLanguage() {
        return language != null ? language : "EN";
    }

    // --- Setters with persistence ---

    @DataBoundSetter
    public void setOmpassServerUrl(String ompassServerUrl) {
        this.ompassServerUrl = ompassServerUrl;
        save();
    }

    @DataBoundSetter
    public void setClientId(String clientId) {
        this.clientId = clientId;
        save();
    }

    @DataBoundSetter
    public void setSecretKey(Secret secretKey) {
        this.secretKey = secretKey;
        save();
    }

    @DataBoundSetter
    public void setEnableOmpass2fa(Boolean enableOmpass2fa) {
        this.enableOmpass2fa = enableOmpass2fa;
        save();
    }

    @DataBoundSetter
    public void setLanguage(String language) {
        this.language = language;
        save();
    }
}
