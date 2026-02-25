package io.jenkins.plugins.ompass;

import hudson.Extension;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.model.GlobalConfiguration;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest2;

import java.util.logging.Logger;

/**
 * Global configuration for the OMPASS 2FA plugin.
 * Stores the OMPASS server URL, client credentials, and 2FA enabled state.
 * Configuration is persisted to a custom XML file under the Jenkins plugin directory.
 */
@Extension
@Symbol("ompass-2fa")
public class OmpassGlobalConfig extends GlobalConfiguration {

    private static final Logger LOGGER = Logger.getLogger(OmpassGlobalConfig.class.getName());

    private String ompassServerUrl;
    private String clientId;
    private Secret secretKey;
    private Boolean enableOmpass2fa;
    private String language;

    @DataBoundConstructor
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

    public boolean isEnableOmpass2fa() {
        return enableOmpass2fa != null ? enableOmpass2fa : false;
    }

    public String getLanguage() {
        return language != null ? language : "EN";
    }

    public ListBoxModel doFillLanguageItems() {
        ListBoxModel items = new ListBoxModel();
        items.add("English", "EN");
        items.add("Korean", "KR");
        return items;
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
