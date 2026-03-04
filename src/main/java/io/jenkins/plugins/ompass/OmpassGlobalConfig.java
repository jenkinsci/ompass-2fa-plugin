package io.jenkins.plugins.ompass;

import com.ompasscloud.sdk.OmpassClient;
import com.ompasscloud.sdk.OmpassConfig;
import com.ompasscloud.sdk.exception.OmpassApiException;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.model.GlobalConfiguration;
import jenkins.model.GlobalConfigurationCategory;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.verb.POST;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Global configuration for the OMPASS 2FA plugin.
 * Stores the OMPASS server URL, client credentials, and 2FA enabled state.
 * Shown on the Manage Jenkins &gt; Security page.
 */
@Extension
@Symbol("ompass-2fa")
public class OmpassGlobalConfig extends GlobalConfiguration {

    private static final Logger LOGGER = Logger.getLogger(OmpassGlobalConfig.class.getName());

    private String ompassServerUrl;
    private String clientId;
    private Secret secretKey;
    private boolean enableOmpass2fa;
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
    @NonNull
    public GlobalConfigurationCategory getCategory() {
        return GlobalConfigurationCategory.get(GlobalConfigurationCategory.Security.class);
    }

    @Override
    public boolean configure(StaplerRequest2 req, JSONObject json) throws FormException {
        req.bindJSON(this, json);
        save();
        return true;
    }

    // --- Getters ---

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
        return enableOmpass2fa;
    }

    public String getLanguage() {
        return language != null ? language : "EN";
    }

    // --- Setters ---

    @DataBoundSetter
    public void setOmpassServerUrl(String ompassServerUrl) {
        this.ompassServerUrl = ompassServerUrl;
    }

    @DataBoundSetter
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    @DataBoundSetter
    public void setSecretKey(Secret secretKey) {
        this.secretKey = secretKey;
    }

    @DataBoundSetter
    public void setEnableOmpass2fa(boolean enableOmpass2fa) {
        this.enableOmpass2fa = enableOmpass2fa;
    }

    @DataBoundSetter
    public void setLanguage(String language) {
        this.language = language;
    }

    // --- Form population ---

    public ListBoxModel doFillLanguageItems() {
        ListBoxModel items = new ListBoxModel();
        items.add("English", "EN");
        items.add("Korean", "KR");
        return items;
    }

    // --- Form validation ---

    @POST
    public FormValidation doCheckOmpassServerUrl(@QueryParameter String value) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        if (value == null || value.trim().isEmpty()) {
            return FormValidation.error("OMPASS Server URL is required");
        }
        if (!value.startsWith("http://") && !value.startsWith("https://")) {
            return FormValidation.error("URL must start with http:// or https://");
        }
        if (value.endsWith("/")) {
            return FormValidation.warning("URL should not end with a trailing slash");
        }
        return FormValidation.ok();
    }

    @POST
    public FormValidation doCheckClientId(@QueryParameter String value) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        if (value == null || value.trim().isEmpty()) {
            return FormValidation.error("Client ID is required");
        }
        return FormValidation.ok();
    }

    @POST
    public FormValidation doCheckSecretKey(@QueryParameter String value) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        if (value == null || value.trim().isEmpty()) {
            return FormValidation.error("Secret Key is required");
        }
        return FormValidation.ok();
    }

    // --- Test connection (f:validateButton handler) ---

    @POST
    public FormValidation doTestConnection(
            @QueryParameter String ompassServerUrl,
            @QueryParameter String clientId,
            @QueryParameter String secretKey) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        if (ompassServerUrl == null || ompassServerUrl.trim().isEmpty()) {
            return FormValidation.error("OMPASS Server URL is required");
        }
        if (clientId == null || clientId.trim().isEmpty()) {
            return FormValidation.error("Client ID is required");
        }
        if (secretKey == null || secretKey.trim().isEmpty()) {
            return FormValidation.error("Secret Key is required");
        }

        try {
            OmpassConfig sdkConfig = OmpassConfig.builder()
                    .clientId(clientId)
                    .secretKey(secretKey)
                    .baseUrl(ompassServerUrl)
                    .connectTimeout(10)
                    .readTimeout(10)
                    .build();

            try (OmpassClient client = new OmpassClient(sdkConfig)) {
                client.getAuthenticators("__connection_test__");
                return FormValidation.ok("Connection successful");
            }
        } catch (OmpassApiException e) {
            int statusCode = e.getHttpStatusCode();
            if (statusCode == 400 || statusCode == 401 || statusCode == 404) {
                return FormValidation.ok("Connection successful (server responded)");
            }
            return FormValidation.error("Server responded with error: " + e.getErrorMessage());
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Connection test failed", e);
            return FormValidation.error("Connection failed: " + e.getMessage());
        }
    }
}
