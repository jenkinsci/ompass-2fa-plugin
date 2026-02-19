package io.jenkins.plugins.ompass;

import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.model.ManagementLink;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.kohsuke.stapler.verb.POST;

import javax.servlet.ServletException;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * ManagementLink that provides the OMPASS 2FA configuration page,
 * accessible from the "Manage Jenkins" Security section.
 * Only administrators can view and access this configuration page.
 */
@Extension
public class OmpassGlobalConfigView extends ManagementLink implements Describable<OmpassGlobalConfigView> {

    private static final Logger LOGGER = Logger.getLogger(OmpassGlobalConfigView.class.getName());

    @Override
    public String getIconFileName() {
        if (isAdmin()) {
            return "/plugin/ompass-2fa/images/ompass-icon.png";
        }
        return null;
    }

    @Override
    public String getDisplayName() {
        return "OMPASS 2FA Configuration";
    }

    @Override
    public String getUrlName() {
        return "ompass2fa-config";
    }

    @Override
    public String getDescription() {
        return "Configure OMPASS two-factor authentication settings";
    }

    @Override
    public Category getCategory() {
        return Category.SECURITY;
    }

    /**
     * Checks whether the current user has Jenkins administrator permissions.
     */
    public boolean isAdmin() {
        Jenkins jenkins = Jenkins.getInstanceOrNull();
        if (jenkins == null) {
            return false;
        }
        return jenkins.getACL().hasPermission(Jenkins.ADMINISTER);
    }

    /**
     * Returns the current OMPASS global configuration for use in the Jelly view.
     */
    public OmpassGlobalConfig getGlobalConfig() {
        return OmpassGlobalConfig.get();
    }

    /**
     * Handles the OMPASS configuration save form submission.
     * Requires a POST request with administrator permissions and a valid CRUMB.
     */
    @RequirePOST
    public void doSaveSettings(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        if (config == null) {
            LOGGER.severe("OmpassGlobalConfig instance is null; unable to save settings");
            rsp.sendError(500, "OMPASS configuration is not available");
            return;
        }

        String serverUrl = req.getParameter("ompassServerUrl");
        String clientId = req.getParameter("clientId");
        String secretKeyParam = req.getParameter("secretKey");
        String enableParam = req.getParameter("enableOmpass2fa");
        String language = req.getParameter("language");

        config.setOmpassServerUrl(serverUrl != null ? serverUrl : "");
        config.setClientId(clientId != null ? clientId : "");
        config.setSecretKey(Secret.fromString(secretKeyParam != null ? secretKeyParam : ""));
        config.setEnableOmpass2fa("on".equals(enableParam) || "true".equals(enableParam));
        config.setLanguage(language != null ? language : "EN");
        config.save();

        LOGGER.info("OMPASS 2FA settings saved successfully");
        rsp.sendRedirect(".");
    }

    /**
     * Tests the connection to the OMPASS server using the provided settings.
     * Returns a JSON response indicating success or failure.
     */
    @RequirePOST
    public void doTestConnection(StaplerRequest req, StaplerResponse rsp) throws IOException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        rsp.setContentType("application/json;charset=UTF-8");
        PrintWriter writer = rsp.getWriter();

        try {
            String serverUrl = req.getParameter("ompassServerUrl");
            String clientId = req.getParameter("clientId");
            String secretKeyValue = req.getParameter("secretKey");

            if (serverUrl == null || serverUrl.trim().isEmpty()) {
                writeJsonResponse(writer, false, "OMPASS Server URL is required");
                return;
            }
            if (clientId == null || clientId.trim().isEmpty()) {
                writeJsonResponse(writer, false, "Client ID is required");
                return;
            }
            if (secretKeyValue == null || secretKeyValue.trim().isEmpty()) {
                writeJsonResponse(writer, false, "Secret Key is required");
                return;
            }

            com.ompasscloud.sdk.OmpassConfig sdkConfig = com.ompasscloud.sdk.OmpassConfig.builder()
                    .clientId(clientId)
                    .secretKey(secretKeyValue)
                    .baseUrl(serverUrl)
                    .connectTimeout(10)
                    .readTimeout(10)
                    .build();

            try (com.ompasscloud.sdk.OmpassClient client = new com.ompasscloud.sdk.OmpassClient(sdkConfig)) {
                client.getAuthenticators("__connection_test__");
                writeJsonResponse(writer, true, "Connection successful");
            }
        } catch (com.ompasscloud.sdk.exception.OmpassApiException e) {
            // An API error response means the server is reachable and responding
            // Certain error codes indicate a valid connection
            int statusCode = e.getHttpStatusCode();
            if (statusCode == 400 || statusCode == 401 || statusCode == 404) {
                writeJsonResponse(writer, true, "Connection successful (server responded)");
            } else {
                writeJsonResponse(writer, false, "Server responded with error: " + e.getErrorMessage());
            }
        } catch (com.ompasscloud.sdk.exception.OmpassException e) {
            writeJsonResponse(writer, false, "Connection failed: " + e.getMessage());
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Connection test failed", e);
            writeJsonResponse(writer, false, "Connection failed: " + e.getMessage());
        }
    }

    private void writeJsonResponse(PrintWriter writer, boolean success, String message) {
        JSONObject result = new JSONObject();
        result.put("success", success);
        result.put("message", message);
        writer.print(result.toString());
        writer.flush();
    }

    @Override
    @SuppressWarnings("unchecked")
    public Descriptor<OmpassGlobalConfigView> getDescriptor() {
        return Jenkins.get().getDescriptorOrDie(getClass());
    }

    /**
     * Descriptor for the ManagementLink view that provides form validation.
     */
    @Extension
    public static class DescriptorImpl extends Descriptor<OmpassGlobalConfigView> {

        @Override
        public String getDisplayName() {
            return "OMPASS 2FA Configuration";
        }

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
    }
}
