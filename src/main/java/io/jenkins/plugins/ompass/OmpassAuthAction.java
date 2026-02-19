package io.jenkins.plugins.ompass;

import com.ompasscloud.sdk.OmpassClient;
import com.ompasscloud.sdk.enums.Language;
import com.ompasscloud.sdk.enums.LoginClientType;
import com.ompasscloud.sdk.model.request.AuthStartRequest;
import com.ompasscloud.sdk.model.response.AuthStartResponse;
import hudson.Extension;
import hudson.model.UnprotectedRootAction;
import hudson.model.User;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RootAction that initiates the OMPASS 2FA authentication flow.
 * For users redirected by OmpassFilter, this action calls the OMPASS server's startAuth API
 * and redirects the user directly to the OMPASS authentication page.
 * On error, an error message is displayed via the Jelly view.
 */
@Extension
public class OmpassAuthAction implements UnprotectedRootAction {

    private static final Logger LOGGER = Logger.getLogger(OmpassAuthAction.class.getName());

    private static final String RELAY_STATE_KEY = "ompass_relay_state";

    // Per-request state accessed via ${it.xxx} in the Jelly view
    private String ompassUrl;
    private String relayState;
    private String errorMessage;
    private String username;

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return "OMPASS Authentication";
    }

    @Override
    public String getUrlName() {
        return "ompassAuth";
    }

    // --- Getters for Jelly view binding ---

    public String getOmpassUrl() {
        return ompassUrl;
    }

    public String getRelayState() {
        return relayState;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public String getUsername() {
        return username;
    }

    /**
     * Handles GET requests to /ompassAuth/.
     * Initiates the OMPASS authentication flow for the current user.
     * On success, redirects directly to the OMPASS authentication page.
     * On failure, sets an error message and forwards to the Jelly view.
     */
    public void doIndex(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException, ServletException {
        // Initialize per-request state
        this.ompassUrl = null;
        this.relayState = null;
        this.errorMessage = null;
        this.username = null;

        User currentUser = User.current();
        if (currentUser == null) {
            LOGGER.warning("No authenticated user found, redirecting to login page");
            String contextPath = req.getContextPath();
            rsp.sendRedirect(contextPath + "/login");
            return;
        }

        this.username = currentUser.getId();
        HttpSession session = req.getSession(true);

        // Retrieve the relay state (the URL the user was originally trying to access)
        this.relayState = (String) session.getAttribute(RELAY_STATE_KEY);
        if (this.relayState == null || this.relayState.isEmpty()) {
            this.relayState = req.getContextPath() + "/";
        }

        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        if (config == null) {
            LOGGER.severe("OMPASS global configuration is not available");
            this.errorMessage = "OMPASS configuration is not available. Please contact your administrator.";
            req.getView(this, "index.jelly").forward(req, rsp);
            return;
        }

        // Determine language from configuration
        Language lang;
        try {
            lang = Language.fromValue(config.getLanguage());
        } catch (IllegalArgumentException e) {
            lang = Language.EN;
        }

        try {
            OmpassClient client = OmpassClientFactory.getInstance();

            AuthStartRequest authRequest = AuthStartRequest.builder()
                    .username(this.username)
                    .langInit(lang)
                    .loginClientType(LoginClientType.BROWSER)
                    .build();

            AuthStartResponse authResponse = client.startAuth(authRequest);

            String ompassUrl = authResponse.getOmpassUrl();
            LOGGER.fine("OMPASS authentication started for user, redirecting: " + this.username);

            // Redirect directly to the OMPASS authentication page
            rsp.sendRedirect(ompassUrl);

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to start OMPASS authentication for user: " + this.username, e);
            this.errorMessage = "Failed to initiate OMPASS authentication: " + e.getMessage();
            req.getView(this, "index.jelly").forward(req, rsp);
        }
    }
}
