package io.jenkins.plugins.ompass;

import com.ompasscloud.sdk.OmpassClient;
import com.ompasscloud.sdk.model.request.TokenVerifyRequest;
import com.ompasscloud.sdk.model.response.TokenVerifyResponse;
import hudson.Extension;
import hudson.Util;
import hudson.model.UnprotectedRootAction;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * RootAction that handles the OMPASS authentication callback.
 * When a user completes 2FA through OMPASS, the OMPASS server redirects to this callback
 * with an authentication token. This action verifies the token, marks the user's session
 * as 2FA-verified, and redirects to the original page.
 * On failure, an error message is displayed via the Jelly view.
 */
@Extension
public class OmpassCallbackAction implements UnprotectedRootAction {

    private static final Logger LOGGER = Logger.getLogger(OmpassCallbackAction.class.getName());

    private static final String OMPASS_2FA_VERIFIED_SUFFIX = "_OMPASS_2FA_VERIFIED";

    private static final String RELAY_STATE_KEY = "ompass_relay_state";

    // Per-request state accessed via ${it.xxx} in the Jelly view
    private boolean success;
    private String errorMessage;
    private String username;
    private String relayState;

    @Override
    public String getIconFileName() {
        return null;
    }

    @Override
    public String getDisplayName() {
        return "OMPASS Callback";
    }

    @Override
    public String getUrlName() {
        return "ompassCallback";
    }

    // --- Getters for Jelly view binding ---

    public boolean isSuccess() {
        return success;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public String getUsername() {
        return username;
    }

    public String getRelayState() {
        return relayState;
    }

    /**
     * Handles the callback from the OMPASS server.
     * Validates the token and username parameters, verifies them against the OMPASS server,
     * marks the session as 2FA-verified on success and redirects to the original page,
     * or displays an error page on failure.
     */
    public void doIndex(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException, ServletException {
        // Initialize per-request state
        this.success = false;
        this.errorMessage = null;
        this.username = null;
        this.relayState = null;

        String token = req.getParameter("token");
        this.username = req.getParameter("username");

        // Validate required parameters
        if (token == null || token.trim().isEmpty()) {
            LOGGER.warning("OMPASS callback received without token parameter");
            this.errorMessage = "Missing authentication token";
            req.getView(this, "index.jelly").forward(req, rsp);
            return;
        }

        if (this.username == null || this.username.trim().isEmpty()) {
            LOGGER.warning("OMPASS callback received without username parameter");
            this.errorMessage = "Missing username";
            req.getView(this, "index.jelly").forward(req, rsp);
            return;
        }

        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        if (config == null) {
            LOGGER.severe("OMPASS global configuration is not available during callback processing");
            this.errorMessage = "OMPASS configuration is not available";
            req.getView(this, "index.jelly").forward(req, rsp);
            return;
        }

        try {
            OmpassClient client = OmpassClientFactory.getInstance();

            TokenVerifyRequest verifyRequest = TokenVerifyRequest.builder()
                    .username(this.username)
                    .token(token)
                    .build();

            TokenVerifyResponse verifyResponse = client.verifyToken(verifyRequest);

            // Verify the response matches the expected username and client ID
            boolean verified = verifyResponse != null
                    && this.username.equals(verifyResponse.getUsername())
                    && config.getClientId().equals(verifyResponse.getClientId());

            if (verified) {
                // Read relay state from the old session before invalidation
                HttpSession oldSession = req.getSession(false);
                String destination = null;
                if (oldSession != null) {
                    destination = (String) oldSession.getAttribute(RELAY_STATE_KEY);
                    // Invalidate old session to prevent session fixation attacks
                    oldSession.invalidate();
                }

                // Create a fresh session and mark 2FA as verified
                HttpSession newSession = req.getSession(true);
                newSession.setAttribute(this.username + OMPASS_2FA_VERIFIED_SUFFIX, Boolean.TRUE);
                LOGGER.info("OMPASS 2FA verification succeeded for user: " + this.username);

                // Validate redirect destination to prevent open redirect
                if (destination == null || destination.isEmpty()
                        || !Util.isSafeToRedirectTo(destination)) {
                    destination = req.getContextPath() + "/";
                }

                rsp.sendRedirect(destination);
            } else {
                LOGGER.warning("OMPASS 2FA verification failed for user: " + this.username
                        + " - response username or clientId mismatch");
                this.errorMessage = "Authentication verification failed: credential mismatch";
                req.getView(this, "index.jelly").forward(req, rsp);
            }

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "OMPASS token verification failed for user: " + this.username, e);
            this.errorMessage = "Token verification failed: " + e.getMessage();
            req.getView(this, "index.jelly").forward(req, rsp);
        }
    }
}
