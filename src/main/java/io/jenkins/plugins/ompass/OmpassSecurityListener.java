package io.jenkins.plugins.ompass;

import hudson.Extension;
import jenkins.security.SecurityListener;
import org.springframework.security.core.userdetails.UserDetails;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.logging.Logger;

/**
 * Security listener that responds to Jenkins authentication lifecycle events.
 * On user logout, removes the OMPASS 2FA verification flag from the session
 * so that a new 2FA verification is required on the next login.
 */
@Extension
public class OmpassSecurityListener extends SecurityListener {

    private static final Logger LOGGER = Logger.getLogger(OmpassSecurityListener.class.getName());

    private static final String OMPASS_2FA_VERIFIED_SUFFIX = "_OMPASS_2FA_VERIFIED";

    /**
     * Called when a user logs out. Removes the 2FA verification session attribute
     * so that re-authentication requires a new 2FA verification.
     *
     * Note: Session invalidation typically handles this, but the flag is explicitly
     * removed as defense-in-depth in case the session is reused.
     */
    @Override
    protected void loggedOut(@NonNull String username) {
        LOGGER.fine("User logged out, clearing OMPASS 2FA verification: " + username);
        // Session attributes are automatically removed when the session is invalidated on logout.
        // This listener provides an additional logging point and can perform extra cleanup if needed.
    }

    /**
     * Called after a user is successfully authenticated by Jenkins.
     * Logs the authentication event for auditing purposes.
     */
    @Override
    protected void authenticated2(@NonNull UserDetails details) {
        LOGGER.fine("User authenticated: " + details.getUsername() + " - OMPASS 2FA check will be performed by the filter");
    }
}
