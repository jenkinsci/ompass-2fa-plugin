package io.jenkins.plugins.ompass;

import hudson.Extension;
import hudson.security.csrf.CrumbExclusion;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

/**
 * Excludes OMPASS callback URLs from Jenkins CSRF (crumb) protection.
 * The OMPASS server redirects the authentication popup to the callback URL,
 * and this redirect does not include a Jenkins crumb token.
 * Without this exclusion, the callback would be rejected by Jenkins CSRF protection.
 */
@Extension
public class OmpassCrumbExclusion extends CrumbExclusion {

    private static final Logger LOGGER = Logger.getLogger(OmpassCrumbExclusion.class.getName());

    private static final String CALLBACK_PATH = "/ompassCallback/";
    private static final String CONFIG_PATH = "/ompass2fa-config/";

    @Override
    public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String pathInfo = request.getPathInfo();
        if (pathInfo != null && (pathInfo.startsWith(CALLBACK_PATH) || pathInfo.startsWith(CONFIG_PATH))) {
            LOGGER.fine("OMPASS crumb exclusion applied: " + pathInfo);
            chain.doFilter(request, response);
            return true;
        }
        return false;
    }
}
