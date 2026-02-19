package io.jenkins.plugins.ompass;

import hudson.init.Initializer;
import hudson.init.InitMilestone;
import hudson.model.User;
import hudson.util.PluginServletFilter;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Servlet filter that intercepts all requests to enforce OMPASS 2FA authentication.
 * Unauthenticated requests, static resources, API calls, and plugin-specific URLs are
 * allowed through. Authenticated users who have not completed 2FA are redirected to
 * the OMPASS authentication page.
 *
 * This filter follows a fail-open strategy: if an exception occurs during 2FA evaluation,
 * the request is allowed through rather than blocking access.
 */
public class OmpassFilter implements Filter {

    private static final Logger LOGGER = Logger.getLogger(OmpassFilter.class.getName());

    private static final String OMPASS_2FA_VERIFIED_SUFFIX = "_OMPASS_2FA_VERIFIED";
    private static final String RELAY_STATE_KEY = "ompass_relay_state";

    /**
     * Jenkins system and static resource URLs that should always bypass 2FA.
     */
    private static final List<String> JENKINS_BYPASS_URLS = Arrays.asList(
            "/logout",
            "/login",
            "/adjuncts",
            "/static",
            "/ajaxBuildQueue",
            "/ajaxExecutors",
            "/descriptorByName",
            "/crumbIssuer",
            "/theme"
    );

    /**
     * Plugin-specific URLs that should bypass 2FA to allow the authentication flow itself.
     */
    private static final List<String> PLUGIN_BYPASS_URLS = Arrays.asList(
            "/ompassAuth",
            "/ompassCallback",
            "/ompass2fa-config"
    );

    /**
     * REST and CLI endpoints that should bypass 2FA.
     */
    private static final List<String> API_BYPASS_URLS = Arrays.asList(
            "/api/",
            "/cli"
    );

    /**
     * Static resource file extensions that should bypass 2FA.
     */
    private static final List<String> STATIC_EXTENSIONS = Arrays.asList(
            ".css",
            ".js",
            ".png",
            ".ico",
            ".gif",
            ".jpg",
            ".jpeg",
            ".svg",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot"
    );

    /**
     * Registers this filter with the Jenkins plugin servlet filter chain.
     * Called during Jenkins initialization after plugins are prepared.
     */
    @Initializer(after = InitMilestone.PLUGINS_PREPARED)
    public static void registerFilter() throws ServletException {
        LOGGER.info("Registering OMPASS 2FA servlet filter");
        PluginServletFilter.addFilter(new OmpassFilter());
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // No initialization required
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {
        try {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpServletResponse httpResponse = (HttpServletResponse) response;

            User currentUser = User.current();
            String requestUrl = httpRequest.getPathInfo();
            HttpSession session = httpRequest.getSession(false);

            if (byPass2FA(currentUser, requestUrl, session)) {
                filterChain.doFilter(request, response);
                return;
            }

            // User is authenticated but has not completed 2FA -- redirect to OMPASS auth page
            if (session == null) {
                session = httpRequest.getSession(true);
            }

            // Preserve the request URL so the user can return to the original page after 2FA
            String relayState = httpRequest.getRequestURL().toString();
            String queryString = httpRequest.getQueryString();
            if (queryString != null && !queryString.isEmpty()) {
                relayState = relayState + "?" + queryString;
            }
            session.setAttribute(RELAY_STATE_KEY, relayState);

            String contextPath = httpRequest.getContextPath();
            httpResponse.sendRedirect(contextPath + "/ompassAuth/");
        } catch (Exception e) {
            // Fail-open: allow the request through if an error occurs during 2FA evaluation
            LOGGER.log(Level.WARNING, "Exception in OMPASS 2FA filter, allowing request through", e);
            filterChain.doFilter(request, response);
        }
    }

    /**
     * Determines whether the request should bypass 2FA authentication.
     *
     * @param user    the currently authenticated Jenkins user, or null if anonymous
     * @param url     the request URI
     * @param session the HTTP session, or null if none exists
     * @return true if the request should pass through without 2FA, false otherwise
     */
    boolean byPass2FA(User user, String url, HttpSession session) {
        // 1. Unauthenticated users do not require 2FA
        if (user == null) {
            return true;
        }

        // 2. 2FA is globally disabled
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        if (config == null || !config.getEnableOmpass2fa()) {
            return true;
        }

        // 3. Already verified in this session
        if (session != null) {
            String userId = user.getId();
            Object verified = session.getAttribute(userId + OMPASS_2FA_VERIFIED_SUFFIX);
            if (Boolean.TRUE.equals(verified)) {
                return true;
            }
        }

        // 4. URL is in the bypass list
        if (isUrlBypassed(url)) {
            return true;
        }

        // 5. System property for development/emergency bypass
        String bypassProperty = System.getProperty("ompass.2fa.bypass");
        if ("true".equalsIgnoreCase(bypassProperty)) {
            return true;
        }

        return false;
    }

    /**
     * Checks whether the given URL should be excluded from 2FA enforcement.
     */
    private boolean isUrlBypassed(String url) {
        if (url == null) {
            return false;
        }

        // Check Jenkins system URLs
        for (String bypassUrl : JENKINS_BYPASS_URLS) {
            if (url.startsWith(bypassUrl)) {
                return true;
            }
        }

        // Check plugin URLs
        for (String bypassUrl : PLUGIN_BYPASS_URLS) {
            if (url.startsWith(bypassUrl)) {
                return true;
            }
        }

        // Check API and CLI endpoints
        for (String bypassUrl : API_BYPASS_URLS) {
            if (url.contains(bypassUrl)) {
                return true;
            }
        }

        // Check static resource extensions
        for (String extension : STATIC_EXTENSIONS) {
            if (url.endsWith(extension)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public void destroy() {
        // No cleanup required
    }
}
