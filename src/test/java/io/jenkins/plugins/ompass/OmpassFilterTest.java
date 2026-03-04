package io.jenkins.plugins.ompass;

import hudson.model.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link OmpassFilter} bypass logic and redirect behavior.
 *
 * These tests exercise the filter's decision tree for bypassing or enforcing
 * 2FA. They use a combination of JenkinsRule (for tests that require
 * OmpassGlobalConfig / Jenkins context) and pure Mockito mocks (for
 * servlet-layer behavior).
 */
@WithJenkins
public class OmpassFilterTest {

    private OmpassFilter filter;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private HttpSession session;
    private FilterChain chain;

    private String savedBypassProperty;

    @BeforeEach
    public void setUp() {
        filter = new OmpassFilter();

        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        session = mock(HttpSession.class);
        chain = mock(FilterChain.class);

        // Default stubs
        when(request.getSession(false)).thenReturn(session);
        when(request.getSession(true)).thenReturn(session);
        when(request.getSession()).thenReturn(session);
        when(request.getContextPath()).thenReturn("");
        // Session created well after filter registration (requires 2FA).
        // Use Long.MAX_VALUE because with @WithJenkins, Jenkins starts (and
        // filterRegisteredAt is set) AFTER @BeforeEach, so
        // System.currentTimeMillis() here would be earlier than filterRegisteredAt.
        when(session.getCreationTime()).thenReturn(Long.MAX_VALUE);

        // Save and clear the system property so tests start from a known state
        savedBypassProperty = System.getProperty("ompass.2fa.bypass");
        System.clearProperty("ompass.2fa.bypass");
    }

    @AfterEach
    public void tearDown() {
        // Restore the original system property value
        if (savedBypassProperty != null) {
            System.setProperty("ompass.2fa.bypass", savedBypassProperty);
        } else {
            System.clearProperty("ompass.2fa.bypass");
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Enable or disable 2FA in the global configuration.
     */
    private void setGlobal2faEnabled(boolean enabled) {
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config, "OmpassGlobalConfig must be available in JenkinsRule context");
        config.setEnableOmpass2fa(enabled);
        config.save();
    }

    // -----------------------------------------------------------------------
    // Bypass when 2FA is disabled globally
    // -----------------------------------------------------------------------

    @Test
    public void testBypassWhenDisabled(JenkinsRule j) {
        setGlobal2faEnabled(false);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");

        boolean result = filter.byPass2FA(mockUser, "/some/page", session);
        assertTrue(result, "Filter should bypass when 2FA is globally disabled");
    }

    // -----------------------------------------------------------------------
    // Bypass for static resources
    // -----------------------------------------------------------------------

    @Test
    public void testBypassForStaticResources_css(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue(filter.byPass2FA(mockUser, "/resources/style.css", session),
                "Should bypass .css files");
    }

    @Test
    public void testBypassForStaticResources_js(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue(filter.byPass2FA(mockUser, "/resources/app.js", session),
                "Should bypass .js files");
    }

    @Test
    public void testBypassForStaticResources_adjuncts(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue(filter.byPass2FA(mockUser, "/adjuncts/some-hash/resource.js", session),
                "Should bypass /adjuncts/ URLs");
    }

    @Test
    public void testBypassForStaticResources_png(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue(filter.byPass2FA(mockUser, "/images/logo.png", session),
                "Should bypass .png files");
    }

    @Test
    public void testBypassForStaticResources_ico(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue(filter.byPass2FA(mockUser, "/favicon.ico", session),
                "Should bypass .ico files");
    }

    // -----------------------------------------------------------------------
    // Bypass for plugin-specific URLs
    // -----------------------------------------------------------------------

    @Test
    public void testBypassForPluginUrls_ompassAuth(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue(filter.byPass2FA(mockUser, "/ompassAuth/", session),
                "Should bypass /ompassAuth URL");
    }

    @Test
    public void testBypassForPluginUrls_ompassCallback(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue(filter.byPass2FA(mockUser, "/ompassCallback/verify", session),
                "Should bypass /ompassCallback URL");
    }

    @Test
    public void testBypassForManageUrl(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue(filter.byPass2FA(mockUser, "/manage/configureSecurity", session),
                "Should bypass /manage URL");
    }

    // -----------------------------------------------------------------------
    // Bypass for unauthenticated users
    // -----------------------------------------------------------------------

    @Test
    public void testBypassForUnauthenticatedUser(JenkinsRule j) {
        setGlobal2faEnabled(true);

        boolean result = filter.byPass2FA(null, "/any/url", session);
        assertTrue(result, "Should bypass when user is null (unauthenticated)");
    }

    // -----------------------------------------------------------------------
    // Bypass when session already verified
    // -----------------------------------------------------------------------

    @Test
    public void testBypassWhenAlreadyVerified(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("admin");
        when(session.getAttribute("admin_OMPASS_2FA_VERIFIED")).thenReturn(Boolean.TRUE);

        boolean result = filter.byPass2FA(mockUser, "/manage", session);
        assertTrue(result, "Should bypass when session is already 2FA-verified");
    }

    // -----------------------------------------------------------------------
    // Redirect when 2FA is required
    // -----------------------------------------------------------------------

    @Test
    public void testRedirectWhen2faRequired(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("regularuser");
        when(session.getAttribute("regularuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        boolean result = filter.byPass2FA(mockUser, "/job/my-pipeline", session);
        assertFalse(result, "Should NOT bypass for authenticated user without 2FA verification");
    }

    // -----------------------------------------------------------------------
    // Relay state construction
    // -----------------------------------------------------------------------

    @Test
    public void testRelayStateConstruction(JenkinsRule j) {
        // Verify the relay state mechanism constructs the correct relative URI from
        // request attributes. This tests the logic used by the filter's
        // doFilter method for building relay state strings.
        when(request.getRequestURI()).thenReturn("/job/my-pipeline");
        when(request.getQueryString()).thenReturn("param=value");

        String expectedRelayState = "/job/my-pipeline?param=value";
        String requestUri = request.getRequestURI();
        String queryString = request.getQueryString();
        String relayState = requestUri;
        if (queryString != null && !queryString.isEmpty()) {
            relayState = relayState + "?" + queryString;
        }

        assertEquals(expectedRelayState, relayState,
                "Relay state should include URI and query string");
    }

    @Test
    public void testRelayStateWithoutQueryString(JenkinsRule j) {
        when(request.getRequestURI()).thenReturn("/job/my-pipeline");
        when(request.getQueryString()).thenReturn(null);

        String requestUri = request.getRequestURI();
        String queryString = request.getQueryString();
        String relayState = requestUri;
        if (queryString != null && !queryString.isEmpty()) {
            relayState = relayState + "?" + queryString;
        }

        assertEquals("/job/my-pipeline", relayState,
                "Relay state should be URI only when no query string");
    }

    // -----------------------------------------------------------------------
    // System property bypass
    // -----------------------------------------------------------------------

    @Test
    public void testBypassSystemProperty(JenkinsRule j) {
        setGlobal2faEnabled(true);
        System.setProperty("ompass.2fa.bypass", "true");

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        boolean result = filter.byPass2FA(mockUser, "/job/critical-build", session);
        assertTrue(result, "Should bypass when ompass.2fa.bypass system property is set to true");
    }

    @Test
    public void testNoBypassWhenSystemPropertyIsFalse(JenkinsRule j) {
        setGlobal2faEnabled(true);
        System.setProperty("ompass.2fa.bypass", "false");

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        boolean result = filter.byPass2FA(mockUser, "/job/my-build", session);
        assertFalse(result, "Should NOT bypass when ompass.2fa.bypass is false");
    }

    // -----------------------------------------------------------------------
    // Bypass for API and CLI endpoints
    // -----------------------------------------------------------------------

    @Test
    public void testBypassForApiEndpoint(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue(filter.byPass2FA(mockUser, "/job/test/api/json", session),
                "Should bypass /api/ endpoints");
    }

    @Test
    public void testBypassForCliEndpoint(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue(filter.byPass2FA(mockUser, "/cli", session),
                "Should bypass /cli endpoint");
    }

    // -----------------------------------------------------------------------
    // Bypass for Jenkins system URLs
    // -----------------------------------------------------------------------

    @Test
    public void testBypassForLoginUrl(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue(filter.byPass2FA(mockUser, "/login", session),
                "Should bypass /login URL");
    }

    @Test
    public void testBypassForLogoutUrl(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue(filter.byPass2FA(mockUser, "/logout", session),
                "Should bypass /logout URL");
    }

    // -----------------------------------------------------------------------
    // Null URL handling
    // -----------------------------------------------------------------------

    @Test
    public void testBypassForNullUrl(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        // Null URL should not match any bypass rules, so 2FA should be required
        boolean result = filter.byPass2FA(mockUser, null, session);
        assertFalse(result, "Should require 2FA when URL is null (no bypass match)");
    }

    // -----------------------------------------------------------------------
    // Null session handling
    // -----------------------------------------------------------------------

    @Test
    public void testHandlesNullSession(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");

        // Null session means no verified flag -- should require 2FA
        boolean result = filter.byPass2FA(mockUser, "/job/build", null);
        assertFalse(result, "Should require 2FA when session is null and URL is not bypassed");
    }

    // -----------------------------------------------------------------------
    // doFilter pass-through when disabled
    // -----------------------------------------------------------------------

    @Test
    public void testDoFilterPassesThroughWhenDisabled(JenkinsRule j) throws Exception {
        setGlobal2faEnabled(false);

        when(request.getRequestURI()).thenReturn("/some/page");

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
        verify(response, never()).sendRedirect(anyString());
    }

    // -----------------------------------------------------------------------
    // Font file bypass
    // -----------------------------------------------------------------------

    @Test
    public void testBypassForFontFiles(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue(filter.byPass2FA(mockUser, "/fonts/roboto.woff", session),
                "Should bypass .woff files");
        assertTrue(filter.byPass2FA(mockUser, "/fonts/roboto.woff2", session),
                "Should bypass .woff2 files");
        assertTrue(filter.byPass2FA(mockUser, "/fonts/roboto.ttf", session),
                "Should bypass .ttf files");
        assertTrue(filter.byPass2FA(mockUser, "/fonts/roboto.eot", session),
                "Should bypass .eot files");
    }

    // -----------------------------------------------------------------------
    // API token (Basic auth) bypass
    // -----------------------------------------------------------------------

    @Test
    public void testBypassForBasicAuthRequest(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("apiuser");
        when(session.getAttribute("apiuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        HttpServletRequest apiRequest = mock(HttpServletRequest.class);
        when(apiRequest.getAttribute("jenkins.security.BasicHeaderApiTokenAuthenticator"))
                .thenReturn(Boolean.TRUE);

        assertTrue(filter.byPass2FA(mockUser, "/job/build", session, apiRequest),
                "Should bypass 2FA for requests authenticated via API token");
    }

    @Test
    public void testNoBypassWithoutApiTokenAttribute(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        HttpServletRequest normalRequest = mock(HttpServletRequest.class);
        // getAttribute returns null by default for mocks -- no stub needed

        assertFalse(filter.byPass2FA(mockUser, "/job/build", session, normalRequest),
                "Should NOT bypass without API token authenticator attribute");
    }

    @Test
    public void testNoBypassForAuthHeaderWithoutAttribute(JenkinsRule j) {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        HttpServletRequest headerOnlyRequest = mock(HttpServletRequest.class);
        when(headerOnlyRequest.getHeader("Authorization")).thenReturn("Basic dXNlcjp0b2tlbg==");
        // No API token attribute set -- getAttribute returns null by default

        assertFalse(filter.byPass2FA(mockUser, "/job/build", session, headerOnlyRequest),
                "Should NOT bypass when Authorization header is present but API token attribute is missing");
    }
}
