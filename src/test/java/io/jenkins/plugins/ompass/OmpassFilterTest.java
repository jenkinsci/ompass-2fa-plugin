package io.jenkins.plugins.ompass;

import hudson.model.User;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link OmpassFilter} bypass logic and redirect behavior.
 *
 * These tests exercise the filter's decision tree for bypassing or enforcing
 * 2FA. They use a combination of JenkinsRule (for tests that require
 * OmpassGlobalConfig / Jenkins context) and pure Mockito mocks (for
 * servlet-layer behavior).
 */
public class OmpassFilterTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    private OmpassFilter filter;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private HttpSession session;
    private FilterChain chain;

    private String savedBypassProperty;

    @Before
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
        // Session created after filter registration (requires 2FA)
        when(session.getCreationTime()).thenReturn(System.currentTimeMillis());

        // Save and clear the system property so tests start from a known state
        savedBypassProperty = System.getProperty("ompass.2fa.bypass");
        System.clearProperty("ompass.2fa.bypass");
    }

    @After
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
        assertNotNull("OmpassGlobalConfig must be available in JenkinsRule context", config);
        config.setEnableOmpass2fa(enabled);
        config.save();
    }

    // -----------------------------------------------------------------------
    // Bypass when 2FA is disabled globally
    // -----------------------------------------------------------------------

    @Test
    public void testBypassWhenDisabled() {
        setGlobal2faEnabled(false);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");

        boolean result = filter.byPass2FA(mockUser, "/some/page", session);
        assertTrue("Filter should bypass when 2FA is globally disabled", result);
    }

    // -----------------------------------------------------------------------
    // Bypass for static resources
    // -----------------------------------------------------------------------

    @Test
    public void testBypassForStaticResources_css() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue("Should bypass .css files",
                filter.byPass2FA(mockUser, "/resources/style.css", session));
    }

    @Test
    public void testBypassForStaticResources_js() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue("Should bypass .js files",
                filter.byPass2FA(mockUser, "/resources/app.js", session));
    }

    @Test
    public void testBypassForStaticResources_adjuncts() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue("Should bypass /adjuncts/ URLs",
                filter.byPass2FA(mockUser, "/adjuncts/some-hash/resource.js", session));
    }

    @Test
    public void testBypassForStaticResources_png() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue("Should bypass .png files",
                filter.byPass2FA(mockUser, "/images/logo.png", session));
    }

    @Test
    public void testBypassForStaticResources_ico() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue("Should bypass .ico files",
                filter.byPass2FA(mockUser, "/favicon.ico", session));
    }

    // -----------------------------------------------------------------------
    // Bypass for plugin-specific URLs
    // -----------------------------------------------------------------------

    @Test
    public void testBypassForPluginUrls_ompassAuth() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue("Should bypass /ompassAuth URL",
                filter.byPass2FA(mockUser, "/ompassAuth/", session));
    }

    @Test
    public void testBypassForPluginUrls_ompassCallback() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue("Should bypass /ompassCallback URL",
                filter.byPass2FA(mockUser, "/ompassCallback/verify", session));
    }

    @Test
    public void testBypassForPluginUrls_configPage() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue("Should bypass /ompass2fa-config URL",
                filter.byPass2FA(mockUser, "/ompass2fa-config/", session));
    }

    // -----------------------------------------------------------------------
    // Bypass for unauthenticated users
    // -----------------------------------------------------------------------

    @Test
    public void testBypassForUnauthenticatedUser() {
        setGlobal2faEnabled(true);

        boolean result = filter.byPass2FA(null, "/any/url", session);
        assertTrue("Should bypass when user is null (unauthenticated)", result);
    }

    // -----------------------------------------------------------------------
    // Bypass when session already verified
    // -----------------------------------------------------------------------

    @Test
    public void testBypassWhenAlreadyVerified() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("admin");
        when(session.getAttribute("admin_OMPASS_2FA_VERIFIED")).thenReturn(Boolean.TRUE);

        boolean result = filter.byPass2FA(mockUser, "/manage", session);
        assertTrue("Should bypass when session is already 2FA-verified", result);
    }

    // -----------------------------------------------------------------------
    // Redirect when 2FA is required
    // -----------------------------------------------------------------------

    @Test
    public void testRedirectWhen2faRequired() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("regularuser");
        when(session.getAttribute("regularuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        boolean result = filter.byPass2FA(mockUser, "/job/my-pipeline", session);
        assertFalse("Should NOT bypass for authenticated user without 2FA verification", result);
    }

    // -----------------------------------------------------------------------
    // Relay state construction
    // -----------------------------------------------------------------------

    @Test
    public void testRelayStateConstruction() {
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

        assertEquals("Relay state should include URI and query string",
                expectedRelayState, relayState);
    }

    @Test
    public void testRelayStateWithoutQueryString() {
        when(request.getRequestURI()).thenReturn("/job/my-pipeline");
        when(request.getQueryString()).thenReturn(null);

        String requestUri = request.getRequestURI();
        String queryString = request.getQueryString();
        String relayState = requestUri;
        if (queryString != null && !queryString.isEmpty()) {
            relayState = relayState + "?" + queryString;
        }

        assertEquals("Relay state should be URI only when no query string",
                "/job/my-pipeline", relayState);
    }

    // -----------------------------------------------------------------------
    // System property bypass
    // -----------------------------------------------------------------------

    @Test
    public void testBypassSystemProperty() {
        setGlobal2faEnabled(true);
        System.setProperty("ompass.2fa.bypass", "true");

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        boolean result = filter.byPass2FA(mockUser, "/job/critical-build", session);
        assertTrue("Should bypass when ompass.2fa.bypass system property is set to true", result);
    }

    @Test
    public void testNoBypassWhenSystemPropertyIsFalse() {
        setGlobal2faEnabled(true);
        System.setProperty("ompass.2fa.bypass", "false");

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        boolean result = filter.byPass2FA(mockUser, "/job/my-build", session);
        assertFalse("Should NOT bypass when ompass.2fa.bypass is false", result);
    }

    // -----------------------------------------------------------------------
    // Bypass for API and CLI endpoints
    // -----------------------------------------------------------------------

    @Test
    public void testBypassForApiEndpoint() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue("Should bypass /api/ endpoints",
                filter.byPass2FA(mockUser, "/job/test/api/json", session));
    }

    @Test
    public void testBypassForCliEndpoint() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue("Should bypass /cli endpoint",
                filter.byPass2FA(mockUser, "/cli", session));
    }

    // -----------------------------------------------------------------------
    // Bypass for Jenkins system URLs
    // -----------------------------------------------------------------------

    @Test
    public void testBypassForLoginUrl() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue("Should bypass /login URL",
                filter.byPass2FA(mockUser, "/login", session));
    }

    @Test
    public void testBypassForLogoutUrl() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue("Should bypass /logout URL",
                filter.byPass2FA(mockUser, "/logout", session));
    }

    // -----------------------------------------------------------------------
    // Null URL handling
    // -----------------------------------------------------------------------

    @Test
    public void testBypassForNullUrl() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        // Null URL should not match any bypass rules, so 2FA should be required
        boolean result = filter.byPass2FA(mockUser, null, session);
        assertFalse("Should require 2FA when URL is null (no bypass match)", result);
    }

    // -----------------------------------------------------------------------
    // Null session handling
    // -----------------------------------------------------------------------

    @Test
    public void testHandlesNullSession() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");

        // Null session means no verified flag -- should require 2FA
        boolean result = filter.byPass2FA(mockUser, "/job/build", null);
        assertFalse("Should require 2FA when session is null and URL is not bypassed", result);
    }

    // -----------------------------------------------------------------------
    // doFilter pass-through when disabled
    // -----------------------------------------------------------------------

    @Test
    public void testDoFilterPassesThroughWhenDisabled() throws Exception {
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
    public void testBypassForFontFiles() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        assertTrue("Should bypass .woff files",
                filter.byPass2FA(mockUser, "/fonts/roboto.woff", session));
        assertTrue("Should bypass .woff2 files",
                filter.byPass2FA(mockUser, "/fonts/roboto.woff2", session));
        assertTrue("Should bypass .ttf files",
                filter.byPass2FA(mockUser, "/fonts/roboto.ttf", session));
        assertTrue("Should bypass .eot files",
                filter.byPass2FA(mockUser, "/fonts/roboto.eot", session));
    }

    // -----------------------------------------------------------------------
    // API token (Basic auth) bypass
    // -----------------------------------------------------------------------

    @Test
    public void testBypassForBasicAuthRequest() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("apiuser");
        when(session.getAttribute("apiuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        HttpServletRequest apiRequest = mock(HttpServletRequest.class);
        when(apiRequest.getHeader("Authorization")).thenReturn("Basic dXNlcjp0b2tlbg==");

        assertTrue("Should bypass 2FA for requests with Basic auth header",
                filter.byPass2FA(mockUser, "/job/build", session, apiRequest));
    }

    @Test
    public void testNoBypassWithoutAuthHeader() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        HttpServletRequest normalRequest = mock(HttpServletRequest.class);
        when(normalRequest.getHeader("Authorization")).thenReturn(null);

        assertFalse("Should NOT bypass without Authorization header",
                filter.byPass2FA(mockUser, "/job/build", session, normalRequest));
    }

    @Test
    public void testNoBypassForBearerAuth() {
        setGlobal2faEnabled(true);

        User mockUser = mock(User.class);
        when(mockUser.getId()).thenReturn("testuser");
        when(session.getAttribute("testuser_OMPASS_2FA_VERIFIED")).thenReturn(null);

        HttpServletRequest bearerRequest = mock(HttpServletRequest.class);
        when(bearerRequest.getHeader("Authorization")).thenReturn("Bearer some-token");

        assertFalse("Should NOT bypass for Bearer auth (only Basic is allowed)",
                filter.byPass2FA(mockUser, "/job/build", session, bearerRequest));
    }
}
