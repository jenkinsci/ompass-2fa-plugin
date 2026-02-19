package io.jenkins.plugins.ompass;

import hudson.model.UnprotectedRootAction;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.junit.Assert.*;

/**
 * Tests for {@link OmpassCallbackAction} URL mapping, display properties,
 * and registration as a Jenkins extension.
 *
 * Full integration testing of the callback token verification flow requires
 * a running OMPASS server, so these tests focus on what can be verified
 * without external dependencies: URL name, display name, icon visibility,
 * and consistent registration with the filter's bypass URL list.
 */
public class OmpassCallbackActionTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    // -----------------------------------------------------------------------
    // URL name
    // -----------------------------------------------------------------------

    @Test
    public void testUrlName() {
        OmpassCallbackAction action = findCallbackAction();
        assertNotNull("OmpassCallbackAction should be registered as an extension", action);

        assertEquals("URL name should be 'ompassCallback'",
                "ompassCallback", action.getUrlName());
    }

    // -----------------------------------------------------------------------
    // Display name
    // -----------------------------------------------------------------------

    @Test
    public void testDisplayName() {
        OmpassCallbackAction action = findCallbackAction();
        assertNotNull("OmpassCallbackAction should be registered", action);

        String displayName = action.getDisplayName();
        assertNotNull("Display name should not be null", displayName);
        assertFalse("Display name should not be empty", displayName.isEmpty());
    }

    // -----------------------------------------------------------------------
    // Icon file name (hidden action)
    // -----------------------------------------------------------------------

    @Test
    public void testIconFileName() {
        OmpassCallbackAction action = findCallbackAction();
        assertNotNull("OmpassCallbackAction should be registered", action);

        assertNull("Icon file name should be null so the action is hidden from the sidebar",
                action.getIconFileName());
    }

    // -----------------------------------------------------------------------
    // Registered as Jenkins extension
    // -----------------------------------------------------------------------

    @Test
    public void testRegisteredAsExtension() {
        OmpassCallbackAction action = findCallbackAction();
        assertNotNull("OmpassCallbackAction must be registered as a Jenkins extension " +
                "(annotated with @Extension and implementing UnprotectedRootAction)", action);
        assertTrue("Should implement UnprotectedRootAction",
                action instanceof UnprotectedRootAction);
    }

    // -----------------------------------------------------------------------
    // URL consistency with OmpassFilter bypass list
    // -----------------------------------------------------------------------

    @Test
    public void testUrlNameMatchesFilterBypassList() {
        OmpassCallbackAction action = findCallbackAction();
        assertNotNull(action);

        String callbackUrl = "/" + action.getUrlName();

        // Verify the filter bypasses the callback URL so the authentication
        // flow does not create an infinite redirect loop.
        OmpassGlobalConfig config = OmpassGlobalConfig.get();
        assertNotNull(config);
        config.setEnableOmpass2fa(true);
        config.save();

        OmpassFilter filter = new OmpassFilter();

        hudson.model.User mockUser = org.mockito.Mockito.mock(hudson.model.User.class);
        org.mockito.Mockito.when(mockUser.getId()).thenReturn("testuser");

        javax.servlet.http.HttpSession mockSession =
                org.mockito.Mockito.mock(javax.servlet.http.HttpSession.class);
        org.mockito.Mockito.when(mockSession.getAttribute("testuser_OMPASS_2FA_VERIFIED"))
                .thenReturn(null);

        boolean bypassed = filter.byPass2FA(mockUser, callbackUrl + "/verify", mockSession);
        assertTrue("Filter must bypass the callback URL to avoid redirect loops", bypassed);
    }

    // -----------------------------------------------------------------------
    // OmpassAuthAction consistency check
    // -----------------------------------------------------------------------

    @Test
    public void testAuthActionRegisteredAlongside() {
        // Verify OmpassAuthAction is also registered, since the callback
        // depends on the auth flow initiating first.
        OmpassAuthAction authAction = null;
        for (UnprotectedRootAction rootAction :
                j.getInstance().getExtensionList(UnprotectedRootAction.class)) {
            if (rootAction instanceof OmpassAuthAction) {
                authAction = (OmpassAuthAction) rootAction;
                break;
            }
        }
        assertNotNull("OmpassAuthAction should be registered alongside OmpassCallbackAction",
                authAction);
        assertEquals("ompassAuth", authAction.getUrlName());
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Finds the OmpassCallbackAction from the Jenkins extension registry.
     */
    private OmpassCallbackAction findCallbackAction() {
        for (UnprotectedRootAction rootAction :
                j.getInstance().getExtensionList(UnprotectedRootAction.class)) {
            if (rootAction instanceof OmpassCallbackAction) {
                return (OmpassCallbackAction) rootAction;
            }
        }
        return null;
    }
}
