package io.jenkins.plugins.ompass;

import hudson.model.UnprotectedRootAction;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link OmpassCallbackAction} URL mapping, display properties,
 * and registration as a Jenkins extension.
 *
 * Full integration testing of the callback token verification flow requires
 * a running OMPASS server, so these tests focus on what can be verified
 * without external dependencies: URL name, display name, icon visibility,
 * and consistent registration with the filter's bypass URL list.
 */
@WithJenkins
public class OmpassCallbackActionTest {

    // -----------------------------------------------------------------------
    // URL name
    // -----------------------------------------------------------------------

    @Test
    public void testUrlName(JenkinsRule j) {
        OmpassCallbackAction action = findCallbackAction(j);
        assertNotNull(action, "OmpassCallbackAction should be registered as an extension");

        assertEquals("ompassCallback", action.getUrlName(),
                "URL name should be 'ompassCallback'");
    }

    // -----------------------------------------------------------------------
    // Display name
    // -----------------------------------------------------------------------

    @Test
    public void testDisplayName(JenkinsRule j) {
        OmpassCallbackAction action = findCallbackAction(j);
        assertNotNull(action, "OmpassCallbackAction should be registered");

        String displayName = action.getDisplayName();
        assertNotNull(displayName, "Display name should not be null");
        assertFalse(displayName.isEmpty(), "Display name should not be empty");
    }

    // -----------------------------------------------------------------------
    // Icon file name (hidden action)
    // -----------------------------------------------------------------------

    @Test
    public void testIconFileName(JenkinsRule j) {
        OmpassCallbackAction action = findCallbackAction(j);
        assertNotNull(action, "OmpassCallbackAction should be registered");

        assertNull(action.getIconFileName(),
                "Icon file name should be null so the action is hidden from the sidebar");
    }

    // -----------------------------------------------------------------------
    // Registered as Jenkins extension
    // -----------------------------------------------------------------------

    @Test
    public void testRegisteredAsExtension(JenkinsRule j) {
        OmpassCallbackAction action = findCallbackAction(j);
        assertNotNull(action, "OmpassCallbackAction must be registered as a Jenkins extension " +
                "(annotated with @Extension and implementing UnprotectedRootAction)");
        assertTrue(action instanceof UnprotectedRootAction,
                "Should implement UnprotectedRootAction");
    }

    // -----------------------------------------------------------------------
    // URL consistency with OmpassFilter bypass list
    // -----------------------------------------------------------------------

    @Test
    public void testUrlNameMatchesFilterBypassList(JenkinsRule j) {
        OmpassCallbackAction action = findCallbackAction(j);
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

        jakarta.servlet.http.HttpSession mockSession =
                org.mockito.Mockito.mock(jakarta.servlet.http.HttpSession.class);
        org.mockito.Mockito.when(mockSession.getAttribute("testuser_OMPASS_2FA_VERIFIED"))
                .thenReturn(null);

        boolean bypassed = filter.byPass2FA(mockUser, callbackUrl + "/verify", mockSession);
        assertTrue(bypassed, "Filter must bypass the callback URL to avoid redirect loops");
    }

    // -----------------------------------------------------------------------
    // OmpassAuthAction consistency check
    // -----------------------------------------------------------------------

    @Test
    public void testAuthActionRegisteredAlongside(JenkinsRule j) {
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
        assertNotNull(authAction,
                "OmpassAuthAction should be registered alongside OmpassCallbackAction");
        assertEquals("ompassAuth", authAction.getUrlName());
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Finds the OmpassCallbackAction from the Jenkins extension registry.
     */
    private OmpassCallbackAction findCallbackAction(JenkinsRule j) {
        for (UnprotectedRootAction rootAction :
                j.getInstance().getExtensionList(UnprotectedRootAction.class)) {
            if (rootAction instanceof OmpassCallbackAction) {
                return (OmpassCallbackAction) rootAction;
            }
        }
        return null;
    }
}
