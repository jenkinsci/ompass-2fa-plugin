package io.jenkins.plugins.ompass;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * User property that tracks whether a Jenkins user is registered with the OMPASS 2FA system.
 * This property is stored per user and persisted as part of the user configuration.
 */
public class OmpassUserProperty extends UserProperty {

    private boolean ompassRegistered;

    @DataBoundConstructor
    public OmpassUserProperty() {
        this.ompassRegistered = false;
    }

    public boolean isOmpassRegistered() {
        return ompassRegistered;
    }

    public void setOmpassRegistered(boolean ompassRegistered) {
        this.ompassRegistered = ompassRegistered;
    }

    /**
     * Returns the user that owns this property.
     */
    public User getOwner() {
        return user;
    }

    @Extension
    public static class DescriptorImpl extends UserPropertyDescriptor {

        @Override
        public String getDisplayName() {
            return "OMPASS 2FA";
        }

        @Override
        public UserProperty newInstance(User user) {
            return new OmpassUserProperty();
        }
    }
}
