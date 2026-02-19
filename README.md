<p align="center">
  <img src="src/main/webapp/images/ompass-icon.png" alt="OMPASS" width="80" />
</p>

<h1 align="center">OMPASS 2FA Authentication Plugin for Jenkins</h1>

A Jenkins plugin that adds OMPASS-based two-factor authentication (2FA) to your Jenkins instance. After users log in with their primary credentials, they are required to complete a second authentication step through the OMPASS platform before accessing Jenkins resources.

## Getting Started

Before using this plugin, you need an OMPASS account with a configured application (Client ID and Secret Key).

1. Sign up at **[https://ompasscloud.com/en/](https://ompasscloud.com/en/)**.
2. Create an application in the OMPASS portal to obtain your **Client ID** and **Secret Key**.
3. Install and configure this plugin with those credentials (see [Configuration](#configuration)).

## Features

- **Global 2FA enforcement**: Enable or disable OMPASS 2FA for all users from a single configuration page.
- **Transparent filter-based interception**: A servlet filter intercepts all requests and redirects unauthenticated-2FA users to the OMPASS authentication flow. No changes to the Jenkins security realm are required.
- **Popup-based authentication**: The OMPASS authentication UI opens in a popup window. Once the user completes 2FA, the popup closes automatically and the parent page redirects to the original destination.
- **Token verification**: Authentication tokens are verified server-side against the OMPASS API to prevent tampering.
- **Session persistence**: Once a user completes 2FA, their session is marked as verified for the remainder of the session.
- **Relay state preservation**: The original URL the user was trying to access is preserved and restored after successful 2FA.
- **Connection testing**: Administrators can test the connection to the OMPASS server from the configuration page before enabling 2FA.
- **Multi-language support**: The OMPASS authentication prompt can be displayed in English or Korean.
- **Secret key encryption**: The OMPASS secret key is stored using Jenkins' built-in `Secret` encryption, not as plain text.
- **Fail-open strategy**: If the 2FA filter encounters an unexpected error, the request is allowed through to avoid locking users out.
- **Emergency bypass**: A system property (`ompass.2fa.bypass=true`) allows administrators to disable 2FA without accessing the Jenkins UI.

## Requirements

| Requirement     | Version          |
|-----------------|------------------|
| Jenkins         | 2.361.4 or later |
| Java            | JDK 11 or later  |
| OMPASS Server   | OMPASS interface server with a configured application (Client ID and Secret Key) |

## Installation

### Option 1: Upload HPI file

1. Build the plugin (see [Build Instructions](#build-instructions)) or obtain the `.hpi` file.
2. In Jenkins, navigate to **Manage Jenkins > Plugins > Advanced settings**.
3. Under **Deploy Plugin**, click **Choose File** and select the `.hpi` file.
4. Click **Deploy** and restart Jenkins when prompted.

### Option 2: Manual copy

1. Copy the `.hpi` file to the `$JENKINS_HOME/plugins/` directory.
2. Restart Jenkins.

## Configuration

After installing the plugin, configure it from the Jenkins management page:

1. Navigate to **Manage Jenkins > OMPASS 2FA Configuration** (under the Security section).
2. Fill in the following fields:

| Field              | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| Enable OMPASS 2FA  | Toggle to enable or disable 2FA enforcement for all users.                 |
| OMPASS Server URL  | The URL of your OMPASS interface server (e.g., `https://ompass.example.com`). Do not include a trailing slash. |
| Client ID          | The Client ID provided by OMPASS for this Jenkins application.             |
| Secret Key         | The Secret Key provided by OMPASS for this Jenkins application.            |
| Language           | The language for OMPASS authentication prompts (`EN` for English, `KR` for Korean). |

3. Click **Test Connection** to verify that Jenkins can communicate with the OMPASS server.
4. Click **Save** to apply the configuration.

<!-- Screenshot placeholder: configuration page -->
<!-- ![OMPASS 2FA Configuration](docs/images/configuration.png) -->

## Authentication Flow

The plugin operates through the following flow:

1. **User logs in** to Jenkins with their primary credentials (username/password, LDAP, SSO, etc.).
2. **Filter intercepts** the request. The `OmpassFilter` checks whether the user has completed 2FA for this session.
3. **Redirect to auth page**. If 2FA is not yet verified, the user is redirected to `/ompassAuth/`, and their original URL is saved as the relay state.
4. **OMPASS auth starts**. The `OmpassAuthAction` calls the OMPASS server's `startAuth` API and receives an OMPASS authentication URL.
5. **Popup opens**. The OMPASS authentication URL opens in a popup window where the user completes 2FA (e.g., mobile push notification, biometric verification).
6. **Callback received**. After successful authentication, the OMPASS server redirects the popup to `/ompassCallback/` with a verification token.
7. **Token verified**. The `OmpassCallbackAction` verifies the token against the OMPASS server's `verifyToken` API.
8. **Session marked**. On successful verification, the user's session is marked with a `{userId}_OMPASS_2FA_VERIFIED` attribute.
9. **Popup notifies parent**. The popup window sends a `postMessage` to the parent window indicating success.
10. **Redirect to destination**. The parent page redirects the user to their original URL (relay state).

### URLs Bypassed by the Filter

The following URL patterns are excluded from 2FA enforcement to avoid breaking Jenkins functionality:

- **Jenkins system URLs**: `/logout`, `/login`, `/adjuncts`, `/static`, `/crumbIssuer`, `/theme`
- **Plugin URLs**: `/ompassAuth`, `/ompassCallback`, `/ompass2fa-config`
- **API/CLI endpoints**: `/api/`, `/cli`
- **Static resources**: `.css`, `.js`, `.png`, `.ico`, `.gif`, `.jpg`, `.jpeg`, `.svg`, `.woff`, `.woff2`, `.ttf`, `.eot`

## Troubleshooting

### Emergency Bypass

If you are locked out of Jenkins due to a 2FA misconfiguration, you can bypass 2FA by setting a JVM system property:

```bash
# Add to Jenkins startup arguments
-Dompass.2fa.bypass=true
```

Or set it in the `JAVA_OPTS` or `JENKINS_JAVA_OPTIONS` environment variable before starting Jenkins:

```bash
export JAVA_OPTS="-Dompass.2fa.bypass=true"
```

Once you regain access, disable 2FA from the configuration page and remove the system property.

### Common Errors

| Problem | Possible Cause | Solution |
|---------|---------------|----------|
| "OMPASS configuration is not available" | Plugin not initialized or config file corrupted | Restart Jenkins and reconfigure the plugin |
| "Connection failed" on Test Connection | Incorrect OMPASS Server URL or network issue | Verify the URL is correct, accessible from the Jenkins server, and does not have a trailing slash |
| Popup blocked by browser | Browser popup blocker | Allow popups for the Jenkins URL, or click the "Authenticate with OMPASS" button manually |
| "Token verification failed" | Clock skew, expired token, or incorrect credentials | Verify the Client ID and Secret Key match the OMPASS application configuration. Check server time synchronization. |
| 2FA prompt appears on every request | Session not being persisted | Check that Jenkins is not using a session-less or stateless authentication mechanism. Ensure cookies are enabled in the browser. |
| "Missing authentication token" | Callback received without required parameters | This may indicate a misconfigured callback URL in the OMPASS application settings |

### Logging

To enable detailed logging for the OMPASS 2FA plugin:

1. Navigate to **Manage Jenkins > System Log**.
2. Click **Add new log recorder** and name it `OMPASS 2FA`.
3. Add the logger `io.jenkins.plugins.ompass` with log level `FINE`.
4. Save and reproduce the issue, then review the log entries.

## Build Instructions

### Prerequisites

- **JDK 11** (required - builds fail on JDK 17+ due to Groovy compatibility issues)
- Apache Maven 3.x

### Build

```bash
# macOS (specify JDK 11)
JAVA_HOME=$(/usr/libexec/java_home -v 11) mvn clean package

# Linux (if JDK 11 is the default)
mvn clean package

# Skip tests
JAVA_HOME=$(/usr/libexec/java_home -v 11) mvn clean package -DskipTests

# Release build (remove SNAPSHOT)
JAVA_HOME=$(/usr/libexec/java_home -v 11) mvn clean package -Dchangelist=
```

Build output: `target/ompass-2fa.hpi`

### Run tests

```bash
JAVA_HOME=$(/usr/libexec/java_home -v 11) mvn test
```

### Local development

```bash
# Accessible from localhost only
JAVA_HOME=$(/usr/libexec/java_home -v 11) mvn hpi:run

# Accessible from external IPs as well (e.g., 192.168.x.x)
JAVA_HOME=$(/usr/libexec/java_home -v 11) mvn hpi:run -Dhost=0.0.0.0

# Run without the /jenkins context path (root context)
JAVA_HOME=$(/usr/libexec/java_home -v 11) mvn hpi:run -Dprefix=/
```

By default, Jenkins will be available at `http://localhost:8080/jenkins/`.
With `-Dprefix=/`, it will be available at `http://localhost:8080/`.

### Jenkins Compatibility

| Jenkins Version | Compatibility |
|---|---|
| 2.361.4 ~ 2.462.x | Fully supported |
| 2.463+ (jakarta.servlet) | Requires additional modifications |

## Project Structure

```
src/main/java/io/jenkins/plugins/ompass/
  OmpassGlobalConfig.java       - Global configuration (server URL, credentials, toggle)
  OmpassGlobalConfigView.java   - Management link and configuration UI controller
  OmpassFilter.java             - Servlet filter enforcing 2FA on all requests
  OmpassAuthAction.java         - Initiates the OMPASS authentication flow
  OmpassCallbackAction.java     - Handles the OMPASS authentication callback
  OmpassClientFactory.java      - Thread-safe factory for the OMPASS SDK client
  OmpassUserProperty.java       - Per-user property tracking OMPASS registration status

src/main/resources/io/jenkins/plugins/ompass/
  OmpassAuthAction/index.jelly         - Authentication page with popup logic
  OmpassCallbackAction/index.jelly     - Callback result page (closes popup)
  OmpassGlobalConfigView/index.jelly   - Admin configuration form
  OmpassUserProperty/config.jelly      - User property display in profile
```

## License

This project is licensed under the MIT License. See [LICENSE.md](LICENSE.md) for details.

Copyright (c) 2024 OneMoreSecurity Co., Ltd.
