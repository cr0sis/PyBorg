<?php
/**
 * SAML Single Logout Service (SLS)
 * Handles SAML logout requests and responses
 */

require_once '../../security_config.php';
require_once '../SSOManager.php';
require_once '../SAMLHandler.php';

// Initialize security
initSecureSession();
setSecurityHeaders();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Method not allowed');
}

try {
    // Check if user is logged in with SSO
    if (!isset($_SESSION['sso_provider_id'])) {
        throw new Exception('No SSO session found');
    }
    
    $provider_id = $_SESSION['sso_provider_id'];
    $provider = SSOManager::getProvider($provider_id);
    
    if (!$provider || $provider['type'] !== 'saml') {
        throw new Exception('Invalid SAML provider');
    }
    
    // Process logout request or response
    if (isset($_POST['SAMLRequest'])) {
        // This is a logout request from the IdP
        $saml_request = $_POST['SAMLRequest'];
        $relay_state = $_POST['RelayState'] ?? '';
        
        SSOManager::logSSOEvent('SAML_LOGOUT_REQUEST', $provider_id, $_SESSION['user_id'] ?? null,
            'Received SAML logout request from IdP', 'LOW');
        
        // Perform local logout
        $username = $_SESSION['username'] ?? 'unknown';
        
        // Remove from session monitoring
        require_once '../../session_monitor.php';
        SessionMonitor::removeSession();
        
        // Clear session
        $_SESSION = array();
        
        // Delete session cookie
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        
        session_destroy();
        
        SSOManager::logSSOEvent('SAML_LOGOUT_COMPLETE', $provider_id, null,
            "User $username logged out via SAML SLO", 'LOW');
        
        // Send logout response to IdP
        // TODO: Implement proper SAML logout response
        echo '<!DOCTYPE html>
<html>
<head>
    <title>Logout Complete</title>
    <meta charset="utf-8">
</head>
<body>
    <div style="text-align: center; padding: 50px; font-family: Arial, sans-serif;">
        <h2>Logout Complete</h2>
        <p>You have been successfully logged out.</p>
        <a href="/auth.php">Return to Login</a>
    </div>
</body>
</html>';
        
    } else if (isset($_POST['SAMLResponse'])) {
        // This is a logout response from the IdP
        $saml_response = $_POST['SAMLResponse'];
        
        SSOManager::logSSOEvent('SAML_LOGOUT_RESPONSE', $provider_id, null,
            'Received SAML logout response from IdP', 'LOW');
        
        // Redirect to login page
        header('Location: /auth.php?msg=' . urlencode('You have been logged out'));
        exit;
        
    } else {
        throw new Exception('No SAML logout data provided');
    }
    
} catch (Exception $e) {
    SSOManager::logSSOEvent('SAML_SLS_ERROR', $_SESSION['sso_provider_id'] ?? null, null,
        "SAML SLS error: " . $e->getMessage(), 'HIGH');
    
    // Redirect to login with error
    $error_msg = urlencode('Logout error: ' . $e->getMessage());
    header("Location: /auth.php?error=$error_msg");
    exit;
}
?>