<?php
/**
 * SAML Assertion Consumer Service (ACS)
 * Processes SAML responses from identity providers
 */

session_start();

require_once '../../security_config.php';
require_once '../SSOManager.php';
require_once '../SAMLHandler.php';
require_once '../../auth.php';

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

try {
    // Validate request method
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Invalid request method');
    }
    
    // Rate limiting
    $client_ip = $_SERVER['REMOTE_ADDR'];
    if (!checkRateLimit($client_ip . '_saml_acs', 10, 300)) {
        http_response_code(429);
        die('Rate limit exceeded');
    }
    
    // Get SAML response and relay state
    $saml_response = $_POST['SAMLResponse'] ?? null;
    $relay_state = $_POST['RelayState'] ?? null;
    
    if (empty($saml_response)) {
        throw new Exception('Missing SAML response');
    }
    
    // Validate session state
    $expected_state = $_SESSION['sso_state'] ?? null;
    if (empty($expected_state) || $relay_state !== $expected_state) {
        throw new Exception('Invalid or missing state parameter - possible CSRF attack');
    }
    
    // Check session timeout (10 minutes max)
    $start_time = $_SESSION['sso_start_time'] ?? 0;
    if ((time() - $start_time) > 600) {
        throw new Exception('SSO session expired');
    }
    
    $provider_id = $_SESSION['sso_provider_id'] ?? null;
    if (empty($provider_id)) {
        throw new Exception('Missing provider ID in session');
    }
    
    // Initialize SSO manager and handler
    SSOManager::init();
    $handler = new SAMLHandler($provider_id);
    
    // Process SAML response
    $user_data = $handler->processResponse($saml_response, $relay_state);
    
    // Complete SSO authentication
    $result = SSOManager::completeSSOAuthentication(
        $provider_id,
        $user_data['external_id'],
        $user_data['attributes'],
        [
            'session_index' => $user_data['session_index'] ?? null,
            'auth_method' => 'saml2'
        ]
    );
    
    // Clean up SSO session data
    unset($_SESSION['sso_state'], $_SESSION['sso_nonce'], $_SESSION['sso_provider_id']);
    unset($_SESSION['sso_start_time'], $_SESSION['sso_code_verifier']);
    
    // Handle authentication result
    if ($result['success']) {
        if ($result['requires_2fa']) {
            // Redirect to 2FA verification
            $return_url = $_SESSION['sso_return_url'] ?? '/index.html';
            header('Location: /verify_sso_2fa.php?return_url=' . urlencode($return_url));
        } else {
            // Complete authentication
            $return_url = $_SESSION['sso_return_url'] ?? '/index.html';
            unset($_SESSION['sso_return_url']);
            
            // Set success flag for frontend
            $separator = strpos($return_url, '?') !== false ? '&' : '?';
            header('Location: ' . $return_url . $separator . 'sso_login=success');
        }
    } else {
        throw new Exception($result['message'] ?? 'Authentication failed');
    }
    
} catch (Exception $e) {
    // Log error
    logSecurityEvent('SAML_ACS_ERROR', 'SAML ACS error: ' . $e->getMessage(), 'HIGH', [
        'provider_id' => $_SESSION['sso_provider_id'] ?? 'unknown',
        'error' => $e->getMessage(),
        'has_response' => !empty($saml_response),
        'has_state' => !empty($relay_state)
    ]);
    
    // Clean up session
    unset($_SESSION['sso_state'], $_SESSION['sso_nonce'], $_SESSION['sso_provider_id']);
    unset($_SESSION['sso_start_time'], $_SESSION['sso_code_verifier']);
    
    // Redirect with error
    $return_url = $_SESSION['sso_return_url'] ?? '/index.html';
    unset($_SESSION['sso_return_url']);
    
    $error_msg = urlencode('SAML authentication failed: ' . $e->getMessage());
    $separator = strpos($return_url, '?') !== false ? '&' : '?';
    header('Location: ' . $return_url . $separator . 'sso_error=' . $error_msg);
}
?>