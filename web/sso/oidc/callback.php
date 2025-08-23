<?php
/**
 * OIDC/OAuth2 Callback Handler
 * Processes authorization codes from OIDC/OAuth2 providers
 */

// Disable error display to prevent any output before headers
ini_set('display_errors', 0);
ini_set('log_errors', 1);

session_start();

require_once '../../security_config.php';
require_once '../../security_hardened.php';
require_once '../SSOManager.php';
require_once '../OIDCHandler.php';
require_once '../../auth.php';

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

try {
    // Validate request method
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
        throw new Exception('Invalid request method');
    }
    
    // Rate limiting
    $client_ip = $_SERVER['REMOTE_ADDR'];
    if (!HardcoreSecurityManager::checkRateLimit($client_ip . '_oidc_callback', 10, 300)) {
        http_response_code(429);
        die('Rate limit exceeded');
    }
    
    // Get authorization code and state
    $code = $_GET['code'] ?? null;
    $state = $_GET['state'] ?? null;
    $error = $_GET['error'] ?? null;
    $error_description = $_GET['error_description'] ?? null;
    
    // Handle OAuth2 errors
    if (!empty($error)) {
        $error_msg = 'OAuth2 Error: ' . $error;
        if (!empty($error_description)) {
            $error_msg .= ' - ' . $error_description;
        }
        throw new Exception($error_msg);
    }
    
    if (empty($code)) {
        throw new Exception('Missing authorization code');
    }
    
    // Validate session state
    $expected_state = $_SESSION['sso_state'] ?? null;
    
    // Debug logging
    error_log("OIDC Callback - Received state: " . ($state ?? 'NULL'));
    error_log("OIDC Callback - Expected state: " . ($expected_state ?? 'NULL'));
    error_log("OIDC Callback - Session ID: " . session_id());
    error_log("OIDC Callback - Session data: " . json_encode([
        'sso_state' => $_SESSION['sso_state'] ?? 'not set',
        'sso_provider_id' => $_SESSION['sso_provider_id'] ?? 'not set',
        'sso_start_time' => $_SESSION['sso_start_time'] ?? 'not set'
    ]));
    
    if (empty($expected_state) || $state !== $expected_state) {
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
    $handler = new OIDCHandler($provider_id);
    
    // Set session data for handler
    $handler->setSessionData([
        'state' => $expected_state,
        'nonce' => $_SESSION['sso_nonce'] ?? null,
        'code_verifier' => $_SESSION['sso_code_verifier'] ?? null
    ]);
    
    // Process callback
    error_log("OIDC Callback - About to process callback");
    $user_data = $handler->processCallback($code, $state);
    error_log("OIDC Callback - Callback processed successfully");
    
    // Complete SSO authentication  
    error_log("OIDC Callback - About to complete SSO authentication");
    
    try {
        $result = SSOManager::completeSSOAuthentication(
            $provider_id,
            $user_data['external_id'],
            $user_data['attributes'],
            [
                'access_token' => $user_data['access_token'] ?? null,
                'refresh_token' => $user_data['refresh_token'] ?? null,
                'auth_method' => 'oidc'
            ]
        );
        error_log("OIDC Callback - SSO authentication completed");
        error_log("OIDC Callback - Result: " . json_encode($result));
        
        // Handle authentication result
        if ($result['success']) {
            error_log("OIDC Callback - Authentication successful, requires_2fa: " . ($result['requires_2fa'] ? 'true' : 'false'));
            if ($result['requires_2fa']) {
                // Redirect to unified 2FA verification
                $return_url = $_SESSION['sso_return_url'] ?? '/index.html';
                error_log("OIDC Callback - Redirecting to 2FA verification with return_url: $return_url");
                header('Location: /verify_2fa.php?return_url=' . urlencode($return_url));
                exit;
            } else {
                // Complete authentication
                $return_url = $_SESSION['sso_return_url'] ?? '/index.html';
                unset($_SESSION['sso_return_url']);
                
                // Set success flag for frontend
                $separator = strpos($return_url, '?') !== false ? '&' : '?';
                error_log("OIDC Callback - Redirecting to return_url: " . $return_url . $separator . 'sso_login=success');
                header('Location: ' . $return_url . $separator . 'sso_login=success');
                exit;
            }
        } else {
            throw new Exception($result['message'] ?? 'Authentication failed');
        }
        
    } catch (Exception $e) {
        error_log("OIDC Callback - SSO authentication failed: " . $e->getMessage());
        throw $e;
    }
    
    // Clean up SSO session data
    unset($_SESSION['sso_state'], $_SESSION['sso_nonce'], $_SESSION['sso_provider_id']);
    unset($_SESSION['sso_start_time'], $_SESSION['sso_code_verifier']);
    
} catch (Exception $e) {
    // Log error
    logSecurityEvent('OIDC_CALLBACK_ERROR', 'OIDC callback error: ' . $e->getMessage(), 'HIGH', [
        'provider_id' => $_SESSION['sso_provider_id'] ?? 'unknown',
        'error' => $e->getMessage(),
        'has_code' => !empty($code),
        'has_state' => !empty($state),
        'oauth_error' => $error ?? 'none'
    ]);
    
    // Session cleanup already handled in main execution flow
    
    // Redirect with error
    $return_url = $_SESSION['sso_return_url'] ?? '/index.html';
    unset($_SESSION['sso_return_url']);
    
    $error_msg = urlencode('OIDC authentication failed: ' . $e->getMessage());
    $separator = strpos($return_url, '?') !== false ? '&' : '?';
    header('Location: ' . $return_url . $separator . 'sso_error=' . $error_msg);
}
?>