<?php
/**
 * SSO Authentication Entry Point
 * Initiates SSO authentication flow for specified provider
 */

session_start();

require_once 'security_config.php';
require_once 'security_hardened.php';
require_once 'sso/SSOManager.php';
require_once 'crypto_utils.php';

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

try {
    // Rate limiting for SSO attempts
    $client_ip = $_SERVER['REMOTE_ADDR'];
    if (!HardcoreSecurityManager::checkRateLimit($client_ip . '_sso', 5, 300)) { // 5 attempts per 5 minutes
        http_response_code(429);
        die('Rate limit exceeded for SSO authentication');
    }
    
    // Get provider ID
    $provider_id = $_GET['provider'] ?? null;
    if (empty($provider_id) || !is_numeric($provider_id)) {
        throw new Exception('Invalid provider ID');
    }
    
    // Initialize SSO manager
    SSOManager::init();
    
    // Get provider configuration
    $provider = SSOManager::getProvider($provider_id);
    if (!$provider || !$provider['is_active']) {
        throw new Exception('Provider not found or inactive');
    }
    
    // Check admin-only providers
    if ($provider['admin_only'] && !isLoggedInAdmin()) {
        throw new Exception('This SSO provider is restricted to administrators only');
    }
    
    // Generate secure state and nonce for CSRF protection
    $state = CryptoUtils::generateSecureRandom(32);
    $nonce = CryptoUtils::generateSecureRandom(32);
    
    // Store SSO session data
    $_SESSION['sso_state'] = $state;
    $_SESSION['sso_nonce'] = $nonce;
    $_SESSION['sso_provider_id'] = $provider_id;
    $_SESSION['sso_start_time'] = time();
    $_SESSION['sso_return_url'] = $_GET['return_url'] ?? '/index.html';
    
    // Debug logging
    error_log("SSO Auth - Generated state: $state");
    error_log("SSO Auth - Provider ID: $provider_id");
    error_log("SSO Auth - Session ID: " . session_id());
    
    // Generate PKCE parameters for OIDC
    if (in_array($provider['type'], ['oidc', 'oauth2'])) {
        $code_verifier = CryptoUtils::generateSecureRandom(128, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~');
        $_SESSION['sso_code_verifier'] = $code_verifier;
    }
    
    // Create session data for handler
    $session_data = [
        'state' => $state,
        'nonce' => $nonce,
        'provider_id' => $provider_id,
        'code_verifier' => $_SESSION['sso_code_verifier'] ?? null,
        'return_url' => $_SESSION['sso_return_url']
    ];
    
    // Route to appropriate handler
    switch ($provider['type']) {
        case 'saml':
            require_once 'sso/SAMLHandler.php';
            $handler = new SAMLHandler($provider_id);
            $auth_request = $handler->createAuthRequest($session_data);
            
            // Redirect to SAML SSO
            if ($auth_request['binding'] === 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST') {
                // HTTP-POST binding - show form
                echo generateSAMLPostForm($auth_request);
            } else {
                // HTTP-Redirect binding
                $redirect_url = $auth_request['sso_url'] . '?SAMLRequest=' . urlencode($auth_request['request']);
                if (!empty($auth_request['relay_state'])) {
                    $redirect_url .= '&RelayState=' . urlencode($auth_request['relay_state']);
                }
                header('Location: ' . $redirect_url);
            }
            break;
            
        case 'oidc':
        case 'oauth2':
            require_once 'sso/OIDCHandler.php';
            $handler = new OIDCHandler($provider_id);
            $auth_request = $handler->createAuthRequest($session_data);
            
            // Redirect to OIDC authorization endpoint
            header('Location: ' . $auth_request['auth_url']);
            break;
            
        default:
            throw new Exception('Unsupported provider type: ' . $provider['type']);
    }
    
    // Log SSO initiation
    logSecurityEvent('SSO_AUTH_INITIATED', "SSO authentication initiated for provider: {$provider['name']}", 'LOW', [
        'provider_id' => $provider_id,
        'provider_type' => $provider['type'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ]);
    
} catch (Exception $e) {
    // Log error
    logSecurityEvent('SSO_AUTH_ERROR', "SSO authentication error: " . $e->getMessage(), 'HIGH', [
        'provider_id' => $provider_id ?? 'unknown',
        'error' => $e->getMessage()
    ]);
    
    // Clean up session
    unset($_SESSION['sso_state'], $_SESSION['sso_nonce'], $_SESSION['sso_provider_id']);
    unset($_SESSION['sso_start_time'], $_SESSION['sso_code_verifier'], $_SESSION['sso_return_url']);
    
    // Redirect with error
    $error_msg = urlencode('SSO authentication failed: ' . $e->getMessage());
    $return_url = $_SESSION['sso_return_url'] ?? '/index.html';
    header('Location: ' . $return_url . '?sso_error=' . $error_msg);
}

/**
 * Generate SAML POST form for HTTP-POST binding
 */
function generateSAMLPostForm($auth_request) {
    $saml_request = htmlspecialchars($auth_request['request'], ENT_QUOTES | ENT_HTML5);
    $relay_state = htmlspecialchars($auth_request['relay_state'] ?? '', ENT_QUOTES | ENT_HTML5);
    $sso_url = htmlspecialchars($auth_request['sso_url'], ENT_QUOTES | ENT_HTML5);
    
    return '<!DOCTYPE html>
<html>
<head>
    <title>Redirecting to SSO Provider</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
            background: #f8fafc; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            min-height: 100vh; 
            margin: 0; 
        }
        .redirect-container { 
            text-align: center; 
            background: white; 
            padding: 2rem; 
            border-radius: 12px; 
            box-shadow: 0 4px 20px rgba(0,0,0,0.1); 
            max-width: 400px; 
        }
        .spinner { 
            border: 3px solid #e2e8f0; 
            border-top: 3px solid #3b82f6; 
            border-radius: 50%; 
            width: 40px; 
            height: 40px; 
            animation: spin 1s linear infinite; 
            margin: 0 auto 1rem; 
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .btn { 
            background: #3b82f6; 
            color: white; 
            border: none; 
            padding: 12px 24px; 
            border-radius: 8px; 
            font-size: 14px; 
            cursor: pointer; 
            margin-top: 1rem; 
        }
        .btn:hover { background: #2563eb; }
    </style>
</head>
<body>
    <div class="redirect-container">
        <div class="spinner"></div>
        <h3>Connecting to SSO Provider</h3>
        <p>Please wait while we redirect you to your identity provider...</p>
        
        <form id="samlForm" method="post" action="' . $sso_url . '" style="display: none;">
            <input type="hidden" name="SAMLRequest" value="' . $saml_request . '">
            ' . ($relay_state ? '<input type="hidden" name="RelayState" value="' . $relay_state . '">' : '') . '
        </form>
        
        <button class="btn" onclick="document.getElementById(\'samlForm\').submit();">
            Continue Manually
        </button>
    </div>
    
    <script>
        // Auto-submit form after 2 seconds
        setTimeout(function() {
            document.getElementById("samlForm").submit();
        }, 2000);
    </script>
</body>
</html>';
}

/**
 * Check if user is logged in admin
 */
function isLoggedInAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true;
}
?>