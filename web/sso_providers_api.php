<?php
/**
 * SSO Providers API Endpoint
 * Returns active SSO providers for client-side display
 */

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

require_once 'security_config.php';
require_once 'sso/SSOManager.php';

try {
    // Initialize SSO manager
    SSOManager::init();
    
    // Get active providers
    $providers = SSOManager::getActiveProviders();
    
    // Filter providers for public display
    $public_providers = [];
    foreach ($providers as $provider) {
        // Only show active providers
        if (!$provider['is_active']) {
            continue;
        }
        
        // Map provider icons
        $icon_map = [
            'google' => 'fab fa-google',
            'microsoft' => 'fab fa-microsoft',
            'azure' => 'fab fa-microsoft',
            'okta' => 'fas fa-shield-alt',
            'auth0' => 'fas fa-lock',
            'github' => 'fab fa-github',
            'gitlab' => 'fab fa-gitlab',
            'saml' => 'fas fa-certificate',
            'oidc' => 'fas fa-id-card',
            'oauth2' => 'fas fa-key'
        ];
        
        // Determine icon based on provider name
        $provider_key = strtolower($provider['name']);
        $icon = $icon_map[$provider_key] ?? 'fas fa-sign-in-alt';
        
        // Check for specific provider patterns
        if (stripos($provider['name'], 'google') !== false) {
            $icon = $icon_map['google'];
        } elseif (stripos($provider['name'], 'microsoft') !== false || stripos($provider['name'], 'azure') !== false) {
            $icon = $icon_map['microsoft'];
        } elseif (stripos($provider['name'], 'okta') !== false) {
            $icon = $icon_map['okta'];
        } elseif (stripos($provider['name'], 'auth0') !== false) {
            $icon = $icon_map['auth0'];
        } elseif (stripos($provider['name'], 'github') !== false) {
            $icon = $icon_map['github'];
        } elseif (stripos($provider['name'], 'gitlab') !== false) {
            $icon = $icon_map['gitlab'];
        } elseif ($provider['provider_type'] === 'saml2') {
            $icon = $icon_map['saml'];
        } elseif ($provider['provider_type'] === 'oidc') {
            $icon = $icon_map['oidc'];
        }
        
        $public_providers[] = [
            'id' => $provider['id'],
            'name' => $provider['name'],
            'display_name' => $provider['display_name'] ?? $provider['name'],
            'provider_type' => $provider['type'],
            'icon' => $icon,
            'admin_only' => (bool)($provider['admin_only'] ?? false),
            'domain_hint' => $provider['domain_match'] ?? ''
        ];
    }
    
    echo json_encode([
        'success' => true,
        'providers' => $public_providers,
        'count' => count($public_providers)
    ]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Unable to load SSO providers',
        'debug' => $_GET['debug'] ? $e->getMessage() : null
    ]);
}
?>