<?php
/**
 * SAML Service Provider Metadata
 * Provides SP metadata for IdP configuration
 */

require_once '../../security_config.php';
require_once '../SAMLHandler.php';

header('Content-Type: application/xml');

try {
    // For metadata, we can use any SAML provider configuration
    // The metadata is the same regardless of the specific provider
    $providers = SSOManager::getActiveProviders();
    $saml_provider = null;
    
    foreach ($providers as $provider) {
        if ($provider['type'] === 'saml') {
            $saml_provider = $provider;
            break;
        }
    }
    
    if (!$saml_provider) {
        http_response_code(404);
        exit('<?xml version="1.0"?><error>No SAML providers configured</error>');
    }
    
    $handler = new SAMLHandler($saml_provider['id']);
    echo $handler->generateMetadata();
    
} catch (Exception $e) {
    http_response_code(500);
    echo '<?xml version="1.0"?><error>Metadata generation failed</error>';
    error_log("SAML metadata error: " . $e->getMessage());
}
?>