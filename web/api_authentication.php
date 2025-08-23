<?php
/**
 * API Authentication System - Phase 6: API Security Layer
 * Advanced authentication and authorization for API endpoints
 */

require_once 'auth.php';
require_once 'config_paths.php';
require_once 'security_middleware.php';
require_once 'input_sanitizer.php';

class APIAuthentication {
    
    private static $apiKeysFile = ConfigPaths::getStoragePath('api_keys');
    private static $apiSessionsFile = ConfigPaths::getStoragePath('api_sessions');
    private static $tokenExpiry = 3600; // 1 hour
    
    // API permission levels
    const PERMISSION_READ = 'read';
    const PERMISSION_WRITE = 'write';
    const PERMISSION_ADMIN = 'admin';
    const PERMISSION_SYSTEM = 'system';
    
    // Authentication methods
    const AUTH_SESSION = 'session';
    const AUTH_API_KEY = 'api_key';
    const AUTH_JWT_TOKEN = 'jwt_token';
    const AUTH_BEARER_TOKEN = 'bearer_token';
    
    /**
     * Authenticate API request using multiple methods
     */
    public static function authenticateRequest() {
        // Try different authentication methods
        $authMethods = [
            self::AUTH_SESSION => 'authenticateBySession',
            self::AUTH_API_KEY => 'authenticateByAPIKey',
            self::AUTH_BEARER_TOKEN => 'authenticateByBearerToken',
            self::AUTH_JWT_TOKEN => 'authenticateByJWT'
        ];
        
        foreach ($authMethods as $method => $function) {
            $result = self::$function();
            if ($result['authenticated']) {
                // Log successful authentication
                SecurityMiddleware::logSecurityEvent('API_AUTH_SUCCESS', [
                    'method' => $method,
                    'user_id' => $result['user_id'] ?? 'unknown',
                    'permissions' => $result['permissions'] ?? [],
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ], 'INFO');
                
                return $result;
            }
        }
        
        // Log failed authentication
        SecurityMiddleware::logSecurityEvent('API_AUTH_FAILED', [
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'attempted_methods' => array_keys($authMethods)
        ], 'MEDIUM');
        
        return [
            'authenticated' => false,
            'error' => 'Authentication required',
            'supported_methods' => array_keys($authMethods)
        ];
    }
    
    /**
     * Authenticate using existing session
     */
    private static function authenticateBySession() {
        if (!isUserLoggedIn()) {
            return ['authenticated' => false, 'reason' => 'no_active_session'];
        }
        
        $userId = $_SESSION['user_id'];
        $isAdmin = isUserAdmin();
        
        // Determine permissions based on user role
        $permissions = [self::PERMISSION_READ];
        if ($isAdmin) {
            $permissions[] = self::PERMISSION_WRITE;
            $permissions[] = self::PERMISSION_ADMIN;
        } else {
            $permissions[] = self::PERMISSION_WRITE; // Regular users can write their own data
        }
        
        return [
            'authenticated' => true,
            'method' => self::AUTH_SESSION,
            'user_id' => $userId,
            'is_admin' => $isAdmin,
            'permissions' => $permissions,
            'session_id' => session_id()
        ];
    }
    
    /**
     * Authenticate using API key
     */
    private static function authenticateByAPIKey() {
        $apiKey = self::extractAPIKey();
        if (!$apiKey) {
            return ['authenticated' => false, 'reason' => 'no_api_key'];
        }
        
        $keyData = self::validateAPIKey($apiKey);
        if (!$keyData) {
            return ['authenticated' => false, 'reason' => 'invalid_api_key'];
        }
        
        // Check if key is expired
        if (isset($keyData['expires_at']) && time() > $keyData['expires_at']) {
            self::logAPIKeyEvent($apiKey, 'KEY_EXPIRED');
            return ['authenticated' => false, 'reason' => 'api_key_expired'];
        }
        
        // Check if key is active
        if (!($keyData['active'] ?? true)) {
            self::logAPIKeyEvent($apiKey, 'KEY_DISABLED');
            return ['authenticated' => false, 'reason' => 'api_key_disabled'];
        }
        
        // Update last used timestamp
        self::updateAPIKeyUsage($apiKey);
        
        self::logAPIKeyEvent($apiKey, 'KEY_USED_SUCCESS');
        
        return [
            'authenticated' => true,
            'method' => self::AUTH_API_KEY,
            'user_id' => $keyData['user_id'],
            'api_key_id' => $keyData['id'],
            'permissions' => $keyData['permissions'] ?? [self::PERMISSION_READ],
            'key_name' => $keyData['name'] ?? 'Unnamed Key'
        ];
    }
    
    /**
     * Authenticate using Bearer token
     */
    private static function authenticateByBearerToken() {
        $token = self::extractBearerToken();
        if (!$token) {
            return ['authenticated' => false, 'reason' => 'no_bearer_token'];
        }
        
        $tokenData = self::validateBearerToken($token);
        if (!$tokenData) {
            return ['authenticated' => false, 'reason' => 'invalid_bearer_token'];
        }
        
        return [
            'authenticated' => true,
            'method' => self::AUTH_BEARER_TOKEN,
            'user_id' => $tokenData['user_id'],
            'permissions' => $tokenData['permissions'] ?? [self::PERMISSION_READ],
            'expires_at' => $tokenData['expires_at']
        ];
    }
    
    /**
     * Authenticate using JWT token (placeholder for future implementation)
     */
    private static function authenticateByJWT() {
        $jwt = self::extractJWTToken();
        if (!$jwt) {
            return ['authenticated' => false, 'reason' => 'no_jwt_token'];
        }
        
        // JWT validation would go here
        // For now, return not authenticated
        return ['authenticated' => false, 'reason' => 'jwt_not_implemented'];
    }
    
    /**
     * Extract API key from request
     */
    private static function extractAPIKey() {
        // Check header first
        if (isset($_SERVER['HTTP_X_API_KEY'])) {
            return InputSanitizer::sanitizeString($_SERVER['HTTP_X_API_KEY']);
        }
        
        // Check query parameter
        if (isset($_GET['api_key'])) {
            return InputSanitizer::sanitizeString($_GET['api_key']);
        }
        
        // Check POST parameter
        if (isset($_POST['api_key'])) {
            return InputSanitizer::sanitizeString($_POST['api_key']);
        }
        
        return null;
    }
    
    /**
     * Extract Bearer token from Authorization header
     */
    private static function extractBearerToken() {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        
        if (preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            return InputSanitizer::sanitizeString($matches[1]);
        }
        
        return null;
    }
    
    /**
     * Extract JWT token from Authorization header
     */
    private static function extractJWTToken() {
        $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        
        if (preg_match('/JWT\s+(.*)$/i', $authHeader, $matches)) {
            return InputSanitizer::sanitizeString($matches[1]);
        }
        
        return null;
    }
    
    /**
     * Validate API key
     */
    private static function validateAPIKey($apiKey) {
        if (!file_exists(self::$apiKeysFile)) {
            return false;
        }
        
        $apiKeys = json_decode(file_get_contents(self::$apiKeysFile), true) ?: [];
        
        // Hash the provided key for comparison
        $hashedKey = hash('sha256', $apiKey);
        
        foreach ($apiKeys as $keyData) {
            if (isset($keyData['key_hash']) && hash_equals($keyData['key_hash'], $hashedKey)) {
                return $keyData;
            }
        }
        
        return false;
    }
    
    /**
     * Validate Bearer token
     */
    private static function validateBearerToken($token) {
        if (!file_exists(self::$apiSessionsFile)) {
            return false;
        }
        
        $sessions = json_decode(file_get_contents(self::$apiSessionsFile), true) ?: [];
        
        $hashedToken = hash('sha256', $token);
        
        foreach ($sessions as $sessionId => $sessionData) {
            if (isset($sessionData['token_hash']) && hash_equals($sessionData['token_hash'], $hashedToken)) {
                // Check if token is expired
                if ($sessionData['expires_at'] < time()) {
                    self::removeExpiredSession($sessionId);
                    return false;
                }
                
                return $sessionData;
            }
        }
        
        return false;
    }
    
    /**
     * Check if user has required permission
     */
    public static function hasPermission($authData, $requiredPermission) {
        if (!$authData['authenticated']) {
            return false;
        }
        
        $userPermissions = $authData['permissions'] ?? [];
        
        // System permission grants all access
        if (in_array(self::PERMISSION_SYSTEM, $userPermissions)) {
            return true;
        }
        
        // Admin permission grants read/write access
        if ($requiredPermission !== self::PERMISSION_SYSTEM && 
            in_array(self::PERMISSION_ADMIN, $userPermissions)) {
            return true;
        }
        
        // Check specific permission
        return in_array($requiredPermission, $userPermissions);
    }
    
    /**
     * Generate new API key for user
     */
    public static function generateAPIKey($userId, $permissions = [self::PERMISSION_READ], $name = 'API Key', $expiresInDays = null) {
        if (!isUserLoggedIn() || (!isUserAdmin() && $_SESSION['user_id'] != $userId)) {
            return ['error' => 'Insufficient permissions'];
        }
        
        // Generate random API key
        $apiKey = bin2hex(random_bytes(32));
        $keyHash = hash('sha256', $apiKey);
        
        // Prepare key data
        $keyData = [
            'id' => uniqid('key_'),
            'user_id' => $userId,
            'name' => $name,
            'key_hash' => $keyHash,
            'permissions' => $permissions,
            'created_at' => time(),
            'last_used_at' => null,
            'usage_count' => 0,
            'active' => true
        ];
        
        if ($expiresInDays) {
            $keyData['expires_at'] = time() + ($expiresInDays * 24 * 3600);
        }
        
        // Load existing keys
        $apiKeys = [];
        if (file_exists(self::$apiKeysFile)) {
            $apiKeys = json_decode(file_get_contents(self::$apiKeysFile), true) ?: [];
        }
        
        // Add new key
        $apiKeys[] = $keyData;
        
        // Save keys
        file_put_contents(self::$apiKeysFile, json_encode($apiKeys, JSON_PRETTY_PRINT));
        
        // Log key generation
        SecurityMiddleware::logSecurityEvent('API_KEY_GENERATED', [
            'key_id' => $keyData['id'],
            'user_id' => $userId,
            'permissions' => $permissions,
            'name' => $name
        ], 'INFO');
        
        return [
            'success' => true,
            'api_key' => $apiKey,
            'key_id' => $keyData['id'],
            'permissions' => $permissions,
            'expires_at' => $keyData['expires_at'] ?? null
        ];
    }
    
    /**
     * Generate Bearer token for API session
     */
    public static function generateBearerToken($userId, $permissions = [self::PERMISSION_READ], $expiresInMinutes = 60) {
        if (!isUserLoggedIn()) {
            return ['error' => 'Authentication required'];
        }
        
        // Generate random token
        $token = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $token);
        $sessionId = uniqid('session_');
        
        // Prepare session data
        $sessionData = [
            'user_id' => $userId,
            'token_hash' => $tokenHash,
            'permissions' => $permissions,
            'created_at' => time(),
            'expires_at' => time() + ($expiresInMinutes * 60),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ];
        
        // Load existing sessions
        $sessions = [];
        if (file_exists(self::$apiSessionsFile)) {
            $sessions = json_decode(file_get_contents(self::$apiSessionsFile), true) ?: [];
        }
        
        // Add new session
        $sessions[$sessionId] = $sessionData;
        
        // Clean expired sessions
        self::cleanExpiredSessions($sessions);
        
        // Save sessions
        file_put_contents(self::$apiSessionsFile, json_encode($sessions, JSON_PRETTY_PRINT));
        
        return [
            'success' => true,
            'bearer_token' => $token,
            'session_id' => $sessionId,
            'expires_at' => $sessionData['expires_at'],
            'permissions' => $permissions
        ];
    }
    
    /**
     * Revoke API key
     */
    public static function revokeAPIKey($keyId) {
        if (!isUserLoggedIn()) {
            return ['error' => 'Authentication required'];
        }
        
        if (!file_exists(self::$apiKeysFile)) {
            return ['error' => 'No API keys found'];
        }
        
        $apiKeys = json_decode(file_get_contents(self::$apiKeysFile), true) ?: [];
        $found = false;
        
        foreach ($apiKeys as &$keyData) {
            if ($keyData['id'] === $keyId) {
                // Check permissions
                if (!isUserAdmin() && $keyData['user_id'] != $_SESSION['user_id']) {
                    return ['error' => 'Insufficient permissions'];
                }
                
                $keyData['active'] = false;
                $keyData['revoked_at'] = time();
                $found = true;
                break;
            }
        }
        
        if (!$found) {
            return ['error' => 'API key not found'];
        }
        
        // Save updated keys
        file_put_contents(self::$apiKeysFile, json_encode($apiKeys, JSON_PRETTY_PRINT));
        
        // Log revocation
        SecurityMiddleware::logSecurityEvent('API_KEY_REVOKED', [
            'key_id' => $keyId,
            'revoked_by' => $_SESSION['user_id']
        ], 'INFO');
        
        return ['success' => true, 'message' => 'API key revoked'];
    }
    
    /**
     * List API keys for user
     */
    public static function listAPIKeys($userId = null) {
        if (!isUserLoggedIn()) {
            return ['error' => 'Authentication required'];
        }
        
        $userId = $userId ?: $_SESSION['user_id'];
        
        // Check permissions
        if (!isUserAdmin() && $userId != $_SESSION['user_id']) {
            return ['error' => 'Insufficient permissions'];
        }
        
        if (!file_exists(self::$apiKeysFile)) {
            return ['success' => true, 'keys' => []];
        }
        
        $apiKeys = json_decode(file_get_contents(self::$apiKeysFile), true) ?: [];
        $userKeys = [];
        
        foreach ($apiKeys as $keyData) {
            if ($keyData['user_id'] == $userId) {
                // Remove sensitive data
                unset($keyData['key_hash']);
                $userKeys[] = $keyData;
            }
        }
        
        return ['success' => true, 'keys' => $userKeys];
    }
    
    /**
     * Update API key usage statistics
     */
    private static function updateAPIKeyUsage($apiKey) {
        if (!file_exists(self::$apiKeysFile)) {
            return;
        }
        
        $apiKeys = json_decode(file_get_contents(self::$apiKeysFile), true) ?: [];
        $hashedKey = hash('sha256', $apiKey);
        
        foreach ($apiKeys as &$keyData) {
            if (isset($keyData['key_hash']) && hash_equals($keyData['key_hash'], $hashedKey)) {
                $keyData['last_used_at'] = time();
                $keyData['usage_count'] = ($keyData['usage_count'] ?? 0) + 1;
                break;
            }
        }
        
        file_put_contents(self::$apiKeysFile, json_encode($apiKeys, JSON_PRETTY_PRINT));
    }
    
    /**
     * Clean expired sessions
     */
    private static function cleanExpiredSessions(&$sessions) {
        $now = time();
        
        foreach ($sessions as $sessionId => $sessionData) {
            if ($sessionData['expires_at'] < $now) {
                unset($sessions[$sessionId]);
            }
        }
    }
    
    /**
     * Remove specific expired session
     */
    private static function removeExpiredSession($sessionId) {
        if (!file_exists(self::$apiSessionsFile)) {
            return;
        }
        
        $sessions = json_decode(file_get_contents(self::$apiSessionsFile), true) ?: [];
        unset($sessions[$sessionId]);
        
        file_put_contents(self::$apiSessionsFile, json_encode($sessions, JSON_PRETTY_PRINT));
    }
    
    /**
     * Log API key related events
     */
    private static function logAPIKeyEvent($apiKey, $event) {
        SecurityMiddleware::logSecurityEvent('API_KEY_EVENT', [
            'event' => $event,
            'key_hash' => hash('sha256', $apiKey),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ], 'INFO');
    }
    
    /**
     * Get authentication statistics
     */
    public static function getAuthStats($hours = 24) {
        // This would analyze authentication logs and return statistics
        // Implementation would read from security logs and provide insights
        return [
            'total_auth_attempts' => 0,
            'successful_auths' => 0,
            'failed_auths' => 0,
            'auth_methods_used' => [],
            'top_api_keys' => []
        ];
    }
}
?>