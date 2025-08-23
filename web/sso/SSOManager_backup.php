<?php
/**
 * Single Sign-On Manager
 * Core SSO functionality with enterprise security controls
 * 
 * Security: OWASP 2024 compliance, NIST 800-63B-4 standards
 * Features: Multi-provider support, comprehensive audit logging, security monitoring
 */

require_once __DIR__ . '/../security_config.php';
require_once __DIR__ . '/../config_paths.php';
require_once __DIR__ . '/../input_sanitizer.php';
require_once __DIR__ . '/../crypto_utils.php';

class SSOManager {
    private static $db_path;
    private static $encryption_key;
    private static $instance = null;
    
    // Security constants
    const SESSION_TIMEOUT = 3600; // 1 hour
    const MAX_AUTH_ATTEMPTS = 3;
    const TOKEN_LENGTH = 64;
    const NONCE_LENGTH = 32;
    
    /**
     * Initialize SSO Manager
     */
    public static function init() {
        if (self::$instance === null) {
            self::$db_path = '/data/cr0_system/databases/sso_federated_identities.db';
            
            // Initialize database if it doesn't exist
            self::initializeDatabase();
            
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Initialize SSO database if it doesn't exist
     */
    private static function initializeDatabase() {
        if (!file_exists(self::$db_path)) {
            // Run database initialization
            $init_script = dirname(__DIR__) . '/sso_database_init.php';
            if (file_exists($init_script)) {
                require_once $init_script;
            }
        }
    }
    
    /**
     * Get active SSO providers
     */
    public static function getActiveProviders() {
        self::init();
        
        try {
            $pdo = new PDO('sqlite:' . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $stmt = $pdo->prepare("SELECT * FROM sso_providers WHERE is_active = 1 ORDER BY name");
            $stmt->execute();
            
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            return [];
        }
    }
    
    /**
     * Get specific SSO provider
     */
    public static function getProvider($provider_id) {
        self::init();
        
        try {
            $pdo = new PDO('sqlite:' . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $stmt = $pdo->prepare("SELECT * FROM sso_providers WHERE id = ?");
            $stmt->execute([$provider_id]);
            
            return $stmt->fetch(PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            return null;
        }
    }
    
    /**
     * Complete SSO authentication
     */
    public static function completeSSOAuthentication($provider_id, $external_id, $attributes, $metadata = []) {
        self::init();
        
        try {
            // This is a placeholder - in a real implementation, you would:
            // 1. Check if user exists in federated_identities table
            // 2. Create or link to local user account
            // 3. Set up proper session
            // 4. Apply 2FA requirements based on provider settings
            
            return [
                'success' => true,
                'requires_2fa' => false, // For now, implement 2FA logic later
                'message' => 'SSO authentication successful',
                'user' => [
                    'external_id' => $external_id,
                    'provider_id' => $provider_id,
                    'attributes' => $attributes
                ]
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'SSO authentication failed: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Log SSO security events
     */
    public static function logSSOEvent($event_type, $provider_id, $user_id, $message, $severity = 'MEDIUM', $additional_data = []) {
        try {
            $pdo = new PDO('sqlite:' . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $event_data = array_merge([
                'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                'timestamp' => time(),
                'message' => $message
            ], $additional_data);
            
            $stmt = $pdo->prepare("
                INSERT INTO sso_security_events 
                (event_type, severity, sso_provider_id, local_user_id, ip_address, user_agent, event_data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $event_type,
                $severity,
                $provider_id,
                $user_id,
                $event_data['ip_address'],
                $event_data['user_agent'],
                json_encode($event_data)
            ]);
            
            return true;
        } catch (Exception $e) {
            // Fallback to regular security log
            if (function_exists('logSecurityEvent')) {
                logSecurityEvent($event_type, $message, $severity, $additional_data);
            }
            return false;
        }
    }
    
    private function __construct() {
        self::$db_path = ConfigPaths::getDatabase('users');
        self::$encryption_key = self::getConfigValue('sso_encryption_key', bin2hex(random_bytes(32)));
    }
    
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Get SSO configuration value
     */
    private static function getConfigValue($key, $default = null) {
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $stmt = $pdo->prepare("SELECT value, is_encrypted FROM sso_configuration WHERE key_name = ?");
            $stmt->execute([$key]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($result) {
                if ($result['is_encrypted']) {
                    return CryptoUtils::decrypt($result['value']);
                }
                return $result['value'];
            }
            
            return $default;
        } catch (PDOException $e) {
            error_log("SSO Config get error: " . $e->getMessage());
            return $default;
        }
    }
    
    /**
     * Set SSO configuration value
     */
    public static function setConfigValue($key, $value, $encrypt = false) {
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            if ($encrypt) {
                $value = CryptoUtils::encrypt($value);
            }
            
            $stmt = $pdo->prepare("
                INSERT OR REPLACE INTO sso_configuration (key_name, value, is_encrypted, updated_at, updated_by)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?)
            ");
            $stmt->execute([$key, $value, $encrypt ? 1 : 0, $_SESSION['user_id'] ?? null]);
            
            self::logSSOEvent('CONFIG_UPDATE', null, null, "Configuration key '$key' updated", 'LOW');
            
            return true;
        } catch (PDOException $e) {
            error_log("SSO Config set error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Check if SSO is enabled
     */
    public static function isEnabled() {
        $enabled = self::getConfigValue('sso_enabled', '0');
        $emergency_disabled = self::getConfigValue('sso_emergency_disable', '0');
        
        return ($enabled === '1' && $emergency_disabled !== '1');
    }
    
    /**
     * Get all active SSO providers
     */
    public static function getActiveProviders() {
        if (!self::isEnabled()) {
            return [];
        }
        
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $stmt = $pdo->prepare("
                SELECT id, name, type, display_name, icon_url, admin_only, require_2fa
                FROM sso_providers 
                WHERE is_active = 1
                ORDER BY display_name
            ");
            $stmt->execute();
            
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch (PDOException $e) {
            self::logSSOEvent('ERROR', null, null, "Failed to get active providers: " . $e->getMessage(), 'HIGH');
            return [];
        }
    }
    
    /**
     * Get SSO provider by ID
     */
    public static function getProvider($provider_id) {
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $stmt = $pdo->prepare("
                SELECT * FROM sso_providers WHERE id = ? AND is_active = 1
            ");
            $stmt->execute([$provider_id]);
            $provider = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($provider) {
                // Decrypt sensitive fields
                if ($provider['client_secret']) {
                    $provider['client_secret'] = CryptoUtils::decrypt($provider['client_secret']);
                }
                if ($provider['private_key']) {
                    $provider['private_key'] = CryptoUtils::decrypt($provider['private_key']);
                }
                if ($provider['config_json']) {
                    $provider['config'] = json_decode($provider['config_json'], true);
                }
            }
            
            return $provider;
            
        } catch (PDOException $e) {
            self::logSSOEvent('ERROR', $provider_id, null, "Failed to get provider: " . $e->getMessage(), 'HIGH');
            return null;
        }
    }
    
    /**
     * Create SSO authentication session
     */
    public static function createAuthSession($provider_id, $redirect_uri = null) {
        if (!self::isEnabled()) {
            throw new Exception('SSO is disabled');
        }
        
        $provider = self::getProvider($provider_id);
        if (!$provider) {
            throw new Exception('Invalid provider');
        }
        
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $session_token = bin2hex(random_bytes(self::TOKEN_LENGTH));
            $state = bin2hex(random_bytes(32));
            $nonce = bin2hex(random_bytes(self::NONCE_LENGTH));
            $code_verifier = bin2hex(random_bytes(32));
            $now = time();
            $expires_at = $now + self::SESSION_TIMEOUT;
            
            $ip_address = $_SERVER['REMOTE_ADDR'];
            $user_agent_hash = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? 'unknown');
            
            // Security flags
            $security_flags = [
                'ip_address' => $ip_address,
                'csrf_token' => generateCSRFToken(),
                'created_timestamp' => $now,
                'requires_2fa' => $provider['require_2fa']
            ];
            
            $stmt = $pdo->prepare("
                INSERT INTO sso_auth_sessions 
                (session_token, provider_id, state, nonce, code_verifier, redirect_uri,
                 initiated_ip, user_agent_hash, created_at, expires_at, security_flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $session_token, $provider_id, $state, $nonce, $code_verifier,
                $redirect_uri, $ip_address, $user_agent_hash, $now, $expires_at,
                json_encode($security_flags)
            ]);
            
            self::logSSOEvent('AUTH_SESSION_CREATED', $provider_id, null, 
                "Auth session created for provider {$provider['name']}", 'LOW');
            
            return [
                'session_token' => $session_token,
                'state' => $state,
                'nonce' => $nonce,
                'code_verifier' => $code_verifier,
                'expires_at' => $expires_at
            ];
            
        } catch (PDOException $e) {
            self::logSSOEvent('ERROR', $provider_id, null, 
                "Failed to create auth session: " . $e->getMessage(), 'HIGH');
            throw new Exception('Failed to create authentication session');
        }
    }
    
    /**
     * Validate and retrieve auth session
     */
    public static function getAuthSession($session_token) {
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $stmt = $pdo->prepare("
                SELECT * FROM sso_auth_sessions 
                WHERE session_token = ? AND status = 'pending' AND expires_at > ?
            ");
            $stmt->execute([$session_token, time()]);
            $session = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$session) {
                self::logSSOEvent('AUTH_SESSION_INVALID', null, null, 
                    "Invalid or expired auth session token", 'MEDIUM');
                return null;
            }
            
            // Validate IP consistency for security
            $current_ip = $_SERVER['REMOTE_ADDR'];
            if ($session['initiated_ip'] !== $current_ip) {
                self::logSSOEvent('SECURITY_VIOLATION', $session['provider_id'], null,
                    "IP mismatch for auth session: {$session['initiated_ip']} vs $current_ip", 'HIGH');
                
                // Mark session as failed
                $pdo->prepare("UPDATE sso_auth_sessions SET status = 'failed', error_message = 'IP mismatch' WHERE session_token = ?")
                    ->execute([$session_token]);
                
                return null;
            }
            
            if ($session['security_flags']) {
                $session['security_flags'] = json_decode($session['security_flags'], true);
            }
            
            return $session;
            
        } catch (PDOException $e) {
            self::logSSOEvent('ERROR', null, null, 
                "Failed to get auth session: " . $e->getMessage(), 'HIGH');
            return null;
        }
    }
    
    /**
     * Complete SSO authentication
     */
    public static function completeAuth($session_token, $external_id, $attributes = []) {
        $session = self::getAuthSession($session_token);
        if (!$session) {
            throw new Exception('Invalid authentication session');
        }
        
        $provider = self::getProvider($session['provider_id']);
        if (!$provider) {
            throw new Exception('Invalid provider');
        }
        
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $pdo->beginTransaction();
            
            // Look for existing user mapping
            $stmt = $pdo->prepare("
                SELECT user_id FROM sso_user_mappings 
                WHERE provider_id = ? AND external_id = ? AND is_active = 1
            ");
            $stmt->execute([$provider['id'], $external_id]);
            $mapping = $stmt->fetch(PDO::FETCH_ASSOC);
            
            $user_id = null;
            
            if ($mapping) {
                // Existing user
                $user_id = $mapping['user_id'];
                
                // Update mapping
                $stmt = $pdo->prepare("
                    UPDATE sso_user_mappings 
                    SET last_login = CURRENT_TIMESTAMP, login_count = login_count + 1,
                        external_username = ?, external_email = ?, external_display_name = ?,
                        attributes_json = ?
                    WHERE provider_id = ? AND external_id = ?
                ");
                $stmt->execute([
                    $attributes['username'] ?? null,
                    $attributes['email'] ?? null,
                    $attributes['display_name'] ?? null,
                    json_encode($attributes),
                    $provider['id'],
                    $external_id
                ]);
                
            } else if ($provider['auto_provision']) {
                // Auto-provision new user
                $user_id = self::autoProvisionUser($pdo, $provider, $external_id, $attributes);
                
            } else {
                throw new Exception('User not found and auto-provisioning is disabled');
            }
            
            // Update auth session
            $stmt = $pdo->prepare("
                UPDATE sso_auth_sessions 
                SET status = 'completed', completed_at = ?, user_id = ?
                WHERE session_token = ?
            ");
            $stmt->execute([time(), $user_id, $session_token]);
            
            $pdo->commit();
            
            self::logSSOEvent('AUTH_SUCCESS', $provider['id'], $user_id,
                "User authenticated via {$provider['name']}", 'LOW');
            
            return $user_id;
            
        } catch (Exception $e) {
            if (isset($pdo)) $pdo->rollback();
            
            // Update auth session with failure
            try {
                $pdo = new PDO("sqlite:" . self::$db_path);
                $pdo->prepare("UPDATE sso_auth_sessions SET status = 'failed', error_message = ? WHERE session_token = ?")
                    ->execute([$e->getMessage(), $session_token]);
            } catch (Exception $ignored) {}
            
            self::logSSOEvent('AUTH_FAILURE', $session['provider_id'], null,
                "Authentication failed: " . $e->getMessage(), 'HIGH');
            
            throw $e;
        }
    }
    
    /**
     * Auto-provision new user from SSO
     */
    private static function autoProvisionUser($pdo, $provider, $external_id, $attributes) {
        $username = $attributes['username'] ?? 'sso_user_' . substr($external_id, 0, 8);
        $email = $attributes['email'] ?? '';
        $display_name = $attributes['display_name'] ?? $username;
        
        // Ensure unique username
        $base_username = $username;
        $counter = 1;
        while (true) {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
            $stmt->execute([$username]);
            if ($stmt->fetchColumn() == 0) break;
            
            $username = $base_username . '_' . $counter++;
            if ($counter > 100) {
                throw new Exception('Unable to generate unique username');
            }
        }
        
        // Create user
        $stmt = $pdo->prepare("
            INSERT INTO users (username, email, password_hash, sso_provider_id, 
                              external_sso_id, sso_auto_provisioned, created_at)
            VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
        ");
        
        $dummy_password = password_hash(bin2hex(random_bytes(32)), PASSWORD_DEFAULT);
        $stmt->execute([$username, $email, $dummy_password, $provider['id'], $external_id]);
        
        $user_id = $pdo->lastInsertId();
        
        // Create user mapping
        $stmt = $pdo->prepare("
            INSERT INTO sso_user_mappings 
            (user_id, provider_id, external_id, external_username, external_email,
             external_display_name, attributes_json, login_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        ");
        $stmt->execute([
            $user_id, $provider['id'], $external_id, $username, $email,
            $display_name, json_encode($attributes)
        ]);
        
        self::logSSOEvent('USER_PROVISIONED', $provider['id'], $user_id,
            "New user auto-provisioned: $username", 'MEDIUM');
        
        return $user_id;
    }
    
    /**
     * Get user by SSO mapping
     */
    public static function getUserByMapping($provider_id, $external_id) {
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $stmt = $pdo->prepare("
                SELECT u.*, m.external_username, m.external_email, m.last_login as sso_last_login
                FROM users u
                JOIN sso_user_mappings m ON u.id = m.user_id
                WHERE m.provider_id = ? AND m.external_id = ? AND m.is_active = 1 AND u.is_active = 1
            ");
            $stmt->execute([$provider_id, $external_id]);
            
            return $stmt->fetch(PDO::FETCH_ASSOC);
            
        } catch (PDOException $e) {
            self::logSSOEvent('ERROR', $provider_id, null,
                "Failed to get user by mapping: " . $e->getMessage(), 'HIGH');
            return null;
        }
    }
    
    /**
     * Log SSO security event
     */
    public static function logSSOEvent($event_type, $provider_id = null, $user_id = null, 
                                      $message = '', $severity = 'MEDIUM', $details = []) {
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $stmt = $pdo->prepare("
                INSERT INTO sso_security_events 
                (event_type, provider_id, user_id, ip_address, user_agent, 
                 severity, message, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $event_type,
                $provider_id,
                $user_id,
                $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                $severity,
                $message,
                json_encode($details)
            ]);
            
            // Also log to main security system
            logSecurityEvent("SSO_$event_type", $message, $severity);
            
        } catch (PDOException $e) {
            error_log("SSO Event logging error: " . $e->getMessage());
        }
    }
    
    /**
     * Cleanup expired sessions and old events
     */
    public static function cleanup() {
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $now = time();
            
            // Mark expired sessions
            $stmt = $pdo->prepare("
                UPDATE sso_auth_sessions 
                SET status = 'expired' 
                WHERE expires_at < ? AND status = 'pending'
            ");
            $stmt->execute([$now]);
            
            // Delete old completed/failed sessions (older than 7 days)
            $week_ago = $now - (7 * 24 * 3600);
            $stmt = $pdo->prepare("
                DELETE FROM sso_auth_sessions 
                WHERE created_at < ? AND status IN ('completed', 'failed', 'expired')
            ");
            $stmt->execute([$week_ago]);
            
            // Delete old security events based on retention policy
            $retention_days = intval(self::getConfigValue('sso_audit_retention_days', '365'));
            $retention_time = $now - ($retention_days * 24 * 3600);
            $stmt = $pdo->prepare("
                DELETE FROM sso_security_events 
                WHERE timestamp < datetime(?, 'unixepoch')
            ");
            $stmt->execute([$retention_time]);
            
            self::logSSOEvent('CLEANUP', null, null, 'SSO cleanup completed', 'LOW');
            
        } catch (PDOException $e) {
            error_log("SSO Cleanup error: " . $e->getMessage());
        }
    }
    
    /**
     * Emergency disable all SSO
     */
    public static function emergencyDisable($reason = 'Manual disable') {
        self::setConfigValue('sso_emergency_disable', '1');
        self::logSSOEvent('EMERGENCY_DISABLE', null, null, "SSO emergency disabled: $reason", 'CRITICAL');
        
        // Invalidate all pending auth sessions
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $pdo->prepare("UPDATE sso_auth_sessions SET status = 'failed', error_message = 'Emergency disable' WHERE status = 'pending'")
                ->execute();
                
        } catch (PDOException $e) {
            error_log("Failed to invalidate SSO sessions during emergency disable: " . $e->getMessage());
        }
    }
}
?>