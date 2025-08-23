<?php
/**
 * Single Sign-On Manager (Clean Version)
 * Core SSO functionality with enterprise security controls
 */

require_once __DIR__ . '/../security_config.php';
require_once __DIR__ . '/../crypto_utils.php';

class SSOManager {
    private static $db_path;
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
            require_once __DIR__ . '/../config_paths.php';
            self::$db_path = ConfigPaths::getDatabase('sso');
            
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
            $provider = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Parse config_json into config array
            if ($provider && !empty($provider['config_json'])) {
                $decoded = json_decode($provider['config_json'], true);
                $provider['config'] = is_array($decoded) ? $decoded : [];
            } elseif ($provider) {
                $provider['config'] = [];
            }
            
            return $provider;
        } catch (Exception $e) {
            return null;
        }
    }
    
    /**
     * Complete SSO authentication
     */
    public static function completeSSOAuthentication($provider_id, $external_id, $attributes, $metadata = []) {
        self::init();
        
        error_log("SSO completeSSOAuthentication - Starting with provider_id: $provider_id, external_id: $external_id");
        
        try {
            // Get users database path
            $users_db_path = ConfigPaths::getDatabase('users');
            error_log("SSO completeSSOAuthentication - Users DB path: $users_db_path");
            $pdo = new PDO('sqlite:' . $users_db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            error_log("SSO completeSSOAuthentication - Database connection established");
            
            // Check if user already exists by SSO mapping first
            $stmt = $pdo->prepare("SELECT * FROM users WHERE external_sso_id = ? AND sso_provider_id = ?");
            $stmt->execute([$external_id, $provider_id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // If no SSO mapping exists, check by email address for existing users
            if (!$user) {
                $email = $attributes['email'] ?? '';
                if (!empty($email)) {
                    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
                    $stmt->execute([$email]);
                    $existing_user = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    if ($existing_user) {
                        // Link existing user to SSO provider
                        $stmt = $pdo->prepare("
                            UPDATE users SET 
                            sso_provider_id = ?, 
                            external_sso_id = ?,
                            sso_auto_provisioned = 0,
                            sso_last_login = CURRENT_TIMESTAMP,
                            last_login = CURRENT_TIMESTAMP
                            WHERE id = ?
                        ");
                        $stmt->execute([$provider_id, $external_id, $existing_user['id']]);
                        
                        $user = $existing_user;
                        $user['sso_provider_id'] = $provider_id;
                        $user['external_sso_id'] = $external_id;
                        
                        self::logSSOEvent('SSO_USER_LINKED', $provider_id, $user['id'],
                            "Existing user linked to SSO provider: {$user['username']}", 'MEDIUM', [
                                'email' => $email,
                                'external_id' => $external_id
                            ]);
                    }
                }
            }
            
            if ($user) {
                // Update last login
                $stmt = $pdo->prepare("UPDATE users SET sso_last_login = CURRENT_TIMESTAMP, last_login = CURRENT_TIMESTAMP WHERE id = ?");
                $stmt->execute([$user['id']]);
            } else {
                // Auto-provision new user
                $email = $attributes['email'] ?? $external_id . '@oauth.local';
                $username = $attributes['name'] ?? $attributes['given_name'] ?? 'oauth_user_' . substr($external_id, 0, 8);
                
                // Check if this is an admin email (cr0sis Google account)
                $admin_emails = [
                    'gazman86@gmail.com', // Your actual Google email
                    'cr0sis@gmail.com', // Alternative admin email
                    // Add other admin emails as needed
                ];
                $is_admin = in_array(strtolower($email), array_map('strtolower', $admin_emails)) ? 1 : 0;
                
                // Make username unique if needed
                $original_username = $username;
                $counter = 1;
                while (true) {
                    $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
                    $stmt->execute([$username]);
                    if (!$stmt->fetch()) break;
                    $username = $original_username . '_' . $counter++;
                }
                
                // Create new user
                $stmt = $pdo->prepare("
                    INSERT INTO users (username, email, password_hash, sso_provider_id, external_sso_id, 
                                     sso_auto_provisioned, sso_last_login, last_login, is_active, is_admin)
                    VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, ?)
                ");
                $stmt->execute([
                    $username,
                    $email,
                    'SSO_AUTHENTICATED', // Special marker for SSO users
                    $provider_id,
                    $external_id,
                    $is_admin
                ]);
                
                $user_id = $pdo->lastInsertId();
                $user = [
                    'id' => $user_id,
                    'username' => $username,
                    'email' => $email,
                    'is_admin' => $is_admin,
                    'sso_provider_id' => $provider_id,
                    'external_sso_id' => $external_id
                ];
                
                if ($is_admin) {
                    self::logSSOEvent('SSO_ADMIN_PROVISIONED', $provider_id, $user_id,
                        "Admin user auto-provisioned via SSO: $email", 'MEDIUM', [
                            'email' => $email,
                            'external_id' => $external_id
                        ]);
                }
            }
            
            // Check if existing user should be promoted to admin
            if (!$user['is_admin']) {
                $email = $user['email'] ?? $attributes['email'] ?? '';
                $admin_emails = [
                    'gazman86@gmail.com', // Your actual Google email
                    'cr0sis@gmail.com', // Alternative admin email
                    // Add other admin emails as needed
                ];
                
                if (in_array(strtolower($email), array_map('strtolower', $admin_emails))) {
                    // Promote to admin
                    $stmt = $pdo->prepare("UPDATE users SET is_admin = 1 WHERE id = ?");
                    $stmt->execute([$user['id']]);
                    $user['is_admin'] = 1;
                    
                    self::logSSOEvent('SSO_ADMIN_PROMOTION', $provider_id, $user['id'],
                        "User promoted to admin via SSO: $email", 'HIGH', [
                            'email' => $email,
                            'external_id' => $external_id
                        ]);
                }
            }
            
            // Get provider configuration for 2FA requirements
            $provider = self::getProvider($provider_id);
            $provider_requires_2fa = $provider ? (bool)$provider['require_2fa'] : false;
            $user_is_admin = (bool)($user['is_admin'] ?? 0);
            
            error_log("SSO completeSSOAuthentication - Provider requires 2FA: " . ($provider_requires_2fa ? 'yes' : 'no') . ", User is admin: " . ($user_is_admin ? 'yes' : 'no'));
            
            // Check if 2FA is required and enabled for user
            $requires_2fa = false;
            if ($provider_requires_2fa || $user_is_admin) {
                // Check if user has 2FA enabled
                require_once __DIR__ . '/../two_factor_auth.php';
                if (class_exists('TwoFactorAuth') && method_exists('TwoFactorAuth', 'isEnabledForUser')) {
                    $requires_2fa = TwoFactorAuth::isEnabledForUser($user['id']);
                    error_log("SSO completeSSOAuthentication - 2FA enabled for user {$user['id']}: " . ($requires_2fa ? 'yes' : 'no'));
                }
            }
            
            if ($requires_2fa) {
                // Store pending 2FA data in session
                $_SESSION['pending_sso_2fa_user_id'] = $user['id'];
                $_SESSION['pending_sso_2fa_username'] = $user['username'];
                $_SESSION['pending_sso_2fa_is_admin'] = $user_is_admin;
                $_SESSION['pending_sso_2fa_provider'] = $provider_id;
                $_SESSION['pending_sso_2fa_attributes'] = $attributes;
                
                error_log("SSO completeSSOAuthentication - 2FA required for user {$user['username']} (ID: {$user['id']}, admin: $user_is_admin)");
                
                self::logSSOEvent('SSO_2FA_REQUIRED', $provider_id, $user['id'],
                    "2FA required for SSO user {$user['username']}", 'LOW', [
                        'external_id' => $external_id,
                        'is_admin' => $user_is_admin
                    ]);
                
                return [
                    'success' => true,
                    'requires_2fa' => true,
                    'message' => '2FA verification required',
                    'user' => $user
                ];
            } else {
                // Set up user session directly
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['is_admin'] = $user_is_admin;
                $_SESSION['login_time'] = time();
                $_SESSION['login_ip'] = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                $_SESSION['sso_authenticated'] = true;
                $_SESSION['sso_provider_id'] = $provider_id;
                
                error_log("SSO completeSSOAuthentication - Direct login for user {$user['username']} (no 2FA required)");
                
                self::logSSOEvent('SSO_LOGIN_SUCCESS', $provider_id, $user['id'],
                    "SSO authentication successful for user {$user['username']}", 'LOW', [
                        'external_id' => $external_id,
                        'auto_provisioned' => !isset($user['id']) ? false : true
                    ]);
                
                return [
                    'success' => true,
                    'requires_2fa' => false,
                    'message' => 'SSO authentication successful',
                    'user' => $user
                ];
            }
            
        } catch (Exception $e) {
            error_log("SSO completeSSOAuthentication - Exception caught: " . $e->getMessage());
            error_log("SSO completeSSOAuthentication - Exception trace: " . $e->getTraceAsString());
            
            self::logSSOEvent('SSO_LOGIN_ERROR', $provider_id, null,
                "SSO authentication failed: " . $e->getMessage(), 'HIGH', [
                    'external_id' => $external_id,
                    'error' => $e->getMessage()
                ]);
            
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
}
?>