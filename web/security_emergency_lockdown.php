<?php
/**
 * Emergency Security Lockdown System
 * This file implements immediate security measures to prevent score exploitation
 */

class EmergencyLockdown {
    private static $lockdown_file = '/tmp/game_security_lockdown.flag';
    private static $maintenance_config = '/tmp/game_maintenance_config.json';
    
    /**
     * Enable emergency lockdown mode
     */
    public static function enableLockdown($reason = 'Security vulnerability detected', $admin_user = 'System') {
        $lockdown_data = [
            'enabled' => true,
            'timestamp' => time(),
            'reason' => $reason,
            'admin_user' => $admin_user,
            'lockdown_id' => bin2hex(random_bytes(8))
        ];
        
        file_put_contents(self::$lockdown_file, json_encode($lockdown_data));
        file_put_contents(self::$maintenance_config, json_encode([
            'maintenance_mode' => true,
            'message' => 'Game temporarily unavailable due to security maintenance',
            'admin_contact' => 'Please contact administrator',
            'estimated_restoration' => 'Within 24 hours'
        ]));
        
        error_log("EMERGENCY LOCKDOWN ENABLED: $reason by $admin_user");
        return $lockdown_data['lockdown_id'];
    }
    
    /**
     * Disable emergency lockdown mode
     */
    public static function disableLockdown($admin_user = 'System') {
        if (file_exists(self::$lockdown_file)) {
            unlink(self::$lockdown_file);
        }
        if (file_exists(self::$maintenance_config)) {
            unlink(self::$maintenance_config);
        }
        
        error_log("EMERGENCY LOCKDOWN DISABLED by $admin_user");
        return true;
    }
    
    /**
     * Check if lockdown is currently active
     */
    public static function isLockdownActive() {
        return file_exists(self::$lockdown_file);
    }
    
    /**
     * Get lockdown details
     */
    public static function getLockdownDetails() {
        if (!self::isLockdownActive()) {
            return null;
        }
        
        $data = file_get_contents(self::$lockdown_file);
        return json_decode($data, true);
    }
    
    /**
     * Enforce lockdown - exits with error if lockdown is active, unless admin bypass is valid
     */
    public static function enforceLockdown() {
        if (self::isLockdownActive()) {
            // Check for valid admin bypass
            if (self::isAdminBypassValid()) {
                error_log("ADMIN BYPASS: Lockdown bypassed by authenticated admin user");
                return; // Allow access for authenticated admin
            }
            
            $details = self::getLockdownDetails();
            http_response_code(503);
            header('Content-Type: application/json');
            echo json_encode([
                'error' => 'Service temporarily unavailable',
                'message' => 'Game is under security maintenance',
                'details' => [
                    'reason' => $details['reason'] ?? 'Security maintenance',
                    'timestamp' => $details['timestamp'] ?? time(),
                    'contact' => 'Please contact administrator if this persists'
                ]
            ]);
            exit;
        }
    }
    
    /**
     * Check if admin bypass is valid for current session
     */
    private static function isAdminBypassValid() {
        // Ensure session is started
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
        
        // Must be logged in admin user
        if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
            return false;
        }
        
        // Must have user_id
        if (!isset($_SESSION['user_id']) || empty($_SESSION['user_id'])) {
            return false;
        }
        
        // Must have recent login (within last 4 hours)
        if (!isset($_SESSION['login_time']) || (time() - $_SESSION['login_time']) > 14400) {
            error_log("ADMIN BYPASS DENIED: Session too old for user " . ($_SESSION['username'] ?? 'unknown'));
            return false;
        }
        
        // Enhanced security: Check for 2FA verification if admin has 2FA enabled
        if (isset($_SESSION['2fa_verified_time'])) {
            // If 2FA is verified, it must be recent (within last hour)
            if ((time() - $_SESSION['2fa_verified_time']) > 3600) {
                error_log("ADMIN BYPASS DENIED: 2FA verification too old for user " . ($_SESSION['username'] ?? 'unknown'));
                return false;
            }
        }
        
        // IP binding check - admin session must be from same IP
        if (isset($_SESSION['login_ip'])) {
            $current_ip = $_SERVER['REMOTE_ADDR'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? 'unknown';
            if (strpos($current_ip, ',') !== false) {
                $current_ip = trim(explode(',', $current_ip)[0]);
            }
            
            if ($_SESSION['login_ip'] !== $current_ip) {
                error_log("ADMIN BYPASS DENIED: IP mismatch for user " . ($_SESSION['username'] ?? 'unknown') . " - Session IP: " . $_SESSION['login_ip'] . ", Current IP: $current_ip");
                return false;
            }
        }
        
        // Log successful admin bypass
        error_log("ADMIN BYPASS GRANTED: User " . ($_SESSION['username'] ?? 'unknown') . " (ID: " . $_SESSION['user_id'] . ") bypassing lockdown from IP " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        
        return true;
    }
}

// If called directly, enable lockdown
if (basename(__FILE__) === basename($_SERVER['SCRIPT_NAME'])) {
    EmergencyLockdown::enableLockdown('Manual activation via direct script access');
    echo "Emergency lockdown enabled\n";
}
?>