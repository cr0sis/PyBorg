<?php
/**
 * Core Security System
 * Consolidated security configuration and hardening
 * Replaces: security_config.php + security_hardened.php + parts of security_middleware.php
 */

// Prevent direct access
if (!defined('SECURITY_SYSTEM_LOADED')) {
    define('SECURITY_SYSTEM_LOADED', true);
} else {
    exit('Direct access not allowed');
}

// Set timezone for all operations
date_default_timezone_set('Europe/London');

// Core security constants
define('ENCRYPTION_KEY', 'cr0bot_security_key_2024_v2_ultra_secure_' . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost'));
define('MAX_REQUEST_SIZE', 1024 * 1024); // 1MB
define('MAX_JSON_DEPTH', 10);
define('MAX_LOGIN_ATTEMPTS', 3);
define('LOCKOUT_DURATION', 1800); // 30 minutes
define('MAX_SESSION_LIFETIME', 3600); // 1 hour

// File paths for security data
define('BLOCKED_IPS_FILE', '/data/cr0_system/logs/security/blocked_ips.json');
define('SECURITY_EVENTS_FILE', '/data/cr0_system/logs/security/security_events.json');
define('TRUSTED_IPS_FILE', __DIR__ . '/trusted_ips.php');

/**
 * Comprehensive Security Manager
 * Handles all security operations in one place
 */
class SecurityManager {
    private static $instance = null;
    private static $blockedIPs = [];
    private static $securityEvents = [];
    private static $trustedIPs = ['127.0.0.1', '::1', 'localhost'];
    
    public static function getInstance(): SecurityManager {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->loadSecurityData();
        $this->enforceBasicSecurity();
    }
    
    /**
     * Initialize all security measures
     */
    private function enforceBasicSecurity(): void {
        $this->enforceRequestLimits();
        $this->checkIPBlacklist();
        $this->detectSuspiciousActivity();
    }
    
    /**
     * Load security data from files
     */
    private function loadSecurityData(): void {
        // Load blocked IPs
        if (file_exists(BLOCKED_IPS_FILE)) {
            $data = json_decode(file_get_contents(BLOCKED_IPS_FILE), true);
            self::$blockedIPs = $data ?: [];
        }
        
        // Load trusted IPs
        if (file_exists(TRUSTED_IPS_FILE)) {
            $additionalIPs = include TRUSTED_IPS_FILE;
            if (is_array($additionalIPs)) {
                self::$trustedIPs = array_merge(self::$trustedIPs, $additionalIPs);
            }
        }
    }
    
    /**
     * Enforce request size and other limits
     */
    private function enforceRequestLimits(): void {
        $contentLength = $_SERVER['CONTENT_LENGTH'] ?? 0;
        if ($contentLength > MAX_REQUEST_SIZE) {
            $this->logSecurityEvent('ATTACK', 'Request size exceeded limit', 'HIGH');
            http_response_code(413);
            exit('Request too large');
        }
    }
    
    /**
     * Check if current IP is blacklisted
     */
    private function checkIPBlacklist(): void {
        $clientIP = $_SERVER['REMOTE_ADDR'];
        
        // Skip check for trusted IPs
        if (in_array($clientIP, self::$trustedIPs)) {
            return;
        }
        
        // Check if IP is blocked
        if (isset(self::$blockedIPs[$clientIP])) {
            $blockInfo = self::$blockedIPs[$clientIP];
            if (time() < $blockInfo['until']) {
                $this->logSecurityEvent('BLOCKED_IP_ACCESS', "Blocked IP attempted access: $clientIP", 'HIGH');
                http_response_code(403);
                exit('Access denied: IP blocked');
            } else {
                // Block expired, remove it
                unset(self::$blockedIPs[$clientIP]);
                $this->saveBlockedIPs();
            }
        }
    }
    
    /**
     * Detect suspicious activity patterns
     */
    private function detectSuspiciousActivity(): void {
        $clientIP = $_SERVER['REMOTE_ADDR'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        // Check for common attack patterns
        $suspiciousPatterns = [
            '/\.\./i' => 'Path traversal attempt',
            '/<script/i' => 'XSS attempt',
            '/union.*select/i' => 'SQL injection attempt',
            '/eval\(/i' => 'Code injection attempt',
            '/\${/i' => 'Template injection attempt'
        ];
        
        $requestUri = $_SERVER['REQUEST_URI'] ?? '';
        $queryString = $_SERVER['QUERY_STRING'] ?? '';
        $postData = file_get_contents('php://input');
        
        $content = $requestUri . ' ' . $queryString . ' ' . $postData;
        
        foreach ($suspiciousPatterns as $pattern => $description) {
            if (preg_match($pattern, $content)) {
                $this->logSecurityEvent('ATTACK_DETECTED', "$description from IP: $clientIP", 'CRITICAL');
                $this->blockIP($clientIP, 3600, $description); // Block for 1 hour
                http_response_code(403);
                exit('Suspicious activity detected');
            }
        }
    }
    
    /**
     * Block an IP address
     */
    public function blockIP(string $ip, int $duration = 1800, string $reason = 'Security violation'): void {
        self::$blockedIPs[$ip] = [
            'blocked_at' => time(),
            'until' => time() + $duration,
            'reason' => $reason
        ];
        $this->saveBlockedIPs();
        $this->logSecurityEvent('IP_BLOCKED', "IP blocked: $ip - Reason: $reason", 'HIGH');
    }
    
    /**
     * Save blocked IPs to file
     */
    private function saveBlockedIPs(): void {
        $dir = dirname(BLOCKED_IPS_FILE);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        file_put_contents(BLOCKED_IPS_FILE, json_encode(self::$blockedIPs, JSON_PRETTY_PRINT));
    }
    
    /**
     * Log security event
     */
    public function logSecurityEvent(string $type, string $message, string $severity = 'MEDIUM'): void {
        $event = [
            'timestamp' => date('c'),
            'type' => $type,
            'message' => $message,
            'severity' => $severity,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown'
        ];
        
        // Log to file
        $logFile = '/data/cr0_system/logs/security/events/' . date('Y-m-d') . '.log';
        $dir = dirname($logFile);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        
        error_log(json_encode($event) . "\n", 3, $logFile);
        
        // Also log critical events to system log
        if ($severity === 'CRITICAL') {
            error_log("SECURITY CRITICAL: $type - $message");
        }
    }
    
    /**
     * Safe JSON parsing with depth limits
     */
    public static function safeJSONParse(string $json): mixed {
        if (strlen($json) > MAX_REQUEST_SIZE) {
            return false;
        }
        
        $result = json_decode($json, true, MAX_JSON_DEPTH);
        return (json_last_error() === JSON_ERROR_NONE) ? $result : false;
    }
}

/**
 * Initialize secure session with comprehensive security
 */
function initSecureSession(): void {
    if (session_status() === PHP_SESSION_NONE) {
        // Enhanced session security settings
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', 0); // Set to 1 if using HTTPS
        ini_set('session.cookie_samesite', 'Lax');
        ini_set('session.use_strict_mode', 1);
        ini_set('session.gc_maxlifetime', MAX_SESSION_LIFETIME);
        ini_set('session.gc_probability', 1);
        ini_set('session.gc_divisor', 1000);
        
        session_start();
    }
    
    // Enhanced IP binding for admin sessions
    if (isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true) {
        validateSessionIP();
    }
    
    // Session regeneration for security
    if (!isset($_SESSION['last_regeneration']) || 
        (time() - $_SESSION['last_regeneration']) > 1800) {
        session_regenerate_id(true);
        $_SESSION['last_regeneration'] = time();
    }
}

/**
 * Validate session IP binding for admin sessions
 */
function validateSessionIP(): void {
    $currentIP = $_SERVER['REMOTE_ADDR'];
    
    if (!isset($_SESSION['bound_ip'])) {
        $_SESSION['bound_ip'] = $currentIP;
        $_SESSION['ip_bind_time'] = time();
        SecurityManager::getInstance()->logSecurityEvent('SESSION_IP_BOUND', "Admin session bound to IP: $currentIP");
    } else {
        if ($_SESSION['bound_ip'] !== $currentIP) {
            SecurityManager::getInstance()->logSecurityEvent('SESSION_HIJACK_ATTEMPT', 
                "IP mismatch! Session IP: {$_SESSION['bound_ip']}, Current IP: $currentIP", 'CRITICAL');
            
            $_SESSION = array();
            session_destroy();
            
            header('HTTP/1.1 403 Forbidden');
            header('Location: /auth.php?error=session_hijack_detected');
            exit('Session hijacking detected. Please log in again.');
        }
    }
}

/**
 * Global security event logging function for compatibility
 */
function logSecurityEvent(string $type, string $message, string $severity = 'MEDIUM'): void {
    SecurityManager::getInstance()->logSecurityEvent($type, $message, $severity);
}

// Auto-initialize security system
SecurityManager::getInstance();