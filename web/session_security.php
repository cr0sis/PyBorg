<?php
/**
 * Advanced Session Security Manager
 * Provides comprehensive session protection against hijacking and fixation attacks
 */

require_once 'security_logger.php';
require_once 'security_middleware.php';

class SessionSecurity {
    
    private static $sessionTimeout = 604800; // 7 days for admin persistence (was 24 hours)
    private static $regenerateInterval = 604800; // 7 days (reduce regeneration frequency)
    private static $maxSessionsPerUser = 3;
    
    /**
     * Initialize secure session with comprehensive protection
     */
    public static function initSecureSession() {
        // Configure secure session settings
        self::configureSessionSecurity();
        
        // Start session if not already started
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        // Validate existing session
        if (!self::validateSession()) {
            self::destroySession();
            session_start();
        }
        
        // Set up session security fingerprint
        self::setupSessionFingerprint();
        
        // Handle session regeneration
        self::handleSessionRegeneration();
        
        // Log session activity
        self::logSessionActivity('SESSION_VALIDATED');
        
        return session_id();
    }
    
    /**
     * Configure PHP session security settings
     */
    private static function configureSessionSecurity() {
        // Prevent session fixation
        ini_set('session.use_only_cookies', 1);
        ini_set('session.use_strict_mode', 1);
        
        // Secure cookie settings
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) ? 1 : 0);
        ini_set('session.cookie_samesite', 'Strict');
        
        // Session regeneration settings
        ini_set('session.gc_maxlifetime', self::$sessionTimeout);
        ini_set('session.gc_probability', 1);
        ini_set('session.gc_divisor', 1000); // Only run garbage collection 0.1% of the time
        ini_set('session.cookie_lifetime', 0); // Session cookies
        
        // Strong session ID generation
        ini_set('session.sid_length', 48);
        ini_set('session.sid_bits_per_character', 6);
        
        // Custom session name for security through obscurity
        session_name('PHPSESSID_' . substr(md5($_SERVER['SERVER_NAME'] ?? 'localhost'), 0, 8));
    }
    
    /**
     * Validate current session integrity
     */
    private static function validateSession() {
        // Check if session is expired - much longer timeout for admin users
        $timeoutPeriod = self::$sessionTimeout;
        if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
            $timeoutPeriod = self::$sessionTimeout * 7; // 7x timeout for admins (49 days)
        }
        
        if (isset($_SESSION['session_start_time']) && 
            (time() - $_SESSION['session_start_time']) > $timeoutPeriod) {
            self::logSessionActivity('SESSION_EXPIRED');
            return false;
        }
        
        // Check session fingerprint
        if (!self::validateFingerprint()) {
            self::logSessionActivity('SESSION_FINGERPRINT_MISMATCH', 'HIGH');
            return false;
        }
        
        // Check for session hijacking indicators
        if (self::detectSessionHijacking()) {
            self::logSessionActivity('SESSION_HIJACKING_DETECTED', 'CRITICAL');
            return false;
        }
        
        // Validate user agent consistency
        if (!self::validateUserAgent()) {
            self::logSessionActivity('SESSION_USER_AGENT_MISMATCH', 'HIGH');
            return false;
        }
        
        // Check concurrent sessions limit
        if (!self::validateConcurrentSessions()) {
            self::logSessionActivity('CONCURRENT_SESSION_LIMIT_EXCEEDED', 'MEDIUM');
            return false;
        }
        
        return true;
    }
    
    /**
     * Create and validate session fingerprint
     */
    private static function setupSessionFingerprint() {
        $fingerprint = self::generateFingerprint();
        
        if (!isset($_SESSION['session_fingerprint'])) {
            $_SESSION['session_fingerprint'] = $fingerprint;
            $_SESSION['session_start_time'] = time();
            $_SESSION['session_creation_ip'] = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        }
    }
    
    /**
     * Generate unique session fingerprint
     */
    private static function generateFingerprint() {
        $components = [
            $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'unknown',
            $_SERVER['HTTP_ACCEPT_ENCODING'] ?? 'unknown',
            $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            $_SERVER['SERVER_NAME'] ?? 'unknown'
        ];
        
        return hash('sha256', implode('|', $components) . session_id());
    }
    
    /**
     * Validate session fingerprint
     */
    private static function validateFingerprint() {
        if (!isset($_SESSION['session_fingerprint'])) {
            return false;
        }
        
        $currentFingerprint = self::generateFingerprint();
        return hash_equals($_SESSION['session_fingerprint'], $currentFingerprint);
    }
    
    /**
     * Detect potential session hijacking
     */
    private static function detectSessionHijacking() {
        // Check for IP address changes (with some tolerance for load balancers)
        if (isset($_SESSION['session_creation_ip'])) {
            $currentIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $originalIP = $_SESSION['session_creation_ip'];
            
            // Allow for load balancer IP variations (same subnet)
            if (!self::isIPInSameSubnet($currentIP, $originalIP)) {
                return true;
            }
        }
        
        // Check for suspicious timing patterns
        if (isset($_SESSION['last_activity'])) {
            $timeDiff = time() - $_SESSION['last_activity'];
            
            // Detect impossibly fast requests (possible automation)
            if ($timeDiff < 1 && isset($_SESSION['rapid_request_count'])) {
                $_SESSION['rapid_request_count']++;
                if ($_SESSION['rapid_request_count'] > 10) {
                    return true;
                }
            } else {
                $_SESSION['rapid_request_count'] = 0;
            }
        }
        
        $_SESSION['last_activity'] = time();
        return false;
    }
    
    /**
     * Check if two IPs are in the same subnet (for load balancer tolerance)
     */
    private static function isIPInSameSubnet($ip1, $ip2) {
        // For IPv4, check if they're in the same /24 subnet
        if (filter_var($ip1, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && 
            filter_var($ip2, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $subnet1 = ip2long($ip1) >> 8;
            $subnet2 = ip2long($ip2) >> 8;
            return $subnet1 === $subnet2;
        }
        
        // For IPv6 or other cases, require exact match
        return $ip1 === $ip2;
    }
    
    /**
     * Validate User Agent consistency
     */
    private static function validateUserAgent() {
        if (!isset($_SESSION['original_user_agent'])) {
            $_SESSION['original_user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            return true;
        }
        
        $currentAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        return $_SESSION['original_user_agent'] === $currentAgent;
    }
    
    /**
     * Validate concurrent sessions limit per user
     */
    private static function validateConcurrentSessions() {
        if (!isset($_SESSION['user_id'])) {
            return true; // No user logged in
        }
        
        $userId = $_SESSION['user_id'];
        $sessionsFile = "/tmp/user_sessions_{$userId}.json";
        
        $sessions = [];
        if (file_exists($sessionsFile)) {
            $sessions = json_decode(file_get_contents($sessionsFile), true) ?: [];
        }
        
        // Clean expired sessions
        $currentTime = time();
        $activeSessions = [];
        foreach ($sessions as $sessionData) {
            if (($currentTime - $sessionData['last_activity']) < self::$sessionTimeout) {
                $activeSessions[] = $sessionData;
            }
        }
        
        // Add current session
        $currentSession = [
            'session_id' => session_id(),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'last_activity' => $currentTime,
            'created' => $_SESSION['session_start_time'] ?? $currentTime
        ];
        
        // Update existing session or add new one
        $sessionUpdated = false;
        foreach ($activeSessions as &$session) {
            if ($session['session_id'] === session_id()) {
                $session['last_activity'] = $currentTime;
                $sessionUpdated = true;
                break;
            }
        }
        
        if (!$sessionUpdated) {
            $activeSessions[] = $currentSession;
        }
        
        // Check session limit
        if (count($activeSessions) > self::$maxSessionsPerUser) {
            self::logSessionActivity('CONCURRENT_SESSION_LIMIT_EXCEEDED', 'MEDIUM');
            
            // Remove oldest session
            usort($activeSessions, function($a, $b) {
                return $a['created'] - $b['created'];
            });
            array_shift($activeSessions);
        }
        
        // Save updated sessions
        file_put_contents($sessionsFile, json_encode($activeSessions));
        
        return true;
    }
    
    /**
     * Handle periodic session regeneration
     */
    private static function handleSessionRegeneration() {
        $shouldRegenerate = false;
        
        // Force regeneration if no regeneration timestamp
        if (!isset($_SESSION['last_regeneration'])) {
            $shouldRegenerate = true;
        }
        // Regenerate based on time interval
        elseif ((time() - $_SESSION['last_regeneration']) > self::$regenerateInterval) {
            $shouldRegenerate = true;
        }
        // Regenerate on privilege escalation
        elseif (isset($_SESSION['privilege_changed']) && $_SESSION['privilege_changed']) {
            $shouldRegenerate = true;
            unset($_SESSION['privilege_changed']);
        }
        
        if ($shouldRegenerate) {
            self::regenerateSession();
        }
    }
    
    /**
     * Securely regenerate session ID
     */
    public static function regenerateSession() {
        $oldSessionId = session_id();
        
        // Regenerate session ID
        if (session_regenerate_id(true)) {
            $_SESSION['last_regeneration'] = time();
            $_SESSION['session_fingerprint'] = self::generateFingerprint();
            
            self::logSessionActivity('SESSION_REGENERATED', 'INFO', [
                'old_session_id' => substr($oldSessionId, 0, 8) . '...',
                'new_session_id' => substr(session_id(), 0, 8) . '...'
            ]);
        }
    }
    
    /**
     * Mark session for privilege escalation regeneration
     */
    public static function markPrivilegeChange() {
        $_SESSION['privilege_changed'] = true;
        self::logSessionActivity('PRIVILEGE_ESCALATION_MARKED', 'MEDIUM');
    }
    
    /**
     * Securely destroy session
     */
    public static function destroySession() {
        $sessionId = session_id();
        
        // Clear session data
        $_SESSION = [];
        
        // Delete session cookie
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params['path'],
                $params['domain'],
                $params['secure'],
                $params['httponly']
            );
        }
        
        // Destroy session file
        session_destroy();
        
        self::logSessionActivity('SESSION_DESTROYED', 'INFO', [
            'session_id' => substr($sessionId, 0, 8) . '...'
        ]);
    }
    
    /**
     * Get session security status
     */
    public static function getSessionStatus() {
        return [
            'session_id' => substr(session_id(), 0, 8) . '...',
            'started' => $_SESSION['session_start_time'] ?? 'unknown',
            'last_regeneration' => $_SESSION['last_regeneration'] ?? 'never',
            'fingerprint_valid' => self::validateFingerprint(),
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 100),
            'expires_in' => self::$sessionTimeout - (time() - ($_SESSION['session_start_time'] ?? time())),
            'is_secure' => isset($_SERVER['HTTPS']),
            'cookie_settings' => [
                'httponly' => ini_get('session.cookie_httponly'),
                'secure' => ini_get('session.cookie_secure'),
                'samesite' => ini_get('session.cookie_samesite')
            ]
        ];
    }
    
    /**
     * Log session security events
     */
    private static function logSessionActivity($event, $severity = 'INFO', $details = []) {
        $logData = array_merge([
            'session_id' => substr(session_id(), 0, 8) . '...',
            'user_id' => $_SESSION['user_id'] ?? 'anonymous',
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 100)
        ], $details);
        
        SecurityLogger::logEvent($event, $logData, $severity);
    }
    
    /**
     * Get active sessions for a user (admin function)
     */
    public static function getUserSessions($userId) {
        $sessionsFile = "/tmp/user_sessions_{$userId}.json";
        
        if (!file_exists($sessionsFile)) {
            return [];
        }
        
        $sessions = json_decode(file_get_contents($sessionsFile), true) ?: [];
        $currentTime = time();
        
        // Filter active sessions and add human-readable info
        $activeSessions = [];
        foreach ($sessions as $session) {
            if (($currentTime - $session['last_activity']) < self::$sessionTimeout) {
                $session['active_duration'] = $currentTime - $session['created'];
                $session['last_activity_human'] = date('Y-m-d H:i:s', $session['last_activity']);
                $session['created_human'] = date('Y-m-d H:i:s', $session['created']);
                $activeSessions[] = $session;
            }
        }
        
        return $activeSessions;
    }
    
    /**
     * Revoke a specific session (admin function)
     */
    public static function revokeSession($userId, $sessionId) {
        $sessionsFile = "/tmp/user_sessions_{$userId}.json";
        
        if (!file_exists($sessionsFile)) {
            return false;
        }
        
        $sessions = json_decode(file_get_contents($sessionsFile), true) ?: [];
        $updated = false;
        
        foreach ($sessions as $key => $session) {
            if ($session['session_id'] === $sessionId) {
                unset($sessions[$key]);
                $updated = true;
                break;
            }
        }
        
        if ($updated) {
            file_put_contents($sessionsFile, json_encode(array_values($sessions)));
            self::logSessionActivity('SESSION_REVOKED_BY_ADMIN', 'HIGH', [
                'revoked_user_id' => $userId,
                'revoked_session_id' => substr($sessionId, 0, 8) . '...'
            ]);
        }
        
        return $updated;
    }
}

// Auto-initialize session security for all requests
SessionSecurity::initSecureSession();
?>