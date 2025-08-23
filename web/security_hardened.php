<?php
/**
 * HARDCORE SECURITY CONFIGURATION
 * For Pi exposed to internet - maximum hardening without breaking functionality
 */

require_once 'security_config.php';

// Critical security constants
define('MAX_REQUEST_SIZE', 1024 * 1024); // 1MB max request
define('MAX_JSON_DEPTH', 10);
define('MAX_LOGIN_ATTEMPTS', 3);
define('LOCKOUT_DURATION', 1800); // 30 minutes
define('MAX_SESSION_LIFETIME', 3600); // 1 hour
define('BLOCKED_IPS_FILE', '/tmp/blocked_ips.json');
define('SECURITY_EVENTS_FILE', '/tmp/security_events.json');

class HardcoreSecurityManager {
    private static $blockedIPs = [];
    private static $securityEvents = [];
    
    public static function init() {
        self::loadBlockedIPs();
        self::loadSecurityEvents();
        self::enforceRequestLimits();
        self::checkIPBlacklist();
        self::detectSuspiciousActivity();
    }
    
    // Enforce strict request limits
    private static function enforceRequestLimits() {
        // Block requests that are too large
        $contentLength = $_SERVER['CONTENT_LENGTH'] ?? 0;
        if ($contentLength > MAX_REQUEST_SIZE) {
            self::logSecurityEvent('ATTACK', 'Request size exceeded limit', $_SERVER['REMOTE_ADDR']);
            http_response_code(413);
            exit('Request too large');
        }
        
        // Limit concurrent connections per IP - DISABLED for legitimate admin usage
        // if (!self::checkConcurrentConnections()) {
        //     self::logSecurityEvent('ATTACK', 'Too many concurrent connections', $_SERVER['REMOTE_ADDR']);
        //     http_response_code(429);
        //     exit('Too many concurrent connections');
        // }
    }
    
    // Check if IP is blacklisted
    private static function checkIPBlacklist() {
        $clientIP = $_SERVER['REMOTE_ADDR'];
        
        // Whitelist localhost and local IPs
        $trustedIPs = ['127.0.0.1', '::1', 'localhost'];
        
        // Load additional trusted IPs from secure config file
        $trustedIPsFile = __DIR__ . '/trusted_ips.php';
        if (file_exists($trustedIPsFile)) {
            $additionalIPs = include $trustedIPsFile;
            if (is_array($additionalIPs)) {
                $trustedIPs = array_merge($trustedIPs, $additionalIPs);
            }
        }
        
        if (in_array($clientIP, $trustedIPs)) {
            return; // Allow localhost and trusted IPs always
        }
        
        if (isset(self::$blockedIPs[$clientIP])) {
            $blockInfo = self::$blockedIPs[$clientIP];
            if (time() < $blockInfo['until']) {
                self::logSecurityEvent('BLOCKED', 'Blocked IP attempted access', $clientIP);
                http_response_code(403);
                exit('Access denied');
            } else {
                // Unblock expired IPs
                unset(self::$blockedIPs[$clientIP]);
                self::saveBlockedIPs();
            }
        }
    }
    
    // Block IP address
    public static function blockIP($ip, $reason = 'Security violation', $duration = LOCKOUT_DURATION) {
        self::$blockedIPs[$ip] = [
            'blocked_at' => time(),
            'until' => time() + $duration,
            'reason' => $reason,
            'attempts' => (self::$blockedIPs[$ip]['attempts'] ?? 0) + 1
        ];
        self::saveBlockedIPs();
        self::logSecurityEvent('BLOCK', "IP blocked: $reason", $ip);
    }
    
    // Enhanced rate limiting with persistent storage
    public static function checkRateLimit($identifier, $maxAttempts, $timeWindow) {
        // Whitelist localhost - allow unlimited requests from localhost
        if (in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1', 'localhost'])) {
            return true;
        }
        
        // Check trusted IPs from configuration file
        $trustedIPs = ['127.0.0.1', '::1', 'localhost'];
        $trustedIPsFile = __DIR__ . '/trusted_ips.php';
        if (file_exists($trustedIPsFile)) {
            $additionalIPs = include $trustedIPsFile;
            if (is_array($additionalIPs)) {
                $trustedIPs = array_merge($trustedIPs, $additionalIPs);
            }
        }
        
        if (in_array($_SERVER['REMOTE_ADDR'], $trustedIPs)) {
            return true;
        }
        
        // Skip rate limiting for logged-in admin users (if session already active)
        if (session_status() == PHP_SESSION_ACTIVE && isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
            return true;
        }
        
        $now = time();
        $key = hash('sha256', $identifier);
        $attemptsFile = "/tmp/rate_limit_$key.json";
        
        $attempts = [];
        if (file_exists($attemptsFile)) {
            $attempts = json_decode(file_get_contents($attemptsFile), true) ?: [];
        }
        
        // Clean old attempts
        $attempts = array_filter($attempts, function($timestamp) use ($now, $timeWindow) {
            return ($now - $timestamp) < $timeWindow;
        });
        
        // Check if limit exceeded
        if (count($attempts) >= $maxAttempts) {
            self::logSecurityEvent('RATE_LIMIT', 'Rate limit exceeded', $_SERVER['REMOTE_ADDR']);
            
            // Auto-block after repeated violations
            $ip = $_SERVER['REMOTE_ADDR'];
            $violationCount = self::getViolationCount($ip);
            if ($violationCount >= 3) {
                self::blockIP($ip, 'Repeated rate limit violations');
            }
            
            return false;
        }
        
        // Record attempt
        $attempts[] = $now;
        file_put_contents($attemptsFile, json_encode($attempts));
        
        return true;
    }
    
    // Detect suspicious activity patterns
    private static function detectSuspiciousActivity() {
        $ip = $_SERVER['REMOTE_ADDR'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $requestUri = $_SERVER['REQUEST_URI'] ?? '';
        
        // Whitelist localhost and local IPs
        $trustedIPs = ['127.0.0.1', '::1', 'localhost'];
        
        // Load additional trusted IPs from secure config file
        $trustedIPsFile = __DIR__ . '/trusted_ips.php';
        if (file_exists($trustedIPsFile)) {
            $additionalIPs = include $trustedIPsFile;
            if (is_array($additionalIPs)) {
                $trustedIPs = array_merge($trustedIPs, $additionalIPs);
            }
        }
        
        if (in_array($ip, $trustedIPs)) {
            return; // Allow localhost and trusted IPs always
        }
        
        // Detect common attack patterns - DISABLED for trusted IPs to prevent false positives
        $suspiciousPatterns = [
            '/\.\./i' => 'Directory traversal attempt',
            '/union.*select/i' => 'SQL injection attempt',
            '/<script|javascript:|on\w+=/i' => 'XSS attempt',
            '/\$\{.*\}/i' => 'Template injection attempt',
            // DISABLED: '/curl|wget|python|perl|bash/i' => 'Command injection attempt',
            '/\x00/i' => 'Null byte injection',
            '/@.*@/i' => 'Email harvesting attempt'
        ];
        
        foreach ($suspiciousPatterns as $pattern => $description) {
            if (preg_match($pattern, $requestUri . $userAgent)) {
                self::logSecurityEvent('ATTACK', $description, $ip);
                self::blockIP($ip, $description);
                http_response_code(403);
                exit('Suspicious activity detected');
            }
        }
        
        // Detect bot patterns
        $botPatterns = [
            '/bot|crawler|spider|scraper/i',
            '/^$/i', // Empty user agent
            '/curl|wget|python-requests/i'
        ];
        
        foreach ($botPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                self::logSecurityEvent('BOT', 'Bot detected', $ip);
                // Don't block immediately, but monitor
            }
        }
    }
    
    // Safe JSON parsing with limits
    public static function safeJSONParse($jsonString) {
        if (strlen($jsonString) > MAX_REQUEST_SIZE) {
            self::logSecurityEvent('ATTACK', 'JSON bomb attempt - size', $_SERVER['REMOTE_ADDR']);
            return false;
        }
        
        // Detect JSON bomb patterns
        $suspiciousCount = substr_count($jsonString, '{') + substr_count($jsonString, '[');
        if ($suspiciousCount > 100) {
            self::logSecurityEvent('ATTACK', 'JSON bomb attempt - nesting', $_SERVER['REMOTE_ADDR']);
            return false;
        }
        
        $data = json_decode($jsonString, true, MAX_JSON_DEPTH);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            self::logSecurityEvent('WARNING', 'JSON parsing error: ' . json_last_error_msg(), $_SERVER['REMOTE_ADDR']);
            return false;
        }
        
        return $data;
    }
    
    // Sanitize log input to prevent log injection
    public static function sanitizeLogInput($input) {
        // Remove control characters, newlines, and potential injection attempts
        $cleaned = preg_replace('/[\r\n\t\x00-\x1F\x7F]/', '', $input);
        $cleaned = preg_replace('/\x1b\[[0-9;]*m/', '', $cleaned); // Remove ANSI codes
        return substr($cleaned, 0, 200); // Limit length
    }
    
    // Enhanced security logging
    public static function logSecurityEvent($type, $message, $ip = null) {
        $ip = $ip ?: ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        $timestamp = date('Y-m-d H:i:s');
        $userAgent = self::sanitizeLogInput($_SERVER['HTTP_USER_AGENT'] ?? 'unknown');
        $uri = self::sanitizeLogInput($_SERVER['REQUEST_URI'] ?? 'unknown');
        
        $event = [
            'timestamp' => $timestamp,
            'type' => $type,
            'message' => self::sanitizeLogInput($message),
            'ip' => $ip,
            'user_agent' => $userAgent,
            'uri' => $uri,
            'session_id' => substr(session_id(), 0, 8) . '...'
        ];
        
        // Add to security events
        self::$securityEvents[] = $event;
        
        // Keep only last 1000 events
        if (count(self::$securityEvents) > 1000) {
            self::$securityEvents = array_slice(self::$securityEvents, -1000);
        }
        
        self::saveSecurityEvents();
        
        // Also log to system
        $logLine = "[$timestamp] SECURITY[$type] [$ip] $message";
        error_log($logLine);
    }
    
    // File system access protection
    public static function validateFilePath($path, $allowedDirs = ['/tmp/', '/var/log/']) {
        $realPath = realpath($path);
        
        if ($realPath === false) {
            return false; // File doesn't exist or path is invalid
        }
        
        foreach ($allowedDirs as $allowedDir) {
            if (strpos($realPath, realpath($allowedDir)) === 0) {
                return true;
            }
        }
        
        self::logSecurityEvent('ATTACK', 'Path traversal attempt: ' . $path, $_SERVER['REMOTE_ADDR']);
        return false;
    }
    
    private static function checkConcurrentConnections() {
        $ip = $_SERVER['REMOTE_ADDR'];
        
        // Whitelist localhost - allow unlimited connections from localhost
        if (in_array($ip, ['127.0.0.1', '::1', 'localhost'])) {
            return true;
        }
        
        // Skip concurrent connection check for logged-in admin users
        if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
            return true;
        }
        
        $connectionsFile = "/tmp/connections_$ip.json";
        $now = time();
        
        $connections = [];
        if (file_exists($connectionsFile)) {
            $connections = json_decode(file_get_contents($connectionsFile), true) ?: [];
        }
        
        // Remove old connections (older than 30 seconds)
        $connections = array_filter($connections, function($timestamp) use ($now) {
            return ($now - $timestamp) < 30;
        });
        
        // Check limit (max 5 concurrent connections per IP)
        if (count($connections) >= 5) {
            return false;
        }
        
        $connections[] = $now;
        file_put_contents($connectionsFile, json_encode($connections));
        
        return true;
    }
    
    private static function getViolationCount($ip) {
        $count = 0;
        foreach (self::$securityEvents as $event) {
            if ($event['ip'] === $ip && 
                in_array($event['type'], ['RATE_LIMIT', 'ATTACK']) && 
                time() - strtotime($event['timestamp']) < 3600) {
                $count++;
            }
        }
        return $count;
    }
    
    private static function loadBlockedIPs() {
        if (file_exists(BLOCKED_IPS_FILE)) {
            self::$blockedIPs = json_decode(file_get_contents(BLOCKED_IPS_FILE), true) ?: [];
        }
    }
    
    private static function saveBlockedIPs() {
        file_put_contents(BLOCKED_IPS_FILE, json_encode(self::$blockedIPs, JSON_PRETTY_PRINT));
    }
    
    private static function loadSecurityEvents() {
        if (file_exists(SECURITY_EVENTS_FILE)) {
            self::$securityEvents = json_decode(file_get_contents(SECURITY_EVENTS_FILE), true) ?: [];
        }
    }
    
    private static function saveSecurityEvents() {
        file_put_contents(SECURITY_EVENTS_FILE, json_encode(self::$securityEvents, JSON_PRETTY_PRINT));
    }
    
    // Get security dashboard data
    public static function getSecurityDashboard() {
        return [
            'blocked_ips' => count(self::$blockedIPs),
            'recent_events' => array_slice(self::$securityEvents, -50),
            'event_summary' => self::getEventSummary(),
            'active_blocks' => self::getActiveBlocks()
        ];
    }
    
    private static function getEventSummary() {
        $summary = [];
        $hourAgo = time() - 3600;
        
        foreach (self::$securityEvents as $event) {
            if (strtotime($event['timestamp']) > $hourAgo) {
                $summary[$event['type']] = ($summary[$event['type']] ?? 0) + 1;
            }
        }
        
        return $summary;
    }
    
    private static function getActiveBlocks() {
        $active = [];
        $now = time();
        
        foreach (self::$blockedIPs as $ip => $info) {
            if ($now < $info['until']) {
                $active[$ip] = $info;
            }
        }
        
        return $active;
    }
}

// Initialize hardcore security
HardcoreSecurityManager::init();
?>