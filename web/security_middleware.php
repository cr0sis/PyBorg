<?php
/**
 * Security Middleware - Additive Security Layer
 * Provides comprehensive security without breaking existing functionality
 */

require_once 'security_alerts.php';

class SecurityMiddleware {
    private static $logFile = '/home/cr0/cr0bot/logs/security.log';
    private static $rateLimitFile = '/tmp/security_rate_limits.json';
    
    /**
     * Lightweight admin access validation
     */
    public static function validateAdminAccess() {
        // Only do lightweight checks for performance
        $user_ip = self::getUserIP();
        
        // Check if user is authenticated admin - skip IP blocking for admins
        $isAuthenticatedAdmin = false;
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        if (isset($_SESSION['user_id']) && isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
            $isAuthenticatedAdmin = true;
        }
        
        // Check if IP is blocked by alert system (skip for authenticated admins)
        if (!$isAuthenticatedAdmin && SecurityAlerts::isIPBlocked($user_ip)) {
            http_response_code(403);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Access denied']);
            exit();
        }
        
        // Apply throttling if IP is throttled
        $throttleDelay = SecurityAlerts::getIPThrottle($user_ip);
        if ($throttleDelay > 0) {
            usleep($throttleDelay * 1000); // Convert ms to microseconds
        }
        
        // Quick rate limiting check (memory-based, not file-based)
        self::quickRateLimit($user_ip);
        
        // Only do expensive checks occasionally (1 in 10 requests)
        if (rand(1, 10) === 1) {
            self::logAccessAttempt($user_ip);
            self::detectSuspiciousActivity($user_ip);
        }
        
        return true;
    }
    
    /**
     * Quick in-memory rate limiting
     */
    private static function quickRateLimit($ip) {
        static $requests = [];
        $current_time = time();
        
        // Clean old entries
        if (count($requests) > 100) {
            $requests = array_filter($requests, function($timestamp) use ($current_time) {
                return ($current_time - $timestamp) < 60;
            });
        }
        
        // Count recent requests from this IP
        $recent_requests = array_filter($requests, function($data) use ($ip, $current_time) {
            return $data['ip'] === $ip && ($current_time - $data['time']) < 60;
        });
        
        if (count($recent_requests) > 30) {
            // Light delay only for excessive requests
            usleep(100000); // 0.1 second instead of full seconds
        }
        
        // Store this request
        $requests[] = ['ip' => $ip, 'time' => $current_time];
    }
    
    /**
     * 2FA Implementation (optional layer that doesn't break existing auth)
     */
    public static function require2FA($username) {
        // Only suggest 2FA for admin users, don't enforce
        if ($username === 'admin') {
            self::logSecurityEvent('2FA_OPPORTUNITY', [
                'username' => $username,
                'ip' => self::getUserIP(),
                'message' => '2FA could be enabled for enhanced security'
            ], 'INFO');
        }
        return true; // Don't break existing login flow
    }
    
    /**
     * Lightweight rate limiting implementation (called only occasionally)
     */
    private static function implementRateLimit($ip) {
        // Only check rate limits occasionally to avoid file I/O on every request
        static $lastCheck = 0;
        $currentTime = time();
        
        // Only do file-based rate limiting every 30 seconds
        if ($currentTime - $lastCheck < 30) {
            return;
        }
        $lastCheck = $currentTime;
        
        $rateLimits = self::getRateLimits();
        
        if (!isset($rateLimits[$ip])) {
            $rateLimits[$ip] = ['count' => 1, 'last_request' => $currentTime];
        } else {
            $timeDiff = $currentTime - $rateLimits[$ip]['last_request'];
            
            if ($timeDiff < 300) { // Within 5 minutes (longer window, less frequent checks)
                $rateLimits[$ip]['count']++;
                
                // Only trigger on very high counts
                if ($rateLimits[$ip]['count'] > 100) {
                    self::logSecurityEvent('RATE_LIMIT_TRIGGERED', [
                        'ip' => $ip,
                        'request_count' => $rateLimits[$ip]['count']
                    ], 'MEDIUM');
                }
            } else {
                // Reset counter after 5 minutes
                $rateLimits[$ip] = ['count' => 1, 'last_request' => $currentTime];
            }
        }
        
        $rateLimits[$ip]['last_request'] = $currentTime;
        self::saveRateLimits($rateLimits);
    }
    
    /**
     * Detect suspicious activity patterns
     */
    private static function detectSuspiciousActivity($ip) {
        // Check for common attack patterns in User-Agent
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $suspiciousPatterns = [
            '/sqlmap/i',
            '/nikto/i',
            '/nmap/i',
            '/wget/i',
            '/curl.*bot/i',
            '/python-requests/i'
        ];
        
        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                self::logSecurityEvent('SUSPICIOUS_USER_AGENT', [
                    'ip' => $ip,
                    'user_agent' => $userAgent,
                    'pattern_matched' => $pattern
                ], 'HIGH');
                break;
            }
        }
        
        // Check for suspicious request patterns
        $requestUri = $_SERVER['REQUEST_URI'] ?? '';
        $suspiciousRequests = [
            '/\.\./i',  // Directory traversal
            '/union.*select/i',  // SQL injection
            '/<script/i',  // XSS attempts
            '/eval\(/i',  // Code injection
            '/base64_decode/i'  // Obfuscated attacks
        ];
        
        foreach ($suspiciousRequests as $pattern) {
            if (preg_match($pattern, $requestUri)) {
                self::logSecurityEvent('SUSPICIOUS_REQUEST', [
                    'ip' => $ip,
                    'request_uri' => $requestUri,
                    'pattern_matched' => $pattern
                ], 'HIGH');
                break;
            }
        }
    }
    
    /**
     * Log access attempts for monitoring
     */
    private static function logAccessAttempt($ip) {
        self::logSecurityEvent('ACCESS_ATTEMPT', [
            'ip' => $ip,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
            'referer' => $_SERVER['HTTP_REFERER'] ?? 'direct'
        ], 'INFO');
    }
    
    /**
     * Get user IP address (handles proxies)
     */
    private static function getUserIP() {
        $ipKeys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
        
        foreach ($ipKeys as $key) {
            if (!empty($_SERVER[$key])) {
                $ips = explode(',', $_SERVER[$key]);
                $ip = trim($ips[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }
    
    /**
     * Fast, non-blocking security event logging
     */
    public static function logSecurityEvent($type, $details, $severity = 'INFO') {
        // Process through alert system
        SecurityAlerts::processEvent($type, array_merge($details, [
            'severity' => $severity,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]));
        
        // For performance, only log critical events immediately
        if ($severity === 'CRITICAL' || $severity === 'HIGH') {
            error_log("SECURITY EVENT [$severity]: $type - " . json_encode($details));
        }
        
        // Queue other events for batch processing (non-blocking)
        static $eventQueue = [];
        
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'type' => $type,
            'severity' => $severity,
            'details' => $details,
            'session_id' => session_id() ?: 'no_session'
        ];
        
        $eventQueue[] = $logEntry;
        
        // Flush queue when it gets large (batch write)
        if (count($eventQueue) >= 10) {
            self::flushEventQueue($eventQueue);
            $eventQueue = [];
        }
    }
    
    /**
     * Flush event queue to log file (non-blocking)
     */
    private static function flushEventQueue($events) {
        try {
            $logDir = dirname(self::$logFile);
            if (!is_dir($logDir)) {
                mkdir($logDir, 0755, true);
            }
            
            $logData = '';
            foreach ($events as $event) {
                $logData .= json_encode($event) . "\n";
            }
            
            // Non-blocking write
            file_put_contents(self::$logFile, $logData, FILE_APPEND | LOCK_EX);
        } catch (Exception $e) {
            // Silently fail to avoid breaking the app
        }
    }
    
    /**
     * Get rate limits from storage
     */
    private static function getRateLimits() {
        if (file_exists(self::$rateLimitFile)) {
            $data = file_get_contents(self::$rateLimitFile);
            $limits = json_decode($data, true);
            return is_array($limits) ? $limits : [];
        }
        return [];
    }
    
    /**
     * Save rate limits to storage
     */
    private static function saveRateLimits($limits) {
        // Clean old entries (older than 1 hour)
        $currentTime = time();
        foreach ($limits as $ip => $data) {
            if ($currentTime - $data['last_request'] > 3600) {
                unset($limits[$ip]);
            }
        }
        
        file_put_contents(self::$rateLimitFile, json_encode($limits), LOCK_EX);
    }
    
    /**
     * Enhanced session security
     */
    public static function enhanceSessionSecurity() {
        if (session_status() == PHP_SESSION_NONE) {
            // Set secure session parameters
            ini_set('session.cookie_httponly', 1);
            ini_set('session.use_strict_mode', 1);
            ini_set('session.cookie_samesite', 'Strict');
            
            // Only set secure flag if HTTPS
            if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
                ini_set('session.cookie_secure', 1);
            }
            
            session_start();
            
            // Session regeneration for security
            if (!isset($_SESSION['last_regeneration'])) {
                session_regenerate_id(true);
                $_SESSION['last_regeneration'] = time();
            } elseif (time() - $_SESSION['last_regeneration'] > 300) { // Every 5 minutes
                session_regenerate_id(true);
                $_SESSION['last_regeneration'] = time();
            }
            
            // Session fingerprinting (log but don't block)
            self::validateSessionFingerprint();
        }
    }
    
    /**
     * Validate session fingerprint
     */
    private static function validateSessionFingerprint() {
        $fingerprint = hash('sha256', 
            ($_SERVER['HTTP_USER_AGENT'] ?? '') . 
            ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '') .
            ($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '')
        );
        
        if (!isset($_SESSION['security_fingerprint'])) {
            $_SESSION['security_fingerprint'] = $fingerprint;
        } elseif ($_SESSION['security_fingerprint'] !== $fingerprint) {
            self::logSecurityEvent('SESSION_FINGERPRINT_MISMATCH', [
                'stored_fingerprint' => $_SESSION['security_fingerprint'],
                'current_fingerprint' => $fingerprint,
                'ip' => self::getUserIP()
            ], 'MEDIUM');
            
            // Update fingerprint (don't break session)
            $_SESSION['security_fingerprint'] = $fingerprint;
        }
    }
    
    /**
     * Generate security headers
     */
    public static function generateSecurityHeaders() {
        // Content Security Policy
        header("Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com https://accounts.google.com https://apis.google.com; img-src 'self' data: https: https://accounts.google.com; connect-src 'self' https://accounts.google.com https://oauth2.googleapis.com https://www.googleapis.com; frame-src 'self' https://accounts.google.com;");
        
        // XSS Protection
        header("X-XSS-Protection: 1; mode=block");
        
        // Content Type Options
        header("X-Content-Type-Options: nosniff");
        
        // Frame Options
        header("X-Frame-Options: SAMEORIGIN");
        
        // Referrer Policy
        header("Referrer-Policy: strict-origin-when-cross-origin");
        
        // Remove server information
        header_remove("X-Powered-By");
        
        // Add security headers specific to admin areas
        if (strpos($_SERVER['REQUEST_URI'], 'admin') !== false) {
            header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
            header("Pragma: no-cache");
            header("Expires: 0");
        }
    }
    
    /**
     * Secure CORS implementation
     */
    public static function generateSecureCORS() {
        $allowed_origins = [
            'https://cr0s.is',
            'http://localhost',
            'http://127.0.0.1',
            'http://localhost:3000',
            'http://localhost:8080'
        ];
        
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        $host = $_SERVER['HTTP_HOST'] ?? '';
        
        // Only allow explicitly listed origins
        if (in_array($origin, $allowed_origins)) {
            header("Access-Control-Allow-Origin: $origin");
        } elseif (strpos($host, 'localhost') !== false || strpos($host, '127.0.0.1') !== false) {
            // For localhost development, be more permissive but still validate
            if (strpos($origin, 'localhost') !== false || strpos($origin, '127.0.0.1') !== false || empty($origin)) {
                header("Access-Control-Allow-Origin: " . ($origin ?: 'http://localhost'));
            } else {
                // Block non-localhost origins when accessed via localhost
                header('Access-Control-Allow-Origin: null');
                self::logSecurityEvent('CORS_BLOCKED', [
                    'origin' => $origin,
                    'host' => $host,
                    'reason' => 'Malicious origin blocked'
                ], 'MEDIUM');
            }
        } else {
            // Default to main site for production
            header('Access-Control-Allow-Origin: https://cr0s.is');
            
            // Log blocked attempts
            if (!empty($origin) && !in_array($origin, $allowed_origins)) {
                self::logSecurityEvent('CORS_BLOCKED', [
                    'origin' => $origin,
                    'host' => $host,
                    'reason' => 'Origin not in allowed list'
                ], 'MEDIUM');
            }
        }
        
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization');
        header('Access-Control-Max-Age: 86400');
    }
}

// Auto-initialize security when file is included
SecurityMiddleware::enhanceSessionSecurity();
SecurityMiddleware::generateSecurityHeaders();
?>