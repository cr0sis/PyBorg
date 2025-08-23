<?php
/**
 * Security Configuration
 * Centralized security settings and functions
 */

// Set timezone to Europe/London for all PHP operations
date_default_timezone_set('Europe/London');

// Security constants
define('ENCRYPTION_KEY', 'cr0bot_security_key_2024_v2_ultra_secure_' . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost'));

// Secure session configuration
function initSecureSession() {
    // Configure session settings before starting if no session is active
    if (session_status() === PHP_SESSION_NONE) {
        // Session security settings
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', 0); // Set to 1 if using HTTPS
        ini_set('session.cookie_samesite', 'Lax');
        ini_set('session.use_strict_mode', 1);
        ini_set('session.gc_maxlifetime', 3600);
        ini_set('session.gc_probability', 1);
        ini_set('session.gc_divisor', 1000);
        
        session_start();
    } elseif (session_status() === PHP_SESSION_ACTIVE) {
        // Session already active, just continue
        return;
    }
    
    // IP binding for admin sessions
    if (isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true) {
        validateSessionIP();
    }
}

// IP binding validation for admin sessions
function validateSessionIP() {
    $current_ip = $_SERVER['REMOTE_ADDR'];
    
    if (!isset($_SESSION['bound_ip'])) {
        // First time - bind this session to current IP
        $_SESSION['bound_ip'] = $current_ip;
        $_SESSION['ip_bind_time'] = time();
        logSecurityEvent('SESSION_IP_BOUND', "Admin session bound to IP: $current_ip");
    } else {
        // Validate IP hasn't changed
        if ($_SESSION['bound_ip'] !== $current_ip) {
            // Check if this is a proxy/CDN situation by looking at headers
            $proxy_ips = [
                $_SERVER['HTTP_CF_CONNECTING_IP'] ?? null,
                $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null,
                $_SERVER['HTTP_X_REAL_IP'] ?? null
            ];
            
            $is_proxy_change = false;
            foreach ($proxy_ips as $proxy_ip) {
                if ($proxy_ip && $_SESSION['bound_ip'] === $proxy_ip) {
                    $is_proxy_change = true;
                    break;
                }
            }
            
            if (!$is_proxy_change) {
                logSecurityEvent('SESSION_HIJACK_ATTEMPT', "IP mismatch! Session IP: {$_SESSION['bound_ip']}, Current IP: $current_ip");
                
                // Prevent redirect loops by checking if we're already on auth page
                if (!isset($_SERVER['REQUEST_URI']) || $_SERVER['REQUEST_URI'] !== '/auth.php') {
                    // Destroy compromised session
                    $_SESSION = array();
                    session_destroy();
                    
                    // Redirect to login with error
                    header('HTTP/1.1 403 Forbidden');
                    header('Location: /auth.php?error=session_hijack_detected');
                    exit('Session hijacking detected. Please log in again.');
                }
            } else {
                // Update bound IP for proxy/CDN changes
                $_SESSION['bound_ip'] = $current_ip;
                logSecurityEvent('SESSION_IP_UPDATED', "Admin session IP updated due to proxy/CDN: $current_ip");
            }
        }
    }
}

// Security event logging
function logSecurityEvent($event_type, $message, $severity = 'HIGH') {
    $log_entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'event_type' => $event_type,
        'severity' => $severity,
        'message' => $message,
        'ip_address' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'session_id' => session_id(),
        'user_id' => $_SESSION['user_id'] ?? 'anonymous'
    ];
    
    $log_file = '/tmp/admin_security.log';
    file_put_contents($log_file, json_encode($log_entry) . "\n", FILE_APPEND | LOCK_EX);
    
    // Also log to system error log for critical events
    if ($severity === 'CRITICAL') {
        error_log("CRITICAL SECURITY EVENT: $event_type - $message");
    }
}

// CSRF Token Functions
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function getCSRFTokenHTML() {
    $token = generateCSRFToken();
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
}

// Input Sanitization Functions
function sanitizeInput($input, $type = 'string') {
    if ($input === null) return null;
    
    switch ($type) {
        case 'string':
            return trim(htmlspecialchars($input, ENT_QUOTES, 'UTF-8'));
        case 'int':
            return filter_var($input, FILTER_VALIDATE_INT);
        case 'email':
            return filter_var($input, FILTER_VALIDATE_EMAIL);
        case 'url':
            return filter_var($input, FILTER_VALIDATE_URL);
        case 'alphanumeric':
            return preg_replace('/[^a-zA-Z0-9]/', '', $input);
        case 'filename':
            return preg_replace('/[^a-zA-Z0-9._-]/', '', $input);
        default:
            return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    }
}

// Rate Limiting
class RateLimit {
    private static $attempts = [];
    
    public static function check($identifier, $maxAttempts = 5, $timeWindow = 300) {
        // Whitelist localhost - allow unlimited requests from localhost
        if (in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1', 'localhost'])) {
            return true;
        }
        
        // Skip rate limiting for logged-in admin users
        if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
            return true;
        }
        
        $now = time();
        $key = md5($identifier);
        
        // Clean old attempts
        if (isset(self::$attempts[$key])) {
            self::$attempts[$key] = array_filter(
                self::$attempts[$key], 
                function($timestamp) use ($now, $timeWindow) {
                    return ($now - $timestamp) < $timeWindow;
                }
            );
        } else {
            self::$attempts[$key] = [];
        }
        
        // Check if limit exceeded
        if (count(self::$attempts[$key]) >= $maxAttempts) {
            return false;
        }
        
        // Record attempt
        self::$attempts[$key][] = $now;
        return true;
    }
}

// Safe command execution (whitelist approach)
class SafeCommand {
    private static $allowedCommands = [
        'ps' => '/bin/ps',
        'screen' => '/usr/bin/screen',
        'tail' => '/usr/bin/tail',
        'getconf' => '/usr/bin/getconf',
        'awk' => '/usr/bin/awk'
    ];
    
    private static $allowedArgs = [
        'ps' => ['aux'],
        'screen' => ['-list', '-S', '-X'],
        'tail' => ['-100', '-n'],
        'getconf' => ['CLK_TCK'],
        'awk' => ['/btime/ {print $2}', '/proc/stat']
    ];
    
    public static function execute($command, $args = [], $input = null) {
        // Validate command exists in whitelist
        if (!isset(self::$allowedCommands[$command])) {
            throw new Exception("Command not allowed: $command");
        }
        
        $executable = self::$allowedCommands[$command];
        if (!file_exists($executable)) {
            throw new Exception("Command executable not found: $executable");
        }
        
        // Validate arguments
        foreach ($args as $arg) {
            if (!in_array($arg, self::$allowedArgs[$command]) && 
                !preg_match('/^[a-zA-Z0-9._\/\-]+$/', $arg)) {
                throw new Exception("Invalid argument: $arg");
            }
        }
        
        // Build safe command
        $safeArgs = array_map('escapeshellarg', $args);
        $fullCommand = $executable . ' ' . implode(' ', $safeArgs);
        
        // Execute with timeout and capture output safely
        $descriptors = [
            0 => ["pipe", "r"],  // stdin
            1 => ["pipe", "w"],  // stdout
            2 => ["pipe", "w"]   // stderr
        ];
        
        $process = proc_open($fullCommand, $descriptors, $pipes);
        
        if (!is_resource($process)) {
            throw new Exception("Failed to execute command");
        }
        
        // Set timeout
        stream_set_timeout($pipes[1], 10);
        stream_set_timeout($pipes[2], 10);
        
        // Get output
        $output = stream_get_contents($pipes[1]);
        $error = stream_get_contents($pipes[2]);
        
        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        
        $return_value = proc_close($process);
        
        if ($return_value !== 0) {
            throw new Exception("Command failed with error: $error");
        }
        
        return $output;
    }
}

// Security Headers
function setSecurityHeaders() {
    // Prevent XSS
    header('X-XSS-Protection: 1; mode=block');
    
    // Prevent clickjacking
    header('X-Frame-Options: DENY');
    
    // Prevent MIME sniffing
    header('X-Content-Type-Options: nosniff');
    
    // Content Security Policy
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://accounts.google.com https://apis.google.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data: https://accounts.google.com; connect-src 'self' https://accounts.google.com https://oauth2.googleapis.com https://www.googleapis.com; frame-src 'self' https://accounts.google.com;");
    
    // Referrer Policy
    header('Referrer-Policy: strict-origin-when-cross-origin');
    
    // HTTP Strict Transport Security (uncomment if using HTTPS)
    // header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// Authentication helpers
function requireAuth() {
    if (!isset($_SESSION['user_id'])) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Authentication required']);
        exit;
    }
}

function requireAdmin() {
    requireAuth();
    if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Admin access required']);
        exit;
    }
}

// Logging function
function securityLog($message, $level = 'INFO') {
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $user = $_SESSION['username'] ?? 'anonymous';
    
    $logEntry = "[$timestamp] [$level] [$ip] [$user] $message\n";
    
    // Try to write to security log, fall back to PHP error log if not writable
    $logFile = '/var/log/website_security.log';
    if (is_writable(dirname($logFile))) {
        error_log($logEntry, 3, $logFile);
    } else {
        // Fall back to PHP error log
        error_log("Security: $logEntry");
    }
}

// Initialize security
initSecureSession();
setSecurityHeaders();
?>