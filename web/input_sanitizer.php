<?php
/**
 * High-Performance Input Sanitization System
 * Provides comprehensive input validation while preserving functionality
 */

require_once 'security_middleware.php';

class InputSanitizer {
    
    /**
     * Sanitize all input data recursively (preserves structure)
     */
    public static function sanitizeAll($data) {
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeAll'], $data);
        }
        
        if (!is_string($data)) {
            return $data; // Don't modify non-strings
        }
        
        // Multi-layer sanitization
        $data = self::removeNullBytes($data);
        $data = self::sanitizeXSS($data);
        $data = self::preventSQLInjection($data);
        
        return $data;
    }
    
    /**
     * Remove null bytes and control characters
     */
    private static function removeNullBytes($input) {
        return str_replace(["\0", "\x00"], '', $input);
    }
    
    /**
     * XSS protection while preserving legitimate HTML when needed
     */
    public static function sanitizeXSS($input, $allowHTML = false) {
        if (!$allowHTML) {
            // Standard XSS protection
            return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
        
        // For cases where some HTML is needed, filter dangerous tags
        $allowedTags = '<b><strong><i><em><u><br><p><div><span>';
        return strip_tags($input, $allowedTags);
    }
    
    /**
     * SQL injection prevention (additional layer beyond prepared statements)
     */
    private static function preventSQLInjection($input) {
        $dangerous_patterns = [
            '/(\s|^)(union\s+select)/i',
            '/(\s|^)(drop\s+table)/i',
            '/(\s|^)(delete\s+from)/i',
            '/(\s|^)(insert\s+into)/i',
            '/(\s|^)(update\s+.*set)/i',
            '/(\s|^)(create\s+table)/i',
            '/(\s|^)(alter\s+table)/i',
            '/(exec|execute)\s*\(/i'
        ];
        
        foreach ($dangerous_patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                SecurityMiddleware::logSecurityEvent('SQL_INJECTION_ATTEMPT', [
                    'input' => $input,
                    'pattern' => $pattern,
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ], 'HIGH');
                
                // Don't block completely, just sanitize
                $input = preg_replace($pattern, '[BLOCKED_SQL]', $input);
            }
        }
        
        return $input;
    }
    
    /**
     * Validate API actions against whitelist
     */
    public static function validateAction($action) {
        $allowed_actions = [
            // Bot management
            'bot_status', 'system_health', 'restart_bot', 'start_bot', 'stop_bot',
            'restart_rizon', 'restart_libera', 'full', 'quick', 'send_command',
            'realtime', 'status', 'public_status', 'events', 'stats', 'trigger_check',
            
            // User and stats
            'user_stats', 'get_user_stats', 'get_all_users', 'update_admin_status', 'update_user_status',
            
            // Game management
            'breakout_stats', 'get_high_scores', 'delete_score', 'reset_scores', 'ban_player',
            'pigs_stats', 'uno_stats',
            
            // Logs and monitoring
            'get_logs', 'get_rizon_logs', 'get_libera_logs', 'get_bot_logs', 'sync_logs', 'get_live_logs',
            
            // Database operations
            'database_status', 'backup_database', 'cleanup_database', 'optimize_database',
            
            // Bot analytics
            'bot_analytics', 'bot_config'
        ];
        
        if (!in_array($action, $allowed_actions)) {
            SecurityMiddleware::logSecurityEvent('INVALID_ACTION_ATTEMPT', [
                'action' => $action,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ], 'MEDIUM');
            
            return 'bot_status'; // Default safe action
        }
        
        return $action;
    }
    
    /**
     * Validate and sanitize file paths
     */
    public static function validateFilePath($path) {
        // Remove null bytes and normalize path
        $path = str_replace(["\0", "\x00"], '', $path);
        $path = realpath($path);
        
        if (!$path) {
            return null; // Invalid path
        }
        
        $allowed_paths = [
            '/home/cr0/cr0bot/logs/',
            '/var/www/html/data/',
            '/tmp/',
            '/home/cr0/cr0bot/data/' // Add additional safe paths as needed
        ];
        
        foreach ($allowed_paths as $allowed) {
            $allowedReal = realpath($allowed);
            if ($allowedReal && strpos($path, $allowedReal) === 0) {
                return $path; // Safe path
            }
        }
        
        // Log directory traversal attempts
        SecurityMiddleware::logSecurityEvent('DIRECTORY_TRAVERSAL_ATTEMPT', [
            'attempted_path' => $_REQUEST['path'] ?? 'unknown',
            'resolved_path' => $path,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ], 'HIGH');
        
        return null; // Block dangerous paths
    }
    
    /**
     * Validate player names for games
     */
    public static function validatePlayerName($name) {
        // Remove dangerous characters but preserve functionality
        $name = preg_replace('/[<>"\'\x00-\x1f\x7f-\xff]/', '', $name);
        $name = trim($name);
        
        // Limit length
        if (strlen($name) > 50) {
            $name = substr($name, 0, 50);
        }
        
        // Ensure not empty after sanitization
        if (empty($name)) {
            return 'Anonymous';
        }
        
        return $name;
    }
    
    /**
     * Validate numeric inputs
     */
    public static function validateNumeric($input, $min = null, $max = null) {
        if (!is_numeric($input)) {
            return 0;
        }
        
        $number = (float)$input;
        
        if ($min !== null && $number < $min) {
            return $min;
        }
        
        if ($max !== null && $number > $max) {
            return $max;
        }
        
        return $number;
    }
    
    /**
     * Validate email addresses
     */
    public static function validateEmail($email) {
        $email = filter_var($email, FILTER_SANITIZE_EMAIL);
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return false;
        }
        
        return $email;
    }
    
    /**
     * Validate and sanitize database IDs
     */
    public static function validateID($id) {
        if (!is_numeric($id) || $id < 1) {
            SecurityMiddleware::logSecurityEvent('INVALID_ID_ATTEMPT', [
                'id' => $id,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ], 'LOW');
            return false;
        }
        
        return (int)$id;
    }
    
    /**
     * Command injection prevention
     */
    public static function sanitizeCommand($input) {
        // Remove dangerous characters for shell commands
        $dangerous_chars = ['|', '&', ';', '`', '$', '(', ')', '<', '>', '\n', '\r'];
        $sanitized = str_replace($dangerous_chars, '', $input);
        
        if ($sanitized !== $input) {
            SecurityMiddleware::logSecurityEvent('COMMAND_INJECTION_ATTEMPT', [
                'original' => $input,
                'sanitized' => $sanitized,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ], 'HIGH');
        }
        
        return $sanitized;
    }
    
    /**
     * Validate JSON input
     */
    public static function validateJSON($json) {
        if (!is_string($json)) {
            return false;
        }
        
        $decoded = json_decode($json, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            SecurityMiddleware::logSecurityEvent('INVALID_JSON_ATTEMPT', [
                'json' => substr($json, 0, 200),
                'error' => json_last_error_msg(),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ], 'LOW');
            return false;
        }
        
        // Sanitize the decoded data
        return self::sanitizeAll($decoded);
    }
    
    /**
     * Rate limit specific operations
     */
    public static function checkOperationRateLimit($operation, $limit = 10, $window = 60) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $key = "rate_limit_{$operation}_{$ip}";
        $cache_file = "/tmp/{$key}";
        
        $current_time = time();
        $count = 1;
        
        if (file_exists($cache_file)) {
            $data = json_decode(file_get_contents($cache_file), true);
            if ($data && ($current_time - $data['start_time']) < $window) {
                $count = $data['count'] + 1;
                if ($count > $limit) {
                    SecurityMiddleware::logSecurityEvent('OPERATION_RATE_LIMIT_EXCEEDED', [
                        'operation' => $operation,
                        'ip' => $ip,
                        'count' => $count,
                        'limit' => $limit
                    ], 'MEDIUM');
                    return false;
                }
            } else {
                // Reset counter if window expired
                $count = 1;
            }
        }
        
        // Update counter
        file_put_contents($cache_file, json_encode([
            'count' => $count,
            'start_time' => ($count === 1) ? $current_time : $data['start_time']
        ]));
        
        return true;
    }
    
    /**
     * Clean up temporary rate limit files
     */
    public static function cleanupRateLimitFiles() {
        $files = glob('/tmp/rate_limit_*');
        $current_time = time();
        
        foreach ($files as $file) {
            if (file_exists($file) && ($current_time - filemtime($file)) > 3600) {
                unlink($file);
            }
        }
    }
}

/**
 * Input Sanitizer Error Handler - Prevents information disclosure
 */
class InputSanitizerErrorHandler {
    
    public static function handleError($error, $userMessage = "An error occurred", $logLevel = 'ERROR') {
        // Log detailed error for developers
        SecurityMiddleware::logSecurityEvent('APPLICATION_ERROR', [
            'error' => $error,
            'user_message' => $userMessage,
            'trace' => debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3)
        ], $logLevel);
        
        // Return generic message to users (prevent information disclosure)
        $response = ['error' => $userMessage];
        
        // Only include debug info in development
        if (defined('DEBUG_MODE') && DEBUG_MODE) {
            $response['debug'] = $error;
        }
        
        return $response;
    }
    
    public static function handleDatabaseError($error, $query_type = 'unknown') {
        SecurityMiddleware::logSecurityEvent('DATABASE_ERROR', [
            'error' => $error,
            'query_type' => $query_type,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ], 'HIGH');
        
        return ['error' => 'Database operation failed'];
    }
    
    public static function handleFileError($error, $file_path = 'unknown') {
        SecurityMiddleware::logSecurityEvent('FILE_ERROR', [
            'error' => $error,
            'file_path' => $file_path,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ], 'MEDIUM');
        
        return ['error' => 'File operation failed'];
    }
}

// Auto-cleanup rate limit files occasionally
if (rand(1, 100) === 1) {
    InputSanitizer::cleanupRateLimitFiles();
}
?>