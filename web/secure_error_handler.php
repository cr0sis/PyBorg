<?php
/**
 * Secure Error Handler
 * Prevents information disclosure through error messages
 */

require_once 'security_logger.php';
require_once 'config_paths.php';

class SecureErrorHandler {
    
    private static $initialized = false;
    private static $errorLogPath;
    
    /**
     * Initialize secure error handling
     */
    public static function init() {
        if (self::$initialized) {
            return;
        }
        
        // Get centralized error log path
        self::$errorLogPath = ConfigPaths::LOG_WEBSITE_ERRORS . '/';
        
        // Create error log directory using ConfigPaths
        ConfigPaths::ensureDirectory(self::$errorLogPath);
        
        // Set error handlers
        set_error_handler([self::class, 'handleError']);
        set_exception_handler([self::class, 'handleException']);
        register_shutdown_function([self::class, 'handleShutdown']);
        
        // Configure PHP error settings
        error_reporting(E_ALL);
        ini_set('display_errors', 0);
        ini_set('display_startup_errors', 0);
        ini_set('log_errors', 1);
        ini_set('error_log', self::$errorLogPath . 'php_errors.log');
        
        self::$initialized = true;
    }
    
    /**
     * Handle PHP errors
     */
    public static function handleError($errno, $errstr, $errfile, $errline) {
        // Don't handle suppressed errors
        if (!(error_reporting() & $errno)) {
            return false;
        }
        
        $errorType = self::getErrorType($errno);
        
        // Log detailed error internally
        $errorData = [
            'type' => $errorType,
            'message' => $errstr,
            'file' => $errfile,
            'line' => $errline,
            'trace' => debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS),
            'context' => [
                'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
                'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]
        ];
        
        self::logError($errorData);
        
        // Determine severity for security logging
        $severity = 'LOW';
        if (in_array($errno, [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            $severity = 'HIGH';
        } elseif (in_array($errno, [E_WARNING, E_CORE_WARNING, E_COMPILE_WARNING])) {
            $severity = 'MEDIUM';
        }
        
        // Log to security system
        SecurityLogger::logEvent('PHP_ERROR', [
            'error_type' => $errorType,
            'file' => basename($errfile),
            'line' => $errline
        ], $severity);
        
        // Return generic message to user
        if (self::isProduction()) {
            self::showGenericError();
        }
        
        // Don't execute PHP internal error handler
        return true;
    }
    
    /**
     * Handle uncaught exceptions
     */
    public static function handleException($exception) {
        $errorData = [
            'type' => 'EXCEPTION',
            'class' => get_class($exception),
            'message' => $exception->getMessage(),
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'trace' => $exception->getTraceAsString(),
            'context' => [
                'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
                'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]
        ];
        
        self::logError($errorData);
        
        // Log to security system
        SecurityLogger::logEvent('UNCAUGHT_EXCEPTION', [
            'exception_class' => get_class($exception),
            'file' => basename($exception->getFile()),
            'line' => $exception->getLine()
        ], 'HIGH');
        
        // Show generic error
        self::showGenericError();
    }
    
    /**
     * Handle fatal errors on shutdown
     */
    public static function handleShutdown() {
        $error = error_get_last();
        
        if ($error !== null && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            $errorData = [
                'type' => 'FATAL',
                'message' => $error['message'],
                'file' => $error['file'],
                'line' => $error['line'],
                'context' => [
                    'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
                    'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]
            ];
            
            self::logError($errorData);
            
            // Log to security system
            SecurityLogger::logEvent('FATAL_ERROR', [
                'file' => basename($error['file']),
                'line' => $error['line']
            ], 'CRITICAL');
            
            // Show generic error
            self::showGenericError();
        }
    }
    
    /**
     * Log error details internally
     */
    private static function logError($errorData) {
        $logFile = self::$errorLogPath . date('Y-m-d') . '_errors.log';
        
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'error' => $errorData
        ];
        
        $logLine = json_encode($logEntry) . "\n";
        file_put_contents($logFile, $logLine, FILE_APPEND | LOCK_EX);
        
        // Also log to audit trail
        SecurityLogger::auditLog('ERROR_OCCURRED', [
            'type' => $errorData['type'],
            'file' => basename($errorData['file']),
            'line' => $errorData['line']
        ]);
    }
    
    /**
     * Show generic error message
     */
    private static function showGenericError() {
        // Clean any existing output
        if (ob_get_level() > 0) {
            ob_clean();
        }
        
        // Check if this is an API request and return JSON instead of HTML
        $isApiRequest = (
            strpos($_SERVER['REQUEST_URI'] ?? '', 'admin_api.php') !== false ||
            strpos($_SERVER['REQUEST_URI'] ?? '', '/api/') !== false ||
            ($_SERVER['HTTP_ACCEPT'] ?? '') === 'application/json'
        );
        
        // Set appropriate status code
        if (!headers_sent()) {
            http_response_code(500);
            if ($isApiRequest) {
                header('Content-Type: application/json; charset=UTF-8');
                echo json_encode([
                    'error' => 'An internal error occurred',
                    'code' => uniqid('ERR_')
                ]);
                exit();
            } else {
                header('Content-Type: text/html; charset=UTF-8');
            }
        }
        
        // Generic error page
        echo '<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            color: #333;
            margin: 0;
            padding: 50px;
            text-align: center;
        }
        .error-container {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 40px;
            max-width: 500px;
            margin: 0 auto;
        }
        h1 {
            color: #e74c3c;
            margin-bottom: 20px;
        }
        p {
            color: #666;
            line-height: 1.6;
        }
        .error-code {
            font-size: 12px;
            color: #999;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <h1>Oops! Something went wrong</h1>
        <p>We apologize for the inconvenience. The system encountered an error while processing your request.</p>
        <p>Please try again later or contact support if the problem persists.</p>
        <div class="error-code">Error Code: ' . uniqid('ERR_') . '</div>
    </div>
</body>
</html>';
        
        exit();
    }
    
    /**
     * Get error type name
     */
    private static function getErrorType($errno) {
        $types = [
            E_ERROR => 'ERROR',
            E_WARNING => 'WARNING',
            E_PARSE => 'PARSE',
            E_NOTICE => 'NOTICE',
            E_CORE_ERROR => 'CORE_ERROR',
            E_CORE_WARNING => 'CORE_WARNING',
            E_COMPILE_ERROR => 'COMPILE_ERROR',
            E_COMPILE_WARNING => 'COMPILE_WARNING',
            E_USER_ERROR => 'USER_ERROR',
            E_USER_WARNING => 'USER_WARNING',
            E_USER_NOTICE => 'USER_NOTICE',
            E_STRICT => 'STRICT',
            E_RECOVERABLE_ERROR => 'RECOVERABLE_ERROR',
            E_DEPRECATED => 'DEPRECATED',
            E_USER_DEPRECATED => 'USER_DEPRECATED'
        ];
        
        return $types[$errno] ?? 'UNKNOWN';
    }
    
    /**
     * Check if in production mode
     */
    private static function isProduction() {
        // Temporarily allow your IP to see actual errors for debugging
        return !in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1', 'localhost', '88.97.248.150']);
    }
    
    /**
     * Handle API errors
     */
    public static function handleAPIError($error, $statusCode = 500) {
        // Log the error
        $errorData = [
            'type' => 'API_ERROR',
            'message' => $error,
            'status_code' => $statusCode,
            'context' => [
                'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown',
                'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]
        ];
        
        self::logError($errorData);
        
        // Return JSON error response
        if (!headers_sent()) {
            http_response_code($statusCode);
            header('Content-Type: application/json');
        }
        
        echo json_encode([
            'error' => 'An error occurred processing your request',
            'code' => uniqid('API_ERR_')
        ]);
        
        exit();
    }
    
    /**
     * Safe error message for users
     */
    public static function getUserMessage($error) {
        // Map technical errors to user-friendly messages
        $messages = [
            'database' => 'Unable to process your request. Please try again.',
            'validation' => 'Invalid input provided. Please check and try again.',
            'authentication' => 'Authentication required. Please log in.',
            'authorization' => 'You do not have permission to perform this action.',
            'rate_limit' => 'Too many requests. Please wait before trying again.',
            'maintenance' => 'System is under maintenance. Please try again later.',
            'default' => 'An error occurred. Please try again.'
        ];
        
        // Determine error category
        $category = 'default';
        $errorLower = strtolower($error);
        
        foreach (array_keys($messages) as $key) {
            if (strpos($errorLower, $key) !== false) {
                $category = $key;
                break;
            }
        }
        
        return $messages[$category];
    }
    
    /**
     * Get error statistics
     */
    public static function getErrorStats() {
        $stats = [
            'today' => 0,
            'yesterday' => 0,
            'week' => 0,
            'by_type' => []
        ];
        
        // Read today's log
        $todayLog = self::$errorLogPath . date('Y-m-d') . '_errors.log';
        if (file_exists($todayLog)) {
            $lines = file($todayLog);
            $stats['today'] = count($lines);
            
            foreach ($lines as $line) {
                $entry = json_decode(trim($line), true);
                if ($entry && isset($entry['error']['type'])) {
                    $type = $entry['error']['type'];
                    $stats['by_type'][$type] = ($stats['by_type'][$type] ?? 0) + 1;
                }
            }
        }
        
        // Read yesterday's log
        $yesterdayLog = self::$errorLogPath . date('Y-m-d', strtotime('-1 day')) . '_errors.log';
        if (file_exists($yesterdayLog)) {
            $stats['yesterday'] = count(file($yesterdayLog));
        }
        
        // Calculate week total
        for ($i = 0; $i < 7; $i++) {
            $log = self::$errorLogPath . date('Y-m-d', strtotime("-$i days")) . '_errors.log';
            if (file_exists($log)) {
                $stats['week'] += count(file($log));
            }
        }
        
        return $stats;
    }
}

// Initialize error handler
SecureErrorHandler::init();
?>