<?php
/**
 * Secure API Wrapper - Phase 6: API Security Layer
 * Comprehensive API security framework with rate limiting, authentication, and monitoring
 */

require_once 'security_middleware.php';
require_once 'config_paths.php';
require_once 'input_sanitizer.php';
require_once 'auth.php';
require_once 'file_access_logger.php';

class SecureAPIWrapper {
    
    private static $rateLimitFile = ConfigPaths::getStoragePath('api_rate_limits');
    private static $apiLogFile = ConfigPaths::getLogPath('api_access');
    private static $apiKeysFile = ConfigPaths::getStoragePath('api_keys');
    
    // Rate limiting configuration
    private static $rateLimits = [
        'default' => ['requests' => 100, 'window' => 3600], // 100 requests per hour
        'authenticated' => ['requests' => 500, 'window' => 3600], // 500 requests per hour
        'admin' => ['requests' => 1000, 'window' => 3600], // 1000 requests per hour
        'critical' => ['requests' => 10, 'window' => 3600] // 10 requests per hour for sensitive endpoints
    ];
    
    // API endpoint definitions
    private static $endpoints = [
        'auth' => [
            'file' => 'auth.php',
            'methods' => ['POST'],
            'rate_limit' => 'critical',
            'auth_required' => false,
            'admin_required' => false
        ],
        'admin_api' => [
            'file' => 'admin_api.php',
            'methods' => ['GET', 'POST'],
            'rate_limit' => 'admin',
            'auth_required' => true,
            'admin_required' => true
        ],
        'user_data' => [
            'file' => 'user_data_api.php',
            'methods' => ['GET', 'POST', 'PUT'],
            'rate_limit' => 'authenticated',
            'auth_required' => true,
            'admin_required' => false
        ],
        'file_upload' => [
            'file' => 'secure_upload_handler.php',
            'methods' => ['POST'],
            'rate_limit' => 'authenticated',
            'auth_required' => true,
            'admin_required' => false
        ],
        'security_monitor' => [
            'file' => 'security_monitor.php',
            'methods' => ['GET'],
            'rate_limit' => 'admin',
            'auth_required' => true,
            'admin_required' => true
        ]
    ];
    
    /**
     * Process API request with comprehensive security checks
     */
    public static function processRequest($endpoint, $method = null, $data = null) {
        $startTime = microtime(true);
        $method = $method ?: $_SERVER['REQUEST_METHOD'];
        $data = $data ?: self::getRequestData();
        $clientIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        
        // Initialize response structure
        $response = [
            'success' => false,
            'data' => null,
            'error' => null,
            'timestamp' => date('Y-m-d H:i:s'),
            'request_id' => uniqid('req_')
        ];
        
        try {
            // 1. Validate endpoint exists
            if (!isset(self::$endpoints[$endpoint])) {
                self::logAPIRequest($endpoint, $method, 'INVALID_ENDPOINT', $clientIP, $userAgent);
                return self::errorResponse('Invalid endpoint', 404, $response['request_id']);
            }
            
            $endpointConfig = self::$endpoints[$endpoint];
            
            // 2. Validate HTTP method
            if (!in_array($method, $endpointConfig['methods'])) {
                self::logAPIRequest($endpoint, $method, 'METHOD_NOT_ALLOWED', $clientIP, $userAgent);
                return self::errorResponse('Method not allowed', 405, $response['request_id']);
            }
            
            // 3. Check rate limiting
            $rateLimitResult = self::checkRateLimit($clientIP, $endpointConfig['rate_limit'], $endpoint);
            if (!$rateLimitResult['allowed']) {
                self::logAPIRequest($endpoint, $method, 'RATE_LIMITED', $clientIP, $userAgent, [
                    'limit_info' => $rateLimitResult
                ]);
                return self::errorResponse('Rate limit exceeded', 429, $response['request_id'], [
                    'retry_after' => $rateLimitResult['retry_after']
                ]);
            }
            
            // 4. Authentication check
            if ($endpointConfig['auth_required'] && !isUserLoggedIn()) {
                self::logAPIRequest($endpoint, $method, 'AUTHENTICATION_REQUIRED', $clientIP, $userAgent);
                return self::errorResponse('Authentication required', 401, $response['request_id']);
            }
            
            // 5. Admin authorization check
            if ($endpointConfig['admin_required'] && !isUserAdmin()) {
                self::logAPIRequest($endpoint, $method, 'ADMIN_REQUIRED', $clientIP, $userAgent);
                return self::errorResponse('Admin privileges required', 403, $response['request_id']);
            }
            
            // 6. Input validation and sanitization
            $sanitizedData = self::sanitizeRequestData($data, $endpoint);
            if (isset($sanitizedData['error'])) {
                self::logAPIRequest($endpoint, $method, 'VALIDATION_FAILED', $clientIP, $userAgent, [
                    'validation_errors' => $sanitizedData['errors']
                ]);
                return self::errorResponse('Input validation failed', 400, $response['request_id'], [
                    'validation_errors' => $sanitizedData['errors']
                ]);
            }
            
            // 7. CORS validation
            $corsResult = self::validateCORS();
            if (!$corsResult['allowed']) {
                self::logAPIRequest($endpoint, $method, 'CORS_VIOLATION', $clientIP, $userAgent, [
                    'origin' => $_SERVER['HTTP_ORIGIN'] ?? 'none'
                ]);
                return self::errorResponse('CORS policy violation', 403, $response['request_id']);
            }
            
            // 8. Execute endpoint
            $endpointResult = self::executeEndpoint($endpoint, $method, $sanitizedData['data']);
            
            // 9. Filter response data
            $filteredResponse = self::filterResponseData($endpointResult, $endpoint);
            
            // 10. Log successful request
            $processingTime = (microtime(true) - $startTime) * 1000; // Convert to milliseconds
            self::logAPIRequest($endpoint, $method, 'SUCCESS', $clientIP, $userAgent, [
                'processing_time_ms' => round($processingTime, 2),
                'response_size' => strlen(json_encode($filteredResponse))
            ]);
            
            return [
                'success' => true,
                'data' => $filteredResponse,
                'timestamp' => $response['timestamp'],
                'request_id' => $response['request_id'],
                'processing_time' => round($processingTime, 2) . 'ms'
            ];
            
        } catch (Exception $e) {
            // Log error
            self::logAPIRequest($endpoint, $method, 'ERROR', $clientIP, $userAgent, [
                'error_message' => $e->getMessage(),
                'error_file' => $e->getFile(),
                'error_line' => $e->getLine()
            ]);
            
            // Security event for unexpected errors
            SecurityMiddleware::logSecurityEvent('API_ERROR', [
                'endpoint' => $endpoint,
                'method' => $method,
                'error' => $e->getMessage(),
                'ip' => $clientIP
            ], 'MEDIUM');
            
            return self::errorResponse('Internal server error', 500, $response['request_id']);
        }
    }
    
    /**
     * Check rate limiting for client IP and endpoint
     */
    private static function checkRateLimit($clientIP, $limitType, $endpoint) {
        if (!isset(self::$rateLimits[$limitType])) {
            $limitType = 'default';
        }
        
        $limit = self::$rateLimits[$limitType];
        $window = $limit['window'];
        $maxRequests = $limit['requests'];
        
        // Load rate limit data
        $rateLimitData = [];
        if (file_exists(self::$rateLimitFile)) {
            $rateLimitData = json_decode(file_get_contents(self::$rateLimitFile), true) ?: [];
        }
        
        // Create key for this IP and endpoint
        $key = $clientIP . '_' . $endpoint;
        $now = time();
        
        // Initialize or get existing data for this key
        if (!isset($rateLimitData[$key])) {
            $rateLimitData[$key] = [
                'requests' => [],
                'blocked_until' => 0
            ];
        }
        
        $clientData = &$rateLimitData[$key];
        
        // Check if client is currently blocked
        if ($clientData['blocked_until'] > $now) {
            return [
                'allowed' => false,
                'reason' => 'temporarily_blocked',
                'retry_after' => $clientData['blocked_until'] - $now
            ];
        }
        
        // Clean old requests outside the window
        $clientData['requests'] = array_filter($clientData['requests'], function($timestamp) use ($now, $window) {
            return ($now - $timestamp) < $window;
        });
        
        // Check if limit exceeded
        if (count($clientData['requests']) >= $maxRequests) {
            // Block client for the remainder of the window
            $oldestRequest = min($clientData['requests']);
            $clientData['blocked_until'] = $oldestRequest + $window;
            
            // Log rate limit violation
            SecurityMiddleware::logSecurityEvent('RATE_LIMIT_EXCEEDED', [
                'ip' => $clientIP,
                'endpoint' => $endpoint,
                'requests_count' => count($clientData['requests']),
                'max_requests' => $maxRequests,
                'window_seconds' => $window
            ], 'MEDIUM');
            
            // Save updated data
            file_put_contents(self::$rateLimitFile, json_encode($rateLimitData));
            
            return [
                'allowed' => false,
                'reason' => 'rate_limit_exceeded',
                'retry_after' => $clientData['blocked_until'] - $now
            ];
        }
        
        // Add current request
        $clientData['requests'][] = $now;
        
        // Save updated data
        file_put_contents(self::$rateLimitFile, json_encode($rateLimitData));
        
        return [
            'allowed' => true,
            'remaining_requests' => $maxRequests - count($clientData['requests']),
            'window_seconds' => $window
        ];
    }
    
    /**
     * Get request data from various sources
     */
    private static function getRequestData() {
        $data = [];
        
        // GET parameters
        if (!empty($_GET)) {
            $data = array_merge($data, $_GET);
        }
        
        // POST parameters
        if (!empty($_POST)) {
            $data = array_merge($data, $_POST);
        }
        
        // JSON body
        $jsonInput = file_get_contents('php://input');
        if ($jsonInput) {
            $jsonData = json_decode($jsonInput, true);
            if ($jsonData) {
                $data = array_merge($data, $jsonData);
            }
        }
        
        return $data;
    }
    
    /**
     * Sanitize request data based on endpoint requirements
     */
    private static function sanitizeRequestData($data, $endpoint) {
        $sanitizedData = [];
        $errors = [];
        
        try {
            foreach ($data as $key => $value) {
                // Basic key sanitization
                $sanitizedKey = InputSanitizer::sanitizeString($key);
                if ($sanitizedKey !== $key) {
                    $errors[] = "Invalid parameter name: $key";
                    continue;
                }
                
                // Value sanitization based on type
                if (is_string($value)) {
                    $sanitizedValue = InputSanitizer::sanitizeString($value);
                    
                    // Check for potential XSS
                    if (InputSanitizer::detectXSS($value)) {
                        $errors[] = "Potential XSS detected in parameter: $key";
                        SecurityMiddleware::logSecurityEvent('API_XSS_ATTEMPT', [
                            'endpoint' => $endpoint,
                            'parameter' => $key,
                            'value' => substr($value, 0, 100),
                            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                        ], 'HIGH');
                        continue;
                    }
                    
                    // Check for SQL injection patterns
                    if (InputSanitizer::detectSQLInjection($value)) {
                        $errors[] = "Potential SQL injection detected in parameter: $key";
                        SecurityMiddleware::logSecurityEvent('API_SQL_INJECTION_ATTEMPT', [
                            'endpoint' => $endpoint,
                            'parameter' => $key,
                            'value' => substr($value, 0, 100),
                            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                        ], 'HIGH');
                        continue;
                    }
                    
                    $sanitizedData[$sanitizedKey] = $sanitizedValue;
                    
                } elseif (is_numeric($value)) {
                    $sanitizedData[$sanitizedKey] = $value;
                } elseif (is_array($value)) {
                    // Recursively sanitize arrays
                    $arrayResult = self::sanitizeArray($value, $endpoint, $key);
                    if (isset($arrayResult['error'])) {
                        $errors = array_merge($errors, $arrayResult['errors']);
                    } else {
                        $sanitizedData[$sanitizedKey] = $arrayResult['data'];
                    }
                } else {
                    // For other types, convert to string and sanitize
                    $sanitizedData[$sanitizedKey] = InputSanitizer::sanitizeString((string)$value);
                }
            }
            
            if (!empty($errors)) {
                return ['error' => true, 'errors' => $errors];
            }
            
            return ['success' => true, 'data' => $sanitizedData];
            
        } catch (Exception $e) {
            return ['error' => true, 'errors' => ['Sanitization failed: ' . $e->getMessage()]];
        }
    }
    
    /**
     * Sanitize array data recursively
     */
    private static function sanitizeArray($array, $endpoint, $parentKey) {
        $sanitized = [];
        $errors = [];
        
        foreach ($array as $key => $value) {
            $fullKey = $parentKey . '[' . $key . ']';
            
            if (is_string($value)) {
                if (InputSanitizer::detectXSS($value) || InputSanitizer::detectSQLInjection($value)) {
                    $errors[] = "Malicious content detected in $fullKey";
                    continue;
                }
                $sanitized[$key] = InputSanitizer::sanitizeString($value);
            } elseif (is_array($value)) {
                $arrayResult = self::sanitizeArray($value, $endpoint, $fullKey);
                if (isset($arrayResult['error'])) {
                    $errors = array_merge($errors, $arrayResult['errors']);
                } else {
                    $sanitized[$key] = $arrayResult['data'];
                }
            } else {
                $sanitized[$key] = $value;
            }
        }
        
        if (!empty($errors)) {
            return ['error' => true, 'errors' => $errors];
        }
        
        return ['success' => true, 'data' => $sanitized];
    }
    
    /**
     * Validate CORS requests
     */
    private static function validateCORS() {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        
        // Allowed origins
        $allowedOrigins = [
            'https://cr0s.is',
            'http://localhost',
            'http://127.0.0.1'
        ];
        
        // If no origin header, it's likely a same-origin request
        if (empty($origin)) {
            return ['allowed' => true, 'reason' => 'same_origin'];
        }
        
        // Check against allowed origins
        foreach ($allowedOrigins as $allowedOrigin) {
            if (strpos($origin, $allowedOrigin) === 0) {
                return ['allowed' => true, 'reason' => 'allowed_origin'];
            }
        }
        
        return ['allowed' => false, 'reason' => 'unauthorized_origin'];
    }
    
    /**
     * Execute the actual endpoint
     */
    private static function executeEndpoint($endpoint, $method, $data) {
        $endpointConfig = self::$endpoints[$endpoint];
        $file = $endpointConfig['file'];
        
        // Set up environment for the endpoint
        $_REQUEST = array_merge($_REQUEST, $data);
        $_POST = $method === 'POST' ? array_merge($_POST, $data) : $_POST;
        $_GET = $method === 'GET' ? array_merge($_GET, $data) : $_GET;
        
        // Capture output
        ob_start();
        
        try {
            // Include the endpoint file
            if (file_exists("/var/www/html/$file")) {
                include "/var/www/html/$file";
            } else {
                throw new Exception("Endpoint file not found: $file");
            }
            
            $output = ob_get_contents();
            ob_end_clean();
            
            // Try to decode as JSON first
            $jsonOutput = json_decode($output, true);
            if ($jsonOutput !== null) {
                return $jsonOutput;
            }
            
            // Return raw output if not JSON
            return ['raw_output' => $output];
            
        } catch (Exception $e) {
            ob_end_clean();
            throw $e;
        }
    }
    
    /**
     * Filter response data to remove sensitive information
     */
    private static function filterResponseData($data, $endpoint) {
        // Sensitive fields to remove
        $sensitiveFields = [
            'password', 'hash', 'salt', 'token', 'secret',
            'api_key', 'private_key', 'session_id', 'csrf_token'
        ];
        
        return self::recursiveFilter($data, $sensitiveFields);
    }
    
    /**
     * Recursively filter sensitive data
     */
    private static function recursiveFilter($data, $sensitiveFields) {
        if (is_array($data)) {
            $filtered = [];
            foreach ($data as $key => $value) {
                $keyLower = strtolower($key);
                $isSensitive = false;
                
                foreach ($sensitiveFields as $sensitiveField) {
                    if (strpos($keyLower, $sensitiveField) !== false) {
                        $isSensitive = true;
                        break;
                    }
                }
                
                if ($isSensitive) {
                    $filtered[$key] = '[FILTERED]';
                } else {
                    $filtered[$key] = self::recursiveFilter($value, $sensitiveFields);
                }
            }
            return $filtered;
        }
        
        return $data;
    }
    
    /**
     * Log API request
     */
    private static function logAPIRequest($endpoint, $method, $status, $clientIP, $userAgent, $details = []) {
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'endpoint' => $endpoint,
            'method' => $method,
            'status' => $status,
            'ip' => $clientIP,
            'user_agent' => $userAgent,
            'user_id' => $_SESSION['user_id'] ?? 'anonymous',
            'session_id' => session_id() ?: 'none',
            'details' => $details
        ];
        
        // Ensure log directory exists
        $logDir = dirname(self::$apiLogFile);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        
        // Write to log file
        file_put_contents(self::$apiLogFile, json_encode($logEntry) . "\n", FILE_APPEND | LOCK_EX);
        
        // Also log via FileAccessLogger for integration
        FileAccessLogger::logAccess('API_REQUEST', $endpoint, $status, array_merge([
            'method' => $method,
            'user_agent' => $userAgent
        ], $details));
    }
    
    /**
     * Create error response
     */
    private static function errorResponse($message, $httpCode, $requestId, $additionalData = []) {
        http_response_code($httpCode);
        
        return array_merge([
            'success' => false,
            'error' => $message,
            'http_code' => $httpCode,
            'timestamp' => date('Y-m-d H:i:s'),
            'request_id' => $requestId
        ], $additionalData);
    }
    
    /**
     * Get API usage statistics
     */
    public static function getAPIStats($hours = 24) {
        if (!file_exists(self::$apiLogFile)) {
            return [
                'total_requests' => 0,
                'successful_requests' => 0,
                'failed_requests' => 0,
                'endpoints' => [],
                'top_ips' => [],
                'error_types' => []
            ];
        }
        
        $stats = [
            'total_requests' => 0,
            'successful_requests' => 0,
            'failed_requests' => 0,
            'endpoints' => [],
            'top_ips' => [],
            'error_types' => []
        ];
        
        $cutoffTime = time() - ($hours * 3600);
        $ipCounts = [];
        $errorTypes = [];
        
        $handle = fopen(self::$apiLogFile, 'r');
        if ($handle) {
            while (($line = fgets($handle)) !== false) {
                $entry = json_decode($line, true);
                if ($entry && strtotime($entry['timestamp']) >= $cutoffTime) {
                    $stats['total_requests']++;
                    
                    if ($entry['status'] === 'SUCCESS') {
                        $stats['successful_requests']++;
                    } else {
                        $stats['failed_requests']++;
                        $errorTypes[$entry['status']] = ($errorTypes[$entry['status']] ?? 0) + 1;
                    }
                    
                    // Count endpoints
                    $endpoint = $entry['endpoint'];
                    $stats['endpoints'][$endpoint] = ($stats['endpoints'][$endpoint] ?? 0) + 1;
                    
                    // Count IPs
                    $ip = $entry['ip'];
                    $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1;
                }
            }
            fclose($handle);
        }
        
        // Sort and limit top items
        arsort($ipCounts);
        arsort($stats['endpoints']);
        arsort($errorTypes);
        
        $stats['top_ips'] = array_slice($ipCounts, 0, 10, true);
        $stats['error_types'] = $errorTypes;
        
        return $stats;
    }
    
    /**
     * Clean old rate limit data
     */
    public static function cleanRateLimitData() {
        if (!file_exists(self::$rateLimitFile)) {
            return ['message' => 'No rate limit data to clean'];
        }
        
        $rateLimitData = json_decode(file_get_contents(self::$rateLimitFile), true) ?: [];
        $now = time();
        $cleaned = 0;
        
        foreach ($rateLimitData as $key => $data) {
            // Clean old requests
            $data['requests'] = array_filter($data['requests'], function($timestamp) use ($now) {
                return ($now - $timestamp) < 3600; // Keep last hour
            });
            
            // Remove blocked status if expired
            if ($data['blocked_until'] < $now) {
                $data['blocked_until'] = 0;
            }
            
            // Remove empty entries
            if (empty($data['requests']) && $data['blocked_until'] == 0) {
                unset($rateLimitData[$key]);
                $cleaned++;
            } else {
                $rateLimitData[$key] = $data;
            }
        }
        
        file_put_contents(self::$rateLimitFile, json_encode($rateLimitData));
        
        return [
            'success' => true,
            'cleaned_entries' => $cleaned,
            'remaining_entries' => count($rateLimitData)
        ];
    }
}
?>