<?php
/**
 * Automated Security Alert System
 * Monitors and responds to security events automatically
 */

require_once 'security_logger.php';
require_once 'security_middleware.php';
require_once 'config_paths.php';

class SecurityAlerts {
    
    private static $alertConfigFile;
    private static $alertQueueFile;
    
    /**
     * Initialize alert system with default rules
     */
    public static function init() {
        // Get centralized config paths
        self::$alertConfigFile = ConfigPaths::getLogPath('security_config');
        self::$alertQueueFile = ConfigPaths::getLogPath('security_queue');
        
        // Ensure directories exist
        ConfigPaths::ensureDirectory(dirname(self::$alertConfigFile));
        
        // Create default alert configuration if not exists
        if (!file_exists(self::$alertConfigFile)) {
            $defaultConfig = [
                'enabled' => true,
                'rules' => [
                    [
                        'name' => 'Multiple Failed Logins',
                        'condition' => 'failed_login_count',
                        'threshold' => 5,
                        'timeframe' => 300, // 5 minutes
                        'action' => 'block_ip',
                        'severity' => 'HIGH',
                        'enabled' => true
                    ],
                    [
                        'name' => 'SQL Injection Attempts',
                        'condition' => 'sql_injection_count',
                        'threshold' => 3,
                        'timeframe' => 600, // 10 minutes
                        'action' => 'block_ip',
                        'severity' => 'CRITICAL',
                        'enabled' => true
                    ],
                    [
                        'name' => 'XSS Attempts',
                        'condition' => 'xss_attempt_count',
                        'threshold' => 5,
                        'timeframe' => 600,
                        'action' => 'monitor',
                        'severity' => 'HIGH',
                        'enabled' => true
                    ],
                    [
                        'name' => 'Directory Traversal',
                        'condition' => 'directory_traversal_count',
                        'threshold' => 2,
                        'timeframe' => 300,
                        'action' => 'block_ip',
                        'severity' => 'CRITICAL',
                        'enabled' => true
                    ],
                    [
                        'name' => 'Rate Limit Violations',
                        'condition' => 'rate_limit_exceeded',
                        'threshold' => 10,
                        'timeframe' => 60,
                        'action' => 'throttle',
                        'severity' => 'MEDIUM',
                        'enabled' => true
                    ],
                    [
                        'name' => 'Suspicious Bot Activity',
                        'condition' => 'bot_pattern_detected',
                        'threshold' => 20,
                        'timeframe' => 300,
                        'action' => 'challenge',
                        'severity' => 'MEDIUM',
                        'enabled' => true
                    ]
                ],
                'notification_channels' => [
                    'dashboard' => true,
                    'log_file' => true,
                    'webhook' => false,
                    'webhook_url' => ''
                ],
                'auto_response' => true,
                'ban_duration' => 3600 // 1 hour default
            ];
            
            file_put_contents(self::$alertConfigFile, json_encode($defaultConfig, JSON_PRETTY_PRINT));
        }
    }
    
    /**
     * Process security event for alerts
     */
    public static function processEvent($eventType, $eventData) {
        $config = self::getConfig();
        
        if (!$config['enabled']) {
            return;
        }
        
        // Map event types to conditions
        $conditionMap = [
            'LOGIN_FAILED' => 'failed_login_count',
            'SQL_INJECTION_ATTEMPT' => 'sql_injection_count',
            'XSS_ATTEMPT' => 'xss_attempt_count',
            'DIRECTORY_TRAVERSAL_ATTEMPT' => 'directory_traversal_count',
            'RATE_LIMIT_EXCEEDED' => 'rate_limit_exceeded',
            'SUSPICIOUS_ACTIVITY' => 'bot_pattern_detected'
        ];
        
        $condition = $conditionMap[$eventType] ?? null;
        if (!$condition) {
            return;
        }
        
        // Check each rule
        foreach ($config['rules'] as $rule) {
            if ($rule['enabled'] && $rule['condition'] === $condition) {
                self::evaluateRule($rule, $eventData);
            }
        }
    }
    
    /**
     * Evaluate alert rule
     */
    private static function evaluateRule($rule, $eventData) {
        $ip = $eventData['ip'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $cacheKey = "alert_{$rule['condition']}_{$ip}";
        $cacheFile = "/tmp/{$cacheKey}";
        
        // Get current count
        $data = ['count' => 0, 'first_seen' => time()];
        if (file_exists($cacheFile)) {
            $cached = json_decode(file_get_contents($cacheFile), true);
            if ($cached && (time() - $cached['first_seen']) < $rule['timeframe']) {
                $data = $cached;
            }
        }
        
        $data['count']++;
        $data['last_seen'] = time();
        
        // Check threshold
        if ($data['count'] >= $rule['threshold']) {
            // Trigger alert
            self::triggerAlert($rule, $eventData, $data);
            
            // Reset counter
            unlink($cacheFile);
        } else {
            // Update counter
            file_put_contents($cacheFile, json_encode($data));
        }
    }
    
    /**
     * Trigger security alert
     */
    private static function triggerAlert($rule, $eventData, $stats) {
        $alert = [
            'id' => uniqid('ALERT_'),
            'timestamp' => date('Y-m-d H:i:s'),
            'rule' => $rule['name'],
            'severity' => $rule['severity'],
            'action' => $rule['action'],
            'ip' => $eventData['ip'] ?? 'unknown',
            'details' => [
                'count' => $stats['count'],
                'timeframe' => $rule['timeframe'],
                'first_seen' => date('Y-m-d H:i:s', $stats['first_seen']),
                'last_seen' => date('Y-m-d H:i:s', $stats['last_seen']),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                'request_uri' => $_SERVER['REQUEST_URI'] ?? 'unknown'
            ]
        ];
        
        // Log alert
        SecurityLogger::logEvent('ALERT_TRIGGERED', $alert, $rule['severity']);
        
        // Add to alert queue
        self::queueAlert($alert);
        
        // Execute automatic response
        $config = self::getConfig();
        if ($config['auto_response']) {
            self::executeResponse($rule['action'], $alert);
        }
        
        // Send notifications
        self::sendNotifications($alert);
    }
    
    /**
     * Execute automatic response action
     */
    private static function executeResponse($action, $alert) {
        $ip = $alert['ip'];
        
        // Check if IP is trusted - skip blocking for trusted IPs
        $trustedIPs = ['127.0.0.1', '::1', 'localhost'];
        $trustedIPsFile = __DIR__ . '/trusted_ips.php';
        if (file_exists($trustedIPsFile)) {
            $additionalIPs = include $trustedIPsFile;
            if (is_array($additionalIPs)) {
                $trustedIPs = array_merge($trustedIPs, $additionalIPs);
            }
        }
        
        if (in_array($ip, $trustedIPs)) {
            // Log but don't execute blocking actions for trusted IPs
            self::logAlert('INFO', $ip, $alert['rule'], 'Skipped blocking trusted IP');
            return;
        }
        
        switch ($action) {
            case 'block_ip':
                self::blockIP($ip, $alert['rule']);
                break;
                
            case 'throttle':
                self::throttleIP($ip);
                break;
                
            case 'challenge':
                self::setChallengeFlag($ip);
                break;
                
            case 'monitor':
                // Just log, no action
                SecurityLogger::auditLog('MONITORING_IP', [
                    'ip' => $ip,
                    'reason' => $alert['rule']
                ]);
                break;
        }
    }
    
    /**
     * Block IP address
     */
    private static function blockIP($ip, $reason) {
        $blockedFile = ConfigPaths::LOG_BLOCKED_IPS;
        $blocked = [];
        
        if (file_exists($blockedFile)) {
            $blocked = json_decode(file_get_contents($blockedFile), true) ?: [];
        }
        
        $config = self::getConfig();
        $blocked[$ip] = [
            'blocked_at' => time(),
            'expires_at' => time() + $config['ban_duration'],
            'reason' => $reason,
            'permanent' => false
        ];
        
        file_put_contents($blockedFile, json_encode($blocked, JSON_PRETTY_PRINT));
        
        SecurityLogger::auditLog('IP_BLOCKED', [
            'ip' => $ip,
            'reason' => $reason,
            'duration' => $config['ban_duration']
        ]);
    }
    
    /**
     * Throttle IP address
     */
    private static function throttleIP($ip) {
        $throttleFile = ConfigPaths::LOG_THROTTLED_IPS;
        $throttled = [];
        
        if (file_exists($throttleFile)) {
            $throttled = json_decode(file_get_contents($throttleFile), true) ?: [];
        }
        
        $throttled[$ip] = [
            'throttled_at' => time(),
            'expires_at' => time() + 300, // 5 minutes
            'delay_ms' => 2000 // 2 second delay
        ];
        
        file_put_contents($throttleFile, json_encode($throttled, JSON_PRETTY_PRINT));
    }
    
    /**
     * Set challenge flag for IP
     */
    private static function setChallengeFlag($ip) {
        $challengeFile = ConfigPaths::LOG_CHALLENGE_IPS;
        $challenges = [];
        
        if (file_exists($challengeFile)) {
            $challenges = json_decode(file_get_contents($challengeFile), true) ?: [];
        }
        
        $challenges[$ip] = [
            'created_at' => time(),
            'expires_at' => time() + 3600, // 1 hour
            'type' => 'javascript_check'
        ];
        
        file_put_contents($challengeFile, json_encode($challenges, JSON_PRETTY_PRINT));
    }
    
    /**
     * Check if IP is blocked
     */
    public static function isIPBlocked($ip) {
        $blockedFile = ConfigPaths::LOG_BLOCKED_IPS;
        
        if (!file_exists($blockedFile)) {
            return false;
        }
        
        $blocked = json_decode(file_get_contents($blockedFile), true) ?: [];
        
        if (isset($blocked[$ip])) {
            // Check if ban expired
            if ($blocked[$ip]['permanent'] || time() < $blocked[$ip]['expires_at']) {
                return true;
            } else {
                // Remove expired ban
                unset($blocked[$ip]);
                file_put_contents($blockedFile, json_encode($blocked, JSON_PRETTY_PRINT));
            }
        }
        
        return false;
    }
    
    /**
     * Check if IP is throttled
     */
    public static function getIPThrottle($ip) {
        $throttleFile = ConfigPaths::LOG_THROTTLED_IPS;
        
        if (!file_exists($throttleFile)) {
            return 0;
        }
        
        $throttled = json_decode(file_get_contents($throttleFile), true) ?: [];
        
        if (isset($throttled[$ip])) {
            if (time() < $throttled[$ip]['expires_at']) {
                return $throttled[$ip]['delay_ms'];
            } else {
                // Remove expired throttle
                unset($throttled[$ip]);
                file_put_contents($throttleFile, json_encode($throttled, JSON_PRETTY_PRINT));
            }
        }
        
        return 0;
    }
    
    /**
     * Queue alert for processing
     */
    private static function queueAlert($alert) {
        $queue = [];
        
        if (file_exists(self::$alertQueueFile)) {
            $queue = json_decode(file_get_contents(self::$alertQueueFile), true) ?: [];
        }
        
        $queue[] = $alert;
        
        // Keep only last 100 alerts
        if (count($queue) > 100) {
            $queue = array_slice($queue, -100);
        }
        
        file_put_contents(self::$alertQueueFile, json_encode($queue, JSON_PRETTY_PRINT));
    }
    
    /**
     * Send alert notifications
     */
    private static function sendNotifications($alert) {
        $config = self::getConfig();
        
        // Dashboard notification (already handled by queue)
        
        // Log file notification
        if ($config['notification_channels']['log_file']) {
            $logFile = ConfigPaths::LOG_ALERT_NOTIFICATIONS;
            $entry = date('Y-m-d H:i:s') . ' - ' . json_encode($alert) . "\n";
            file_put_contents($logFile, $entry, FILE_APPEND);
        }
        
        // Webhook notification
        if ($config['notification_channels']['webhook'] && !empty($config['webhook_url'])) {
            self::sendWebhook($config['webhook_url'], $alert);
        }
    }
    
    /**
     * Send webhook notification
     */
    private static function sendWebhook($url, $alert) {
        $payload = json_encode([
            'alert' => $alert,
            'system' => 'CR0 Bot Security',
            'timestamp' => time()
        ]);
        
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        
        curl_exec($ch);
        curl_close($ch);
    }
    
    /**
     * Get alert configuration
     */
    private static function getConfig() {
        if (file_exists(self::$alertConfigFile)) {
            return json_decode(file_get_contents(self::$alertConfigFile), true);
        }
        return [];
    }
    
    /**
     * Update alert configuration
     */
    public static function updateConfig($config) {
        file_put_contents(self::$alertConfigFile, json_encode($config, JSON_PRETTY_PRINT));
    }
    
    /**
     * Get alert queue
     */
    public static function getAlertQueue() {
        if (file_exists(self::$alertQueueFile)) {
            return json_decode(file_get_contents(self::$alertQueueFile), true) ?: [];
        }
        return [];
    }
    
    /**
     * Clear alert queue
     */
    public static function clearAlertQueue() {
        file_put_contents(self::$alertQueueFile, '[]');
    }
    
    /**
     * Get blocked IPs list
     */
    public static function getBlockedIPs() {
        $blockedFile = ConfigPaths::LOG_BLOCKED_IPS;
        
        if (file_exists($blockedFile)) {
            return json_decode(file_get_contents($blockedFile), true) ?: [];
        }
        return [];
    }
    
    /**
     * Unblock IP address
     */
    public static function unblockIP($ip) {
        $blockedFile = ConfigPaths::LOG_BLOCKED_IPS;
        $blocked = self::getBlockedIPs();
        
        if (isset($blocked[$ip])) {
            unset($blocked[$ip]);
            file_put_contents($blockedFile, json_encode($blocked, JSON_PRETTY_PRINT));
            
            SecurityLogger::auditLog('IP_UNBLOCKED', ['ip' => $ip]);
            return true;
        }
        
        return false;
    }
}

// Initialize alert system
SecurityAlerts::init();

// Hook into security middleware events
if (defined('SECURITY_EVENT_TYPE') && defined('SECURITY_EVENT_DATA')) {
    SecurityAlerts::processEvent(SECURITY_EVENT_TYPE, SECURITY_EVENT_DATA);
}
?>