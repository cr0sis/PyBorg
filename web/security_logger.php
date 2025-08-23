<?php
/**
 * Advanced Security Logging System
 * Provides comprehensive event logging with analysis and alerting
 */

require_once 'security_middleware.php';
require_once 'config_paths.php';

class SecurityLogger {
    
    private static $logPath;
    private static $alertThresholds = [
        'CRITICAL' => 1,
        'HIGH' => 5,
        'MEDIUM' => 20,
        'LOW' => 50
    ];
    
    /**
     * Initialize logging system
     */
    public static function init() {
        // Get centralized security log path
        self::$logPath = ConfigPaths::getLogPath('security_dir') . '/';
        
        // Create security log directory if needed
        ConfigPaths::ensureDirectory(self::$logPath);
        
        // Create subdirectories
        $dirs = ['events', 'alerts', 'analysis', 'audit'];
        foreach ($dirs as $dir) {
            $path = self::$logPath . $dir;
            ConfigPaths::ensureDirectory($path);
        }
    }
    
    /**
     * Log security event with analysis
     */
    public static function logEvent($type, $data, $severity = 'LOW') {
        $timestamp = date('Y-m-d H:i:s');
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
        $requestUri = $_SERVER['REQUEST_URI'] ?? 'unknown';
        
        $event = [
            'timestamp' => $timestamp,
            'type' => $type,
            'severity' => $severity,
            'ip' => $ip,
            'user_agent' => $userAgent,
            'request_uri' => $requestUri,
            'data' => $data,
            'session_id' => session_id(),
            'fingerprint' => self::generateFingerprint()
        ];
        
        // Log to daily file
        $filename = self::$logPath . 'events/' . date('Y-m-d') . '.log';
        $logEntry = json_encode($event) . "\n";
        file_put_contents($filename, $logEntry, FILE_APPEND | LOCK_EX);
        
        // Analyze for patterns
        self::analyzeEvent($event);
        
        // Check alert thresholds
        self::checkAlertThreshold($type, $severity, $ip);
        
        // Real-time monitoring
        self::updateRealTimeStats($event);
        
        return true;
    }
    
    /**
     * Analyze security events for patterns
     */
    private static function analyzeEvent($event) {
        $analysisFile = self::$logPath . 'analysis/patterns.json';
        $patterns = [];
        
        if (file_exists($analysisFile)) {
            $patterns = json_decode(file_get_contents($analysisFile), true) ?: [];
        }
        
        // Update pattern tracking
        $key = $event['type'] . '_' . $event['ip'];
        if (!isset($patterns[$key])) {
            $patterns[$key] = [
                'count' => 0,
                'first_seen' => $event['timestamp'],
                'last_seen' => $event['timestamp'],
                'severity_counts' => []
            ];
        }
        
        $patterns[$key]['count']++;
        $patterns[$key]['last_seen'] = $event['timestamp'];
        $patterns[$key]['severity_counts'][$event['severity']] = 
            ($patterns[$key]['severity_counts'][$event['severity']] ?? 0) + 1;
        
        // Detect suspicious patterns
        if ($patterns[$key]['count'] > 10) {
            self::detectSuspiciousPattern($event, $patterns[$key]);
        }
        
        // Save updated patterns
        file_put_contents($analysisFile, json_encode($patterns, JSON_PRETTY_PRINT), LOCK_EX);
    }
    
    /**
     * Detect suspicious patterns
     */
    private static function detectSuspiciousPattern($event, $pattern) {
        $alerts = [];
        
        // Rapid fire attacks
        $timeDiff = strtotime($pattern['last_seen']) - strtotime($pattern['first_seen']);
        if ($timeDiff > 0) {
            $rate = $pattern['count'] / ($timeDiff / 60); // Events per minute
            if ($rate > 10) {
                $alerts[] = [
                    'type' => 'RAPID_FIRE_ATTACK',
                    'message' => "High rate of {$event['type']} events: {$rate} per minute",
                    'severity' => 'HIGH'
                ];
            }
        }
        
        // Severity escalation
        if (isset($pattern['severity_counts']['CRITICAL']) && 
            $pattern['severity_counts']['CRITICAL'] > 2) {
            $alerts[] = [
                'type' => 'CRITICAL_EVENTS',
                'message' => "Multiple critical events from IP: {$event['ip']}",
                'severity' => 'CRITICAL'
            ];
        }
        
        foreach ($alerts as $alert) {
            self::raiseAlert($alert, $event);
        }
    }
    
    /**
     * Check alert thresholds
     */
    private static function checkAlertThreshold($type, $severity, $ip) {
        $cacheFile = self::$logPath . 'alerts/threshold_cache.json';
        $cache = [];
        
        if (file_exists($cacheFile)) {
            $cache = json_decode(file_get_contents($cacheFile), true) ?: [];
        }
        
        $key = "{$severity}_{$ip}";
        $now = time();
        
        // Clean old entries (older than 1 hour)
        foreach ($cache as $k => $v) {
            if ($now - $v['timestamp'] > 3600) {
                unset($cache[$k]);
            }
        }
        
        if (!isset($cache[$key])) {
            $cache[$key] = ['count' => 0, 'timestamp' => $now];
        }
        
        $cache[$key]['count']++;
        
        // Check threshold
        if ($cache[$key]['count'] >= self::$alertThresholds[$severity]) {
            self::raiseAlert([
                'type' => 'THRESHOLD_EXCEEDED',
                'message' => "Alert threshold exceeded for {$severity} events from {$ip}",
                'severity' => $severity,
                'count' => $cache[$key]['count']
            ]);
            
            // Reset counter after alert
            $cache[$key]['count'] = 0;
        }
        
        file_put_contents($cacheFile, json_encode($cache), LOCK_EX);
    }
    
    /**
     * Raise security alert
     */
    private static function raiseAlert($alert, $context = []) {
        $alertFile = self::$logPath . 'alerts/' . date('Y-m-d') . '_alerts.log';
        
        $alertEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'alert' => $alert,
            'context' => $context
        ];
        
        $logEntry = json_encode($alertEntry) . "\n";
        file_put_contents($alertFile, $logEntry, FILE_APPEND | LOCK_EX);
        
        // For critical alerts, create immediate notification
        if ($alert['severity'] === 'CRITICAL') {
            self::sendCriticalAlert($alert, $context);
        }
    }
    
    /**
     * Send critical alert notification
     */
    private static function sendCriticalAlert($alert, $context) {
        $notificationFile = self::$logPath . 'alerts/critical_notifications.json';
        
        $notification = [
            'timestamp' => date('Y-m-d H:i:s'),
            'alert' => $alert,
            'context' => $context,
            'status' => 'pending'
        ];
        
        // Append to notifications file
        $notifications = [];
        if (file_exists($notificationFile)) {
            $notifications = json_decode(file_get_contents($notificationFile), true) ?: [];
        }
        
        $notifications[] = $notification;
        
        // Keep only last 100 notifications
        if (count($notifications) > 100) {
            $notifications = array_slice($notifications, -100);
        }
        
        file_put_contents($notificationFile, json_encode($notifications, JSON_PRETTY_PRINT), LOCK_EX);
    }
    
    /**
     * Update real-time statistics
     */
    private static function updateRealTimeStats($event) {
        $statsFile = self::$logPath . 'analysis/realtime_stats.json';
        $stats = [
            'last_updated' => date('Y-m-d H:i:s'),
            'events_today' => 0,
            'events_by_type' => [],
            'events_by_severity' => [],
            'top_ips' => [],
            'recent_events' => []
        ];
        
        if (file_exists($statsFile)) {
            $stats = json_decode(file_get_contents($statsFile), true) ?: $stats;
        }
        
        // Update counters
        $stats['events_today']++;
        $stats['events_by_type'][$event['type']] = ($stats['events_by_type'][$event['type']] ?? 0) + 1;
        $stats['events_by_severity'][$event['severity']] = ($stats['events_by_severity'][$event['severity']] ?? 0) + 1;
        
        // Track top IPs
        if (!isset($stats['top_ips'][$event['ip']])) {
            $stats['top_ips'][$event['ip']] = 0;
        }
        $stats['top_ips'][$event['ip']]++;
        
        // Keep only top 10 IPs
        arsort($stats['top_ips']);
        $stats['top_ips'] = array_slice($stats['top_ips'], 0, 10, true);
        
        // Add to recent events
        array_unshift($stats['recent_events'], [
            'timestamp' => $event['timestamp'],
            'type' => $event['type'],
            'severity' => $event['severity'],
            'ip' => $event['ip']
        ]);
        
        // Keep only last 20 events
        $stats['recent_events'] = array_slice($stats['recent_events'], 0, 20);
        
        file_put_contents($statsFile, json_encode($stats, JSON_PRETTY_PRINT), LOCK_EX);
    }
    
    /**
     * Generate device fingerprint for tracking
     */
    private static function generateFingerprint() {
        $data = [
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $_SERVER['HTTP_ACCEPT'] ?? '',
            $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            $_SERVER['HTTP_ACCEPT_ENCODING'] ?? ''
        ];
        
        return md5(implode('|', $data));
    }
    
    /**
     * Get security statistics
     */
    public static function getStats($period = 'today') {
        $statsFile = self::$logPath . 'analysis/realtime_stats.json';
        
        if (!file_exists($statsFile)) {
            return ['error' => 'No statistics available'];
        }
        
        return json_decode(file_get_contents($statsFile), true);
    }
    
    /**
     * Get recent alerts
     */
    public static function getRecentAlerts($limit = 10) {
        $alertFile = self::$logPath . 'alerts/' . date('Y-m-d') . '_alerts.log';
        
        if (!file_exists($alertFile)) {
            return [];
        }
        
        $lines = file($alertFile);
        $alerts = [];
        
        foreach (array_reverse($lines) as $line) {
            $alert = json_decode(trim($line), true);
            if ($alert) {
                $alerts[] = $alert;
                if (count($alerts) >= $limit) {
                    break;
                }
            }
        }
        
        return $alerts;
    }
    
    /**
     * Audit trail logging
     */
    public static function auditLog($action, $details = []) {
        $auditFile = self::$logPath . 'audit/' . date('Y-m') . '.log';
        
        $entry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'action' => $action,
            'user' => $_SESSION['username'] ?? 'anonymous',
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'details' => $details
        ];
        
        $logEntry = json_encode($entry) . "\n";
        file_put_contents($auditFile, $logEntry, FILE_APPEND | LOCK_EX);
    }
    
    /**
     * Clean old log files
     */
    public static function cleanOldLogs($daysToKeep = 30) {
        $directories = ['events', 'alerts', 'audit'];
        $cutoffTime = time() - ($daysToKeep * 24 * 60 * 60);
        
        foreach ($directories as $dir) {
            $path = self::$logPath . $dir . '/';
            $files = glob($path . '*.log');
            
            foreach ($files as $file) {
                if (filemtime($file) < $cutoffTime) {
                    unlink($file);
                }
            }
        }
    }
}

// Initialize on load
SecurityLogger::init();

// Clean old logs occasionally
if (rand(1, 100) === 1) {
    SecurityLogger::cleanOldLogs();
}
?>