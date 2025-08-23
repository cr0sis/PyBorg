<?php
/**
 * File Access Logger - Phase 5: File System Security
 * Comprehensive logging system for all file operations
 */

require_once 'security_middleware.php';
require_once 'config_paths.php';

class FileAccessLogger {
    
    private static $logFile;
    private static $alertFile;
    private static $maxLogSize = 52428800; // 50MB
    private static $suspiciousThreshold = 10; // alerts per minute
    
    /**
     * Initialize file access logger
     */
    public static function init() {
        if (!self::$logFile) {
            self::$logFile = ConfigPaths::getLogPath('file_access');
            self::$alertFile = ConfigPaths::LOG_SECURITY_DIR . '/file_access_alerts.json';
        }
    }
    
    /**
     * Log file access attempt
     */
    public static function logAccess($operation, $filepath, $result = 'SUCCESS', $details = []) {
        self::init();
        
        $logEntry = [
            'timestamp' => date('Y-m-d H:i:s'),
            'operation' => $operation,
            'filepath' => $filepath,
            'result' => $result,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'session_id' => session_id() ?: 'none',
            'user_id' => $_SESSION['user_id'] ?? 'anonymous',
            'details' => $details
        ];
        
        // Write to log file
        self::writeLogEntry($logEntry);
        
        // Check for suspicious activity
        if ($result !== 'SUCCESS') {
            self::checkSuspiciousActivity($operation, $filepath, $result);
        }
        
        // Also log to security middleware for critical operations
        if (in_array($operation, ['DELETE', 'WRITE', 'UPLOAD'])) {
            SecurityMiddleware::logSecurityEvent('FILE_' . $operation, [
                'file' => $filepath,
                'result' => $result,
                'ip' => $logEntry['ip'],
                'user_id' => $logEntry['user_id']
            ], $result === 'SUCCESS' ? 'INFO' : 'MEDIUM');
        }
    }
    
    /**
     * Log directory listing attempt
     */
    public static function logDirectoryAccess($directory, $pattern = '*', $result = 'SUCCESS', $fileCount = 0) {
        self::logAccess('LIST_DIRECTORY', $directory, $result, [
            'pattern' => $pattern,
            'file_count' => $fileCount
        ]);
    }
    
    /**
     * Log file upload attempt
     */
    public static function logUpload($originalName, $savedPath, $result = 'SUCCESS', $details = []) {
        self::logAccess('UPLOAD', $savedPath, $result, array_merge([
            'original_name' => $originalName,
            'file_size' => filesize($savedPath) ?: 0
        ], $details));
    }
    
    /**
     * Log file download attempt
     */
    public static function logDownload($filepath, $result = 'SUCCESS', $bytesTransferred = 0) {
        self::logAccess('DOWNLOAD', $filepath, $result, [
            'bytes_transferred' => $bytesTransferred
        ]);
    }
    
    /**
     * Log file deletion attempt
     */
    public static function logDeletion($filepath, $result = 'SUCCESS') {
        $fileSize = file_exists($filepath) ? filesize($filepath) : 0;
        self::logAccess('DELETE', $filepath, $result, [
            'file_size' => $fileSize
        ]);
    }
    
    /**
     * Log file permission change
     */
    public static function logPermissionChange($filepath, $oldPerms, $newPerms, $result = 'SUCCESS') {
        self::logAccess('CHMOD', $filepath, $result, [
            'old_permissions' => decoct($oldPerms),
            'new_permissions' => decoct($newPerms)
        ]);
    }
    
    /**
     * Log suspicious file activity
     */
    public static function logSuspiciousActivity($type, $filepath, $reason, $severity = 'MEDIUM') {
        self::logAccess('SUSPICIOUS_' . $type, $filepath, 'BLOCKED', [
            'reason' => $reason,
            'severity' => $severity
        ]);
        
        // Create alert
        self::createAlert($type, $filepath, $reason, $severity);
    }
    
    /**
     * Write log entry to file
     */
    private static function writeLogEntry($logEntry) {
        // Ensure log directory exists
        $logDir = dirname(self::$logFile);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        
        // Rotate log if too large
        if (file_exists(self::$logFile) && filesize(self::$logFile) > self::$maxLogSize) {
            self::rotateLog();
        }
        
        // Format log entry
        $logLine = json_encode($logEntry) . "\n";
        
        // Write to log file
        file_put_contents(self::$logFile, $logLine, FILE_APPEND | LOCK_EX);
    }
    
    /**
     * Rotate log file when it gets too large
     */
    private static function rotateLog() {
        if (file_exists(self::$logFile)) {
            $rotatedFile = self::$logFile . '.' . date('Y-m-d_H-i-s');
            rename(self::$logFile, $rotatedFile);
            
            // Compress old log
            if (function_exists('gzopen')) {
                $compressed = $rotatedFile . '.gz';
                $data = file_get_contents($rotatedFile);
                $gz = gzopen($compressed, 'w9');
                gzwrite($gz, $data);
                gzclose($gz);
                unlink($rotatedFile);
            }
        }
    }
    
    /**
     * Check for suspicious activity patterns
     */
    private static function checkSuspiciousActivity($operation, $filepath, $result) {
        $now = time();
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        // Count recent failed attempts from this IP
        $recentAttempts = self::countRecentAttempts($ip, 60); // last minute
        
        if ($recentAttempts >= self::$suspiciousThreshold) {
            self::createAlert('EXCESSIVE_FAILED_ATTEMPTS', $filepath, 
                "IP $ip made $recentAttempts failed file access attempts in the last minute", 'HIGH');
            
            // Log to security middleware
            SecurityMiddleware::logSecurityEvent('SUSPICIOUS_FILE_ACTIVITY', [
                'ip' => $ip,
                'operation' => $operation,
                'filepath' => $filepath,
                'attempts_count' => $recentAttempts
            ], 'HIGH');
        }
        
        // Check for directory traversal patterns
        if (strpos($filepath, '..') !== false || strpos($filepath, '/./') !== false) {
            self::createAlert('DIRECTORY_TRAVERSAL_ATTEMPT', $filepath,
                "Potential directory traversal in file path: $filepath", 'HIGH');
        }
        
        // Check for access to sensitive files
        $sensitivePatterns = [
            '/etc/passwd',
            '/etc/shadow',
            '/.env',
            '/config/',
            '/admin/',
            '/.git/',
            '/backup/'
        ];
        
        foreach ($sensitivePatterns as $pattern) {
            if (stripos($filepath, $pattern) !== false) {
                self::createAlert('SENSITIVE_FILE_ACCESS', $filepath,
                    "Attempt to access sensitive file: $filepath", 'HIGH');
                break;
            }
        }
    }
    
    /**
     * Count recent failed attempts from an IP
     */
    private static function countRecentAttempts($ip, $timeWindow) {
        if (!file_exists(self::$logFile)) {
            return 0;
        }
        
        $count = 0;
        $cutoffTime = time() - $timeWindow;
        
        $handle = fopen(self::$logFile, 'r');
        if ($handle) {
            while (($line = fgets($handle)) !== false) {
                $entry = json_decode($line, true);
                if ($entry && isset($entry['ip']) && $entry['ip'] === $ip) {
                    $entryTime = strtotime($entry['timestamp']);
                    if ($entryTime >= $cutoffTime && $entry['result'] !== 'SUCCESS') {
                        $count++;
                    }
                }
            }
            fclose($handle);
        }
        
        return $count;
    }
    
    /**
     * Create security alert
     */
    private static function createAlert($type, $filepath, $reason, $severity) {
        $alert = [
            'id' => uniqid('alert_'),
            'timestamp' => date('Y-m-d H:i:s'),
            'type' => $type,
            'severity' => $severity,
            'filepath' => $filepath,
            'reason' => $reason,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'session_id' => session_id() ?: 'none',
            'user_id' => $_SESSION['user_id'] ?? 'anonymous',
            'status' => 'open'
        ];
        
        // Load existing alerts
        $alerts = [];
        if (file_exists(self::$alertFile)) {
            $alerts = json_decode(file_get_contents(self::$alertFile), true) ?: [];
        }
        
        // Add new alert
        $alerts[] = $alert;
        
        // Keep only recent alerts (last 1000)
        if (count($alerts) > 1000) {
            $alerts = array_slice($alerts, -1000);
        }
        
        // Save alerts
        file_put_contents(self::$alertFile, json_encode($alerts, JSON_PRETTY_PRINT));
    }
    
    /**
     * Get recent file access statistics
     */
    public static function getAccessStats($hours = 24) {
        if (!file_exists(self::$logFile)) {
            return [
                'total_accesses' => 0,
                'successful' => 0,
                'failed' => 0,
                'operations' => [],
                'top_files' => [],
                'top_ips' => []
            ];
        }
        
        $stats = [
            'total_accesses' => 0,
            'successful' => 0,
            'failed' => 0,
            'operations' => [],
            'top_files' => [],
            'top_ips' => []
        ];
        
        $cutoffTime = time() - ($hours * 3600);
        $fileAccess = [];
        $ipAccess = [];
        
        $handle = fopen(self::$logFile, 'r');
        if ($handle) {
            while (($line = fgets($handle)) !== false) {
                $entry = json_decode($line, true);
                if ($entry && strtotime($entry['timestamp']) >= $cutoffTime) {
                    $stats['total_accesses']++;
                    
                    if ($entry['result'] === 'SUCCESS') {
                        $stats['successful']++;
                    } else {
                        $stats['failed']++;
                    }
                    
                    // Count operations
                    $op = $entry['operation'];
                    $stats['operations'][$op] = ($stats['operations'][$op] ?? 0) + 1;
                    
                    // Count file accesses
                    $file = basename($entry['filepath']);
                    $fileAccess[$file] = ($fileAccess[$file] ?? 0) + 1;
                    
                    // Count IP accesses
                    $ip = $entry['ip'];
                    $ipAccess[$ip] = ($ipAccess[$ip] ?? 0) + 1;
                }
            }
            fclose($handle);
        }
        
        // Sort and limit top items
        arsort($fileAccess);
        arsort($ipAccess);
        arsort($stats['operations']);
        
        $stats['top_files'] = array_slice($fileAccess, 0, 10, true);
        $stats['top_ips'] = array_slice($ipAccess, 0, 10, true);
        
        return $stats;
    }
    
    /**
     * Get recent alerts
     */
    public static function getRecentAlerts($limit = 20) {
        if (!file_exists(self::$alertFile)) {
            return [];
        }
        
        $alerts = json_decode(file_get_contents(self::$alertFile), true) ?: [];
        return array_slice(array_reverse($alerts), 0, $limit);
    }
    
    /**
     * Search file access logs
     */
    public static function searchLogs($criteria = []) {
        if (!file_exists(self::$logFile)) {
            return [];
        }
        
        $results = [];
        $handle = fopen(self::$logFile, 'r');
        
        if ($handle) {
            while (($line = fgets($handle)) !== false) {
                $entry = json_decode($line, true);
                if ($entry && self::matchesCriteria($entry, $criteria)) {
                    $results[] = $entry;
                }
            }
            fclose($handle);
        }
        
        return array_reverse($results); // Most recent first
    }
    
    /**
     * Check if log entry matches search criteria
     */
    private static function matchesCriteria($entry, $criteria) {
        foreach ($criteria as $field => $value) {
            switch ($field) {
                case 'ip':
                    if ($entry['ip'] !== $value) return false;
                    break;
                case 'operation':
                    if ($entry['operation'] !== $value) return false;
                    break;
                case 'result':
                    if ($entry['result'] !== $value) return false;
                    break;
                case 'filepath_contains':
                    if (stripos($entry['filepath'], $value) === false) return false;
                    break;
                case 'user_id':
                    if ($entry['user_id'] !== $value) return false;
                    break;
                case 'since':
                    if (strtotime($entry['timestamp']) < strtotime($value)) return false;
                    break;
                case 'until':
                    if (strtotime($entry['timestamp']) > strtotime($value)) return false;
                    break;
            }
        }
        return true;
    }
    
    /**
     * Get file access history for a specific file
     */
    public static function getFileHistory($filepath, $limit = 50) {
        $criteria = ['filepath_contains' => $filepath];
        $results = self::searchLogs($criteria);
        return array_slice($results, 0, $limit);
    }
    
    /**
     * Get user activity summary
     */
    public static function getUserActivity($userId, $hours = 24) {
        $criteria = [
            'user_id' => $userId,
            'since' => date('Y-m-d H:i:s', time() - ($hours * 3600))
        ];
        
        $activities = self::searchLogs($criteria);
        
        $summary = [
            'total_operations' => count($activities),
            'successful' => 0,
            'failed' => 0,
            'operations' => [],
            'files_accessed' => []
        ];
        
        foreach ($activities as $activity) {
            if ($activity['result'] === 'SUCCESS') {
                $summary['successful']++;
            } else {
                $summary['failed']++;
            }
            
            $op = $activity['operation'];
            $summary['operations'][$op] = ($summary['operations'][$op] ?? 0) + 1;
            
            $summary['files_accessed'][] = $activity['filepath'];
        }
        
        $summary['files_accessed'] = array_unique($summary['files_accessed']);
        
        return $summary;
    }
    
    /**
     * Clean old log entries
     */
    public static function cleanOldLogs($daysToKeep = 30) {
        if (!file_exists(self::$logFile)) {
            return ['message' => 'No log file to clean'];
        }
        
        $cutoffTime = time() - ($daysToKeep * 24 * 3600);
        $tempFile = self::$logFile . '.tmp';
        $keptEntries = 0;
        $removedEntries = 0;
        
        $readHandle = fopen(self::$logFile, 'r');
        $writeHandle = fopen($tempFile, 'w');
        
        if ($readHandle && $writeHandle) {
            while (($line = fgets($readHandle)) !== false) {
                $entry = json_decode($line, true);
                if ($entry && strtotime($entry['timestamp']) >= $cutoffTime) {
                    fwrite($writeHandle, $line);
                    $keptEntries++;
                } else {
                    $removedEntries++;
                }
            }
            
            fclose($readHandle);
            fclose($writeHandle);
            
            // Replace original file
            rename($tempFile, self::$logFile);
            
            return [
                'message' => 'Log cleanup completed',
                'kept_entries' => $keptEntries,
                'removed_entries' => $removedEntries
            ];
        }
        
        return ['error' => 'Failed to clean logs'];
    }
}
?>