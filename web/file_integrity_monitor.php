<?php
/**
 * File Integrity Monitor - Phase 5: File System Security
 * Real-time monitoring of critical file changes and integrity validation
 */

require_once 'security_middleware.php';
require_once 'config_paths.php';
require_once 'file_access_logger.php';

class FileIntegrityMonitor {
    
    private static $hashFile = ConfigPaths::getStoragePath('file_hashes');
    private static $alertFile = ConfigPaths::getLogPath('integrity_alerts');
    private static $configFile = ConfigPaths::getStoragePath('integrity_config');
    
    // Critical files to monitor by default
    private static $defaultMonitoredFiles = [
        '/var/www/html/auth.php',
        '/var/www/html/admin_panel.php',
        '/var/www/html/security_middleware.php',
        '/var/www/html/session_security.php',
        '/var/www/html/input_sanitizer.php',
        '/var/www/html/.htaccess',
        '/var/www/html/index.html'
    ];
    
    // Critical directories to monitor
    private static $defaultMonitoredDirectories = [
        '/var/www/html/core/',
        '/var/www/html/data/',
        '/data/cr0_system/logs/'
    ];
    
    /**
     * Initialize file integrity monitoring
     */
    public static function initialize() {
        // Create necessary directories
        $storageDir = dirname(self::$hashFile);
        if (!is_dir($storageDir)) {
            mkdir($storageDir, 0755, true);
        }
        
        $logsDir = dirname(self::$alertFile);
        if (!is_dir($logsDir)) {
            mkdir($logsDir, 0755, true);
        }
        
        // Load or create configuration
        self::loadConfiguration();
        
        // Initial scan if no baseline exists
        if (!file_exists(self::$hashFile)) {
            self::createBaseline();
        }
        
        return ['success' => true, 'message' => 'File integrity monitoring initialized'];
    }
    
    /**
     * Create baseline hashes for monitored files
     */
    public static function createBaseline() {
        $config = self::loadConfiguration();
        $hashes = [];
        $processed = 0;
        $errors = [];
        
        // Process monitored files
        foreach ($config['monitored_files'] as $filepath) {
            if (file_exists($filepath)) {
                $hashData = self::calculateFileHash($filepath);
                if ($hashData) {
                    $hashes[$filepath] = $hashData;
                    $processed++;
                } else {
                    $errors[] = "Failed to hash: $filepath";
                }
            } else {
                $errors[] = "File not found: $filepath";
            }
        }
        
        // Process monitored directories
        foreach ($config['monitored_directories'] as $directory) {
            if (is_dir($directory)) {
                $dirFiles = self::scanDirectory($directory);
                foreach ($dirFiles as $filepath) {
                    $hashData = self::calculateFileHash($filepath);
                    if ($hashData) {
                        $hashes[$filepath] = $hashData;
                        $processed++;
                    } else {
                        $errors[] = "Failed to hash: $filepath";
                    }
                }
            } else {
                $errors[] = "Directory not found: $directory";
            }
        }
        
        // Save baseline
        $baseline = [
            'created' => date('Y-m-d H:i:s'),
            'files_count' => $processed,
            'hashes' => $hashes
        ];
        
        file_put_contents(self::$hashFile, json_encode($baseline, JSON_PRETTY_PRINT));
        
        // Log baseline creation
        SecurityMiddleware::logSecurityEvent('INTEGRITY_BASELINE_CREATED', [
            'files_processed' => $processed,
            'errors_count' => count($errors),
            'errors' => $errors
        ], 'INFO');
        
        return [
            'success' => true,
            'files_processed' => $processed,
            'errors' => $errors
        ];
    }
    
    /**
     * Perform integrity check on all monitored files
     */
    public static function performIntegrityCheck() {
        if (!file_exists(self::$hashFile)) {
            return ['error' => 'No baseline found. Run createBaseline() first.'];
        }
        
        $baseline = json_decode(file_get_contents(self::$hashFile), true);
        if (!$baseline) {
            return ['error' => 'Failed to load baseline'];
        }
        
        $results = [
            'timestamp' => date('Y-m-d H:i:s'),
            'files_checked' => 0,
            'files_changed' => 0,
            'files_missing' => 0,
            'new_files' => 0,
            'changes' => [],
            'missing' => [],
            'new' => []
        ];
        
        // Check existing baseline files
        foreach ($baseline['hashes'] as $filepath => $baselineHash) {
            $results['files_checked']++;
            
            if (!file_exists($filepath)) {
                $results['files_missing']++;
                $results['missing'][] = $filepath;
                
                self::createIntegrityAlert('FILE_MISSING', $filepath, [
                    'baseline_hash' => $baselineHash
                ]);
                
                continue;
            }
            
            $currentHash = self::calculateFileHash($filepath);
            if (!$currentHash) {
                continue;
            }
            
            // Compare hashes
            if ($currentHash['sha256'] !== $baselineHash['sha256'] ||
                $currentHash['size'] !== $baselineHash['size'] ||
                $currentHash['modified'] !== $baselineHash['modified']) {
                
                $results['files_changed']++;
                $results['changes'][] = [
                    'file' => $filepath,
                    'baseline' => $baselineHash,
                    'current' => $currentHash,
                    'changes' => self::detectChanges($baselineHash, $currentHash)
                ];
                
                self::createIntegrityAlert('FILE_MODIFIED', $filepath, [
                    'baseline' => $baselineHash,
                    'current' => $currentHash,
                    'changes' => self::detectChanges($baselineHash, $currentHash)
                ]);
            }
        }
        
        // Check for new files in monitored directories
        $config = self::loadConfiguration();
        foreach ($config['monitored_directories'] as $directory) {
            if (is_dir($directory)) {
                $currentFiles = self::scanDirectory($directory);
                foreach ($currentFiles as $filepath) {
                    if (!isset($baseline['hashes'][$filepath])) {
                        $results['new_files']++;
                        $newFileHash = self::calculateFileHash($filepath);
                        $results['new'][] = [
                            'file' => $filepath,
                            'hash' => $newFileHash
                        ];
                        
                        self::createIntegrityAlert('NEW_FILE_DETECTED', $filepath, [
                            'file_hash' => $newFileHash
                        ]);
                    }
                }
            }
        }
        
        // Update baseline if configured to do so
        if ($config['auto_update_baseline'] ?? false) {
            self::updateBaseline();
        }
        
        return $results;
    }
    
    /**
     * Calculate file hash and metadata
     */
    private static function calculateFileHash($filepath) {
        if (!file_exists($filepath) || !is_readable($filepath)) {
            return false;
        }
        
        try {
            $content = file_get_contents($filepath);
            if ($content === false) {
                return false;
            }
            
            $stat = stat($filepath);
            
            return [
                'sha256' => hash('sha256', $content),
                'md5' => md5($content),
                'size' => $stat['size'],
                'modified' => $stat['mtime'],
                'permissions' => decoct($stat['mode'] & 0777),
                'calculated_at' => time()
            ];
        } catch (Exception $e) {
            FileAccessLogger::logSuspiciousActivity('HASH_CALCULATION_ERROR', $filepath,
                'Error calculating file hash: ' . $e->getMessage(), 'MEDIUM');
            return false;
        }
    }
    
    /**
     * Detect specific changes between baseline and current
     */
    private static function detectChanges($baseline, $current) {
        $changes = [];
        
        if ($baseline['sha256'] !== $current['sha256']) {
            $changes[] = 'content_modified';
        }
        
        if ($baseline['size'] !== $current['size']) {
            $changes[] = 'size_changed';
        }
        
        if ($baseline['modified'] !== $current['modified']) {
            $changes[] = 'timestamp_changed';
        }
        
        if ($baseline['permissions'] !== $current['permissions']) {
            $changes[] = 'permissions_changed';
        }
        
        return $changes;
    }
    
    /**
     * Scan directory for files to monitor
     */
    private static function scanDirectory($directory, $recursive = true) {
        $files = [];
        
        if (!is_dir($directory)) {
            return $files;
        }
        
        $iterator = $recursive ? 
            new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory)) :
            new DirectoryIterator($directory);
        
        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $filepath = $file->getRealPath();
                
                // Skip certain file types
                $extension = strtolower(pathinfo($filepath, PATHINFO_EXTENSION));
                if (!in_array($extension, ['log', 'tmp', 'cache', 'lock'])) {
                    $files[] = $filepath;
                }
            }
        }
        
        return $files;
    }
    
    /**
     * Create integrity alert
     */
    private static function createIntegrityAlert($type, $filepath, $details) {
        $alert = [
            'id' => uniqid('integrity_'),
            'timestamp' => date('Y-m-d H:i:s'),
            'type' => $type,
            'file' => $filepath,
            'severity' => self::getSeverityLevel($type, $filepath),
            'details' => $details,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'system',
            'status' => 'open'
        ];
        
        // Load existing alerts
        $alerts = [];
        if (file_exists(self::$alertFile)) {
            $alerts = json_decode(file_get_contents(self::$alertFile), true) ?: [];
        }
        
        // Add new alert
        $alerts[] = $alert;
        
        // Keep only recent alerts (last 500)
        if (count($alerts) > 500) {
            $alerts = array_slice($alerts, -500);
        }
        
        // Save alerts
        file_put_contents(self::$alertFile, json_encode($alerts, JSON_PRETTY_PRINT));
        
        // Log to security middleware
        SecurityMiddleware::logSecurityEvent('FILE_INTEGRITY_ALERT', [
            'alert_type' => $type,
            'file' => $filepath,
            'severity' => $alert['severity']
        ], $alert['severity']);
        
        // If critical, send immediate notification
        if ($alert['severity'] === 'CRITICAL') {
            self::sendCriticalAlert($alert);
        }
    }
    
    /**
     * Determine severity level based on alert type and file
     */
    private static function getSeverityLevel($type, $filepath) {
        // Critical files
        $criticalFiles = [
            '/var/www/html/auth.php',
            '/var/www/html/admin_panel.php',
            '/var/www/html/.htaccess'
        ];
        
        // High priority files
        $highPriorityFiles = [
            '/var/www/html/security_middleware.php',
            '/var/www/html/session_security.php',
            '/var/www/html/input_sanitizer.php'
        ];
        
        if (in_array($filepath, $criticalFiles)) {
            return 'CRITICAL';
        } elseif (in_array($filepath, $highPriorityFiles) || $type === 'FILE_MISSING') {
            return 'HIGH';
        } elseif ($type === 'NEW_FILE_DETECTED') {
            return 'MEDIUM';
        } else {
            return 'LOW';
        }
    }
    
    /**
     * Send critical alert notification
     */
    private static function sendCriticalAlert($alert) {
        // This could be extended to send email, webhook, etc.
        $notification = [
            'timestamp' => date('Y-m-d H:i:s'),
            'alert' => $alert,
            'notification_method' => 'log',
            'status' => 'sent'
        ];
        
        $criticalLogFile = ConfigPaths::LOG_SECURITY_DIR . '/critical_integrity_alerts.json';
        
        $criticalAlerts = [];
        if (file_exists($criticalLogFile)) {
            $criticalAlerts = json_decode(file_get_contents($criticalLogFile), true) ?: [];
        }
        
        $criticalAlerts[] = $notification;
        file_put_contents($criticalLogFile, json_encode($criticalAlerts, JSON_PRETTY_PRINT));
    }
    
    /**
     * Load configuration
     */
    private static function loadConfiguration() {
        if (file_exists(self::$configFile)) {
            $config = json_decode(file_get_contents(self::$configFile), true);
            if ($config) {
                return $config;
            }
        }
        
        // Create default configuration
        $defaultConfig = [
            'monitored_files' => self::$defaultMonitoredFiles,
            'monitored_directories' => self::$defaultMonitoredDirectories,
            'auto_update_baseline' => false,
            'check_interval_minutes' => 60,
            'alert_on_new_files' => true,
            'alert_on_missing_files' => true,
            'ignore_patterns' => ['*.log', '*.tmp', '*.cache']
        ];
        
        file_put_contents(self::$configFile, json_encode($defaultConfig, JSON_PRETTY_PRINT));
        return $defaultConfig;
    }
    
    /**
     * Update baseline with current file states
     */
    public static function updateBaseline() {
        $result = self::createBaseline();
        
        SecurityMiddleware::logSecurityEvent('INTEGRITY_BASELINE_UPDATED', [
            'files_processed' => $result['files_processed'] ?? 0
        ], 'INFO');
        
        return $result;
    }
    
    /**
     * Add file to monitoring list
     */
    public static function addMonitoredFile($filepath) {
        $config = self::loadConfiguration();
        
        if (!in_array($filepath, $config['monitored_files'])) {
            $config['monitored_files'][] = $filepath;
            file_put_contents(self::$configFile, json_encode($config, JSON_PRETTY_PRINT));
            
            // Calculate hash for new file
            if (file_exists($filepath)) {
                $baseline = json_decode(file_get_contents(self::$hashFile), true);
                $baseline['hashes'][$filepath] = self::calculateFileHash($filepath);
                file_put_contents(self::$hashFile, json_encode($baseline, JSON_PRETTY_PRINT));
            }
            
            return ['success' => true, 'message' => 'File added to monitoring'];
        }
        
        return ['success' => false, 'message' => 'File already monitored'];
    }
    
    /**
     * Remove file from monitoring list
     */
    public static function removeMonitoredFile($filepath) {
        $config = self::loadConfiguration();
        
        $key = array_search($filepath, $config['monitored_files']);
        if ($key !== false) {
            unset($config['monitored_files'][$key]);
            $config['monitored_files'] = array_values($config['monitored_files']);
            file_put_contents(self::$configFile, json_encode($config, JSON_PRETTY_PRINT));
            
            // Remove from baseline
            $baseline = json_decode(file_get_contents(self::$hashFile), true);
            unset($baseline['hashes'][$filepath]);
            file_put_contents(self::$hashFile, json_encode($baseline, JSON_PRETTY_PRINT));
            
            return ['success' => true, 'message' => 'File removed from monitoring'];
        }
        
        return ['success' => false, 'message' => 'File not in monitoring list'];
    }
    
    /**
     * Get integrity status summary
     */
    public static function getIntegrityStatus() {
        if (!file_exists(self::$hashFile)) {
            return ['status' => 'not_initialized', 'message' => 'No baseline found'];
        }
        
        $baseline = json_decode(file_get_contents(self::$hashFile), true);
        $config = self::loadConfiguration();
        
        $status = [
            'baseline_created' => $baseline['created'],
            'monitored_files_count' => count($baseline['hashes']),
            'monitored_directories' => count($config['monitored_directories']),
            'last_check' => 'never',
            'pending_alerts' => 0
        ];
        
        // Check for recent alerts
        if (file_exists(self::$alertFile)) {
            $alerts = json_decode(file_get_contents(self::$alertFile), true) ?: [];
            $pendingAlerts = array_filter($alerts, function($alert) {
                return $alert['status'] === 'open';
            });
            $status['pending_alerts'] = count($pendingAlerts);
            
            if (!empty($alerts)) {
                $status['last_check'] = end($alerts)['timestamp'];
            }
        }
        
        return $status;
    }
    
    /**
     * Get recent integrity alerts
     */
    public static function getRecentAlerts($limit = 20) {
        if (!file_exists(self::$alertFile)) {
            return [];
        }
        
        $alerts = json_decode(file_get_contents(self::$alertFile), true) ?: [];
        return array_slice(array_reverse($alerts), 0, $limit);
    }
    
    /**
     * Manual integrity check trigger
     */
    public static function triggerManualCheck() {
        return self::performIntegrityCheck();
    }
}
?>