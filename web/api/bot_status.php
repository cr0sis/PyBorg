<?php
/**
 * Centralized Bot Status API
 * Provides comprehensive bot status information for all admin panel components
 */

require_once __DIR__ . '/../security_config.php';
require_once __DIR__ . '/../secure_admin_functions.php';
require_once __DIR__ . '/../security_middleware.php';
require_once __DIR__ . '/../input_sanitizer.php';

// Initialize security
SecurityMiddleware::validateAdminAccess();

header('Content-Type: application/json');

// Secure CORS implementation
SecurityMiddleware::generateSecureCORS();
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type');

class BotStatusManager {
    private $botManager;
    private $cacheFile = '/tmp/bot_status_cache.json';
    private $cacheLifetime = 30; // seconds - increased from 5 to reduce server load
    
    public function __construct() {
        $this->botManager = new SecureBotManager();
    }
    
    /**
     * Get comprehensive bot status with caching
     */
    public function getComprehensiveStatus() {
        // Check cache first
        if ($this->isCacheValid()) {
            $cached = $this->getCachedStatus();
            if ($cached) {
                return $cached;
            }
        }
        
        // Generate fresh status data
        $status = $this->generateFreshStatus();
        
        // Cache the results
        $this->cacheStatus($status);
        
        return $status;
    }
    
    private function generateFreshStatus() {
        $botStatus = $this->getEnhancedBotStatus();
        
        $status = [
            'timestamp' => time(),
            'networks' => [],
            'overall' => [
                'bots_online' => 0,
                'total_bots' => 2,
                'all_online' => false,
                'any_online' => false,
                'uptime_summary' => []
            ],
            'system' => [
                'screen_sessions' => $this->getScreenSessions(),
                'process_info' => $this->getProcessInfo()
            ]
        ];
        
        foreach (['rizon', 'libera'] as $network) {
            $networkStatus = $botStatus[$network] ?? ['online' => false, 'pid' => null, 'uptime' => null];
            
            $status['networks'][$network] = [
                'online' => $networkStatus['online'],
                'pid' => $networkStatus['pid'],
                'uptime' => $networkStatus['uptime'],
                'uptime_seconds' => $this->getUptimeSeconds($networkStatus['pid']),
                'screen_session' => $this->hasScreenSession($network),
                'log_file' => $this->getLogFileInfo($network),
                'last_activity' => $this->getLastActivity($network),
                'status_color' => $networkStatus['online'] ? '#059669' : '#dc2626',
                'status_icon' => $networkStatus['online'] ? '🟢' : '🔴',
                'status_text' => $networkStatus['online'] ? 'Online' : 'Offline'
            ];
            
            if ($networkStatus['online']) {
                $status['overall']['bots_online']++;
                $status['overall']['uptime_summary'][] = [
                    'network' => $network,
                    'uptime' => $networkStatus['uptime'],
                    'uptime_seconds' => $this->getUptimeSeconds($networkStatus['pid'])
                ];
            }
        }
        
        $status['overall']['all_online'] = $status['overall']['bots_online'] === $status['overall']['total_bots'];
        $status['overall']['any_online'] = $status['overall']['bots_online'] > 0;
        $status['overall']['status_text'] = $this->getOverallStatusText($status['overall']['bots_online']);
        $status['overall']['status_color'] = $this->getOverallStatusColor($status['overall']['bots_online']);
        
        return $status;
    }
    
    /**
     * Enhanced bot status detection that doesn't rely solely on PID files
     */
    private function getEnhancedBotStatus() {
        $botStatus = [];
        
        foreach (['rizon', 'libera'] as $network) {
            $botStatus[$network] = $this->checkBotProcessEnhanced($network);
        }
        
        return $botStatus;
    }
    
    /**
     * Enhanced process checking with multiple detection methods
     */
    private function checkBotProcessEnhanced($network) {
        $running = false;
        $pid = null;
        $uptime = null;
        
        try {
            // Method 1: Check for python process with bot_v2.py and network argument
            $output = SafeCommand::execute('ps', ['aux']);
            $lines = explode("\n", $output);
            
            foreach ($lines as $line) {
                // Look for: python bot_v2.py [network] but exclude SCREEN processes
                if (preg_match('/\s+(\d+)\s+.*python.*bot_v2\.py\s+' . preg_quote($network, '/') . '(\s|$)/', $line, $matches) 
                    && strpos($line, 'SCREEN') === false) {
                    $running = true;
                    $pid = (int)$matches[1];
                    
                    // Get process uptime
                    $uptime = $this->getProcessUptimeFromPS($line);
                    break;
                }
            }
            
            // Method 2: Check screen sessions if no process found
            if (!$running) {
                $screenOutput = SafeCommand::execute('screen', ['-list']);
                $sessionExists = strpos($screenOutput, "{$network}-bot") !== false;
                
                if ($sessionExists) {
                    // Screen session exists, try to find the process inside it
                    $running = true;
                    // We'll show as running but PID might be unknown
                }
            }
            
            // Method 3: Check log file activity (recent activity indicates bot is alive)
            if (!$running) {
                require_once '../config_paths.php';
                $logFile = ConfigPaths::getLogPath('bot', $network);
                if (file_exists($logFile)) {
                    $lastModified = filemtime($logFile);
                    // If log was modified in last 2 minutes, consider bot likely running
                    if ((time() - $lastModified) < 120) {
                        $running = true; // Probably running based on recent log activity
                    }
                }
            }
            
        } catch (Exception $e) {
            error_log("Enhanced bot status check error for $network: " . $e->getMessage());
        }
        
        return [
            'online' => $running,
            'pid' => $pid,
            'uptime' => $uptime ? $this->formatUptime($uptime) : null
        ];
    }
    
    /**
     * Extract uptime from ps command output
     */
    private function getProcessUptimeFromPS($psLine) {
        try {
            $parts = preg_split('/\s+/', trim($psLine));
            if (count($parts) >= 9) {
                $startTime = $parts[8]; // TIME or START column
                
                // If it's in TIME format (mm:ss or hh:mm:ss), it started today
                if (preg_match('/^\d{1,2}:\d{2}(:\d{2})?$/', $startTime)) {
                    // Process started today, calculate uptime from TIME
                    $timeParts = explode(':', $startTime);
                    if (count($timeParts) == 2) {
                        // mm:ss format
                        return $timeParts[0] * 60 + $timeParts[1];
                    } elseif (count($timeParts) == 3) {
                        // hh:mm:ss format  
                        return $timeParts[0] * 3600 + $timeParts[1] * 60 + $timeParts[2];
                    }
                } else {
                    // START format (date), process started on different day
                    // ps command shows local system time, convert properly
                    $startTimestamp = strtotime($startTime);
                    if ($startTimestamp !== false) {
                        // Both time() and strtotime() now use the same timezone (Europe/London)
                        return time() - $startTimestamp;
                    }
                }
            }
        } catch (Exception $e) {
            // Fallback: return null if we can't parse
        }
        
        return null;
    }
    
    private function formatUptime($seconds) {
        if (!$seconds || $seconds < 0) return '0s';
        if ($seconds < 60) return $seconds . 's';
        if ($seconds < 3600) return floor($seconds/60) . 'm ' . ($seconds%60) . 's';
        if ($seconds < 86400) return floor($seconds/3600) . 'h ' . floor(($seconds%3600)/60) . 'm';
        return floor($seconds/86400) . 'd ' . floor(($seconds%86400)/3600) . 'h';
    }
    
    private function getScreenSessions() {
        try {
            $output = SafeCommand::execute('screen', ['-list']);
            $sessions = [];
            $lines = explode("\n", $output);
            
            foreach ($lines as $line) {
                if (preg_match('/(\d+)\.([a-z]+-bot)\s+\(([^)]+)\)/', trim($line), $matches)) {
                    $sessions[] = [
                        'id' => $matches[1],
                        'name' => $matches[2],
                        'status' => $matches[3],
                        'network' => str_replace('-bot', '', $matches[2])
                    ];
                }
            }
            
            return $sessions;
        } catch (Exception $e) {
            return [];
        }
    }
    
    private function getProcessInfo() {
        try {
            $output = SafeCommand::execute('ps', ['aux']);
            $processes = [];
            $lines = explode("\n", $output);
            
            foreach ($lines as $line) {
                if (preg_match('/python3\s+bot_v2\.py\s+(rizon|libera)/', $line, $matches) 
                    && strpos($line, 'SCREEN') === false) {
                    $parts = preg_split('/\s+/', trim($line));
                    if (count($parts) >= 11) {
                        $processes[] = [
                            'network' => $matches[1],
                            'pid' => $parts[1],
                            'cpu' => $parts[2],
                            'memory' => $parts[3],
                            'start_time' => $parts[8],
                            'command' => implode(' ', array_slice($parts, 10))
                        ];
                    }
                }
            }
            
            return $processes;
        } catch (Exception $e) {
            return [];
        }
    }
    
    private function hasScreenSession($network) {
        try {
            $output = SafeCommand::execute('screen', ['-list']);
            return strpos($output, "{$network}-bot") !== false;
        } catch (Exception $e) {
            return false;
        }
    }
    
    private function getLogFileInfo($network) {
        require_once '../config_paths.php';
        $logFile = ConfigPaths::getLogPath('bot', $network);
        
        if (!file_exists($logFile)) {
            return ['exists' => false];
        }
        
        $stat = stat($logFile);
        return [
            'exists' => true,
            'size' => $stat['size'],
            'size_human' => $this->formatBytes($stat['size']),
            'last_modified' => $stat['mtime'],
            'last_modified_human' => date('Y-m-d H:i:s', $stat['mtime'])
        ];
    }
    
    private function getLastActivity($network) {
        require_once '../config_paths.php';
        $logFile = ConfigPaths::getLogPath('bot', $network);
        
        if (!file_exists($logFile)) {
            return null;
        }
        
        try {
            // Get last few lines of log file
            $lines = [];
            $file = new SplFileObject($logFile);
            $file->seek(PHP_INT_MAX);
            $lastLine = $file->key();
            
            // Read last 5 lines
            for ($i = max(0, $lastLine - 5); $i <= $lastLine; $i++) {
                $file->seek($i);
                $line = trim($file->current());
                if (!empty($line)) {
                    $lines[] = $line;
                }
            }
            
            // Extract timestamp from last line
            $lastLine = end($lines);
            if (preg_match('/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/', $lastLine, $matches)) {
                return [
                    'timestamp' => $matches[1],
                    'seconds_ago' => time() - strtotime($matches[1]),
                    'human' => $this->timeAgo(strtotime($matches[1]))
                ];
            }
            
            return null;
        } catch (Exception $e) {
            return null;
        }
    }
    
    private function getUptimeSeconds($pid) {
        if (!$pid || !file_exists("/proc/$pid")) {
            return 0;
        }
        
        try {
            $stat_file = "/proc/$pid/stat";
            if (!file_exists($stat_file)) {
                return 0;
            }
            
            $stat = file_get_contents($stat_file);
            $stat_parts = explode(' ', $stat);
            
            if (count($stat_parts) < 22) {
                return 0;
            }
            
            $starttime = intval($stat_parts[21]);
            $clock_ticks = (int)SafeCommand::execute('getconf', ['CLK_TCK']);
            $boot_time_output = SafeCommand::execute('awk', ['/btime/ {print $2}', '/proc/stat']);
            $boot_time = (int)trim($boot_time_output);
            
            $process_start = $boot_time + ($starttime / $clock_ticks);
            return time() - $process_start;
            
        } catch (Exception $e) {
            return 0;
        }
    }
    
    private function getOverallStatusText($onlineCount) {
        if ($onlineCount === 2) return 'All Bots Online';
        if ($onlineCount === 1) return 'Partial Service';
        return 'All Bots Offline';
    }
    
    private function getOverallStatusColor($onlineCount) {
        if ($onlineCount === 2) return '#059669';
        if ($onlineCount === 1) return '#f59e0b';
        return '#dc2626';
    }
    
    private function formatBytes($size) {
        $units = ['B', 'KB', 'MB', 'GB'];
        for ($i = 0; $size > 1024 && $i < count($units) - 1; $i++) {
            $size /= 1024;
        }
        return round($size, 2) . ' ' . $units[$i];
    }
    
    private function timeAgo($timestamp) {
        $diff = time() - $timestamp;
        
        if ($diff < 60) return $diff . 's ago';
        if ($diff < 3600) return floor($diff/60) . 'm ago';
        if ($diff < 86400) return floor($diff/3600) . 'h ago';
        return floor($diff/86400) . 'd ago';
    }
    
    private function isCacheValid() {
        return file_exists($this->cacheFile) && 
               (time() - filemtime($this->cacheFile)) < $this->cacheLifetime;
    }
    
    private function getCachedStatus() {
        if (file_exists($this->cacheFile)) {
            $content = file_get_contents($this->cacheFile);
            return json_decode($content, true);
        }
        return null;
    }
    
    private function cacheStatus($status) {
        file_put_contents($this->cacheFile, json_encode($status));
    }
}

// Handle API request
try {
    // Sanitize all input
    $_GET = InputSanitizer::sanitizeAll($_GET);
    $_POST = InputSanitizer::sanitizeAll($_POST);
    
    // Validate action parameter
    $action = InputSanitizer::validateAction($_GET['action'] ?? $_POST['action'] ?? 'full');
    $statusManager = new BotStatusManager();
    
    switch ($action) {
        case 'full':
            echo json_encode($statusManager->getComprehensiveStatus());
            break;
            
        case 'quick':
            // Just basic online/offline status for lightweight checks
            $botManager = new SecureBotManager();
            $status = $botManager->getBotStatus();
            echo json_encode([
                'rizon' => $status['rizon']['online'] ?? false,
                'libera' => $status['libera']['online'] ?? false,
                'timestamp' => time()
            ]);
            break;
            
        default:
            echo json_encode(['error' => 'Unknown action']);
    }
    
} catch (Exception $e) {
    echo json_encode(['error' => $e->getMessage()]);
}
?>