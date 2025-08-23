<?php
/**
 * Secure Admin Functions
 * Replaces dangerous shell_exec calls with safe alternatives
 */

require_once 'security_config.php';
require_once 'config_paths.php';

class SecureBotManager {
    private $allowedNetworks = ['rizon', 'libera'];
    private function getScriptPath($action, $network = 'all') {
        return ConfigPaths::getBotScript($action, $network);
    }
    
    public function getBotStatus() {
        $status = [];
        
        foreach ($this->allowedNetworks as $network) {
            $status[$network] = $this->checkBotProcess($network);
        }
        
        return $status;
    }
    
    private function checkBotProcess($network) {
        if (!in_array($network, $this->allowedNetworks)) {
            throw new Exception("Invalid network: $network");
        }
        
        $running = false;
        $pid = null;
        
        try {
            // Method 1: Check PID file
            $pidFile = "/home/cr0/cr0bot/{$network}_bot.pid";
            if (file_exists($pidFile)) {
                $pid = (int)trim(file_get_contents($pidFile));
                if ($pid > 0 && file_exists("/proc/$pid")) {
                    $running = true;
                }
            }
            
            // Method 2: Safe process search using SafeCommand
            if (!$running) {
                try {
                    $output = SafeCommand::execute('ps', ['aux']);
                    $lines = explode("\n", $output);
                    
                    foreach ($lines as $line) {
                        // Look specifically for python bot_v2.py processes (python or python3)
                        if (preg_match('/\spython[3]?\s+bot_v2\.py\s+' . preg_quote($network, '/') . '(\s|$)/', $line) &&
                            strpos($line, "grep") === false) {
                            $running = true;
                            // Extract PID from ps output
                            if (preg_match('/^\S+\s+(\d+)/', trim($line), $matches)) {
                                $pid = (int)$matches[1];
                            }
                            break;
                        }
                    }
                } catch (Exception $e) {
                    securityLog("Failed to check process status for $network: " . $e->getMessage(), 'ERROR');
                }
            }
            
            // Method 3: Check screen session
            if (!$running) {
                try {
                    $output = SafeCommand::execute('screen', ['-list']);
                    if (strpos($output, "{$network}-bot") !== false) {
                        $running = true;
                    }
                } catch (Exception $e) {
                    securityLog("Failed to check screen status for $network: " . $e->getMessage(), 'ERROR');
                }
            }
            
        } catch (Exception $e) {
            securityLog("Error checking bot status for $network: " . $e->getMessage(), 'ERROR');
        }
        
        return [
            'online' => $running,
            'pid' => $pid,
            'uptime' => $running ? $this->getBotUptime($pid) : null
        ];
    }
    
    private function getBotUptime($pid) {
        if (!$pid || !file_exists("/proc/$pid")) {
            return null;
        }
        
        try {
            $stat_file = "/proc/$pid/stat";
            if (!file_exists($stat_file)) {
                return null;
            }
            
            $stat = file_get_contents($stat_file);
            $stat_parts = explode(' ', $stat);
            
            if (count($stat_parts) < 22) {
                return null;
            }
            
            // starttime is the 22nd field (index 21)
            $starttime = intval($stat_parts[21]);
            
            // Get system info safely
            $clock_ticks = (int)SafeCommand::execute('getconf', ['CLK_TCK']);
            $boot_time_output = SafeCommand::execute('awk', ['/btime/ {print $2}', '/proc/stat']);
            $boot_time = (int)trim($boot_time_output);
            
            $process_start = $boot_time + ($starttime / $clock_ticks);
            $uptime_seconds = time() - $process_start;
            
            return $this->formatUptime($uptime_seconds);
            
        } catch (Exception $e) {
            securityLog("Error getting uptime for PID $pid: " . $e->getMessage(), 'ERROR');
            return null;
        }
    }
    
    private function formatUptime($seconds) {
        $seconds = (int)$seconds; // Ensure we're working with an integer
        if ($seconds < 60) {
            return sprintf('%ds', $seconds);
        } elseif ($seconds < 3600) {
            return sprintf('%dm %ds', intval($seconds/60), $seconds%60);
        } elseif ($seconds < 86400) {
            return sprintf('%dh %dm', intval($seconds/3600), intval(($seconds%3600)/60));
        } else {
            return sprintf('%dd %dh %dm', intval($seconds/86400), intval(($seconds%86400)/3600), intval(($seconds%3600)/60));
        }
    }
    
    public function executeScript($scriptType) {
        // Parse script type to extract action and network
        $parts = explode('_', $scriptType);
        if (count($parts) < 2) {
            throw new Exception("Invalid script type format: $scriptType");
        }
        
        $action = $parts[0];
        $network = isset($parts[1]) ? $parts[1] : 'all';
        
        $scriptPath = $this->getScriptPath($action, $network);
        
        if (!$scriptPath) {
            throw new Exception("Invalid script type: $scriptType");
        }
        
        if (!file_exists($scriptPath)) {
            throw new Exception("Script not found: $scriptPath");
        }
        
        // Validate script is in allowed directory
        $realPath = realpath($scriptPath);
        $allowedDir = realpath('/var/www/html/');
        
        if (strpos($realPath, $allowedDir) !== 0) {
            throw new Exception("Script outside allowed directory");
        }
        
        // Log the action
        securityLog("Executing bot script: $scriptType");
        
        // Execute script safely
        $command = "sudo -u cr0 bash " . escapeshellarg($scriptPath) . " 2>&1";
        
        // Use proc_open for better control
        $descriptors = [
            0 => ["pipe", "r"],  // stdin
            1 => ["pipe", "w"],  // stdout  
            2 => ["pipe", "w"]   // stderr
        ];
        
        $process = proc_open($command, $descriptors, $pipes);
        
        if (!is_resource($process)) {
            throw new Exception("Failed to execute script");
        }
        
        // Set timeout
        stream_set_timeout($pipes[1], 30);  
        stream_set_timeout($pipes[2], 30);
        
        fclose($pipes[0]); // Close stdin
        
        $output = stream_get_contents($pipes[1]);
        $error = stream_get_contents($pipes[2]);
        
        fclose($pipes[1]);
        fclose($pipes[2]);
        
        $return_value = proc_close($process);
        
        if ($return_value !== 0 && !empty($error)) {
            throw new Exception("Script execution error: $error");
        }
        
        return [
            'success' => true,
            'message' => "Script executed successfully",
            'output' => $output ?: 'Script executed with no output'
        ];
    }
    
    public function getLogContent($logType, $network = null) {
        $allowedLogs = [
            'bot_rizon' => ConfigPaths::getLogPath('bot', 'rizon'),
            'bot_libera' => ConfigPaths::getLogPath('bot', 'libera'), 
            'rizon_errors' => ConfigPaths::getLogPath('errors', 'rizon'),
            'libera_errors' => ConfigPaths::getLogPath('errors', 'libera')
        ];
        
        if ($network && in_array($network, $this->allowedNetworks)) {
            $logKey = "bot_$network";
        } else {
            $logKey = $logType;
        }
        
        if (!isset($allowedLogs[$logKey])) {
            throw new Exception("Invalid log type: $logKey");
        }
        
        $logFile = $allowedLogs[$logKey];
        
        if (!file_exists($logFile)) {
            return ['content' => "Log file not found: $logFile"];
        }
        
        try {
            // Use SafeCommand to get log content
            $content = SafeCommand::execute('tail', ['-100', $logFile]);
            $cleaned = $this->cleanLogFormatting($content);
            
            return [
                'content' => $cleaned ?: 'Log file is empty',
                'live_source' => true
            ];
        } catch (Exception $e) {
            securityLog("Error reading log file $logFile: " . $e->getMessage(), 'ERROR');
            return ['content' => 'Error reading log file'];
        }
    }
    
    private function cleanLogFormatting($content) {
        if (empty($content)) return '';
        
        // Remove ANSI color codes (including escape sequences)
        $content = preg_replace('/\033\[[0-9;]*m/', '', $content);
        $content = preg_replace('/\x1b\[[0-9;]*m/', '', $content);
        $content = preg_replace('/\[32m|\[0m|\[31m|\[33m|\[35m|\[36m/', '', $content);
        
        // Remove IRC formatting codes
        $content = preg_replace('/[\x02\x1f\x0f\x16]|\x03(\d{1,2}(,\d{1,2})?)?/', '', $content);
        
        return $content;
    }
    
    public function createBackup() {
        $backupDir = '/home/cr0/cr0bot/backups';
        
        if (!is_dir($backupDir)) {
            mkdir($backupDir, 0750, true);
        }
        
        $timestamp = date('Y-m-d_H-i-s');
        $backupFile = "$backupDir/bot_backup_$timestamp.tar.gz";
        
        // Validate backup directory
        $realBackupDir = realpath($backupDir);
        if (strpos($realBackupDir, '/home/cr0/cr0bot') !== 0) {
            throw new Exception("Invalid backup directory");
        }
        
        // Create backup safely
        $command = sprintf(
            "cd /home/cr0/cr0bot && tar -czf %s *.db config/ plugins/ 2>/dev/null",
            escapeshellarg($backupFile)
        );
        
        // Execute with proc_open for better control
        $process = proc_open($command, [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
        
        if (is_resource($process)) {
            fclose($pipes[0]);
            fclose($pipes[1]); 
            fclose($pipes[2]);
            proc_close($process);
        }
        
        if (file_exists($backupFile)) {
            securityLog("Backup created: $backupFile");
            return [
                'success' => true, 
                'message' => 'Backup created successfully', 
                'file' => basename($backupFile)
            ];
        } else {
            throw new Exception('Backup creation failed');
        }
    }
}

// System Health Functions
class SystemHealth {
    public static function getSystemInfo() {
        $info = [];
        
        try {
            // Get load average safely
            if (file_exists('/proc/loadavg')) {
                $loadavg = file_get_contents('/proc/loadavg');
                $load = explode(' ', $loadavg);
                $info['load'] = [
                    '1min' => (float)$load[0],
                    '5min' => (float)$load[1], 
                    '15min' => (float)$load[2]
                ];
            }
            
            // Get memory info safely
            if (file_exists('/proc/meminfo')) {
                $meminfo = file_get_contents('/proc/meminfo');
                preg_match('/MemTotal:\s+(\d+)/', $meminfo, $total);
                preg_match('/MemFree:\s+(\d+)/', $meminfo, $free);
                preg_match('/MemAvailable:\s+(\d+)/', $meminfo, $available);
                
                if ($total && $free) {
                    $totalMB = round($total[1] / 1024);
                    $freeMB = round($free[1] / 1024);
                    $availableMB = isset($available[1]) ? round($available[1] / 1024) : $freeMB;
                    // Use available memory for more accurate usage calculation
                    // Available memory includes buffers/cache that can be freed
                    $actualUsedMB = $totalMB - $availableMB;
                    
                    $info['memory'] = [
                        'total' => $totalMB,
                        'used' => $actualUsedMB,
                        'free' => $freeMB,
                        'available' => $availableMB,
                        'usage_percent' => round(($actualUsedMB / $totalMB) * 100, 1)
                    ];
                }
            }
            
            // Get disk usage safely
            $diskTotal = disk_total_space('/');
            $diskFree = disk_free_space('/');
            
            if ($diskTotal && $diskFree) {
                $diskUsed = $diskTotal - $diskFree;
                $info['disk'] = [
                    'total' => round($diskTotal / 1024 / 1024 / 1024, 1),
                    'used' => round($diskUsed / 1024 / 1024 / 1024, 1), 
                    'free' => round($diskFree / 1024 / 1024 / 1024, 1),
                    'usage_percent' => round(($diskUsed / $diskTotal) * 100, 1)
                ];
            }
            
        } catch (Exception $e) {
            securityLog("Error getting system info: " . $e->getMessage(), 'ERROR');
        }
        
        return $info;
    }
}

?>