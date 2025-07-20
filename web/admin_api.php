<?php
session_start();

// Load environment variables from secure location
function loadEnvFile($path) {
    if (!file_exists($path)) {
        return false;
    }
    
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos($line, '=') !== false && !str_starts_with(trim($line), '#')) {
            list($key, $value) = explode('=', $line, 2);
            $_ENV[trim($key)] = trim($value);
        }
    }
    return true;
}

// Load environment variables from bot directory (secure location)
loadEnvFile('/home/cr0/cr0bot/.env');

// Check authentication
if (!isset($_SESSION['admin_authenticated']) || !$_SESSION['admin_authenticated']) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

header('Content-Type: application/json');

$action = $_GET['action'] ?? '';

try {
    switch ($action) {
        case 'bot_status':
            echo json_encode(getBotStatus());
            break;
            
        case 'breakout_stats':
            echo json_encode(getBreakoutStats());
            break;
            
        case 'get_high_scores':
            echo json_encode(getHighScores());
            break;
            
        case 'reset_scores':
            echo json_encode(resetAllScores());
            break;
            
        case 'delete_score':
            $input = json_decode(file_get_contents('php://input'), true);
            echo json_encode(deleteScore($input['id']));
            break;
            
        case 'ban_player':
            $input = json_decode(file_get_contents('php://input'), true);
            echo json_encode(banPlayer($input['player_name']));
            break;
            
        case 'start_bot':
            echo json_encode(startBot());
            break;
            
        case 'stop_bot':
            echo json_encode(stopBot());
            break;
            
        case 'restart_bot':
            echo json_encode(restartBot());
            break;
            
        case 'restart_rizon':
            echo json_encode(restartRizonBot());
            break;
            
        case 'restart_libera':
            echo json_encode(restartLiberaBot());
            break;
            
        case 'get_logs':
            $input = json_decode(file_get_contents('php://input'), true);
            echo json_encode(getLogs($input['type']));
            break;
            
        case 'get_rizon_logs':
            echo json_encode(getRizonLogs());
            break;
            
        case 'get_libera_logs':
            echo json_encode(getLiberaLogs());
            break;
            
        case 'get_bot_logs':
            $input = json_decode(file_get_contents('php://input'), true);
            echo json_encode(getBotLogs($input['network']));
            break;
            
        case 'sync_logs':
            echo json_encode(syncLogs());
            break;
            
        case 'backup_database':
            echo json_encode(backupDatabase());
            break;
            
        case 'cleanup_database':
            echo json_encode(cleanupDatabase());
            break;
            
        case 'get_user_stats':
            echo json_encode(getUserStats());
            break;
            
        case 'save_settings':
            $input = json_decode(file_get_contents('php://input'), true);
            echo json_encode(saveSettings($input));
            break;
            
        case 'reset_local_scores':
            echo json_encode(resetLocalScores());
            break;
            
        case 'check_reset_flag':
            echo json_encode(checkResetFlag());
            break;
            
        case 'system_health':
            echo json_encode(getSystemHealth());
            break;
            
        default:
            echo json_encode(['error' => 'Unknown action']);
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}

// Bot Status Functions
function getBotStatus() {
    $networks = ['rizon', 'libera'];
    $status = [];
    
    foreach ($networks as $network) {
        // Check if bot process is running by searching for the process
        $pid_file = "/tmp/{$network}_bot.pid";
        $running = false;
        $pid = null;
        
        // First try PID file method
        if (file_exists($pid_file)) {
            $pid = trim(file_get_contents($pid_file));
            if (is_numeric($pid) && posix_kill($pid, 0)) {
                $running = true;
            }
        }
        
        // If PID file method fails, search for running process
        if (!$running) {
            $process_search = shell_exec("ps aux | grep 'python.*bot_v2.py.*{$network}' | grep -v grep | head -1");
            if (!empty($process_search)) {
                $running = true;
                // Extract PID from ps output
                preg_match('/^\S+\s+(\d+)/', trim($process_search), $matches);
                if (isset($matches[1])) {
                    $pid = $matches[1];
                }
            }
        }
        
        // Check for screen session as backup
        if (!$running) {
            $screen_check = shell_exec("screen -list | grep '{$network}-bot'");
            $running = !empty(trim($screen_check));
        }
        
        $status[$network] = [
            'online' => $running,
            'pid' => $pid,
            'uptime' => ($running && $pid) ? getProcessUptime($pid) : null,
            'method' => $running ? (file_exists($pid_file) ? 'pidfile' : 'process_search') : 'offline'
        ];
    }
    
    return [
        'online' => array_reduce($status, function($carry, $item) {
            return $carry || $item['online'];
        }, false),
        'networks' => $status
    ];
}

function getProcessUptime($pid) {
    if (!$pid) return null;
    
    $stat_file = "/proc/$pid/stat";
    if (!file_exists($stat_file)) return null;
    
    $stat = file_get_contents($stat_file);
    $stat_parts = explode(' ', $stat);
    
    // starttime is the 22nd field (index 21)
    $starttime = intval($stat_parts[21]);
    $clock_ticks = intval(trim(shell_exec('getconf CLK_TCK')));
    $boot_time = intval(trim(shell_exec("awk '/btime/ {print $2}' /proc/stat")));
    
    $process_start = $boot_time + ($starttime / $clock_ticks);
    $uptime_seconds = time() - $process_start;
    
    return formatUptime($uptime_seconds);
}

function formatUptime($seconds) {
    $days = floor($seconds / 86400);
    $hours = floor(($seconds % 86400) / 3600);
    $minutes = floor(($seconds % 3600) / 60);
    
    if ($days > 0) {
        return "{$days}d {$hours}h {$minutes}m";
    } elseif ($hours > 0) {
        return "{$hours}h {$minutes}m";
    } else {
        return "{$minutes}m";
    }
}

// Breakout Game Functions
function getBreakoutStats() {
    try {
        $pdo = new PDO("sqlite:/tmp/breakout_scores.db");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->query("SELECT COUNT(*) as total_scores, MAX(score) as top_score, COUNT(DISTINCT player_name) as unique_players FROM breakout_scores");
        $stats = $stmt->fetch(PDO::FETCH_ASSOC);
        
        $stmt = $pdo->query("SELECT COUNT(*) as today_games FROM breakout_scores WHERE DATE(date_played) = DATE('now')");
        $today = $stmt->fetch(PDO::FETCH_ASSOC);
        
        return array_merge($stats, $today);
    } catch (PDOException $e) {
        return ['error' => 'Database connection failed'];
    }
}

function getHighScores() {
    try {
        $pdo = new PDO("sqlite:/tmp/breakout_scores.db");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->query("SELECT * FROM breakout_scores ORDER BY score DESC LIMIT 50");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        return [];
    }
}

function resetAllScores() {
    try {
        $pdo = new PDO("sqlite:/tmp/breakout_scores.db");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->prepare("DELETE FROM breakout_scores");
        $stmt->execute();
        
        return ['success' => true, 'message' => 'All scores have been reset'];
    } catch (PDOException $e) {
        return ['error' => 'Failed to reset scores: ' . $e->getMessage()];
    }
}

function deleteScore($scoreId) {
    try {
        if (!$scoreId) {
            return ['error' => 'No score ID provided'];
        }
        
        $pdo = new PDO("sqlite:/tmp/breakout_scores.db");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // First check if the score exists
        $checkStmt = $pdo->prepare("SELECT player_name FROM breakout_scores WHERE id = ?");
        $checkStmt->execute([$scoreId]);
        $existingScore = $checkStmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$existingScore) {
            return ['error' => "Score with ID $scoreId not found"];
        }
        
        // Delete the score
        $stmt = $pdo->prepare("DELETE FROM breakout_scores WHERE id = ?");
        $stmt->execute([$scoreId]);
        
        $deletedRows = $stmt->rowCount();
        
        if ($deletedRows > 0) {
            return ['success' => true, 'message' => "Score for '{$existingScore['player_name']}' deleted successfully"];
        } else {
            return ['error' => 'No score was deleted'];
        }
    } catch (PDOException $e) {
        return ['error' => 'Failed to delete score: ' . $e->getMessage()];
    }
}

function banPlayer($playerName) {
    // Add to banned players list (you might want to store this in database)
    $banned_file = '/tmp/banned_players.txt';
    $banned_players = file_exists($banned_file) ? file($banned_file, FILE_IGNORE_NEW_LINES) : [];
    
    if (!in_array($playerName, $banned_players)) {
        $banned_players[] = $playerName;
        file_put_contents($banned_file, implode("\n", $banned_players));
        
        // Also remove their scores
        try {
            $pdo = new PDO("sqlite:/tmp/breakout_scores.db");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $stmt = $pdo->prepare("DELETE FROM breakout_scores WHERE player_name = ?");
            $stmt->execute([$playerName]);
        } catch (PDOException $e) {
            // Log error but don't fail the ban
        }
        
        return ['success' => true, 'message' => "Player $playerName has been banned"];
    } else {
        return ['error' => 'Player is already banned'];
    }
}

// Bot Control Functions
function startBot() {
    $networks = ['rizon', 'libera'];
    $results = [];
    
    foreach ($networks as $network) {
        $bot_path = "/home/cr0/cr0bot";
        $pid_file = "/tmp/{$network}_bot.pid";
        
        // Check if already running
        if (file_exists($pid_file)) {
            $pid = trim(file_get_contents($pid_file));
            if (is_numeric($pid) && posix_kill($pid, 0)) {
                $results[$network] = "Already running (PID: $pid)";
                continue;
            }
        }
        
        // Start the bot with virtual environment
        $cmd = "cd $bot_path && source /home/cr0/venv/bin/activate && nohup python bot_v2.py $network > /tmp/{$network}_bot.log 2>&1 & echo $! > $pid_file";
        $output = shell_exec("bash -c '$cmd'");
        
        $results[$network] = "Started successfully";
    }
    
    return ['success' => true, 'message' => 'Bot start commands executed', 'details' => $results];
}

function stopBot() {
    $networks = ['rizon', 'libera'];
    $results = [];
    
    foreach ($networks as $network) {
        $pid_file = "/tmp/{$network}_bot.pid";
        
        if (file_exists($pid_file)) {
            $pid = trim(file_get_contents($pid_file));
            if (is_numeric($pid) && posix_kill($pid, 15)) { // SIGTERM
                sleep(2);
                if (posix_kill($pid, 0)) {
                    posix_kill($pid, 9); // SIGKILL if still running
                }
                unlink($pid_file);
                $results[$network] = "Stopped successfully";
            } else {
                $results[$network] = "Process not found";
                if (file_exists($pid_file)) unlink($pid_file);
            }
        } else {
            $results[$network] = "Not running";
        }
    }
    
    return ['success' => true, 'message' => 'Bot stop commands executed', 'details' => $results];
}

function restartBot() {
    $stop_result = stopBot();
    sleep(2);
    $start_result = startBot();
    
    return [
        'success' => true, 
        'message' => 'Bot restart completed',
        'stop_details' => $stop_result['details'],
        'start_details' => $start_result['details']
    ];
}

// Log Functions
function getLogs($type) {
    $log_files = [
        'bot' => '/tmp/rizon_bot.log',
        'error' => '/var/log/nginx/error.log',
        'access' => '/var/log/nginx/access.log'
    ];
    
    $log_file = $log_files[$type] ?? null;
    
    if (!$log_file || !file_exists($log_file)) {
        return ['content' => "Log file not found: $log_file"];
    }
    
    // Get last 100 lines
    $content = shell_exec("tail -100 " . escapeshellarg($log_file));
    
    return ['content' => $content ?: 'Log file is empty'];
}

// Database Functions
function backupDatabase() {
    $backup_dir = '/tmp/backups';
    if (!is_dir($backup_dir)) {
        mkdir($backup_dir, 0755, true);
    }
    
    $timestamp = date('Y-m-d_H-i-s');
    $backup_file = "$backup_dir/bot_backup_$timestamp.tar.gz";
    
    // Backup both network databases and configs
    $cmd = "cd /home/cr0/cr0bot && tar -czf $backup_file *.db config/ plugins/ 2>/dev/null";
    $result = shell_exec($cmd);
    
    if (file_exists($backup_file)) {
        return ['success' => true, 'message' => 'Backup created successfully', 'file' => $backup_file];
    } else {
        return ['error' => 'Backup failed'];
    }
}

function cleanupDatabase() {
    $results = [];
    
    // Clean up old reminders (30+ days)
    try {
        $networks = ['rizon', 'libera'];
        foreach ($networks as $network) {
            $db_file = "/var/www/html/data/{$network}_bot.db";
            if (file_exists($db_file)) {
                $pdo = new PDO("sqlite:$db_file");
                $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                
                $stmt = $pdo->prepare("DELETE FROM reminders WHERE completed = 1 AND created_time < datetime('now', '-30 days')");
                $stmt->execute();
                $deleted = $stmt->rowCount();
                
                $results[$network] = "Cleaned $deleted old reminders";
            }
        }
        
        // Clean up old breakout scores (keep top 1000)
        $pdo = new PDO("sqlite:/tmp/breakout_scores.db");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->prepare("DELETE FROM breakout_scores WHERE id NOT IN (SELECT id FROM breakout_scores ORDER BY score DESC LIMIT 1000)");
        $stmt->execute();
        $deleted = $stmt->rowCount();
        
        $results['breakout'] = "Cleaned $deleted old scores";
        
        return ['success' => true, 'message' => 'Database cleanup completed', 'details' => $results];
        
    } catch (PDOException $e) {
        return ['error' => 'Cleanup failed: ' . $e->getMessage()];
    }
}

function getUserStats() {
    try {
        $networks = ['rizon', 'libera'];
        $stats = [];
        
        foreach ($networks as $network) {
            $db_file = "/var/www/html/data/{$network}_bot.db";
            if (file_exists($db_file)) {
                $pdo = new PDO("sqlite:$db_file");
                $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                
                // Get command usage stats
                $stmt = $pdo->query("SELECT COUNT(DISTINCT user) as unique_users, COUNT(*) as total_commands FROM command_usage WHERE timestamp >= datetime('now', '-7 days')");
                $week_stats = $stmt->fetch(PDO::FETCH_ASSOC);
                
                // Get most active users
                $stmt = $pdo->query("SELECT user, COUNT(*) as command_count FROM command_usage WHERE timestamp >= datetime('now', '-7 days') GROUP BY user ORDER BY command_count DESC LIMIT 5");
                $top_users = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                $stats[$network] = [
                    'week_stats' => $week_stats,
                    'top_users' => $top_users
                ];
            }
        }
        
        return $stats;
    } catch (PDOException $e) {
        return ['error' => 'Failed to get user stats: ' . $e->getMessage()];
    }
}

function saveSettings($settings) {
    // Save settings to configuration file
    $config_file = '/home/cr0/cr0bot/admin_settings.json';
    
    try {
        $current_settings = [];
        if (file_exists($config_file)) {
            $current_settings = json_decode(file_get_contents($config_file), true) ?: [];
        }
        
        $updated_settings = array_merge($current_settings, $settings);
        file_put_contents($config_file, json_encode($updated_settings, JSON_PRETTY_PRINT));
        
        return ['success' => true, 'message' => 'Settings saved successfully'];
    } catch (Exception $e) {
        return ['error' => 'Failed to save settings: ' . $e->getMessage()];
    }
}

function resetLocalScores() {
    // Create a flag file that the main website can check to reset localStorage
    $flag_file = '/tmp/reset_local_scores.flag';
    
    try {
        file_put_contents($flag_file, time());
        return ['success' => true, 'message' => 'LocalStorage reset flag created. Users will see reset scores on next visit.'];
    } catch (Exception $e) {
        return ['error' => 'Failed to create reset flag: ' . $e->getMessage()];
    }
}

function checkResetFlag() {
    $flag_file = '/tmp/reset_local_scores.flag';
    
    if (file_exists($flag_file)) {
        // Check if flag is recent (within last 24 hours)
        $flag_time = intval(file_get_contents($flag_file));
        if (time() - $flag_time < 86400) {
            return ['should_reset' => true];
        } else {
            // Remove old flag
            unlink($flag_file);
        }
    }
    
    return ['should_reset' => false];
}

// Individual Bot Restart Functions
function restartRizonBot() {
    $bot_path = "/home/cr0/cr0bot";
    $script_path = "$bot_path/restart_rizon.sh";
    
    if (!file_exists($script_path)) {
        return ['error' => 'Rizon restart script not found'];
    }
    
    // Execute the restart script
    $cmd = "cd $bot_path && bash restart_rizon.sh 2>&1";
    $output = shell_exec($cmd);
    
    return [
        'success' => true, 
        'message' => 'Rizon bot restart initiated',
        'output' => $output ?: 'Script executed successfully'
    ];
}

function restartLiberaBot() {
    $bot_path = "/home/cr0/cr0bot";
    $script_path = "$bot_path/restart_libera.sh";
    
    if (!file_exists($script_path)) {
        return ['error' => 'Libera restart script not found'];
    }
    
    // Execute the restart script
    $cmd = "cd $bot_path && bash restart_libera.sh 2>&1";
    $output = shell_exec($cmd);
    
    return [
        'success' => true, 
        'message' => 'Libera bot restart initiated',
        'output' => $output ?: 'Script executed successfully'
    ];
}

// Function to clean console formatting codes from log output
function cleanLogFormatting($content) {
    // Remove ANSI color codes like [32m, [0m etc.
    $content = preg_replace('/\[[\d;]*m/', '', $content);
    
    // Remove any remaining control characters except newlines and tabs
    $content = preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', '', $content);
    
    return $content;
}

// Network-specific log functions
function getRizonLogs() {
    $log_file = '/var/www/html/data/logs/rizon_bot.log';
    
    if (!file_exists($log_file)) {
        return ['content' => 'Rizon bot log file not found'];
    }
    
    // Get last 100 lines and clean formatting
    $content = shell_exec("tail -100 " . escapeshellarg($log_file));
    $cleaned_content = cleanLogFormatting($content);
    
    return ['content' => $cleaned_content ?: 'Rizon bot log is empty'];
}

function getLiberaLogs() {
    $log_file = '/var/www/html/data/logs/libera_bot.log';
    
    if (!file_exists($log_file)) {
        return ['content' => 'Libera bot log file not found'];
    }
    
    // Get last 100 lines and clean formatting
    $content = shell_exec("tail -100 " . escapeshellarg($log_file));
    $cleaned_content = cleanLogFormatting($content);
    
    return ['content' => $cleaned_content ?: 'Libera bot log is empty'];
}

function getBotLogs($network) {
    $valid_networks = ['rizon', 'libera'];
    
    if (!in_array($network, $valid_networks)) {
        return ['error' => 'Invalid network specified'];
    }
    
    $log_files = [
        'rizon' => [
            'main' => '/var/www/html/data/logs/rizon_bot.log',
            'errors' => '/var/www/html/data/logs/rizon_errors.log',
            'startup' => '/var/www/html/data/logs/rizon_startup.log'
        ],
        'libera' => [
            'main' => '/var/www/html/data/logs/libera_bot.log', 
            'errors' => '/var/www/html/data/logs/libera_errors.log',
            'startup' => '/var/www/html/data/logs/libera_startup.log'
        ]
    ];
    
    $logs = [];
    
    foreach ($log_files[$network] as $type => $log_file) {
        if (file_exists($log_file)) {
            // Get last 50 lines for each log type
            $content = shell_exec("tail -50 " . escapeshellarg($log_file));
            $logs[$type] = $content ?: 'Log file is empty';
        } else {
            $logs[$type] = 'Log file not found';
        }
    }
    
    return [
        'network' => $network,
        'logs' => $logs,
        'timestamp' => date('Y-m-d H:i:s')
    ];
}

function syncLogs() {
    $script_path = '/var/www/html/scripts/sync_logs.sh';
    
    if (!file_exists($script_path)) {
        return ['error' => 'Log sync script not found'];
    }
    
    // Execute the sync script without sudo
    $output = shell_exec("bash $script_path 2>&1");
    
    if ($output === null) {
        return ['error' => 'Failed to execute sync script'];
    }
    
    return [
        'success' => true,
        'message' => 'Logs synchronized successfully',
        'output' => trim($output)
    ];
}

// System Health Functions
function getSystemHealth() {
    // Function to check if a process is running
    function isProcessRunning($processName) {
        $output = shell_exec("pgrep -f '$processName'");
        return !empty(trim($output));
    }

    // Function to get system load
    function getSystemLoad() {
        $load = sys_getloadavg();
        return $load ? round($load[0], 2) : 0;
    }

    // Function to get memory usage
    function getMemoryUsage() {
        $meminfo = file_get_contents('/proc/meminfo');
        preg_match('/MemTotal:\s+(\d+)/', $meminfo, $total);
        preg_match('/MemAvailable:\s+(\d+)/', $meminfo, $available);
        
        if ($total && $available) {
            $totalMem = $total[1];
            $availableMem = $available[1];
            $usedMem = $totalMem - $availableMem;
            return round(($usedMem / $totalMem) * 100, 1);
        }
        return 0;
    }

    // Function to get disk usage
    function getDiskUsage($path = '/') {
        $total = disk_total_space($path);
        $free = disk_free_space($path);
        if ($total && $free) {
            $used = $total - $free;
            return round(($used / $total) * 100, 1);
        }
        return 0;
    }

    // Function to check database connectivity
    function checkDatabaseHealth() {
        $rizonDb = '/home/cr0/cr0bot/rizon_bot.db';
        $liberaDb = '/home/cr0/cr0bot/libera_bot.db';
        
        $rizonHealth = file_exists($rizonDb) && is_readable($rizonDb);
        $liberaHealth = file_exists($liberaDb) && is_readable($liberaDb);
        
        return [
            'rizon' => $rizonHealth,
            'libera' => $liberaHealth,
            'overall' => $rizonHealth && $liberaHealth
        ];
    }

    // Function to check bot response times
    function checkBotResponseTime() {
        $rizonLog = '/home/cr0/cr0bot/logs/rizon_bot.log';
        $liberaLog = '/home/cr0/cr0bot/logs/libera_bot.log';
        
        $rizonActive = false;
        $liberaActive = false;
        
        // Check if logs have been updated recently (within 5 minutes)
        if (file_exists($rizonLog)) {
            $rizonActive = (time() - filemtime($rizonLog)) < 300;
        }
        
        if (file_exists($liberaLog)) {
            $liberaActive = (time() - filemtime($liberaLog)) < 300;
        }
        
        return [
            'rizon' => $rizonActive,
            'libera' => $liberaActive
        ];
    }

    // Function to calculate overall health score
    function calculateHealthScore($metrics) {
        $score = 0;
        $maxScore = 100;
        
        // Bot processes (30 points)
        if ($metrics['bots']['rizon']) $score += 15;
        if ($metrics['bots']['libera']) $score += 15;
        
        // Database health (20 points)
        if ($metrics['database']['overall']) $score += 20;
        
        // System resources (30 points)
        $memScore = max(0, 15 - ($metrics['memory'] / 100 * 15)); // Lose points as memory increases
        $diskScore = max(0, 15 - ($metrics['disk'] / 100 * 15)); // Lose points as disk increases
        $score += $memScore + $diskScore;
        
        // System load (10 points)
        $loadScore = max(0, 10 - ($metrics['load'] * 2)); // Lose points as load increases
        $score += $loadScore;
        
        // Bot activity (10 points)
        if ($metrics['bot_activity']['rizon']) $score += 5;
        if ($metrics['bot_activity']['libera']) $score += 5;
        
        return min(100, max(0, round($score)));
    }

    try {
        // Gather all metrics
        $metrics = [
            'bots' => [
                'rizon' => isProcessRunning('python.*bot_v2.py.*rizon'),
                'libera' => isProcessRunning('python.*bot_v2.py.*libera')
            ],
            'database' => checkDatabaseHealth(),
            'memory' => getMemoryUsage(),
            'disk' => getDiskUsage(),
            'load' => getSystemLoad(),
            'bot_activity' => checkBotResponseTime(),
            'timestamp' => date('Y-m-d H:i:s')
        ];
        
        // Calculate overall health score
        $healthScore = calculateHealthScore($metrics);
        
        // Determine status levels
        if ($healthScore >= 90) {
            $status = 'excellent';
            $color = '#00ff00';
            $icon = '🟢';
        } elseif ($healthScore >= 75) {
            $status = 'good';
            $color = '#90EE90';
            $icon = '🟡';
        } elseif ($healthScore >= 50) {
            $status = 'warning';
            $color = '#FFA500';
            $icon = '🟠';
        } else {
            $status = 'critical';
            $color = '#ff0000';
            $icon = '🔴';
        }
        
        return [
            'success' => true,
            'health_score' => $healthScore,
            'status' => $status,
            'status_color' => $color,
            'status_icon' => $icon,
            'metrics' => $metrics,
            'components' => [
                'rizon_bot' => $metrics['bots']['rizon'] ? 'Online' : 'Offline',
                'libera_bot' => $metrics['bots']['libera'] ? 'Online' : 'Offline',
                'database' => $metrics['database']['overall'] ? 'Healthy' : 'Issues Detected',
                'system_load' => $metrics['load'] < 2.0 ? 'Normal' : 'High',
                'memory_usage' => $metrics['memory'] < 80 ? 'Normal' : 'High',
                'disk_usage' => $metrics['disk'] < 90 ? 'Normal' : 'High'
            ]
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'error' => 'Failed to retrieve system health: ' . $e->getMessage(),
            'health_score' => 0,
            'status' => 'critical'
        ];
    }
}
?>