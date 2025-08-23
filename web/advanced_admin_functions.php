<?php
/**
 * Advanced Admin Functions
 * All the backend functions for the comprehensive admin panel
 */

require_once 'admin_inject.php';
require_once 'config_paths.php';

class AdvancedAdmin {
    
    /**
     * Map internal command names to user-friendly display names
     * Takes network into account for proper prefix (! for Rizon, ~ for Libera)
     */
    private static function mapCommandName($internalName, $network = 'rizon') {
        // Determine prefix based on network
        $prefix = ($network === 'libera') ? '~' : '!';
        
        $commandMap = [
            // AI commands (from ai_commands.py)
            'ai_chat_gemini_with_context' => $prefix.'speak',
            'speak_command' => $prefix.'speak',
            'speakclear_command' => $prefix.'speakclear',
            
            // API commands (from api_commands.py)
            'weather_command' => $prefix.'weather',
            'hats_command' => $prefix.'hats',
            'iss_command' => $prefix.'iss',
            'dog_command' => $prefix.'dog',
            'cat_command' => $prefix.'cat',
            'fox_command' => $prefix.'fox',
            'duck_command' => $prefix.'duck',
            'bankhol_command' => $prefix.'bankhol',
            'moon_command' => $prefix.'moon',
            'get_moon_emoji' => $prefix.'moon',
            'sun_command' => $prefix.'sun',
            'gdq_command' => $prefix.'gdq',
            
            // Basic commands (from basic_commands.py)
            'piss_command' => $prefix.'piss',
            'piss' => $prefix.'piss',
            'bots_command' => $prefix.'.bots',
            'time_command' => $prefix.'time',
            'check_time' => $prefix.'time',
            'date_command' => $prefix.'date',
            'random_command' => $prefix.'random',
            'random_choice' => $prefix.'random',
            'lenny_command' => $prefix.'lenny',
            'calc_command' => $prefix.'calc',
            'help_command' => $prefix.'help',
            'show_help' => $prefix.'help',
            'stats_command' => $prefix.'stats',
            'get_stats' => $prefix.'stats',
            
            // Game commands (from game_commands.py)
            'roll7_command' => $prefix.'roll7',
            'roll_dice2' => $prefix.'dice',
            'bet7_command' => $prefix.'bet7',
            'bet7_top' => $prefix.'bet7.top',
            'topscores_command' => $prefix.'topscores',
            'bet7_owned' => $prefix.'bet7.owned',
            'scramble_command' => $prefix.'scramble',
            'scramble_start' => $prefix.'scramble',
            'jumble' => $prefix.'scramble',
            'scramble_end' => $prefix.'scramble.end',
            'scramble_top' => $prefix.'scramble.top',
            'scramble_leaderboard' => $prefix.'scramble.top',
            'scramble_stats' => $prefix.'scramble.stats',
            'chk_command' => $prefix.'chk',
            'rds_command' => $prefix.'rds',
            
            // Memo commands (from memo_commands.py)
            'memo_command' => $prefix.'memo',
            'checkmemos_command' => $prefix.'checkmemos',
            
            // PyBorg commands (from pigs_commands.py)
            'pigs_command' => $prefix.'pigs',
            'bank_command' => $prefix.'bank',
            'bank_pigs_command' => $prefix.'bank',
            'pigsquit_command' => $prefix.'pigsquit',
            'pigshelp_command' => $prefix.'pigshelp',
            'pigstats_command' => $prefix.'pigstats',
            
            // Reminder commands (from reminder_commands.py)
            'remind_command' => $prefix.'remind',
            'set_reminder' => $prefix.'remind',
            'reminders_command' => $prefix.'reminders',
            'list_reminders' => $prefix.'reminders',
            'cancelreminder_command' => $prefix.'cancelreminder',
            'cancel_reminder' => $prefix.'cancelreminder',
            
            // Server commands (from server_commands.py)
            'lastdeath_command' => $prefix.'lastdeath',
            'players_command' => $prefix.'players',
            
            // Temperature commands (from temperature.py)
            'temp_command' => $prefix.'temp',
            'temp' => $prefix.'temp',
            'temp2_command' => $prefix.'temp2',
            
            // UNO commands (from uno_commands.py)
            'uno_command' => $prefix.'uno',
            'start_uno_game' => $prefix.'uno',
            'join_command' => $prefix.'join',
            'join_uno_game' => $prefix.'join',
            'start_command' => $prefix.'start',
            'start_uno_round_manual' => $prefix.'start',
            'play_command' => $prefix.'play',
            'play_uno_card' => $prefix.'play',
            'draw_command' => $prefix.'draw',
            'draw_uno_card' => $prefix.'draw',
            'pass_command' => $prefix.'pass',
            'pass_uno_turn' => $prefix.'pass',
            'cards_command' => $prefix.'cards',
            'show_uno_cards' => $prefix.'cards',
            'status_command' => $prefix.'status',
            'show_uno_status' => $prefix.'status',
            'quit_command' => $prefix.'quit',
            'quit_uno_game' => $prefix.'quit',
            'unohelp_command' => $prefix.'unohelp',
            'show_uno_help' => $prefix.'unohelp',
            'unoleaderboard_command' => $prefix.'unoleaderboard',
            'show_uno_leaderboard' => $prefix.'unoleaderboard',
            
            // Admin commands
            'reload_plugins' => $prefix.'reload',
            'restart_bot' => $prefix.'restart'
        ];
        
        return $commandMap[$internalName] ?? $internalName;
    }
    
    /**
     * Get real-time bot statistics and activity
     */
    public static function getBotStatistics() {
        $stats = [
            'rizon' => ['status' => 'Unknown', 'pid' => 'unknown', 'uptime' => 0, 'commands_today' => 0, 'users_active' => 0],
            'libera' => ['status' => 'Unknown', 'pid' => 'unknown', 'uptime' => 0, 'commands_today' => 0, 'users_active' => 0]
        ];
        
        try {
            // Get bot processes using the same corrected logic as the API (avoid including API endpoint)
            foreach (['rizon', 'libera'] as $network) {
                // Use ps with proper filtering to exclude SCREEN sessions
                $cmd = "ps aux | grep 'python.*bot_v2.py $network' | grep -v grep | grep -v SCREEN | awk '{print $2}' | head -1";
                $pid = trim(shell_exec($cmd));
                
                if (!empty($pid) && is_numeric($pid)) {
                    // Get process start time
                    $start_time_cmd = "ps -o lstart= -p $pid 2>/dev/null | head -1";
                    $start_time_str = trim(shell_exec($start_time_cmd));
                    
                    if (!empty($start_time_str)) {
                        $start_timestamp = strtotime($start_time_str);
                        if ($start_timestamp !== false) {
                            $uptime = time() - $start_timestamp;
                            $stats[$network]['status'] = 'Online';
                            $stats[$network]['pid'] = (int)$pid;
                            $stats[$network]['uptime'] = max(0, $uptime); // Ensure positive
                        }
                    }
                }
            }
            
            // Get bot uptime from logs
            foreach (['rizon', 'libera'] as $network) {
                $log_file = "/data/cr0_system/logs/irc_networks/$network/{$network}_bot.log";
                if (file_exists($log_file)) {
                    $log_lines = array_slice(file($log_file), -100);
                    foreach (array_reverse($log_lines) as $line) {
                        if (strpos($line, 'Connected to') !== false) {
                            preg_match('/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/', $line, $matches);
                            if ($matches) {
                                $connect_time = strtotime($matches[1]);
                                $stats[$network]['uptime'] = time() - $connect_time;
                                break;
                            }
                        }
                    }
                }
                
                // Get command count from database
                $db_path = "/data/cr0_system/databases/{$network}_bot.db";
                if (file_exists($db_path)) {
                    $pdo = new PDO("sqlite:$db_path");
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM command_usage WHERE DATE(timestamp) = DATE('now')");
                    $stmt->execute();
                    $stats[$network]['commands_today'] = $stmt->fetchColumn();
                    
                    $stmt = $pdo->prepare("SELECT COUNT(DISTINCT user) FROM command_usage WHERE timestamp > datetime('now', '-1 hour')");
                    $stmt->execute();
                    $stats[$network]['users_active'] = $stmt->fetchColumn();
                }
            }
        } catch (Exception $e) {
            error_log("Error getting bot statistics: " . $e->getMessage());
        }
        
        return $stats;
    }
    
    /**
     * Get recent command activity
     */
    public static function getRecentCommands($limit = 50) {
        $commands = [];
        
        try {
            foreach (['rizon', 'libera'] as $network) {
                $db_path = "/data/cr0_system/databases/{$network}_bot.db";
                if (file_exists($db_path)) {
                    $pdo = new PDO("sqlite:$db_path");
                    $stmt = $pdo->prepare("
                        SELECT command, user as username, channel, timestamp, execution_time_ms, :network as network
                        FROM command_usage 
                        ORDER BY timestamp DESC 
                        LIMIT :limit
                    ");
                    $stmt->execute(['network' => $network, 'limit' => intval($limit / 2)]);
                    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    
                    // Map command names to user-friendly display names
                    foreach ($results as &$result) {
                        $result['display_command'] = self::mapCommandName($result['command'], $network);
                    }
                    
                    $commands = array_merge($commands, $results);
                }
            }
        } catch (Exception $e) {
            error_log("Error getting recent commands: " . $e->getMessage());
        }
        
        // Sort by timestamp
        usort($commands, function($a, $b) {
            return strtotime($b['timestamp']) - strtotime($a['timestamp']);
        });
        
        return array_slice($commands, 0, $limit);
    }
    
    /**
     * Get game statistics and active games
     */
    public static function getGameStatistics() {
        $game_stats = [
            'active_games' => 0,
            'total_players' => 0,
            'games_today' => 0,
            'popular_games' => []
        ];
        
        try {
            foreach (['rizon', 'libera'] as $network) {
                $db_path = "/data/cr0_system/databases/{$network}_bot.db";
                if (file_exists($db_path)) {
                    $pdo = new PDO("sqlite:$db_path");
                    
                    // Check for active games from game_sessions table (games without session_end are active)
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM game_sessions WHERE session_end IS NULL");
                    $stmt->execute();
                    $game_stats['active_games'] += $stmt->fetchColumn() ?: 0;
                    
                    // Count today's games from user_scores
                    $stmt = $pdo->prepare("SELECT COUNT(*) FROM user_scores WHERE DATE(last_played) = DATE('now')");
                    $stmt->execute();
                    $game_stats['games_today'] += $stmt->fetchColumn() ?: 0;
                    
                    // Get popular games by type
                    $stmt = $pdo->prepare("
                        SELECT game_type, SUM(games_played) as plays 
                        FROM user_scores 
                        WHERE last_played > datetime('now', '-7 days')
                        GROUP BY game_type 
                        ORDER BY plays DESC 
                        LIMIT 5
                    ");
                    $stmt->execute();
                    $popular = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    foreach ($popular as $game) {
                        if (!isset($game_stats['popular_games'][$game['game_type']])) {
                            $game_stats['popular_games'][$game['game_type']] = 0;
                        }
                        $game_stats['popular_games'][$game['game_type']] += $game['plays'];
                    }
                }
            }
        } catch (Exception $e) {
            error_log("Error getting game statistics: " . $e->getMessage());
        }
        
        return $game_stats;
    }
    
    /**
     * Get user analytics
     */
    public static function getUserAnalytics() {
        $analytics = [
            'total_users' => 0,
            'active_today' => 0,
            'new_this_week' => 0,
            'top_users' => []
        ];
        
        try {
            // Get web users
            $users_db = "/data/cr0_system/databases/users.db";
            if (file_exists($users_db)) {
                $pdo = new PDO("sqlite:$users_db");
                
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE is_active = 1");
                $stmt->execute();
                $analytics['total_users'] = $stmt->fetchColumn();
                
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE DATE(created_at) > DATE('now', '-7 days')");
                $stmt->execute();
                $analytics['new_this_week'] = $stmt->fetchColumn();
            }
            
            // Get IRC activity
            foreach (['rizon', 'libera'] as $network) {
                $db_path = "/data/cr0_system/databases/{$network}_bot.db";
                if (file_exists($db_path)) {
                    $pdo = new PDO("sqlite:$db_path");
                    
                    $stmt = $pdo->prepare("SELECT COUNT(DISTINCT user) FROM command_usage WHERE DATE(timestamp) = DATE('now')");
                    $stmt->execute();
                    $analytics['active_today'] += $stmt->fetchColumn();
                    
                    $stmt = $pdo->prepare("
                        SELECT user as username, COUNT(*) as command_count 
                        FROM command_usage 
                        WHERE timestamp > datetime('now', '-7 days')
                        GROUP BY user 
                        ORDER BY command_count DESC 
                        LIMIT 10
                    ");
                    $stmt->execute();
                    $top_users = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    foreach ($top_users as $user) {
                        $key = $user['username'];
                        if (!isset($analytics['top_users'][$key])) {
                            $analytics['top_users'][$key] = 0;
                        }
                        $analytics['top_users'][$key] += $user['command_count'];
                    }
                }
            }
            
            // Sort top users
            arsort($analytics['top_users']);
            $analytics['top_users'] = array_slice($analytics['top_users'], 0, 10, true);
            
        } catch (Exception $e) {
            error_log("Error getting user analytics: " . $e->getMessage());
        }
        
        return $analytics;
    }
    
    /**
     * Get security events and alerts
     */
    public static function getSecurityEvents($limit = 20) {
        $events = [];
        
        try {
            $security_log = '/tmp/admin_security.log';
            if (file_exists($security_log)) {
                $log_lines = array_slice(file($security_log), -$limit);
                foreach (array_reverse($log_lines) as $line) {
                    $event = json_decode(trim($line), true);
                    if ($event) {
                        $events[] = $event;
                    }
                }
            }
        } catch (Exception $e) {
            error_log("Error getting security events: " . $e->getMessage());
        }
        
        return $events;
    }
    
    /**
     * Get database health information
     */
    public static function getDatabaseHealth() {
        $health = [
            'databases' => [],
            'total_size' => 0,
            'total_tables' => 0
        ];
        
        try {
            $db_files = [
                'users' => '/data/cr0_system/databases/users.db',
                'rizon_bot' => '/data/cr0_system/databases/rizon_bot.db',
                'libera_bot' => '/data/cr0_system/databases/libera_bot.db'
            ];
            
            foreach ($db_files as $name => $path) {
                if (file_exists($path)) {
                    $size = filesize($path);
                    $health['total_size'] += $size;
                    
                    $pdo = new PDO("sqlite:$path");
                    $stmt = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'");
                    $tables = $stmt->fetchAll(PDO::FETCH_COLUMN);
                    $table_count = count($tables);
                    $health['total_tables'] += $table_count;
                    
                    $health['databases'][$name] = [
                        'size' => $size,
                        'size_mb' => round($size / 1024 / 1024, 2),
                        'tables' => $table_count,
                        'last_modified' => date('Y-m-d H:i:s', filemtime($path))
                    ];
                }
            }
        } catch (Exception $e) {
            error_log("Error getting database health: " . $e->getMessage());
        }
        
        return $health;
    }
    
    /**
     * Execute bot management commands using ConfigPaths
     */
    public static function manageBots($action, $network = 'all') {
        $result = ['success' => false, 'message' => '', 'output' => ''];
        
        try {
            $script_path = null;
            
            // Use wrapper scripts in web directory (www-data has sudo permissions for these)
            switch ($action) {
                case 'restart_rizon':
                    $script_path = '/var/www/html/restart_rizon_web.sh';
                    break;
                case 'restart_libera':
                    $script_path = '/var/www/html/restart_libera_web.sh';
                    break;
                case 'restart_all':
                    $script_path = '/var/www/html/restart_all_bots_web.sh';
                    break;
                case 'stop_all':
                    $script_path = '/var/www/html/stop_all_bots_web.sh';
                    break;
                case 'status':
                    // Get bot status using direct process detection (avoid including API endpoint)
                    $status = ['networks' => []];
                    
                    foreach (['rizon', 'libera'] as $network) {
                        // Use ps with proper filtering to exclude SCREEN sessions
                        $cmd = "ps aux | grep 'python.*bot_v2.py $network' | grep -v grep | grep -v SCREEN | awk '{print $2}' | head -1";
                        $pid = trim(shell_exec($cmd));
                        
                        if (!empty($pid) && is_numeric($pid)) {
                            // Get process start time
                            $start_time = trim(shell_exec("ps -o lstart= -p $pid"));
                            if (!empty($start_time)) {
                                $start_timestamp = strtotime($start_time);
                                $uptime_seconds = time() - $start_timestamp;
                                $uptime = self::formatUptime($uptime_seconds);
                            } else {
                                $uptime = 'Unknown';
                                $uptime_seconds = 0;
                            }
                            
                            $status['networks'][$network] = [
                                'online' => true,
                                'pid' => (int)$pid,
                                'uptime' => $uptime,
                                'uptime_seconds' => $uptime_seconds
                            ];
                        } else {
                            $status['networks'][$network] = [
                                'online' => false,
                                'pid' => null,
                                'uptime' => 'N/A',
                                'uptime_seconds' => 0
                            ];
                        }
                    }
                    
                    $output = "Bot Status Report\n" . str_repeat("=", 40) . "\n\n";
                    
                    // Show Rizon status
                    if (isset($status['networks']['rizon'])) {
                        $rizon = $status['networks']['rizon'];
                        $output .= "Rizon Network:\n";
                        $output .= "  Status: " . ($rizon['online'] ? 'online' : 'offline') . "\n";
                        if ($rizon['online']) {
                            $output .= "  PID: " . ($rizon['pid'] ?? 'N/A') . "\n";
                            $output .= "  Uptime: " . ($rizon['uptime'] ?? '0s') . "\n";
                            $output .= "  Last Activity: " . ($rizon['last_activity']['human'] ?? 'N/A') . "\n";
                        }
                    } else {
                        $output .= "Rizon Network: Status unavailable\n";
                    }
                    
                    $output .= "\n";
                    
                    // Show Libera status  
                    if (isset($status['networks']['libera'])) {
                        $libera = $status['networks']['libera'];
                        $output .= "Libera Network:\n";
                        $output .= "  Status: " . ($libera['online'] ? 'online' : 'offline') . "\n";
                        if ($libera['online']) {
                            $output .= "  PID: " . ($libera['pid'] ?? 'N/A') . "\n";
                            $output .= "  Uptime: " . ($libera['uptime'] ?? '0s') . "\n";
                            $output .= "  Last Activity: " . ($libera['last_activity']['human'] ?? 'N/A') . "\n";
                        }
                    } else {
                        $output .= "Libera Network: Status unavailable\n";
                    }
                    
                    $result['success'] = true;
                    $result['message'] = "Status check completed";
                    $result['output'] = $output;
                    return $result;
                default:
                    throw new Exception("Unknown action: $action");
            }
            
            if ($script_path && file_exists($script_path)) {
                // Write command to queue for execution by privileged process
                $command_file = '/data/cr0_system/tmp/bot_commands/' . uniqid('cmd_') . '.json';
                $command_data = [
                    'action' => $action,
                    'script_path' => $script_path,
                    'timestamp' => time(),
                    'user' => $_SESSION['username'] ?? 'unknown',
                    'status' => 'pending'
                ];
                
                // Ensure command directory exists
                ConfigPaths::ensureDirectory(dirname($command_file));
                
                // Write command to queue
                if (file_put_contents($command_file, json_encode($command_data, JSON_PRETTY_PRINT))) {
                    $result['success'] = true;
                    $result['message'] = "Bot restart command queued successfully";
                    $result['output'] = "Bot restart has been queued for execution. The bot should restart within 30 seconds.";
                    
                    // Log the action
                    logSecurityEvent('BOT_MANAGEMENT', "Admin action '$action' queued by " . ($_SESSION['username'] ?? 'unknown'), 'MEDIUM');
                } else {
                    throw new Exception("Failed to queue command");
                }
            } else {
                throw new Exception("Script not found: $script_path");
            }
            
        } catch (Exception $e) {
            $result['message'] = $e->getMessage();
            error_log("Bot management error: " . $e->getMessage());
        }
        
        return $result;
    }
    
    /**
     * Get command performance analytics
     */
    public static function getCommandPerformance() {
        $performance = [
            'slowest_commands' => [],
            'most_used' => [],
            'error_rates' => []
        ];
        
        try {
            foreach (['rizon', 'libera'] as $network) {
                $db_path = "/data/cr0_system/databases/{$network}_bot.db";
                if (file_exists($db_path)) {
                    $pdo = new PDO("sqlite:$db_path");
                    
                    // Slowest commands
                    $stmt = $pdo->prepare("
                        SELECT command, AVG(execution_time_ms) as avg_time, COUNT(*) as uses
                        FROM command_usage 
                        WHERE timestamp > datetime('now', '-24 hours')
                        GROUP BY command 
                        ORDER BY avg_time DESC 
                        LIMIT 10
                    ");
                    $stmt->execute();
                    $slow = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    foreach ($slow as $cmd) {
                        $cmd['network'] = $network;
                        $cmd['display_command'] = self::mapCommandName($cmd['command'], $network);
                        $performance['slowest_commands'][] = $cmd;
                    }
                    
                    // Most used commands
                    $stmt = $pdo->prepare("
                        SELECT command, COUNT(*) as uses, AVG(execution_time_ms) as avg_time
                        FROM command_usage 
                        WHERE timestamp > datetime('now', '-24 hours')
                        GROUP BY command 
                        ORDER BY uses DESC 
                        LIMIT 10
                    ");
                    $stmt->execute();
                    $popular = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    foreach ($popular as $cmd) {
                        $cmd['network'] = $network;
                        $cmd['display_command'] = self::mapCommandName($cmd['command'], $network);
                        $performance['most_used'][] = $cmd;
                    }
                }
            }
        } catch (Exception $e) {
            error_log("Error getting command performance: " . $e->getMessage());
        }
        
        // Sort combined results to ensure proper distribution between networks
        // Sort slowest commands by avg_time descending
        usort($performance['slowest_commands'], function($a, $b) {
            return ($b['avg_time'] ?? 0) <=> ($a['avg_time'] ?? 0);
        });
        
        // Sort most used commands by uses descending  
        usort($performance['most_used'], function($a, $b) {
            return ($b['uses'] ?? 0) <=> ($a['uses'] ?? 0);
        });
        
        // Limit to top 10 after sorting
        $performance['slowest_commands'] = array_slice($performance['slowest_commands'], 0, 10);
        $performance['most_used'] = array_slice($performance['most_used'], 0, 10);
        
        return $performance;
    }
    
    /**
     * Get live log entries for a specific network
     */
    public static function getLiveLogs($network = 'rizon', $lines = 50) {
        $logs = [];
        
        try {
            $log_file = "/data/cr0_system/logs/irc_networks/$network/{$network}_bot.log";
            if (file_exists($log_file)) {
                $log_lines = array_slice(file($log_file), -$lines);
                foreach ($log_lines as $line) {
                    $line = trim($line);
                    if (!empty($line)) {
                        // Parse log entry
                        if (preg_match('/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: \w+)?) - (.+?) - (\w+) - (.+)$/', $line, $matches)) {
                            $logs[] = [
                                'timestamp' => $matches[1],
                                'source' => $matches[2],
                                'level' => $matches[3],
                                'message' => $matches[4],
                                'network' => $network
                            ];
                        } else {
                            // Fallback for lines that don't match expected format
                            $logs[] = [
                                'timestamp' => date('Y-m-d H:i:s'),
                                'source' => 'unknown',
                                'level' => 'INFO',
                                'message' => $line,
                                'network' => $network
                            ];
                        }
                    }
                }
            }
        } catch (Exception $e) {
            error_log("Error getting live logs: " . $e->getMessage());
        }
        
        return array_reverse($logs); // Most recent first
    }
    
    /**
     * Get bot status from status file
     */
    public static function getBotStatus() {
        $status = [
            'rizon' => ['pid' => null, 'status' => 'Unknown', 'updated' => null],
            'libera' => ['pid' => null, 'status' => 'Unknown', 'updated' => null]
        ];
        
        try {
            $status_file = '/data/cr0_system/shared_storage/bot_status.json';
            if (file_exists($status_file)) {
                $status_data = json_decode(file_get_contents($status_file), true);
                if ($status_data) {
                    foreach (['rizon', 'libera'] as $network) {
                        if (isset($status_data[$network])) {
                            $status[$network] = array_merge($status[$network], $status_data[$network]);
                        }
                    }
                }
            }
        } catch (Exception $e) {
            error_log("Error getting bot status: " . $e->getMessage());
        }
        
        return $status;
    }
    
    /**
     * Get system resource information
     */
    public static function getSystemResources() {
        $resources = [
            'cpu_usage' => 0,
            'memory_usage' => 0,
            'disk_usage' => 0,
            'load_average' => [0, 0, 0],
            'uptime' => 0
        ];
        
        try {
            // CPU load average
            $load = sys_getloadavg();
            $resources['load_average'] = $load;
            $resources['cpu_usage'] = round($load[0] * 100 / 4, 1); // Assuming 4 cores
            
            // Memory usage
            $free_output = shell_exec('free -m');
            if ($free_output) {
                $lines = explode("\n", $free_output);
                if (isset($lines[1])) {
                    $mem_info = preg_split('/\s+/', $lines[1]);
                    if (count($mem_info) >= 3) {
                        $total = (int)$mem_info[1];
                        $used = (int)$mem_info[2];
                        $resources['memory_usage'] = round(($used / $total) * 100, 1);
                    }
                }
            }
            
            // Disk usage
            $disk_free = disk_free_space('/');
            $disk_total = disk_total_space('/');
            if ($disk_free && $disk_total) {
                $resources['disk_usage'] = round((1 - $disk_free / $disk_total) * 100, 1);
            }
            
            // System uptime
            $uptime_output = shell_exec('uptime -s');
            if ($uptime_output) {
                $boot_time = strtotime(trim($uptime_output));
                $resources['uptime'] = time() - $boot_time;
            }
            
        } catch (Exception $e) {
            error_log("Error getting system resources: " . $e->getMessage());
        }
        
        return $resources;
    }
    
    /**
     * Format uptime in human-readable format
     */
    private static function formatUptime($seconds) {
        if ($seconds < 60) {
            return $seconds . 's';
        } elseif ($seconds < 3600) {
            $minutes = floor($seconds / 60);
            $secs = $seconds % 60;
            return $minutes . 'm ' . $secs . 's';
        } elseif ($seconds < 86400) {
            $hours = floor($seconds / 3600);
            $minutes = floor(($seconds % 3600) / 60);
            return $hours . 'h ' . $minutes . 'm';
        } else {
            $days = floor($seconds / 86400);
            $hours = floor(($seconds % 86400) / 3600);
            return $days . 'd ' . $hours . 'h';
        }
    }
    
    /**
     * Hall of Fame Management Functions
     */
    
    public static function deleteHallOfFameScore($score_id) {
        try {
            $db_path = ConfigPaths::getDatabase('breakout_scores');
            $pdo = new PDO("sqlite:$db_path");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Get score details for logging
            $stmt = $pdo->prepare("SELECT player_name, score FROM breakout_scores WHERE id = ?");
            $stmt->execute([$score_id]);
            $score_info = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$score_info) {
                return ['success' => false, 'message' => 'Score not found'];
            }
            
            // Delete the score
            $stmt = $pdo->prepare("DELETE FROM breakout_scores WHERE id = ?");
            $stmt->execute([$score_id]);
            
            // Log the deletion
            error_log("ADMIN: Deleted hall of fame score - ID: $score_id, Player: {$score_info['player_name']}, Score: {$score_info['score']}");
            
            return ['success' => true, 'message' => 'Score deleted successfully'];
            
        } catch (Exception $e) {
            error_log("Error deleting hall of fame score: " . $e->getMessage());
            return ['success' => false, 'message' => 'Database error'];
        }
    }
    
    public static function deleteMultipleHallOfFameScores($score_ids) {
        try {
            $db_path = ConfigPaths::getDatabase('breakout_scores');
            $pdo = new PDO("sqlite:$db_path");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $placeholders = str_repeat('?,', count($score_ids) - 1) . '?';
            
            // Get score details for logging
            $stmt = $pdo->prepare("SELECT id, player_name, score FROM breakout_scores WHERE id IN ($placeholders)");
            $stmt->execute($score_ids);
            $scores = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // Delete the scores
            $stmt = $pdo->prepare("DELETE FROM breakout_scores WHERE id IN ($placeholders)");
            $stmt->execute($score_ids);
            $deleted_count = $stmt->rowCount();
            
            // Log the deletions
            foreach ($scores as $score) {
                error_log("ADMIN: Deleted hall of fame score - ID: {$score['id']}, Player: {$score['player_name']}, Score: {$score['score']}");
            }
            
            return ['success' => true, 'message' => "$deleted_count score(s) deleted successfully"];
            
        } catch (Exception $e) {
            error_log("Error deleting multiple hall of fame scores: " . $e->getMessage());
            return ['success' => false, 'message' => 'Database error'];
        }
    }
    
    public static function banPlayerFromHallOfFame($player_name) {
        try {
            $banned_file = '/tmp/banned_players.txt';
            
            // Get existing banned players
            $banned_players = [];
            if (file_exists($banned_file)) {
                $banned_players = file($banned_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            }
            
            // Check if already banned
            if (in_array($player_name, $banned_players)) {
                return ['success' => false, 'message' => 'Player is already banned'];
            }
            
            // Add to banned list
            $banned_players[] = $player_name;
            
            // Write back to file
            if (file_put_contents($banned_file, implode("\n", $banned_players) . "\n") === false) {
                return ['success' => false, 'message' => 'Failed to update ban list'];
            }
            
            // Also delete existing scores from this player
            $db_path = ConfigPaths::getDatabase('breakout_scores');
            $pdo = new PDO("sqlite:$db_path");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $stmt = $pdo->prepare("DELETE FROM breakout_scores WHERE player_name = ?");
            $stmt->execute([$player_name]);
            $deleted_count = $stmt->rowCount();
            
            // Log the ban
            error_log("ADMIN: Banned player '$player_name' from hall of fame and deleted $deleted_count existing scores");
            
            return ['success' => true, 'message' => "Player '$player_name' banned successfully ($deleted_count existing scores removed)"];
            
        } catch (Exception $e) {
            error_log("Error banning player from hall of fame: " . $e->getMessage());
            return ['success' => false, 'message' => 'Error banning player'];
        }
    }
    
    public static function clearAllHallOfFameScores() {
        try {
            $db_path = ConfigPaths::getDatabase('breakout_scores');
            $pdo = new PDO("sqlite:$db_path");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Get count before deletion
            $stmt = $pdo->query("SELECT COUNT(*) FROM breakout_scores");
            $count = $stmt->fetchColumn();
            
            // Clear all scores
            $pdo->exec("DELETE FROM breakout_scores");
            
            // Log the action
            error_log("ADMIN: Cleared all hall of fame scores ($count records deleted)");
            
            return ['success' => true, 'message' => "All $count scores cleared successfully"];
            
        } catch (Exception $e) {
            error_log("Error clearing all hall of fame scores: " . $e->getMessage());
            return ['success' => false, 'message' => 'Database error'];
        }
    }
}
?>