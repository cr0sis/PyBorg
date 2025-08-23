<?php
/**
 * Admin API - Secure Bot Management Interface
 * All shell commands have been replaced with secure alternatives
 */

require_once 'security_config.php';
require_once 'security_middleware.php';
require_once 'input_sanitizer.php';
require_once 'config_paths.php';

// Initialize security (NO TRUSTED IP BYPASS - ALL CONNECTIONS MUST AUTHENTICATE)
SecurityMiddleware::validateAdminAccess();

// Log security bypass attempt for monitoring
if (in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1', 'localhost'])) {
    logSecurityEvent('LOCALHOST_ADMIN_ACCESS', 
        'Admin access from localhost - no bypass granted', 
        'MEDIUM');
}
require_once 'security_hardened.php';
require_once 'secure_admin_functions.php';
require_once 'secure_database.php';
require_once 'secure_file_handler.php';
require_once 'config_paths.php';

// Load trusted IPs configuration
$trustedIPs = ['127.0.0.1', '::1', 'localhost'];
$trustedIPsFile = __DIR__ . '/trusted_ips.php';
if (file_exists($trustedIPsFile)) {
    $additionalIPs = include $trustedIPsFile;
    if (is_array($additionalIPs)) {
        $trustedIPs = array_merge($trustedIPs, $additionalIPs);
    }
}

// Check if user is authenticated admin before enforcing CSRF
$isAuthenticatedAdmin = false;
if (isset($_SESSION) && isset($_SESSION['user_id']) && isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
    $isAuthenticatedAdmin = true;
}

// HARDCORE CSRF protection for all admin actions (except localhost, trusted IPs, or authenticated admins)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !in_array($_SERVER['REMOTE_ADDR'], $trustedIPs) && !$isAuthenticatedAdmin) {
    $rawInput = file_get_contents('php://input');
    $input = HardcoreSecurityManager::safeJSONParse($rawInput);
    
    if ($input === false) {
        HardcoreSecurityManager::logSecurityEvent('ATTACK', 'Invalid JSON in admin API');
        http_response_code(400);
        echo json_encode(['error' => 'Invalid request format']);
        exit;
    }
    
    if (!validateCSRFToken($input['csrf_token'] ?? '')) {
        // Check if this might be an expired session rather than a malicious attack
        if (isset($_SESSION['user_id']) && isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
            // User is still logged in but CSRF token is invalid - likely expired, regenerate
            HardcoreSecurityManager::logSecurityEvent('WARNING', 'CSRF token expired for admin user - regenerating');
            generateCSRFToken(); // Generate new token
            http_response_code(401);
            echo json_encode(['error' => 'Session expired, please refresh the page and try again']);
            exit;
        } else {
            // No valid admin session - treat as potential attack
            HardcoreSecurityManager::logSecurityEvent('ATTACK', 'CSRF attack on admin API - no valid admin session');
            HardcoreSecurityManager::blockIP($_SERVER['REMOTE_ADDR'], 'CSRF attack on admin API');
            http_response_code(403);
            echo json_encode(['error' => 'Security validation failed']);
            exit;
        }
    }
}

// Enhanced rate limiting for admin actions with IP blocking
if (!HardcoreSecurityManager::checkRateLimit($_SERVER['REMOTE_ADDR'] . '_admin', 20, 300)) {
    HardcoreSecurityManager::blockIP($_SERVER['REMOTE_ADDR'], 'Admin API rate limit exceeded');
    http_response_code(429);
    echo json_encode(['error' => 'Rate limit exceeded - IP blocked']);
    exit;
}

// Require admin authentication
requireAdmin();

header('Content-Type: application/json');

// Initialize secure bot manager
$botManager = new SecureBotManager();
$systemHealth = new SystemHealth();

// Sanitize all input first
$_GET = InputSanitizer::sanitizeAll($_GET);

// Get action - prioritize POST JSON for POST requests, GET for GET requests
$action = '';
$input = null;

error_log("DEBUG: REQUEST_METHOD: " . $_SERVER['REQUEST_METHOD']);
error_log("DEBUG: GET params: " . json_encode($_GET));

// For POST requests, prioritize JSON body
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $rawInput = file_get_contents('php://input');
    error_log("DEBUG: Raw input: " . $rawInput);
    if (!empty($rawInput)) {
        $input = InputSanitizer::validateJSON($rawInput);
        error_log("DEBUG: Parsed JSON: " . json_encode($input));
        if ($input !== false && isset($input['action'])) {
            $action = InputSanitizer::validateAction($input['action']);
            error_log("DEBUG: Action from JSON: " . $action);
        }
    }
    // Only fall back to GET if no JSON action found
    if (empty($action)) {
        $action = InputSanitizer::validateAction($_GET['action'] ?? '');
        error_log("DEBUG: Action from GET fallback: " . $action);
    }
} else {
    // For GET requests, use GET parameter
    $action = InputSanitizer::validateAction($_GET['action'] ?? '');
    error_log("DEBUG: Action from GET: " . $action);
}

error_log("DEBUG: Action parsed as: '$action'");
error_log("DEBUG: Input data: " . json_encode($input));

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
            $scoreId = InputSanitizer::validateID($input['id'] ?? null);
            if ($scoreId === false) {
                echo json_encode(['error' => 'Invalid score ID']);
                break;
            }
            echo json_encode(deleteScore($scoreId));
            break;
            
        case 'ban_player':
            $playerName = InputSanitizer::validatePlayerName($input['player_name'] ?? '');
            if (empty($playerName)) {
                echo json_encode(['error' => 'Invalid player name']);
                break;
            }
            echo json_encode(banPlayer($playerName));
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
            
        case 'start_rizon':
            echo json_encode(startRizonBot());
            break;
            
        case 'start_libera':
            echo json_encode(startLiberaBot());
            break;
            
        case 'stop_rizon':
            echo json_encode(stopRizonBot());
            break;
            
        case 'stop_libera':
            echo json_encode(stopLiberaBot());
            break;
            
        case 'send_command':
            error_log("DEBUG: send_command case reached");
            $command = $input['command'] ?? '';
            $network = $input['network'] ?? 'both';
            error_log("DEBUG: About to call sendManualCommand with command='$command', network='$network'");
            $result = sendManualCommand($command, $network);
            error_log("DEBUG: sendManualCommand returned: " . json_encode($result));
            echo json_encode($result);
            break;
            
        case 'get_logs':
            echo json_encode(getLogs($input['type'] ?? ''));
            break;
            
        case 'get_rizon_logs':
            echo json_encode(getRizonLogs());
            break;
            
        case 'get_libera_logs':
            echo json_encode(getLiberaLogs());
            break;
            
        case 'get_rizon_errors':
            echo json_encode(getRizonErrorLogs());
            break;
            
        case 'get_libera_errors':
            echo json_encode(getLiberaErrorLogs());
            break;
            
        case 'get_bot_logs':
            echo json_encode(getBotLogs($input['network'] ?? ''));
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
            echo json_encode(saveSettings($input ?? []));
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
            
        case 'get_live_logs':
            error_log("DEBUG: get_live_logs case reached. Input: " . json_encode($input));
            if ($input === null) {
                error_log("DEBUG: input is null");
                echo json_encode(['success' => false, 'error' => 'Invalid request format']);
                break;
            }
            $network = in_array($input['network'] ?? 'rizon', ['rizon', 'libera']) ? $input['network'] : 'rizon';
            $logType = in_array($input['log_type'] ?? 'bot', ['bot', 'errors', 'startup']) ? $input['log_type'] : 'bot';
            $lastModified = (int)($input['last_modified'] ?? 0);
            error_log("DEBUG: About to call getLiveLogs with network=$network, logType=$logType, lastModified=$lastModified");
            $result = getLiveLogs($network, $logType, $lastModified);
            error_log("DEBUG: getLiveLogs returned: " . json_encode($result));
            echo json_encode($result);
            break;
            
        default:
            echo json_encode(['error' => 'Unknown action']);
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}

// Bot Status Functions (now using secure methods)
function getBotStatus() {
    global $botManager;
    
    securityLog('Bot status requested');
    
    try {
        return $botManager->getBotStatus();
    } catch (Exception $e) {
        securityLog('Bot status check failed: ' . $e->getMessage(), 'ERROR');
        return [
            'online' => false,
            'networks' => [],
            'error' => 'Status check failed'
        ];
    }
}

// Process uptime function removed - now handled securely in SecureBotManager

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
        $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('breakout'));
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
        $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('breakout'));
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->query("SELECT * FROM breakout_scores ORDER BY score DESC LIMIT 50");
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        return [];
    }
}

function resetAllScores() {
    try {
        $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('breakout'));
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
        
        $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('breakout'));
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
            $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('breakout'));
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

// Bot Control Functions (now secure)
function startBot() {
    global $botManager;
    
    securityLog('Start all bots command initiated');
    
    try {
        return $botManager->executeScript('start_all');
    } catch (Exception $e) {
        securityLog('Start all bots failed: ' . $e->getMessage(), 'ERROR');
        return ['error' => 'Failed to start bots: ' . $e->getMessage()];
    }
}

function stopBot() {
    global $botManager;
    
    securityLog('Stop all bots command initiated');
    
    try {
        return $botManager->executeScript('stop_all');
    } catch (Exception $e) {
        securityLog('Stop all bots failed: ' . $e->getMessage(), 'ERROR');
        return ['error' => 'Failed to stop bots: ' . $e->getMessage()];
    }
}

function restartBot() {
    global $botManager;
    
    securityLog('Restart all bots command initiated');
    
    try {
        return $botManager->executeScript('restart_all');
    } catch (Exception $e) {
        securityLog('Restart all bots failed: ' . $e->getMessage(), 'ERROR');
        return ['error' => 'Failed to restart bots: ' . $e->getMessage()];
    }
}

// Log Functions (now secure)
function getLogs($type) {
    global $botManager;
    
    securityLog("Log access requested: $type");
    
    try {
        return $botManager->getLogContent($type);
    } catch (Exception $e) {
        securityLog('Log access failed: ' . $e->getMessage(), 'ERROR');
        return ['content' => 'Error accessing log file'];
    }
}

// Database Functions (now secure)
function backupDatabase() {
    global $botManager;
    
    securityLog('Database backup initiated');
    
    try {
        return $botManager->createBackup();
    } catch (Exception $e) {
        securityLog('Database backup failed: ' . $e->getMessage(), 'ERROR');
        return ['error' => 'Backup failed: ' . $e->getMessage()];
    }
}

function cleanupDatabase() {
    $results = [];
    
    // Clean up old reminders (30+ days)
    try {
        $networks = ['rizon', 'libera'];
        foreach ($networks as $network) {
            $db_file = ConfigPaths::getDatabase($network . '_bot');
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
        $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('breakout'));
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
            $db_file = ConfigPaths::getDatabase($network . '_bot');
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
    $config_file = __DIR__ . '/../admin_settings.json';
    
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

// Individual Bot Control Functions (now secure)
function restartRizonBot() {
    global $botManager;
    
    securityLog('Rizon bot restart initiated');
    
    try {
        return $botManager->executeScript('restart_rizon');
    } catch (Exception $e) {
        securityLog('Rizon bot restart failed: ' . $e->getMessage(), 'ERROR');
        return ['error' => 'Failed to restart Rizon bot: ' . $e->getMessage()];
    }
}

function restartLiberaBot() {
    global $botManager;
    
    securityLog('Libera bot restart initiated');
    
    try {
        return $botManager->executeScript('restart_libera');
    } catch (Exception $e) {
        securityLog('Libera bot restart failed: ' . $e->getMessage(), 'ERROR');
        return ['error' => 'Failed to restart Libera bot: ' . $e->getMessage()];
    }
}

function startRizonBot() {
    global $botManager;
    
    securityLog('Rizon bot start initiated');
    
    try {
        return $botManager->executeScript('start_rizon');
    } catch (Exception $e) {
        securityLog('Rizon bot start failed: ' . $e->getMessage(), 'ERROR');
        return ['error' => 'Failed to start Rizon bot: ' . $e->getMessage()];
    }
}

function startLiberaBot() {
    global $botManager;
    
    securityLog('Libera bot start initiated');
    
    try {
        return $botManager->executeScript('start_libera');
    } catch (Exception $e) {
        securityLog('Libera bot start failed: ' . $e->getMessage(), 'ERROR');
        return ['error' => 'Failed to start Libera bot: ' . $e->getMessage()];
    }
}

function stopRizonBot() {
    global $botManager;
    
    securityLog('Rizon bot stop initiated');
    
    try {
        return $botManager->executeScript('stop_rizon');
    } catch (Exception $e) {
        securityLog('Rizon bot stop failed: ' . $e->getMessage(), 'ERROR');
        return ['error' => 'Failed to stop Rizon bot: ' . $e->getMessage()];
    }
}

function stopLiberaBot() {
    global $botManager;
    
    securityLog('Libera bot stop initiated');
    
    try {
        return $botManager->executeScript('stop_libera');
    } catch (Exception $e) {
        securityLog('Libera bot stop failed: ' . $e->getMessage(), 'ERROR');
        return ['error' => 'Failed to stop Libera bot: ' . $e->getMessage()];
    }
}

// Manual Command Functions
function sendManualCommand($command, $network = 'both') {
    if (empty($command)) {
        return ['error' => 'No command provided'];
    }
    
    // Decode HTML entities to get raw text for IRC
    $command = html_entity_decode($command, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    
    // Validate network parameter
    $validNetworks = ['rizon', 'libera', 'both'];
    if (!in_array($network, $validNetworks)) {
        return ['error' => "Invalid network specified: $network. Valid options: " . implode(', ', $validNetworks)];
    }
    
    // Validate command format - should start with an IRC command
    $command = trim($command);
    $validCommands = ['PRIVMSG', 'NOTICE', 'JOIN', 'PART', 'QUIT', 'NICK', 'TOPIC', 'MODE', 'KICK', 'BAN', 'UNBAN', 'PING', 'PONG', 'VERSION', 'TIME', 'MOTD', 'WHOIS', 'WHO', 'LIST', 'NAMES', 'ACTION'];
    
    $commandParts = explode(' ', $command, 2);
    $ircCommand = strtoupper($commandParts[0]);
    
    if (!in_array($ircCommand, $validCommands)) {
        return ['error' => "Invalid IRC command: $ircCommand. Allowed commands: " . implode(', ', $validCommands)];
    }
    
    // Determine which networks to send to
    $targetNetworks = [];
    if ($network === 'both') {
        $targetNetworks = ['rizon', 'libera'];
    } else {
        $targetNetworks = [$network];
    }
    
    $results = [];
    
    // Create command directory in centralized location if it doesn't exist
    $commandDir = ConfigPaths::BASE_DATA_DIR . "/tmp/bot_commands";
    if (!is_dir($commandDir)) {
        mkdir($commandDir, 0775, true);
        // Ensure proper ownership for shared access
        @chgrp($commandDir, 'www-data');
    }
    
    foreach ($targetNetworks as $targetNetwork) {
        $commandFile = "$commandDir/{$targetNetwork}_manual_command_" . time() . "_" . rand(1000, 9999) . ".txt";
        
        // Write command to file with timestamp
        $timestamp = date('Y-m-d H:i:s');
        $commandWithMeta = json_encode([
            'command' => $command,
            'timestamp' => $timestamp,
            'source' => 'admin_panel'
        ]);
        
        if (file_put_contents($commandFile, $commandWithMeta) !== false) {
            // Set permissions so bot user can read and delete the file
            chmod($commandFile, 0666);
            $results[$targetNetwork] = "Command queued successfully";
        } else {
            $results[$targetNetwork] = "Failed to queue command";
        }
    }
    
    $networkText = $network === 'both' ? 'both networks' : "$network network";
    
    return [
        'success' => true,
        'message' => "Manual IRC command sent to $networkText",
        'command' => $command,
        'network' => $network,
        'target_networks' => $targetNetworks,
        'details' => $results,
        'note' => 'Command will be processed by bots when they check the command queue'
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

// Network-specific log functions (now secure)
function getRizonLogs() {
    global $botManager;
    
    securityLog('Rizon logs requested');
    
    try {
        return $botManager->getLogContent('bot_rizon');
    } catch (Exception $e) {
        securityLog('Rizon log access failed: ' . $e->getMessage(), 'ERROR');
        return ['content' => 'Error accessing Rizon logs'];
    }
}

function getLiberaLogs() {
    global $botManager;
    
    securityLog('Libera logs requested');
    
    try {
        return $botManager->getLogContent('bot_libera');
    } catch (Exception $e) {
        securityLog('Libera log access failed: ' . $e->getMessage(), 'ERROR');
        return ['content' => 'Error accessing Libera logs'];
    }
}

function getBotLogs($network) {
    global $botManager;
    
    $valid_networks = ['rizon', 'libera'];
    
    if (!in_array($network, $valid_networks)) {
        return ['error' => 'Invalid network specified'];
    }
    
    securityLog("Bot logs requested for network: $network");
    
    try {
        $mainLog = $botManager->getLogContent("bot_$network");
        
        return [
            'network' => $network,
            'logs' => [
                'main' => $mainLog['content'] ?? 'Log not available'
            ],
            'timestamp' => date('Y-m-d H:i:s'),
            'live_source' => true
        ];
    } catch (Exception $e) {
        securityLog("Bot log access failed for $network: " . $e->getMessage(), 'ERROR');
        return ['error' => 'Error accessing bot logs'];
    }
}

function syncLogs() {
    securityLog('Log sync operation initiated');
    
    // For security, sync is now handled automatically
    // Manual sync capability removed to prevent potential exploitation
    return [
        'success' => true,
        'message' => 'Log sync is handled automatically by the system',
        'note' => 'Manual sync disabled for security reasons'
    ];
}

// System Health Functions (now secure)  
function getSystemHealth() {
    global $systemHealth;
    
    securityLog('System health check requested');
    
    try {
        // Add memory limit check to prevent exhaustion
        $memoryUsage = memory_get_usage(true);
        $memoryLimit = ini_get('memory_limit');
        $memoryLimitBytes = (int)$memoryLimit * 1024 * 1024;
        
        if ($memoryUsage > $memoryLimitBytes * 0.8) {
            return [
                'success' => false,
                'error' => 'Insufficient memory for health check',
                'memory_usage' => round($memoryUsage / 1024 / 1024, 2) . 'MB'
            ];
        }
        
        return $systemHealth->getSystemInfo();
    } catch (Exception $e) {
        securityLog('System health check failed: ' . $e->getMessage(), 'ERROR');
        return [
            'success' => false,
            'error' => 'System health check failed',
            'status' => 'critical'
        ];
    }
}

// Error log functions
function getRizonErrorLogs() {
    global $botManager;
    
    securityLog('Rizon error logs requested');
    
    try {
        $errorLogPath = ConfigPaths::getLogPath('errors', 'rizon');
        if (!file_exists($errorLogPath)) {
            $currentDate = date('Y-m-d H:i:s');
            return [
                'content' => "Rizon Error Log - $currentDate\nErrors: 0 (No error log file found)",
                'file_size' => 0,
                'last_modified' => time()
            ];
        }
        
        // Get last 100 lines of error log using SafeCommand
        $content = SafeCommand::execute('tail', ['-100', $errorLogPath]);
        $content = cleanLogFormatting($content);
        
        // Count actual error lines (exclude log cleared messages)
        $errorLines = array_filter(explode("\n", $content), function($line) {
            return !empty(trim($line)) && strpos($line, '=== LOG CLEARED') === false;
        });
        $errorCount = count($errorLines);
        
        $currentDate = date('Y-m-d H:i:s');
        $lastModified = date('Y-m-d H:i:s', filemtime($errorLogPath));
        
        // Format the output with header
        $formattedContent = "Rizon Error Log - $currentDate\n";
        $formattedContent .= "Last Modified: $lastModified\n";
        $formattedContent .= "Errors: $errorCount\n";
        $formattedContent .= "" . str_repeat('-', 50) . "\n";
        
        if ($errorCount > 0) {
            $formattedContent .= $content;
        } else {
            $formattedContent .= "No errors found.";
        }
        
        return [
            'content' => $formattedContent,
            'file_size' => filesize($errorLogPath),
            'last_modified' => filemtime($errorLogPath)
        ];
    } catch (Exception $e) {
        securityLog('Rizon error log access failed: ' . $e->getMessage(), 'ERROR');
        $currentDate = date('Y-m-d H:i:s');
        return [
            'content' => "Rizon Error Log - $currentDate\nErrors: 0 (Error accessing log file: " . $e->getMessage() . ")",
            'file_size' => 0,
            'last_modified' => time()
        ];
    }
}

function getLiberaErrorLogs() {
    global $botManager;
    
    securityLog('Libera error logs requested');
    
    try {
        $errorLogPath = ConfigPaths::getLogPath('errors', 'libera');
        if (!file_exists($errorLogPath)) {
            $currentDate = date('Y-m-d H:i:s');
            return [
                'content' => "Libera Error Log - $currentDate\nErrors: 0 (No error log file found)",
                'file_size' => 0,
                'last_modified' => time()
            ];
        }
        
        // Get last 100 lines of error log using SafeCommand
        $content = SafeCommand::execute('tail', ['-100', $errorLogPath]);
        $content = cleanLogFormatting($content);
        
        // Count actual error lines (exclude log cleared messages)
        $errorLines = array_filter(explode("\n", $content), function($line) {
            return !empty(trim($line)) && strpos($line, '=== LOG CLEARED') === false;
        });
        $errorCount = count($errorLines);
        
        $currentDate = date('Y-m-d H:i:s');
        $lastModified = date('Y-m-d H:i:s', filemtime($errorLogPath));
        
        // Format the output with header
        $formattedContent = "Libera Error Log - $currentDate\n";
        $formattedContent .= "Last Modified: $lastModified\n";
        $formattedContent .= "Errors: $errorCount\n";
        $formattedContent .= "" . str_repeat('-', 50) . "\n";
        
        if ($errorCount > 0) {
            $formattedContent .= $content;
        } else {
            $formattedContent .= "No errors found.";
        }
        
        return [
            'content' => $formattedContent,
            'file_size' => filesize($errorLogPath),
            'last_modified' => filemtime($errorLogPath)
        ];
    } catch (Exception $e) {
        securityLog('Libera error log access failed: ' . $e->getMessage(), 'ERROR');
        $currentDate = date('Y-m-d H:i:s');
        return [
            'content' => "Libera Error Log - $currentDate\nErrors: 0 (Error accessing log file: " . $e->getMessage() . ")",
            'file_size' => 0,
            'last_modified' => time()
        ];
    }
}

function getLiveLogs($network, $logType, $lastModified) {
    securityLog("Live logs requested: {$network} {$logType} lastModified: {$lastModified}");
    
    try {
        $logFile = ConfigPaths::getLogPath($logType, $network);
        
        if (!$logFile || !file_exists($logFile)) {
            return [
                'success' => false,
                'error' => 'Log file not found'
            ];
        }
        
        $currentModified = filemtime($logFile);
        $fileSize = filesize($logFile);
        
        // If this is the initial request (lastModified = 0)
        if ($lastModified === 0) {
            $content = file_get_contents($logFile);
            return [
                'success' => true,
                'content' => $content,
                'last_modified' => $currentModified,
                'file_size' => $fileSize
            ];
        }
        
        // If file hasn't been modified, return no new content
        if ($currentModified <= $lastModified) {
            return [
                'success' => true,
                'last_modified' => $currentModified,
                'file_size' => $fileSize
            ];
        }
        
        // File has been modified - get new content
        // For simplicity, we'll read the entire file and let the client handle filtering
        // In a production system, you'd want more sophisticated tracking
        $content = file_get_contents($logFile);
        
        return [
            'success' => true,
            'content' => $content,
            'last_modified' => $currentModified,
            'file_size' => $fileSize,
            'has_new_content' => true
        ];
        
    } catch (Exception $e) {
        securityLog("Live log access failed: " . $e->getMessage(), 'ERROR');
        return [
            'success' => false,
            'error' => 'Error accessing log file'
        ];
    }
}
?>