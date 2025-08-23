<?php
/**
 * Bot Analytics API - Comprehensive bot usage and performance analytics
 */

require_once '../security_config.php';
require_once '../security_middleware.php';
require_once '../config_paths.php';

// Comment out admin access requirement for public analytics page
// SecurityMiddleware::validateAdminAccess();

header('Content-Type: application/json');

// Secure CORS implementation
SecurityMiddleware::generateSecureCORS();
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

try {
    $network = $_GET['network'] ?? 'rizon';
    $days = (int)($_GET['days'] ?? 30);
    $hours = (int)($_GET['hours'] ?? 24);
    $metric = $_GET['metric'] ?? 'total_commands';
    $limit = (int)($_GET['limit'] ?? 10);
    
    // Validate network
    if (!in_array($network, ['rizon', 'libera'])) {
        throw new Exception('Invalid network specified');
    }
    
    $db_path = ConfigPaths::getDatabase($network . '_bot');
    if (!file_exists($db_path)) {
        throw new Exception("Database not found for network: $network");
    }
    
    $pdo = new PDO("sqlite:$db_path");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    $action = $_GET['action'] ?? 'summary';
    
    switch ($action) {
        case 'summary':
            echo json_encode(getAnalyticsSummary($pdo, $days, $hours, $network));
            break;
            
        case 'user_analytics':
            echo json_encode(getUserAnalytics($pdo, $days));
            break;
            
        case 'channel_analytics':  
            echo json_encode(getChannelAnalytics($pdo, $days));
            break;
            
        case 'performance':
            echo json_encode(getPerformanceAnalytics($pdo, $hours));
            break;
            
        case 'ai_analytics':
            echo json_encode(getAIAnalytics($pdo, $days));
            break;
            
        case 'game_analytics':
            echo json_encode(getGameAnalytics($pdo, $days));
            break;
            
        case 'top_performers':
            echo json_encode(getTopPerformers($pdo, $metric, $limit));
            break;
            
        case 'command_trends':
            echo json_encode(getCommandTrends($pdo, $days));
            break;
            
        case 'activity_heatmap':
            echo json_encode(getActivityHeatmap($pdo, $days));
            break;
            
        default:
            throw new Exception('Invalid action specified');
    }
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}

function getCommandDisplayName($command, $network) {
    // Network-specific command prefixes
    $prefix = ($network === 'rizon') ? '!' : '~';
    
    // Map internal function names to actual IRC commands
    $commandMap = [
        'ai_chat_gemini_with_context' => $prefix . 'speak',
        'ai_chat_gemini' => $prefix . 'speak',
        'play_uno_card' => $prefix . 'play',
        'draw_uno_card' => $prefix . 'draw', 
        'join_uno_game' => $prefix . 'join',
        'leave_uno_game' => $prefix . 'leave',
        'show_uno_cards' => $prefix . 'cards',
        'show_uno_game_state' => $prefix . 'game',
        'call_uno' => $prefix . 'uno',
        'challenge_uno' => $prefix . 'challenge',
        'start_uno_game' => $prefix . 'startuno',
        'end_uno_game' => $prefix . 'enduno',
        'pigs_command' => $prefix . 'pigs',
        'roll_dice' => $prefix . 'roll',
        'roll7_command' => $prefix . 'roll7',
        'bet7_command' => $prefix . 'bet7',
        'check_time' => $prefix . 'time',
        'check_date' => $prefix . 'date',
        'calculator' => $prefix . 'calc',
        'random_choice' => $prefix . 'random',
        'weather_command' => $prefix . 'weather',
        'twitch_stream_status' => $prefix . 'hats',
        'piss_command' => $prefix . 'piss',
        'get_temp' => $prefix . 'temp',
        'show_help' => $prefix . 'help',
        'lenny_face' => $prefix . 'lenny',
        'dog_image' => $prefix . 'dog',
        'set_reminder' => $prefix . 'remind',
        'show_reminders' => $prefix . 'reminders',
        'cancel_reminder' => $prefix . 'cancelreminder',
        'tell_memo' => $prefix . 'memo',
        'memo_command' => $prefix . 'memo',
        'stats_command' => $prefix . 'stats',
        'ginger_command' => $prefix . 'ginger',
        'bank_pigs_command' => $prefix . 'bank',
        'pigs_roll' => $prefix . 'roll',
        'pigs_bank' => $prefix . 'bank',
        'join_pigs_game' => $prefix . 'join',
        'leave_pigs_game' => $prefix . 'leave'
    ];
    
    // Return mapped command or original if not found
    return $commandMap[$command] ?? $command;
}

function getAnalyticsSummary($pdo, $days, $hours, $network = 'rizon') {
    $summary = [];
    
    // Check if enhanced columns exist
    $hasEnhancedColumns = false;
    try {
        $stmt = $pdo->query("PRAGMA table_info(command_usage)");
        $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($columns as $column) {
            if ($column['name'] === 'execution_time_ms') {
                $hasEnhancedColumns = true;
                break;
            }
        }
    } catch (Exception $e) {
        // Continue with legacy mode
    }
    
    // Overall command statistics
    if ($hasEnhancedColumns) {
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(*) as total_commands,
                COUNT(DISTINCT user) as unique_users,
                COUNT(DISTINCT channel) as active_channels,
                ROUND(AVG(execution_time_ms), 2) as avg_execution_time,
                COUNT(CASE WHEN success = 0 THEN 1 END) as error_count,
                COUNT(CASE WHEN rate_limited = 1 THEN 1 END) as rate_limit_hits
            FROM command_usage 
            WHERE timestamp > datetime('now', '-{$days} days')
        ");
    } else {
        // Legacy fallback without enhanced columns
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(*) as total_commands,
                COUNT(DISTINCT user) as unique_users,
                COUNT(DISTINCT channel) as active_channels,
                0 as avg_execution_time,
                COUNT(CASE WHEN success = 0 THEN 1 END) as error_count,
                0 as rate_limit_hits
            FROM command_usage 
            WHERE timestamp > datetime('now', '-{$days} days')
        ");
    }
    $stmt->execute();
    $summary['overview'] = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($summary['overview']['total_commands'] > 0) {
        $summary['overview']['error_rate_percent'] = round(
            ($summary['overview']['error_count'] / $summary['overview']['total_commands']) * 100, 2
        );
    } else {
        $summary['overview']['error_rate_percent'] = 0;
    }
    
    // Most active users (top 5)
    $stmt = $pdo->prepare("
        SELECT user, COUNT(*) as command_count
        FROM command_usage 
        WHERE timestamp > datetime('now', '-{$days} days')
        GROUP BY user 
        ORDER BY command_count DESC 
        LIMIT 5
    ");
    $stmt->execute();
    $summary['top_users'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Most popular commands (top 5)
    $stmt = $pdo->prepare("
        SELECT command, COUNT(*) as usage_count
        FROM command_usage 
        WHERE timestamp > datetime('now', '-{$days} days')
        GROUP BY command 
        ORDER BY usage_count DESC 
        LIMIT 5
    ");
    $stmt->execute();
    $top_commands_raw = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Transform command names to display names with network-aware prefixes
    $summary['top_commands'] = array_map(function($cmd) use ($network) {
        return [
            'command' => getCommandDisplayName($cmd['command'], $network),
            'usage_count' => $cmd['usage_count']
        ];
    }, $top_commands_raw);
    
    // Recent activity (last 24 hours)
    if ($hasEnhancedColumns) {
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(*) as commands_24h,
                COUNT(DISTINCT user) as users_24h,
                ROUND(AVG(execution_time_ms), 2) as avg_time_24h
            FROM command_usage 
            WHERE timestamp > datetime('now', '-24 hours')
        ");
    } else {
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(*) as commands_24h,
                COUNT(DISTINCT user) as users_24h,
                0 as avg_time_24h
            FROM command_usage 
            WHERE timestamp > datetime('now', '-24 hours')
        ");
    }
    $stmt->execute();
    $summary['recent_activity'] = $stmt->fetch(PDO::FETCH_ASSOC);
    
    return $summary;
}

function getUserAnalytics($pdo, $days) {
    // Check if user_analytics table exists
    $stmt = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='user_analytics'");
    if (!$stmt->fetch()) {
        // Check if enhanced columns exist in command_usage
        $hasEnhancedColumns = false;
        try {
            $stmt = $pdo->query("PRAGMA table_info(command_usage)");
            $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($columns as $column) {
                if ($column['name'] === 'execution_time_ms') {
                    $hasEnhancedColumns = true;
                    break;
                }
            }
        } catch (Exception $e) {
            // Continue with legacy mode
        }
        
        // Fallback to command_usage data
        if ($hasEnhancedColumns) {
            $stmt = $pdo->prepare("
                SELECT 
                    user,
                    COUNT(*) as total_commands,
                    COUNT(DISTINCT command) as unique_commands_used,
                    ROUND(AVG(execution_time_ms), 2) as avg_execution_time,
                    COUNT(CASE WHEN success = 0 THEN 1 END) as error_count,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen
                FROM command_usage 
                WHERE timestamp > datetime('now', '-{$days} days')
                GROUP BY user 
                ORDER BY total_commands DESC
            ");
        } else {
            $stmt = $pdo->prepare("
                SELECT 
                    user,
                    COUNT(*) as total_commands,
                    COUNT(DISTINCT command) as unique_commands_used,
                    0 as avg_execution_time,
                    COUNT(CASE WHEN success = 0 THEN 1 END) as error_count,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen
                FROM command_usage 
                WHERE timestamp > datetime('now', '-{$days} days')
                GROUP BY user 
                ORDER BY total_commands DESC
            ");
        }
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
    
    // Use full analytics table if available - check for enhanced columns
    $hasEnhancedColumns = false;
    try {
        $stmt = $pdo->query("PRAGMA table_info(command_usage)");
        $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($columns as $column) {
            if ($column['name'] === 'execution_time_ms') {
                $hasEnhancedColumns = true;
                break;
            }
        }
    } catch (Exception $e) {
        // Continue with legacy mode
    }
    
    if ($hasEnhancedColumns) {
        $stmt = $pdo->prepare("
            SELECT 
                ua.user,
                ua.total_commands,
                ua.commands_this_week,
                ua.commands_this_month,
                ua.favorite_command,
                ua.favorite_channel,
                ua.first_seen,
                ua.last_seen,
                ROUND(AVG(cu.execution_time_ms), 2) as avg_execution_time,
                COUNT(DISTINCT cu.command) as unique_commands_used,
                COUNT(CASE WHEN cu.success = 0 THEN 1 END) as error_count
            FROM user_analytics ua
            LEFT JOIN command_usage cu ON ua.user = cu.user 
                AND cu.timestamp > datetime('now', '-{$days} days')
            GROUP BY ua.user
            ORDER BY ua.total_commands DESC
        ");
    } else {
        $stmt = $pdo->prepare("
            SELECT 
                ua.user,
                ua.total_commands,
                ua.commands_this_week,
                ua.commands_this_month,
                ua.favorite_command,
                ua.favorite_channel,
                ua.first_seen,
                ua.last_seen,
                0 as avg_execution_time,
                COUNT(DISTINCT cu.command) as unique_commands_used,
                COUNT(CASE WHEN cu.success = 0 THEN 1 END) as error_count
            FROM user_analytics ua
            LEFT JOIN command_usage cu ON ua.user = cu.user 
                AND cu.timestamp > datetime('now', '-{$days} days')
            GROUP BY ua.user
            ORDER BY ua.total_commands DESC
        ");
    }
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function getChannelAnalytics($pdo, $days) {
    // Check if enhanced columns exist
    $hasEnhancedColumns = false;
    try {
        $stmt = $pdo->query("PRAGMA table_info(command_usage)");
        $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($columns as $column) {
            if ($column['name'] === 'execution_time_ms') {
                $hasEnhancedColumns = true;
                break;
            }
        }
    } catch (Exception $e) {
        // Continue with legacy mode
    }
    
    if ($hasEnhancedColumns) {
        $stmt = $pdo->prepare("
            SELECT 
                channel,
                COUNT(*) as total_commands,
                COUNT(DISTINCT user) as unique_users,
                COUNT(DISTINCT command) as unique_commands,
                ROUND(AVG(execution_time_ms), 2) as avg_command_time,
                COUNT(CASE WHEN success = 0 THEN 1 END) as error_count,
                MAX(timestamp) as last_activity
            FROM command_usage 
            WHERE timestamp > datetime('now', '-{$days} days')
            GROUP BY channel 
            ORDER BY total_commands DESC
        ");
    } else {
        $stmt = $pdo->prepare("
            SELECT 
                channel,
                COUNT(*) as total_commands,
                COUNT(DISTINCT user) as unique_users,
                COUNT(DISTINCT command) as unique_commands,
                0 as avg_command_time,
                COUNT(CASE WHEN success = 0 THEN 1 END) as error_count,
                MAX(timestamp) as last_activity
            FROM command_usage 
            WHERE timestamp > datetime('now', '-{$days} days')
            GROUP BY channel 
            ORDER BY total_commands DESC
        ");
    }
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function getPerformanceAnalytics($pdo, $hours) {
    // Check if enhanced columns exist
    $hasEnhancedColumns = false;
    try {
        $stmt = $pdo->query("PRAGMA table_info(command_usage)");
        $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($columns as $column) {
            if ($column['name'] === 'execution_time_ms') {
                $hasEnhancedColumns = true;
                break;
            }
        }
    } catch (Exception $e) {
        // Continue with legacy mode
    }
    
    if ($hasEnhancedColumns) {
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(*) as total_commands,
                ROUND(AVG(execution_time_ms), 2) as avg_execution_time,
                MAX(execution_time_ms) as max_execution_time,
                MIN(execution_time_ms) as min_execution_time,
                ROUND(AVG(memory_usage_mb), 2) as avg_memory_usage,
                MAX(memory_usage_mb) as peak_memory_usage,
                COUNT(CASE WHEN success = 0 THEN 1 END) as error_count,
                COUNT(CASE WHEN rate_limited = 1 THEN 1 END) as rate_limit_hits,
                COUNT(DISTINCT user) as unique_users,
                COUNT(DISTINCT channel) as active_channels
            FROM command_usage 
            WHERE timestamp > datetime('now', '-{$hours} hours')
        ");
    } else {
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(*) as total_commands,
                0 as avg_execution_time,
                0 as max_execution_time,
                0 as min_execution_time,
                0 as avg_memory_usage,
                0 as peak_memory_usage,
                COUNT(CASE WHEN success = 0 THEN 1 END) as error_count,
                0 as rate_limit_hits,
                COUNT(DISTINCT user) as unique_users,
                COUNT(DISTINCT channel) as active_channels
            FROM command_usage 
            WHERE timestamp > datetime('now', '-{$hours} hours')
        ");
    }
    $stmt->execute();
    $performance = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($performance['total_commands'] > 0) {
        $performance['error_rate_percent'] = round(
            ($performance['error_count'] / $performance['total_commands']) * 100, 2
        );
        $performance['commands_per_hour'] = round($performance['total_commands'] / $hours, 1);
    } else {
        $performance['error_rate_percent'] = 0;
        $performance['commands_per_hour'] = 0;
    }
    
    return $performance;
}

function getAIAnalytics($pdo, $days) {
    // Check if enhanced columns exist
    $hasEnhancedColumns = false;
    try {
        $stmt = $pdo->query("PRAGMA table_info(command_usage)");
        $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach ($columns as $column) {
            if ($column['name'] === 'execution_time_ms') {
                $hasEnhancedColumns = true;
                break;
            }
        }
    } catch (Exception $e) {
        // Continue with legacy mode
    }
    
    // AI command usage
    if ($hasEnhancedColumns) {
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(*) as total_ai_commands,
                COUNT(DISTINCT user) as unique_ai_users,
                ROUND(AVG(execution_time_ms), 2) as avg_response_time,
                COUNT(CASE WHEN success = 0 THEN 1 END) as ai_errors
            FROM command_usage 
            WHERE (command LIKE '%speak%' OR command LIKE '%ai%' OR command LIKE '%chat%')
                AND timestamp > datetime('now', '-{$days} days')
        ");
    } else {
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(*) as total_ai_commands,
                COUNT(DISTINCT user) as unique_ai_users,
                0 as avg_response_time,
                COUNT(CASE WHEN success = 0 THEN 1 END) as ai_errors
            FROM command_usage 
            WHERE (command LIKE '%speak%' OR command LIKE '%ai%' OR command LIKE '%chat%')
                AND timestamp > datetime('now', '-{$days} days')
        ");
    }
    $stmt->execute();
    $ai_stats = $stmt->fetch(PDO::FETCH_ASSOC);
    
    // Conversation history if available
    $stmt = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='conversation_history'");
    if ($stmt->fetch()) {
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(*) as total_conversations,
                COUNT(DISTINCT user) as unique_conversation_users,
                ROUND(AVG(LENGTH(message)), 1) as avg_message_length,
                ROUND(AVG(LENGTH(response)), 1) as avg_response_length
            FROM conversation_history 
            WHERE timestamp > datetime('now', '-{$days} days')
        ");
        $stmt->execute();
        $conv_stats = $stmt->fetch(PDO::FETCH_ASSOC);
        $ai_stats = array_merge($ai_stats, $conv_stats);
    }
    
    return $ai_stats;
}

function getGameAnalytics($pdo, $days) {
    $analytics = [];
    
    // UNO game analytics
    $stmt = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='uno_leaderboard'");
    if ($stmt->fetch()) {
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(*) as total_uno_players,
                ROUND(AVG(games_played), 1) as avg_games_per_player,
                ROUND(AVG(avg_cards_per_game), 1) as avg_cards_per_game,
                MAX(longest_win_streak) as longest_win_streak,
                SUM(comeback_wins) as total_comeback_wins
            FROM uno_leaderboard
            WHERE last_game > datetime('now', '-{$days} days')
        ");
        $stmt->execute();
        $analytics['uno'] = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // Get actual total games from bot_stats
        $stmt = $pdo->query("SELECT stat_value FROM bot_stats WHERE stat_name = 'uno_total_games'");
        $total_games_result = $stmt->fetch(PDO::FETCH_ASSOC);
        $analytics['uno']['total_uno_games'] = (int)($total_games_result['stat_value'] ?? 0);
    }
    
    // Pigs game analytics
    $stmt = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='pigs_leaderboard'");
    if ($stmt->fetch()) {
        $stmt = $pdo->prepare("
            SELECT 
                COUNT(*) as total_pigs_players,
                ROUND(AVG(games_played), 1) as avg_games_per_player,
                MAX(highest_game_score) as highest_score,
                SUM(pig_outs) as total_pig_outs,
                SUM(oinkers) as total_oinkers,
                ROUND(AVG(total_rolls / NULLIF(games_played, 0)), 1) as avg_rolls_per_game
            FROM pigs_leaderboard
            WHERE last_game > datetime('now', '-{$days} days')
        ");
        $stmt->execute();
        $analytics['pigs'] = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // Get actual total games from bot_stats
        $stmt = $pdo->query("SELECT stat_value FROM bot_stats WHERE stat_name = 'pigs_total_games'");
        $total_games_result = $stmt->fetch(PDO::FETCH_ASSOC);
        $analytics['pigs']['total_pigs_games'] = (int)($total_games_result['stat_value'] ?? 0);
    }
    
    return $analytics;
}

function getTopPerformers($pdo, $metric, $limit) {
    $valid_metrics = [
        'total_commands' => 'COUNT(*)',
        'avg_execution_time' => 'AVG(execution_time_ms)',
        'error_rate' => 'COUNT(CASE WHEN success = 0 THEN 1 END) * 100.0 / COUNT(*)',
        'unique_commands' => 'COUNT(DISTINCT command)'
    ];
    
    if (!isset($valid_metrics[$metric])) {
        $metric = 'total_commands';
    }
    
    $stmt = $pdo->prepare("
        SELECT 
            user,
            COUNT(*) as total_commands,
            ROUND(AVG(execution_time_ms), 2) as avg_execution_time,
            COUNT(DISTINCT command) as unique_commands_used,
            ROUND(COUNT(CASE WHEN success = 0 THEN 1 END) * 100.0 / NULLIF(COUNT(*), 0), 1) as error_rate
        FROM command_usage 
        WHERE timestamp > datetime('now', '-30 days')
        GROUP BY user
        ORDER BY {$valid_metrics[$metric]} DESC
        LIMIT ?
    ");
    $stmt->execute([$limit]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function getCommandTrends($pdo, $days) {
    $stmt = $pdo->prepare("
        SELECT 
            command,
            COUNT(*) as usage_count,
            ROUND(AVG(execution_time_ms), 2) as avg_execution_time,
            COUNT(CASE WHEN success = 0 THEN 1 END) as error_count,
            DATE(timestamp) as date
        FROM command_usage 
        WHERE timestamp > datetime('now', '-{$days} days')
        GROUP BY command, DATE(timestamp)
        ORDER BY date DESC, usage_count DESC
    ");
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function getActivityHeatmap($pdo, $days) {
    $stmt = $pdo->prepare("
        SELECT 
            strftime('%H', timestamp) as hour,
            strftime('%w', timestamp) as day_of_week,
            COUNT(*) as command_count
        FROM command_usage 
        WHERE timestamp > datetime('now', '-{$days} days')
        GROUP BY strftime('%H', timestamp), strftime('%w', timestamp)
        ORDER BY day_of_week, hour
    ");
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}
?>