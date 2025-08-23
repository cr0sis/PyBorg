<?php
/**
 * Public bot status endpoint - no authentication required
 * This provides basic bot status for the admin panel
 */

require_once 'security_config.php';
require_once 'secure_admin_functions.php';
require_once 'secure_database.php';
require_once 'security_middleware.php';
require_once 'config_paths.php';
require_once 'input_sanitizer.php';

header('Content-Type: application/json');

// Secure CORS implementation (replaces wildcard)
SecurityMiddleware::generateSecureCORS();

try {
    // Sanitize all input
    $_GET = InputSanitizer::sanitizeAll($_GET);
    $_POST = InputSanitizer::sanitizeAll($_POST);
    
    // Validate action parameter
    $action = InputSanitizer::validateAction($_GET['action'] ?? $_POST['action'] ?? 'bot_status');
    
    switch ($action) {
        case 'bot_status':
            $botManager = new SecureBotManager();
            $status = $botManager->getBotStatus();
            echo json_encode([
                'networks' => [
                    'rizon' => $status['rizon'] ?? ['online' => false, 'pid' => null, 'uptime' => null],
                    'libera' => $status['libera'] ?? ['online' => false, 'pid' => null, 'uptime' => null]
                ]
            ]);
            break;
            
        case 'system_health':
            $systemHealth = new SystemHealth();
            $rawHealth = $systemHealth->getSystemInfo();
            
            // Calculate comprehensive health metrics like the old format
            $health = [
                'metrics' => $rawHealth,
                'health_score' => 0,
                'status' => 'Unknown',
                'status_color' => '#666',
                'status_icon' => '⚡',
                'health_breakdown' => []
            ];
            
            // Calculate health score based on system metrics
            $totalPoints = 0;
            $earnedPoints = 0;
            
            // System Load Health (20 points max)
            $loadHealth = [
                'category' => 'System Load',
                'max_points' => 20,
                'earned_points' => 20,
                'details' => []
            ];
            
            if (isset($rawHealth['load'])) {
                $load1min = $rawHealth['load']['1min'];
                if ($load1min < 1.0) {
                    $loadHealth['earned_points'] = 20;
                    $loadHealth['details']['load_average'] = ['status' => 'Normal', 'points' => 20, 'max' => 20, 'value' => $load1min];
                } elseif ($load1min < 2.0) {
                    $loadHealth['earned_points'] = 15;
                    $loadHealth['details']['load_average'] = ['status' => 'Moderate', 'points' => 15, 'max' => 20, 'value' => $load1min];
                } else {
                    $loadHealth['earned_points'] = 5;
                    $loadHealth['details']['load_average'] = ['status' => 'High', 'points' => 5, 'max' => 20, 'value' => $load1min];
                }
            }
            
            $health['health_breakdown']['system_load'] = $loadHealth;
            $totalPoints += $loadHealth['max_points'];
            $earnedPoints += $loadHealth['earned_points'];
            
            // Memory Health (25 points max)
            $memoryHealth = [
                'category' => 'Memory Usage',
                'max_points' => 25,
                'earned_points' => 25,
                'details' => []
            ];
            
            if (isset($rawHealth['memory'])) {
                $memUsage = $rawHealth['memory']['usage_percent'];
                if ($memUsage < 70) {
                    $memoryHealth['earned_points'] = 25;
                    $memoryHealth['details']['memory_usage'] = ['status' => 'Healthy', 'points' => 25, 'max' => 25, 'usage' => $memUsage . '%'];
                } elseif ($memUsage < 85) {
                    $memoryHealth['earned_points'] = 15;
                    $memoryHealth['details']['memory_usage'] = ['status' => 'Moderate', 'points' => 15, 'max' => 25, 'usage' => $memUsage . '%'];
                } else {
                    $memoryHealth['earned_points'] = 5;
                    $memoryHealth['details']['memory_usage'] = ['status' => 'Critical', 'points' => 5, 'max' => 25, 'usage' => $memUsage . '%'];
                }
            }
            
            $health['health_breakdown']['memory_usage'] = $memoryHealth;
            $totalPoints += $memoryHealth['max_points'];
            $earnedPoints += $memoryHealth['earned_points'];
            
            // Disk Health (15 points max)
            $diskHealth = [
                'category' => 'Disk Space',
                'max_points' => 15,
                'earned_points' => 15,
                'details' => []
            ];
            
            if (isset($rawHealth['disk'])) {
                $diskUsage = $rawHealth['disk']['usage_percent'];
                if ($diskUsage < 80) {
                    $diskHealth['earned_points'] = 15;
                    $diskHealth['details']['disk_usage'] = ['status' => 'Healthy', 'points' => 15, 'max' => 15, 'usage' => $diskUsage . '%'];
                } elseif ($diskUsage < 90) {
                    $diskHealth['earned_points'] = 10;
                    $diskHealth['details']['disk_usage'] = ['status' => 'Warning', 'points' => 10, 'max' => 15, 'usage' => $diskUsage . '%'];
                } else {
                    $diskHealth['earned_points'] = 2;
                    $diskHealth['details']['disk_usage'] = ['status' => 'Critical', 'points' => 2, 'max' => 15, 'usage' => $diskUsage . '%'];
                }
            }
            
            $health['health_breakdown']['disk_space'] = $diskHealth;
            $totalPoints += $diskHealth['max_points'];
            $earnedPoints += $diskHealth['earned_points'];
            
            // Bot Status Health (40 points max)
            $botManager = new SecureBotManager();
            $botStatus = $botManager->getBotStatus();
            
            $botHealth = [
                'category' => 'Bot Services',
                'max_points' => 40,
                'earned_points' => 0,
                'details' => []
            ];
            
            foreach (['rizon', 'libera'] as $network) {
                $isOnline = $botStatus[$network]['online'] ?? false;
                if ($isOnline) {
                    $botHealth['earned_points'] += 20;
                    $botHealth['details'][$network . '_bot'] = ['status' => 'Online', 'points' => 20, 'max' => 20];
                } else {
                    $botHealth['details'][$network . '_bot'] = ['status' => 'Offline', 'points' => 0, 'max' => 20];
                }
            }
            
            $health['health_breakdown']['bot_services'] = $botHealth;
            $totalPoints += $botHealth['max_points'];
            $earnedPoints += $botHealth['earned_points'];
            
            // Calculate overall health score
            $health['health_score'] = $totalPoints > 0 ? round(($earnedPoints / $totalPoints) * 100) : 0;
            
            // Determine status based on score
            if ($health['health_score'] >= 90) {
                $health['status'] = 'Excellent';
                $health['status_color'] = '#059669';
                $health['status_icon'] = '✅';
            } elseif ($health['health_score'] >= 75) {
                $health['status'] = 'Good';
                $health['status_color'] = '#16a34a';
                $health['status_icon'] = '🟢';
            } elseif ($health['health_score'] >= 60) {
                $health['status'] = 'Fair';
                $health['status_color'] = '#f59e0b';
                $health['status_icon'] = '⚠️';
            } elseif ($health['health_score'] >= 40) {
                $health['status'] = 'Poor';
                $health['status_color'] = '#f97316';
                $health['status_icon'] = '⚠️';
            } else {
                $health['status'] = 'Critical';
                $health['status_color'] = '#dc2626';
                $health['status_icon'] = '❌';
            }
            
            echo json_encode($health);
            break;
            
        case 'user_stats':
            // Get basic user stats from databases
            $stats = [];
            $networks = ['rizon', 'libera'];
            
            foreach ($networks as $network) {
                $db_file = ConfigPaths::getDatabase($network);
                if (file_exists($db_file)) {
                    $pdo = new PDO("sqlite:$db_file");
                    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                    
                    // Get UNO stats
                    $stmt = $pdo->query("SELECT COUNT(*) as total_players, SUM(games_played) as total_games FROM uno_leaderboard WHERE games_played > 0");
                    $uno_stats = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    $stats[$network] = [
                        'uno_players' => (int)$uno_stats['total_players'],
                        'uno_games' => (int)$uno_stats['total_games']
                    ];
                }
            }
            
            echo json_encode($stats);
            break;
            
        case 'breakout_stats':
            // Get breakout game statistics
            $db_file = ConfigPaths::getDatabase('breakout');
            $stats = [
                'total_scores' => 0,
                'top_score' => 0,
                'unique_players' => 0,
                'today_games' => 0
            ];
            
            if (file_exists($db_file)) {
                $pdo = new PDO("sqlite:$db_file");
                $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                
                // Get basic stats
                $stmt = $pdo->query("SELECT COUNT(*) as total_scores, MAX(score) as top_score, COUNT(DISTINCT player_name) as unique_players FROM breakout_scores");
                $result = $stmt->fetch(PDO::FETCH_ASSOC);
                
                $stats['total_scores'] = (int)$result['total_scores'];
                $stats['top_score'] = (int)$result['top_score'];
                $stats['unique_players'] = (int)$result['unique_players'];
                
                // Get today's games
                $stmt = $pdo->query("SELECT COUNT(*) as today_games FROM breakout_scores WHERE DATE(date_played) = DATE('now')");
                $today = $stmt->fetch(PDO::FETCH_ASSOC);
                $stats['today_games'] = (int)$today['today_games'];
            }
            
            echo json_encode($stats);
            break;
            
        case 'pigs_stats':
            // Get Pass the Pigs game statistics
            $stats = [
                'rizon' => ['total_players' => 0, 'total_games' => 0, 'highest_score' => 0, 'total_pig_outs' => 0],
                'libera' => ['total_players' => 0, 'total_games' => 0, 'highest_score' => 0, 'total_pig_outs' => 0]
            ];
            
            $networks = ['rizon', 'libera'];
            foreach ($networks as $network) {
                $db_file = ConfigPaths::getDatabase($network);
                if (file_exists($db_file)) {
                    $pdo = new PDO("sqlite:$db_file");
                    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                    
                    // Get pigs stats from pigs_leaderboard table
                    $stmt = $pdo->query("
                        SELECT 
                            COUNT(*) as total_players,
                            MAX(highest_game_score) as highest_score,
                            SUM(pig_outs) as total_pig_outs
                        FROM pigs_leaderboard 
                        WHERE games_played > 0
                    ");
                    $pigs_stats = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    // Get total games from bot_stats table
                    $stmt = $pdo->query("SELECT stat_value FROM bot_stats WHERE stat_name = 'pigs_total_games'");
                    $total_games_result = $stmt->fetch(PDO::FETCH_ASSOC);
                    $total_games = (int)($total_games_result['stat_value'] ?? 0);
                    
                    $stats[$network] = [
                        'total_players' => (int)($pigs_stats['total_players'] ?? 0),
                        'total_games' => $total_games,
                        'highest_score' => (int)($pigs_stats['highest_score'] ?? 0),
                        'total_pig_outs' => (int)($pigs_stats['total_pig_outs'] ?? 0)
                    ];
                }
            }
            
            echo json_encode($stats);
            break;
            
        default:
            echo json_encode(['error' => 'Unknown action']);
    }
    
} catch (Exception $e) {
    echo json_encode(['error' => $e->getMessage()]);
}
?>