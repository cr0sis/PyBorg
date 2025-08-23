<?php
/**
 * UNO Leaderboard API
 * Serves UNO game statistics from SQLite database
 */

require_once '../security_config.php';
require_once '../security_middleware.php';
require_once '../input_sanitizer.php';
require_once '../config_paths.php';

// Initialize security - public endpoint, no admin access required
// SecurityMiddleware::validateAdminAccess(); // Removed - this is a public leaderboard

header('Content-Type: application/json');
// Secure CORS implementation
SecurityMiddleware::generateSecureCORS();
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type');

// Database configuration
$rizon_db_path = ConfigPaths::getDatabase('rizon');
$libera_db_path = ConfigPaths::getDatabase('libera');

/**
 * Get UNO leaderboard from database
 */
function getUnoLeaderboard($db_path, $limit = 50) {
    try {
        if (!file_exists($db_path)) {
            return [];
        }

        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->prepare("
            SELECT 
                user as player,
                wins,
                games_played as games,
                total_cards_played,
                avg_cards_per_game,
                CAST(wins AS REAL) / games_played as win_rate,
                (CAST(wins AS REAL) / games_played * 100) as win_percentage,
                last_game,
                wild_cards_played,
                plus4_cards_played,
                plus2_cards_played,
                skip_cards_played,
                reverse_cards_played,
                successful_uno_calls,
                caught_no_uno,
                successful_challenges,
                failed_challenges,
                times_challenged,
                fastest_game_seconds,
                longest_game_seconds,
                total_game_time_seconds,
                largest_hand_size,
                comeback_wins,
                uno_wins,
                current_win_streak,
                longest_win_streak,
                red_cards_played,
                blue_cards_played,
                green_cards_played,
                yellow_cards_played,
                games_this_week,
                games_this_month,
                weekend_games,
                weekday_games
            FROM uno_leaderboard 
            WHERE games_played > 0
            ORDER BY win_rate DESC, avg_cards_per_game ASC
            LIMIT :limit
        ");
        
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        
        $results = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            // Calculate derived statistics
            $challenge_success_rate = ($row['times_challenged'] > 0) ? 
                round(($row['successful_challenges'] / $row['times_challenged']) * 100, 1) : 0;
            $uno_call_success_rate = ($row['successful_uno_calls'] > 0) ? 
                round(($row['successful_uno_calls'] / ($row['successful_uno_calls'] + $row['caught_no_uno'])) * 100, 1) : 0;
            $avg_game_time = ($row['games'] > 0 && $row['total_game_time_seconds'] > 0) ? 
                round($row['total_game_time_seconds'] / $row['games']) : 0;
            
            // Calculate color distribution
            $total_color_cards = $row['red_cards_played'] + $row['blue_cards_played'] + 
                               $row['green_cards_played'] + $row['yellow_cards_played'];
            $color_preference = 'None';
            if ($total_color_cards > 0) {
                $colors = [
                    'Red' => $row['red_cards_played'],
                    'Blue' => $row['blue_cards_played'], 
                    'Green' => $row['green_cards_played'],
                    'Yellow' => $row['yellow_cards_played']
                ];
                $color_preference = array_keys($colors, max($colors))[0];
            }
            
            // Format data with comprehensive statistics
            $results[] = [
                // Basic stats
                'player' => $row['player'],
                'games_played' => (int)$row['games'],
                'wins' => (int)$row['wins'],
                'win_rate' => round($row['win_rate'] * 100, 1),
                'last_game' => $row['last_game'],
                
                // Card stats
                'total_cards_played' => (int)$row['total_cards_played'],
                'avg_cards_per_game' => round($row['avg_cards_per_game'], 1),
                
                // Special card stats
                'wild_cards_played' => (int)$row['wild_cards_played'],
                'plus4_cards_played' => (int)$row['plus4_cards_played'],
                'plus2_cards_played' => (int)$row['plus2_cards_played'],
                'skip_cards_played' => (int)$row['skip_cards_played'],
                'reverse_cards_played' => (int)$row['reverse_cards_played'],
                
                // UNO mechanics
                'successful_uno_calls' => (int)$row['successful_uno_calls'],
                'caught_no_uno' => (int)$row['caught_no_uno'],
                'uno_call_success_rate' => $uno_call_success_rate,
                
                // Challenge stats
                'successful_challenges' => (int)$row['successful_challenges'],
                'failed_challenges' => (int)$row['failed_challenges'],
                'times_challenged' => (int)$row['times_challenged'],
                'challenge_success_rate' => $challenge_success_rate,
                
                // Timing stats
                'fastest_game_seconds' => (int)$row['fastest_game_seconds'],
                'longest_game_seconds' => (int)$row['longest_game_seconds'],
                'total_game_time_seconds' => (int)$row['total_game_time_seconds'],
                'avg_game_time_seconds' => $avg_game_time,
                
                // Achievement stats
                'largest_hand_size' => (int)$row['largest_hand_size'],
                'comeback_wins' => (int)$row['comeback_wins'],
                'uno_wins' => (int)$row['uno_wins'],
                'current_win_streak' => (int)$row['current_win_streak'],
                'longest_win_streak' => (int)$row['longest_win_streak'],
                
                // Color distribution
                'red_cards_played' => (int)$row['red_cards_played'],
                'blue_cards_played' => (int)$row['blue_cards_played'],
                'green_cards_played' => (int)$row['green_cards_played'],
                'yellow_cards_played' => (int)$row['yellow_cards_played'],
                'favorite_color' => $color_preference,
                
                // Temporal stats
                'games_this_week' => (int)$row['games_this_week'],
                'games_this_month' => (int)$row['games_this_month'],
                'weekend_games' => (int)$row['weekend_games'],
                'weekday_games' => (int)$row['weekday_games'],
                
                // Backwards compatibility
                'total_score' => (int)$row['total_cards_played'],
                'avg_score' => round($row['avg_cards_per_game'], 1)
            ];
        }
        
        return $results;
        
    } catch (PDOException $e) {
        error_log("Database error: " . $e->getMessage());
        return [];
    }
}

/**
 * Get total games count from database
 * Counts unique games by grouping players with same last_game timestamp
 */
function getTotalGames($db_path) {
    try {
        if (!file_exists($db_path)) {
            return 0;
        }

        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Get actual total games count from bot_stats
        $stmt = $pdo->prepare("SELECT stat_value FROM bot_stats WHERE stat_name = 'uno_total_games'");
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        return (int)($result['stat_value'] ?? 0);
        
    } catch (PDOException $e) {
        error_log("Database error: " . $e->getMessage());
        return 0;
    }
}

// Sanitize all input
$_GET = InputSanitizer::sanitizeAll($_GET);
$_POST = InputSanitizer::sanitizeAll($_POST);

// Validate action parameter
$action = InputSanitizer::validateAction($_GET['action'] ?? $_POST['action'] ?? 'uno_stats');

// Build response data
// Get the most recent database sync time
$rizon_mtime = file_exists($rizon_db_path) ? filemtime($rizon_db_path) : 0;
$libera_mtime = file_exists($libera_db_path) ? filemtime($libera_db_path) : 0;
$latest_sync = max($rizon_mtime, $libera_mtime);

$response = [
    'networks' => [
        'Rizon' => [
            'total_games' => getTotalGames($rizon_db_path),
            'players' => getUnoLeaderboard($rizon_db_path)
        ],
        'Libera' => [
            'total_games' => getTotalGames($libera_db_path),
            'players' => getUnoLeaderboard($libera_db_path)
        ]
    ],
    'last_updated' => date('c', $latest_sync), // Use actual database sync time
    'status' => 'success'
];

// Output JSON response
echo json_encode($response, JSON_PRETTY_PRINT);
?>