<?php
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

try {
    // Sanitize all input
    $_GET = InputSanitizer::sanitizeAll($_GET);
    $_POST = InputSanitizer::sanitizeAll($_POST);
    
    // Validate action parameter
    $action = InputSanitizer::validateAction($_GET['action'] ?? $_POST['action'] ?? 'pigs_stats');
    
    // Get network parameter
    $network = isset($_GET['network']) ? strtolower($_GET['network']) : 'rizon';
    $network = InputSanitizer::validatePlayerName($network); // Basic validation for network name
    
    // Construct database path (centralized data directory)
    $db_path = ConfigPaths::getDatabase($network . '_bot');
    
    if (!file_exists($db_path)) {
        echo json_encode([
            'error' => 'Database not found',
            'players' => [],
            'total_players' => 0,
            'total_games' => 0,
            'highest_score' => 0,
            'total_pig_outs' => 0
        ]);
        exit;
    }
    
    // Connect to SQLite database
    $pdo = new PDO("sqlite:$db_path");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Get leaderboard data with enhanced statistics
    $stmt = $pdo->prepare("
        SELECT 
            user,
            wins,
            games_played,
            total_rolls,
            total_score,
            highest_game_score,
            highest_turn_score,
            pig_outs,
            oinkers,
            last_game,
            total_banks,
            avg_rolls_before_bank,
            risk_tolerance_score,
            current_win_streak,
            longest_win_streak,
            current_no_pigout_streak,
            longest_no_pigout_streak,
            sides_rolled,
            razorbacks_rolled,
            trotters_rolled,
            snouters_rolled,
            leaning_jowlers_rolled,
            double_positions,
            double_razorback,
            double_trotter,
            double_snouter,
            double_leaning_jowler,
            fastest_win_seconds,
            longest_game_seconds,
            total_game_time_seconds,
            comeback_wins,
            close_wins,
            banks_under_10,
            banks_10_to_20,
            banks_20_to_30,
            banks_over_30,
            total_turns,
            successful_turns,
            games_this_week,
            games_this_month,
            weekend_games,
            weekday_games
        FROM pigs_leaderboard 
        ORDER BY wins DESC, highest_game_score DESC, total_score DESC
        LIMIT 50
    ");
    $stmt->execute();
    $players = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Get summary statistics
    $stats_stmt = $pdo->prepare("
        SELECT 
            COUNT(*) as total_players,
            MAX(highest_game_score) as highest_score,
            SUM(pig_outs) as total_pig_outs,
            SUM(oinkers) as total_oinkers
        FROM pigs_leaderboard
        WHERE games_played > 0
    ");
    $stats_stmt->execute();
    $stats = $stats_stmt->fetch(PDO::FETCH_ASSOC);
    
    // Get actual total games count from bot_stats
    $total_games_stmt = $pdo->prepare("SELECT stat_value FROM bot_stats WHERE stat_name = 'pigs_total_games'");
    $total_games_stmt->execute();
    $total_games_result = $total_games_stmt->fetch(PDO::FETCH_ASSOC);
    $total_games = (int)($total_games_result['stat_value'] ?? 0);
    
    // Get database sync time
    $db_sync_time = file_exists($db_path) ? filemtime($db_path) : time();
    
    // Format response
    $response = [
        'players' => $players,
        'total_players' => (int)($stats['total_players'] ?? 0),
        'total_games' => $total_games,
        'highest_score' => (int)($stats['highest_score'] ?? 0),
        'total_pig_outs' => (int)($stats['total_pig_outs'] ?? 0),
        'total_oinkers' => (int)($stats['total_oinkers'] ?? 0),
        'network' => $network,
        'last_updated' => date('c', $db_sync_time)
    ];
    
    echo json_encode($response);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'error' => 'Database error: ' . $e->getMessage(),
        'players' => [],
        'total_players' => 0,
        'total_games' => 0,
        'highest_score' => 0,
        'total_pig_outs' => 0
    ]);
}
?>