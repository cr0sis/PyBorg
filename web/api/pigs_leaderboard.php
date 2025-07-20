<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type');

try {
    // Get network parameter
    $network = isset($_GET['network']) ? strtolower($_GET['network']) : 'example';
    
    // Construct database path
    $db_path = "../data/{$network}_bot.db";
    
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
    
    // Get leaderboard data
    $stmt = $pdo->prepare("
        SELECT 
            user,
            wins,
            games_played,
            total_score,
            highest_game_score,
            highest_turn_score,
            pig_outs,
            oinkers,
            last_game
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
            SUM(games_played) as total_games,
            MAX(highest_game_score) as highest_score,
            SUM(pig_outs) as total_pig_outs,
            SUM(oinkers) as total_oinkers
        FROM pigs_leaderboard
    ");
    $stats_stmt->execute();
    $stats = $stats_stmt->fetch(PDO::FETCH_ASSOC);
    
    // Format response
    $response = [
        'players' => $players,
        'total_players' => (int)($stats['total_players'] ?? 0),
        'total_games' => (int)($stats['total_games'] ?? 0),
        'highest_score' => (int)($stats['highest_score'] ?? 0),
        'total_pig_outs' => (int)($stats['total_pig_outs'] ?? 0),
        'total_oinkers' => (int)($stats['total_oinkers'] ?? 0),
        'network' => $network,
        'last_updated' => date('c')
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