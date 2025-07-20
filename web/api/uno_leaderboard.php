<?php
/**
 * UNO Leaderboard API
 * Serves UNO game statistics from SQLite database
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type');

// Database configuration
$rizon_db_path = '/var/www/html/data/rizon_bot.db';
$libera_db_path = '/var/www/html/data/libera_bot.db';

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
                last_game
            FROM uno_leaderboard 
            WHERE games_played > 0
            ORDER BY win_rate DESC, avg_cards_per_game ASC
            LIMIT :limit
        ");
        
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        
        $results = [];
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            // Format data to match expected structure
            $results[] = [
                'player' => $row['player'],
                'total_score' => 0, // Legacy field for compatibility
                'games_played' => (int)$row['games'],
                'wins' => (int)$row['wins'],
                'avg_score' => round($row['avg_cards_per_game'], 1),
                'win_rate' => round($row['win_rate'] * 100, 1),
                'total_cards_played' => (int)$row['total_cards_played'],
                'last_game' => $row['last_game']
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
 */
function getTotalGames($db_path) {
    try {
        if (!file_exists($db_path)) {
            return 0;
        }

        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->query("SELECT SUM(games_played) as total FROM uno_leaderboard");
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        return (int)($result['total'] ?? 0);
        
    } catch (PDOException $e) {
        error_log("Database error: " . $e->getMessage());
        return 0;
    }
}

// Build response data
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
    'last_updated' => date('c'), // ISO 8601 format
    'status' => 'success'
];

// Output JSON response
echo json_encode($response, JSON_PRETTY_PRINT);
?>