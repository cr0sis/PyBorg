<?php
// Minimal working scores API
session_start();
require_once 'config_paths.php';
require_once 'user_color_system.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

try {
    $db_path = ConfigPaths::getDatabase('breakout_scores');
    $pdo = new PDO("sqlite:$db_path");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $limit = isset($_GET['limit']) ? max(1, min(50, intval($_GET['limit']))) : 10;
        
        $stmt = $pdo->prepare("SELECT player_name, score, level_reached, date_played, color_hex 
                              FROM breakout_scores 
                              ORDER BY score DESC, level_reached DESC 
                              LIMIT ?");
        $stmt->execute([$limit]);
        $scores = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        $current_user_logged_in = isset($_SESSION['username']) && isset($_SESSION['user_id']);
        $current_username = $current_user_logged_in ? $_SESSION['username'] : null;
        
        foreach ($scores as &$score) {
            $is_current_user = $current_user_logged_in && $score['player_name'] === $current_username;
            $score['color'] = getUserColor($score['player_name'], false);
            $score['is_current_user'] = $is_current_user;
            $score['is_registered'] = false;
        }
        
        echo json_encode($scores);
    }
    
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}
?>