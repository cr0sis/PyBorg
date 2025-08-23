<?php
// Minimal working score submission API
session_start();
require_once 'config_paths.php';
require_once 'user_color_system.php';
require_once 'input_sanitizer.php';

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
    
    // Create table if it doesn't exist
    $pdo->exec("CREATE TABLE IF NOT EXISTS breakout_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        player_name TEXT NOT NULL,
        score INTEGER NOT NULL,
        level_reached INTEGER NOT NULL,
        date_played DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        session_id TEXT,
        validation_hash TEXT,
        color_hex TEXT
    )");
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $raw_input = file_get_contents('php://input');
        $input = json_decode($raw_input, true);
        
        if (!$input || !isset($input['player_name']) || !isset($input['score']) || !isset($input['level_reached'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing required fields']);
            exit;
        }
        
        $player_name = substr(trim($input['player_name']), 0, 20);
        $score = max(0, intval($input['score']));
        $level_reached = max(1, intval($input['level_reached']));
        $session_id = $input['session_id'] ?? '';
        
        // Simple validation - prevent empty names
        if (empty($player_name)) {
            http_response_code(400);
            echo json_encode(['error' => 'Player name cannot be empty']);
            exit;
        }
        
        // Check if user is authenticated for bypass
        $is_authenticated = isset($_SESSION['username']) && isset($_SESSION['user_id']);
        
        if ($is_authenticated) {
            // Authenticated users get bypass
            $validation_passed = true;
        } else {
            // For anonymous users, do basic session validation
            if (empty($session_id)) {
                http_response_code(400);
                echo json_encode(['error' => 'Session required']);
                exit;
            }
            $validation_passed = true; // Allow for now, can add validation later
        }
        
        // Get user's color
        $current_color = getUserColor($player_name, $is_authenticated);
        
        // Generate validation hash
        $validation_hash = hash('sha256', $player_name . $score . $level_reached . time() . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        
        // Insert score
        $stmt = $pdo->prepare("INSERT INTO breakout_scores (player_name, score, level_reached, ip_address, session_id, validation_hash, color_hex) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$player_name, $score, $level_reached, $_SERVER['REMOTE_ADDR'] ?? 'unknown', $session_id, $validation_hash, $current_color]);
        $new_id = $pdo->lastInsertId();
        
        echo json_encode(['success' => true, 'id' => $new_id]);
    }
    
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}
?>