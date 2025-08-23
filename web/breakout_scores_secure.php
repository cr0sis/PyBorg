<?php
/**
 * SECURE Breakout Scores API - Complete rewrite with no client-side score acceptance
 * This version ONLY accepts server-side calculated and validated scores
 */

require_once 'security_config.php';
require_once 'input_sanitizer.php';
require_once 'config_paths.php';
require_once 'security_emergency_lockdown.php';
require_once 'secure_game_engine.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// EMERGENCY SECURITY LOCKDOWN CHECK
EmergencyLockdown::enforceLockdown();

try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Rate limiting for all POST requests
        if (!RateLimit::check($_SERVER['REMOTE_ADDR'] . '_secure_game', 5, 60)) {
            http_response_code(429);
            echo json_encode(['error' => 'Rate limit exceeded']);
            exit;
        }
        
        $raw_input = file_get_contents('php://input');
        $input = InputSanitizer::validateJSON($raw_input);
        
        if ($input === false) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid JSON data']);
            exit;
        }
        
        $action = $input['action'] ?? '';
        
        switch ($action) {
            case 'start_session':
                $player_name = InputSanitizer::validatePlayerName($input['player_name'] ?? '');
                if (empty($player_name)) {
                    http_response_code(400);
                    echo json_encode(['error' => 'Invalid player name']);
                    exit;
                }
                
                $session_data = SecureGameEngine::createSecureSession($player_name, $_SERVER['REMOTE_ADDR']);
                if ($session_data === false) {
                    http_response_code(500);
                    echo json_encode(['error' => 'Failed to create session']);
                    exit;
                }
                
                echo json_encode(['success' => true, 'session' => $session_data]);
                break;
                
            case 'game_event':
                $session_id = $input['session_id'] ?? '';
                $validation_token = $input['validation_token'] ?? '';
                $event_type = $input['event_type'] ?? '';
                $event_data = $input['event_data'] ?? [];
                $client_timestamp = $input['timestamp'] ?? time();
                
                if (empty($session_id) || empty($validation_token) || empty($event_type)) {
                    http_response_code(400);
                    echo json_encode(['error' => 'Missing required fields']);
                    exit;
                }
                
                $result = SecureGameEngine::processGameEvent($session_id, $validation_token, $event_type, $event_data, $client_timestamp);
                echo json_encode($result);
                break;
                
            case 'finalize_score':
                $session_id = $input['session_id'] ?? '';
                $validation_token = $input['validation_token'] ?? '';
                $final_game_state = $input['game_state'] ?? [];
                
                if (empty($session_id) || empty($validation_token)) {
                    http_response_code(400);
                    echo json_encode(['error' => 'Missing session data']);
                    exit;
                }
                
                $result = SecureGameEngine::finalizeGameScore($session_id, $validation_token, $final_game_state);
                echo json_encode($result);
                break;
                
            default:
                http_response_code(400);
                echo json_encode(['error' => 'Invalid action']);
        }
        
    } elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
        // Sanitize input
        $_GET = InputSanitizer::sanitizeAll($_GET);
        
        $action = $_GET['action'] ?? 'get_high_scores';
        
        switch ($action) {
            case 'get_scores':
            case 'get_high_scores':
            default:
                // Get high scores - only from validated secure submissions
                $limit = InputSanitizer::validateNumeric($_GET['limit'] ?? 10, 1, 50);
                
                $db_path = ConfigPaths::getDatabase('breakout_scores');
                $pdo = new PDO("sqlite:$db_path");
                $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                
                // Only return scores that were validated by the secure system
                $stmt = $pdo->prepare("SELECT player_name, score, level_reached, date_played 
                                      FROM breakout_scores 
                                      WHERE security_validated = TRUE AND server_side_calculated = TRUE
                                      ORDER BY score DESC, level_reached DESC 
                                      LIMIT ?");
                $stmt->execute([$limit]);
                $scores = $stmt->fetchAll(PDO::FETCH_ASSOC);
                echo json_encode($scores);
                break;
                
            case 'admin_get_all':
                // Admin-only: Get all scores including security metadata
                if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
                    http_response_code(403);
                    echo json_encode(['error' => 'Admin access required']);
                    exit;
                }
                
                $db_path = ConfigPaths::getDatabase('breakout_scores');
                $pdo = new PDO("sqlite:$db_path");
                $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                
                $stmt = $pdo->prepare("SELECT *, 
                                      CASE WHEN security_validated = TRUE THEN 'SECURE' ELSE 'LEGACY' END as validation_status
                                      FROM breakout_scores 
                                      ORDER BY date_played DESC");
                $stmt->execute();
                $scores = $stmt->fetchAll(PDO::FETCH_ASSOC);
                echo json_encode(['success' => true, 'scores' => $scores]);
                break;
        }
    }
    
} catch (PDOException $e) {
    http_response_code(500);
    error_log("Secure breakout scores database error: " . $e->getMessage());
    echo json_encode(['error' => 'Database error']);
} catch (Exception $e) {
    http_response_code(500);
    error_log("Secure breakout scores error: " . $e->getMessage());
    echo json_encode(['error' => 'Server error']);
}
?>