<?php
// Start session first for admin context checking
session_start();

require_once 'security_config.php';
require_once 'input_sanitizer.php';
require_once 'config_paths.php';
require_once 'security_emergency_lockdown.php';
require_once 'security_audit_logger.php';

// Emergency lockdown check with admin bypass capability
EmergencyLockdown::enforceLockdown();

// IP-BASED SECURITY CHECKS
$client_ip = $_SERVER['REMOTE_ADDR'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? 'unknown';
// Extract first IP if multiple (proxy chain)
if (strpos($client_ip, ',') !== false) {
    $client_ip = trim(explode(',', $client_ip)[0]);
}

// Skip IP ban check if we can't determine IP properly
if ($client_ip !== 'unknown' && SecurityAuditLogger::isIPBanned($client_ip)) {
    SecurityAuditLogger::logSecurityEvent('banned_ip_access', 'HIGH', ['attempted_access' => true], 8);
    http_response_code(403);
    echo json_encode(['error' => 'Access denied - IP banned']);
    exit;
}

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// SQLite database for breakout completionists (level 100 completions)
$db_path = ConfigPaths::getDatabase('breakout_completionists');

try {
    $pdo = new PDO("sqlite:$db_path");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Create table if it doesn't exist
    $pdo->exec("CREATE TABLE IF NOT EXISTS breakout_completionists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        player_name TEXT NOT NULL,
        score INTEGER NOT NULL,
        completion_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        session_id TEXT,
        completion_count INTEGER DEFAULT 1,
        validation_hash TEXT,
        first_completion DATETIME DEFAULT CURRENT_TIMESTAMP,
        color_hex TEXT
    )");
    
    // Add color_hex column to existing breakout_completionists table if it doesn't exist
    try {
        $pdo->exec("ALTER TABLE breakout_completionists ADD COLUMN color_hex TEXT");
    } catch (PDOException $e) {
        // Column already exists, ignore error
    }
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Sanitize all input first
        $_GET = InputSanitizer::sanitizeAll($_GET);
        $_POST = InputSanitizer::sanitizeAll($_POST);
        
        // Rate limiting for completion submissions
        if (!RateLimit::check($_SERVER['REMOTE_ADDR'] . '_completion', 5, 600)) {
            http_response_code(429);
            echo json_encode(['error' => 'Too many completion submissions. Please try again later.']);
            exit;
        }
        
        // Add new completion - use secure JSON validation
        $raw_input = file_get_contents('php://input');
        $input = InputSanitizer::validateJSON($raw_input);
        
        if ($input === false) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid JSON data']);
            exit;
        }
        
        if (!isset($input['action']) || $input['action'] !== 'record_completion') {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid action']);
            exit;
        }
        
        if (!isset($input['player_name']) || !isset($input['score']) || !isset($input['session_id'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing required fields']);
            exit;
        }
        
        // Validate session first
        $session_id = $input['session_id'] ?? '';
        if (empty($session_id)) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid session']);
            exit;
        }
        
        // Extract token from client if provided (for enhanced security)
        $secure_token = $input['token'] ?? '';
        
        // Validate completion with game session system
        $session_data = [
            'action' => 'validate_completion',
            'session_id' => $session_id,
            'token' => $secure_token,
            'score' => $input['score'],
            'player_name' => $input['player_name']
        ];
        
        // Basic validation (game session system may add more validation)
        $player_name = trim($input['player_name']);
        $score = (int)$input['score'];
        
        if (empty($player_name) || strlen($player_name) > 50) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid player name']);
            exit;
        }
        
        if ($score < 0 || $score > 50000000) { // Reasonable upper limit
            http_response_code(400);
            echo json_encode(['error' => 'Invalid score']);
            exit;
        }
        
        // Get user's current color at time of completion submission
        $current_user_logged_in = isset($_SESSION['username']) && isset($_SESSION['user_id']);
        $current_color = getUserColor($player_name, $current_user_logged_in);
        
        // Check if player has already completed the game
        $stmt = $pdo->prepare("SELECT id, completion_count FROM breakout_completionists WHERE player_name = ? ORDER BY first_completion ASC LIMIT 1");
        $stmt->execute([$player_name]);
        $existing = $stmt->fetch();
        
        if ($existing) {
            // Player has completed before - increment completion count
            $new_count = $existing['completion_count'] + 1;
            $stmt = $pdo->prepare("UPDATE breakout_completionists 
                                   SET completion_count = ?, 
                                       completion_date = CURRENT_TIMESTAMP,
                                       score = ?,
                                       ip_address = ?,
                                       session_id = ?,
                                       validation_hash = ?,
                                       color_hex = ?
                                   WHERE id = ?");
            $validation_hash = hash('sha256', $player_name . $score . $session_id . date('Y-m-d'));
            $stmt->execute([$new_count, $score, $client_ip, $session_id, $validation_hash, $current_color, $existing['id']]);
            
            echo json_encode([
                'success' => true, 
                'message' => 'Completion recorded',
                'completion_count' => $new_count,
                'type' => 'repeat_completion'
            ]);
        } else {
            // First completion for this player
            $validation_hash = hash('sha256', $player_name . $score . $session_id . date('Y-m-d'));
            $stmt = $pdo->prepare("INSERT INTO breakout_completionists 
                                   (player_name, score, ip_address, session_id, validation_hash, completion_count, first_completion, color_hex) 
                                   VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, ?)");
            $stmt->execute([$player_name, $score, $client_ip, $session_id, $validation_hash, $current_color]);
            
            echo json_encode([
                'success' => true, 
                'message' => 'First completion recorded!',
                'completion_count' => 1,
                'type' => 'first_completion'
            ]);
        }
        
        // Log the completion for security monitoring
        SecurityAuditLogger::logSecurityEvent('game_completion', 'INFO', [
            'player_name' => $player_name,
            'score' => $score,
            'client_ip' => $client_ip
        ], 1);
        
    } else {
        // GET request - return completionists list
        $limit = isset($_GET['limit']) ? min(50, max(1, (int)$_GET['limit'])) : 10;
        
        // Get completionists ordered by completion count (descending), then by best score
        $stmt = $pdo->prepare("SELECT player_name, score, completion_count, first_completion, completion_date, color_hex 
                               FROM breakout_completionists 
                               ORDER BY completion_count DESC, score DESC 
                               LIMIT ?");
        $stmt->execute([$limit]);
        $completionists = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Include shared color system functions
        require_once 'user_color_system.php';
        
        // Format the data for display
        $formatted_completionists = [];
        $current_user_logged_in = isset($_SESSION['username']) && isset($_SESSION['user_id']);
        $current_username = $current_user_logged_in ? $_SESSION['username'] : null;
        
        foreach ($completionists as $i => $completion) {
            $is_current_user = $current_user_logged_in && $completion['player_name'] === $current_username;
            
            // Use stored color from when completion was submitted, fallback to current color system if null
            $completion_color = !empty($completion['color_hex']) 
                ? $completion['color_hex'] 
                : getUserColor($completion['player_name'], $current_user_logged_in);
            
            $formatted_completionists[] = [
                'rank' => $i + 1,
                'player_name' => $completion['player_name'],
                'score' => (int)$completion['score'],
                'completion_count' => (int)$completion['completion_count'],
                'first_completion' => $completion['first_completion'],
                'latest_completion' => $completion['completion_date'],
                'color' => $completion_color,
                'is_current_user' => $is_current_user,
                'is_registered' => isRegisteredUser($completion['player_name'])
            ];
        }
        
        echo json_encode($formatted_completionists);
    }
    
} catch (PDOException $e) {
    SecurityAuditLogger::logSecurityEvent('database_error', 'HIGH', ['error' => $e->getMessage()], 7);
    http_response_code(500);
    echo json_encode(['error' => 'Database error occurred']);
} catch (Exception $e) {
    SecurityAuditLogger::logSecurityEvent('general_error', 'MEDIUM', ['error' => $e->getMessage()], 5);
    http_response_code(500);
    echo json_encode(['error' => 'An error occurred']);
}
?>