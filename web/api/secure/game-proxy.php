<?php
/**
 * Secure Game API Proxy
 * Handles game operations with anti-cheat validation
 * Prevents client-side manipulation of game logic
 */

require_once '../../security_config.php';
require_once '../../GameSession.php';
require_once '../../crypto_utils.php';
require_once '../../emergency_security.php';

// Initialize secure session (handles session_start properly)
initSecureSession();

// Force JSON response
header('Content-Type: application/json');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

/**
 * Secure operation validator
 */
function validateGameOperation($operation, $data) {
    $allowed_operations = [
        'start_session',
        'validate_score', 
        'submit_score',
        'get_leaderboard',
        'health_check'
    ];
    
    if (!in_array($operation, $allowed_operations)) {
        return false;
    }
    
    return true;
}

/**
 * Generate secure game token with cryptographic validation
 */
function generateGameToken($session_data) {
    $payload = [
        'session_id' => $session_data['session_id'],
        'start_time' => $session_data['start_time'],
        'user_ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent_hash' => hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'),
        'timestamp' => time(),
        'nonce' => bin2hex(random_bytes(16))
    ];
    
    return CryptoUtils::generateSecureToken($payload);
}

/**
 * Validate game token
 */
function validateGameToken($token, $session_id) {
    try {
        $payload = CryptoUtils::validateSecureToken($token);
        
        if (!$payload || 
            $payload['session_id'] !== $session_id ||
            $payload['user_ip'] !== $_SERVER['REMOTE_ADDR'] ||
            (time() - $payload['timestamp']) > 3600) { // 1 hour timeout
            return false;
        }
        
        return $payload;
    } catch (Exception $e) {
        return false;
    }
}

// Enhanced input validation
$rawInput = file_get_contents('php://input');
$input = HardcoreSecurityManager::safeJSONParse($rawInput);

if ($input === false) {
    logSecurityEvent('GAME_ATTACK', 'Invalid JSON in game proxy', 'HIGH');
    // Debug log the raw input for troubleshooting
    error_log("GAME_PROXY_DEBUG: Raw input that failed JSON parse: " . substr($rawInput, 0, 500));
    http_response_code(400);
    echo json_encode(['error' => 'INVALID_INPUT', 'message' => 'Request format error']);
    exit;
}

$operation = $input['op'] ?? '';
$gameToken = $input['token'] ?? '';

if (!validateGameOperation($operation, $input)) {
    logSecurityEvent('GAME_INVALID_OP', "Invalid game operation: $operation", 'MEDIUM');
    // Debug log the operation and input for troubleshooting
    error_log("GAME_PROXY_DEBUG: Invalid operation '$operation' with input: " . json_encode($input));
    http_response_code(400);
    echo json_encode(['error' => 'INVALID_OPERATION', 'message' => 'Operation not supported']);
    exit;
}

switch ($operation) {
    case 'start_session':
        $game_type = $input['game_type'] ?? 'breakout';
        $player_name = $input['player_name'] ?? 'Anonymous';
        
        // Validate game type
        $allowed_games = ['breakout', 'pigs'];
        if (!in_array($game_type, $allowed_games)) {
            echo json_encode(['error' => 'INVALID_GAME', 'message' => 'Game type not supported']);
            exit;
        }
        
        // Create secure game session
        $session_data = GameSession::startSession($game_type, $player_name);
        
        if ($session_data) {
            $secure_token = generateGameToken($session_data);
            
            logSecurityEvent('GAME_SESSION_START', 
                "Game session started: {$session_data['session_id']} for $player_name", 'LOW');
            
            echo json_encode([
                'success' => true,
                'session_id' => $session_data['session_id'],
                'secure_token' => $secure_token,
                'validation_hash' => $session_data['validation_hash'],
                'expires' => time() + 3600
            ]);
        } else {
            echo json_encode(['error' => 'SESSION_FAILED', 'message' => 'Could not create game session']);
        }
        break;
        
    case 'validate_score':
        $session_id = $input['session_id'] ?? '';
        $score = intval($input['score'] ?? 0);
        $level = intval($input['level'] ?? 1);
        $game_data = $input['game_data'] ?? [];
        
        if (!validateGameToken($gameToken, $session_id)) {
            logSecurityEvent('GAME_TOKEN_INVALID', 
                "Invalid game token for session: $session_id", 'HIGH');
            echo json_encode(['error' => 'TOKEN_INVALID', 'message' => 'Game token validation failed']);
            exit;
        }
        
        // Validate score using comprehensive anti-cheat
        $validation_result = GameSession::validateScore($session_id, $score, $level, $game_data);
        
        if ($validation_result['valid']) {
            echo json_encode([
                'success' => true,
                'valid' => true,
                'checksum' => $validation_result['checksum'],
                'message' => 'Score validation passed'
            ]);
        } else {
            logSecurityEvent('GAME_CHEAT_DETECTED', 
                "Cheating detected in session $session_id: {$validation_result['reason']}", 'HIGH');
            echo json_encode([
                'success' => false,
                'valid' => false,
                'reason' => 'Score validation failed',
                'message' => 'Invalid game data detected'
            ]);
        }
        break;
        
    case 'submit_score':
        $session_id = $input['session_id'] ?? '';
        $player_name = $input['player_name'] ?? 'Anonymous';
        $score = intval($input['score'] ?? 0);
        $level = intval($input['level'] ?? 1);
        $validation_checksum = $input['checksum'] ?? '';
        
        if (!validateGameToken($gameToken, $session_id)) {
            logSecurityEvent('GAME_SUBMIT_INVALID', 
                "Invalid token for score submission: $session_id", 'HIGH');
            echo json_encode(['error' => 'TOKEN_INVALID', 'message' => 'Submission token invalid']);
            exit;
        }
        
        // Submit score through secure validation
        $result = GameSession::submitSecureScore($session_id, $player_name, $score, $level, $validation_checksum);
        
        if ($result['success']) {
            logSecurityEvent('GAME_SCORE_SUBMITTED', 
                "Score submitted: $player_name scored $score on level $level", 'LOW');
            echo json_encode($result);
        } else {
            logSecurityEvent('GAME_SUBMIT_FAILED', 
                "Score submission failed: {$result['message']}", 'MEDIUM');
            echo json_encode($result);
        }
        break;
        
    case 'get_leaderboard':
        $game_type = $input['game_type'] ?? 'breakout';
        $limit = min(intval($input['limit'] ?? 10), 50); // Max 50 entries
        
        try {
            // Get leaderboard data (cached for performance)
            $cache_key = "leaderboard_{$game_type}_{$limit}";
            $cache_file = "/tmp/{$cache_key}.json";
            
            if (file_exists($cache_file) && (time() - filemtime($cache_file)) < 300) { // 5 min cache
                $leaderboard = json_decode(file_get_contents($cache_file), true);
            } else {
                require_once '../../breakout_scores.php';
                
                if ($game_type === 'breakout') {
                    $leaderboard = getBreakoutLeaderboard($limit);
                } else {
                    $leaderboard = getPigsLeaderboard($limit);
                }
                
                file_put_contents($cache_file, json_encode($leaderboard));
            }
            
            echo json_encode([
                'success' => true,
                'leaderboard' => $leaderboard,
                'game_type' => $game_type,
                'cached' => isset($cached)
            ]);
            
        } catch (Exception $e) {
            echo json_encode(['error' => 'LEADERBOARD_ERROR', 'message' => 'Could not load leaderboard']);
        }
        break;
        
    case 'health_check':
        // Simple health check for game systems
        echo json_encode([
            'success' => true,
            'status' => 'healthy',
            'timestamp' => time(),
            'game_systems' => 'online',
            'anti_cheat' => 'active'
        ]);
        break;
        
    default:
        logSecurityEvent('GAME_UNKNOWN_OP', "Unknown game operation: $operation", 'MEDIUM');
        http_response_code(400);
        echo json_encode(['error' => 'UNKNOWN_OPERATION', 'message' => 'Operation not recognized']);
        break;
}

// Log successful completion
logSecurityEvent('GAME_OP_COMPLETE', "Game operation '$operation' completed", 'LOW');
?>