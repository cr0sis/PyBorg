<?php
require_once 'security_config.php';
require_once 'input_sanitizer.php';
require_once 'config_paths.php';
require_once 'crypto_utils.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Game session tracking database
$db_path = ConfigPaths::getDatabase('game_sessions');

try {
    $pdo = new PDO("sqlite:$db_path");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Create session table
    $pdo->exec("CREATE TABLE IF NOT EXISTS game_sessions (
        session_id TEXT PRIMARY KEY,
        secure_token TEXT NOT NULL,
        player_name TEXT NOT NULL,
        start_time INTEGER NOT NULL,
        last_update INTEGER NOT NULL,
        current_level INTEGER DEFAULT 1,
        blocks_destroyed INTEGER DEFAULT 0,
        lives_lost INTEGER DEFAULT 0,
        powerups_collected INTEGER DEFAULT 0,
        game_duration INTEGER DEFAULT 0,
        ip_address TEXT,
        user_agent TEXT,
        game_state_hash TEXT,
        behavior_flags TEXT,
        status TEXT DEFAULT 'active'
    )");
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Enhanced IP detection for proxy/CDN environments
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? 'unknown';
        // Extract first IP if multiple (proxy chain)
        if (strpos($client_ip, ',') !== false) {
            $client_ip = trim(explode(',', $client_ip)[0]);
        }
        
        // Check if IP is blocked
        $blocked_ips_file = '/tmp/blocked_ips.txt';
        if (file_exists($blocked_ips_file) && $client_ip !== 'unknown') {
            $blocked_ips = file($blocked_ips_file, FILE_IGNORE_NEW_LINES);
            if (in_array($client_ip, $blocked_ips)) {
                http_response_code(403);
                echo json_encode(['error' => 'Access denied - IP blocked']);
                exit;
            }
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
                // Rate limiting for session creation
                if (!RateLimit::check($_SERVER['REMOTE_ADDR'] . '_session', 5, 60)) {
                    http_response_code(429);
                    echo json_encode(['error' => 'Too many session requests']);
                    exit;
                }
                
                // Generate secure session ID and cryptographic token
                $session_id = bin2hex(random_bytes(32)); // Increased length
                $player_name = InputSanitizer::validatePlayerName($input['player_name'] ?? 'Anonymous');
                $start_time = time();
                
                // Create cryptographic token with session data
                $token_data = [
                    'session_id' => $session_id,
                    'player_name' => $player_name,
                    'start_time' => $start_time,
                    'ip_hash' => hash('sha256', $_SERVER['REMOTE_ADDR'] . CryptoUtils::getSecretKey())
                ];
                $secure_token = CryptoUtils::generateSecureToken($token_data);
                $game_state_hash = CryptoUtils::generateGameStateHash(['start_time' => $start_time]);
                
                $stmt = $pdo->prepare("INSERT INTO game_sessions 
                    (session_id, secure_token, player_name, start_time, last_update, ip_address, user_agent, game_state_hash) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
                $stmt->execute([
                    $session_id, 
                    $secure_token, 
                    $player_name, 
                    $start_time, 
                    $start_time, 
                    $_SERVER['REMOTE_ADDR'],
                    $_SERVER['HTTP_USER_AGENT'] ?? '',
                    $game_state_hash
                ]);
                
                // Return obfuscated response
                $response = CryptoUtils::obfuscateResponse([
                    'session_id' => $session_id,
                    'token' => $secure_token
                ]);
                echo json_encode($response);
                break;
                
            case 'update_session':
                $session_id = $input['session_id'] ?? '';
                $level = InputSanitizer::validateNumeric($input['level'] ?? 1, 1, 100);
                $blocks_destroyed = InputSanitizer::validateNumeric($input['blocks_destroyed'] ?? 0, 0, 10000);
                $lives_lost = InputSanitizer::validateNumeric($input['lives_lost'] ?? 0, 0, 10);
                $powerups_collected = InputSanitizer::validateNumeric($input['powerups_collected'] ?? 0, 0, 1000);
                
                if (empty($session_id)) {
                    http_response_code(400);
                    echo json_encode(['error' => 'Invalid session ID']);
                    exit;
                }
                
                // Verify session exists and is active
                $stmt = $pdo->prepare("SELECT start_time, current_level, blocks_destroyed FROM game_sessions WHERE session_id = ? AND status = 'active'");
                $stmt->execute([$session_id]);
                $session = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if (!$session) {
                    http_response_code(404);
                    echo json_encode(['error' => 'Session not found or expired']);
                    exit;
                }
                
                // Validate progression makes sense
                $game_duration = time() - $session['start_time'];
                if ($level < $session['current_level'] || 
                    $blocks_destroyed < $session['blocks_destroyed'] ||
                    $game_duration < 10) { // Minimum 10 seconds
                    
                    http_response_code(400);
                    echo json_encode(['error' => 'Invalid game progression']);
                    exit;
                }
                
                // Update session
                $stmt = $pdo->prepare("UPDATE game_sessions SET 
                    current_level = ?, blocks_destroyed = ?, lives_lost = ?, 
                    powerups_collected = ?, game_duration = ?, last_update = ?
                    WHERE session_id = ?");
                $stmt->execute([$level, $blocks_destroyed, $lives_lost, $powerups_collected, 
                    $game_duration, time(), $session_id]);
                
                echo json_encode(['success' => true]);
                break;
                
            case 'validate_score':
                $session_id = $input['session_id'] ?? '';
                $secure_token = $input['token'] ?? '';
                $final_score = InputSanitizer::validateNumeric($input['score'] ?? 0, 0, 999999);
                $final_level = InputSanitizer::validateNumeric($input['level'] ?? 1, 1, 100);
                
                if (empty($session_id) || empty($secure_token)) {
                    http_response_code(400);
                    echo json_encode(['error' => 'Missing authentication data']);
                    exit;
                }
                
                // Validate cryptographic token first with fallback
                $token_data = CryptoUtils::validateSecureToken($secure_token);
                $crypto_valid = ($token_data && $token_data['session_id'] === $session_id);
                
                if (!$crypto_valid) {
                    // Crypto validation failed - check if we can fall back to basic session validation
                    error_log("Crypto token validation failed for session $session_id - attempting fallback validation");
                    
                    // For fallback, we'll validate the session exists and is reasonably recent
                    $stmt = $pdo->prepare("SELECT * FROM game_sessions WHERE session_id = ? AND status IN ('active', 'completed')");
                    $stmt->execute([$session_id]);
                    $session = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    if (!$session) {
                        error_log("Fallback validation failed - session not found: $session_id");
                        http_response_code(403);
                        echo json_encode(['error' => 'Authentication failed']);
                        exit;
                    }
                    
                    // Check if session is too old (prevent replay attacks)
                    $session_age = time() - $session['start_time'];
                    if ($session_age > 7200) { // 2 hours max
                        error_log("Fallback validation failed - session too old: $session_id");
                        http_response_code(403);
                        echo json_encode(['error' => 'Session expired']);
                        exit;
                    }
                    
                    // Create minimal token data for fallback
                    $token_data = [
                        'session_id' => $session_id,
                        'player_name' => $session['player_name'],
                        'start_time' => $session['start_time'],
                        'ip_hash' => hash('sha256', $session['ip_address'] . CryptoUtils::getSecretKey()),
                        'timestamp' => $session['start_time']
                    ];
                    
                    error_log("Using fallback validation for session $session_id");
                }
                
                // Verify IP hasn't changed significantly (prevents session hijacking)
                // Use more flexible IP validation for real-world usage
                $current_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                $current_ip_hash = hash('sha256', $current_ip . CryptoUtils::getSecretKey());
                $admin_bypass_enabled = isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true;
                
                // Extract base IP for comparison (handle dynamic IPs in same subnet)
                $current_base_ip = implode('.', array_slice(explode('.', $current_ip), 0, 3)) . '.0';
                $current_base_hash = hash('sha256', $current_base_ip . CryptoUtils::getSecretKey());
                
                // Extract even broader IP range for ISPs with dynamic allocation
                $current_broad_ip = implode('.', array_slice(explode('.', $current_ip), 0, 2)) . '.0.0';
                $current_broad_hash = hash('sha256', $current_broad_ip . CryptoUtils::getSecretKey());
                
                $ip_matches = ($token_data['ip_hash'] === $current_ip_hash) || 
                             ($token_data['ip_hash'] === $current_base_hash) ||
                             ($token_data['ip_hash'] === $current_broad_hash);
                
                if (!$ip_matches && !$admin_bypass_enabled) {
                    // More lenient IP validation - allow IP changes for sessions older than 30 minutes
                    $session_timeout = 1800; // 30 minutes timeout for IP changes (reduced from 1 hour)
                    $session_age = time() - ($token_data['timestamp'] ?? 0);
                    
                    if ($session_age < $session_timeout) {
                        error_log("IP mismatch for recent session $session_id - blocking (session age: {$session_age}s)");
                        http_response_code(403);
                        echo json_encode(['error' => 'Session invalid - IP changed too quickly']);
                        exit;
                    } else {
                        error_log("IP mismatch for older session $session_id - allowing due to age (session age: {$session_age}s)");
                    }
                } elseif (!$ip_matches && $admin_bypass_enabled) {
                    error_log("ADMIN BYPASS: IP mismatch allowed for admin session $session_id");
                }
                
                // Get session data if we don't already have it from fallback
                if (!isset($session)) {
                    $stmt = $pdo->prepare("SELECT * FROM game_sessions WHERE session_id = ? AND status IN ('active', 'completed')");
                    $stmt->execute([$session_id]);
                    $session = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    if (!$session) {
                        http_response_code(404);
                        echo json_encode(['error' => 'Session not found']);
                        exit;
                    }
                }
                
                // Verify stored token matches (skip if using fallback validation)
                if ($crypto_valid && $session['secure_token'] !== $secure_token) {
                    error_log("Token mismatch for session $session_id");
                    http_response_code(403);
                    echo json_encode(['error' => 'Session corrupted']);
                    exit;
                } elseif (!$crypto_valid) {
                    error_log("Skipping token comparison for fallback validation session $session_id");
                }
                
                // Calculate expected score range based on session data
                $min_expected_score = $session['blocks_destroyed'] * 5; // Minimum 5 points per block
                $max_expected_score = $session['blocks_destroyed'] * 100 + ($session['powerups_collected'] * 200); // Max with bonuses
                $session_duration = time() - $session['start_time'];
                
                // Validation checks with more lenient thresholds
                $validation_errors = [];
                
                // Score vs blocks destroyed ratio - more generous bounds
                if ($final_score < $min_expected_score * 0.2 || $final_score > $max_expected_score * 5) {
                    $validation_errors[] = 'Score/blocks ratio suspicious';
                }
                
                // Level progression check - allow some flexibility
                if ($final_level > ($session['current_level'] + 2)) { // Allow 2 level buffer
                    $validation_errors[] = 'Level progression mismatch';
                }
                
                // Time-based validation - reduced minimum time per level for skilled players
                $min_time_per_level = 8; // 8 seconds minimum per level (reduced from 15)
                if ($session_duration < ($final_level * $min_time_per_level)) {
                    $validation_errors[] = 'Game completed too quickly';
                }
                
                // Maximum reasonable session duration (4 hours) - increased for long gaming sessions
                if ($session_duration > 14400) {
                    $validation_errors[] = 'Session too long';
                }
                
                // Advanced behavioral analysis with admin context
                $session['final_score'] = $final_score;
                $session['final_level'] = $final_level;
                
                // Start session if not already started for admin context checking
                if (session_status() == PHP_SESSION_NONE) {
                    session_start();
                }
                
                // Check if user is admin to adjust analysis thresholds
                // Use passed admin context from validation request, fallback to session
                $is_admin_context = ($input['admin_context'] ?? false) || (isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true);
                
                if ($input['admin_context'] ?? false) {
                    error_log("ADMIN CONTEXT: Validation request for admin user {$input['admin_username']} with session $session_id");
                }
                
                $behavior_analysis = BehaviorAnalyzer::analyzeGameSession($session, $is_admin_context);
                $ip_analysis = BehaviorAnalyzer::checkIPHistory($_SERVER['REMOTE_ADDR'], $pdo);
                
                // Combine all validation results
                if (!empty($validation_errors)) {
                    $behavior_analysis['flags'] = array_merge($behavior_analysis['flags'], $validation_errors);
                    $behavior_analysis['suspicion_score'] += count($validation_errors);
                }
                
                if ($ip_analysis['suspicious']) {
                    $behavior_analysis['flags'][] = $ip_analysis['reason'];
                    $behavior_analysis['suspicion_score'] += 3;
                }
                
                // Update session with behavior analysis - only update status if currently active
                $stmt = $pdo->prepare("UPDATE game_sessions SET 
                    status = CASE WHEN status = 'active' THEN 'completed' ELSE status END, 
                    behavior_flags = ?,
                    game_state_hash = ?
                    WHERE session_id = ?");
                
                $final_hash = CryptoUtils::generateGameStateHash($session);
                $stmt->execute([
                    json_encode($behavior_analysis), 
                    $final_hash,
                    $session_id
                ]);
                
                // Enhanced decision logic with admin context logging - more lenient validation
                $is_valid = $behavior_analysis['suspicion_score'] < 8 && 
                           $behavior_analysis['risk_level'] !== 'CRITICAL'; // Allow HIGH risk but block CRITICAL
                
                // Enhanced logging with admin context details
                $log_context = [
                    'session_id' => $session_id,
                    'score' => $final_score,
                    'level' => $final_level,
                    'suspicion_score' => $behavior_analysis['suspicion_score'],
                    'risk_level' => $behavior_analysis['risk_level'],
                    'flags' => $behavior_analysis['flags'],
                    'admin_context' => $behavior_analysis['admin_context'] ?? false,
                    'session_ip' => $_SERVER['REMOTE_ADDR'],
                    'validation_result' => $is_valid ? 'ACCEPTED' : 'BLOCKED'
                ];
                
                if (!$is_valid) {
                    // Enhanced logging for blocked submissions
                    error_log("GAME SCORE BLOCKED - " . json_encode($log_context));
                    
                    // Add to suspicious IPs list with more context
                    file_put_contents('/tmp/suspicious_ips.log', 
                        date('Y-m-d H:i:s') . " | " . $_SERVER['REMOTE_ADDR'] . " | $session_id | SCORE:$final_score | SUSPICION:{$behavior_analysis['suspicion_score']} | RISK:{$behavior_analysis['risk_level']} | ADMIN:" . ($behavior_analysis['admin_context'] ? 'YES' : 'NO') . " | FLAGS:" . implode(',', $behavior_analysis['flags']) . "\n", 
                        FILE_APPEND | LOCK_EX);
                } else {
                    // Log successful submissions for monitoring
                    error_log("GAME SCORE ACCEPTED - " . json_encode($log_context));
                }
                
                $response = CryptoUtils::obfuscateResponse([
                    'valid' => $is_valid,
                    'risk_level' => $behavior_analysis['risk_level'],
                    'session_hash' => $final_hash
                ]);
                
                echo json_encode($response);
                break;
                
            case 'check_session_exists':
                $session_id = $input['session_id'] ?? '';
                
                if (empty($session_id)) {
                    http_response_code(400);
                    echo json_encode(['error' => 'Missing session ID']);
                    exit;
                }
                
                // Check if session exists and is reasonably recent
                $stmt = $pdo->prepare("SELECT session_id, start_time, status FROM game_sessions WHERE session_id = ?");
                $stmt->execute([$session_id]);
                $session = $stmt->fetch(PDO::FETCH_ASSOC);
                
                $exists = false;
                if ($session) {
                    $session_age = time() - $session['start_time'];
                    // Allow sessions up to 4 hours old
                    if ($session_age <= 14400) {
                        $exists = true;
                    }
                }
                
                echo json_encode(['exists' => $exists]);
                break;
                
            default:
                http_response_code(400);
                echo json_encode(['error' => 'Invalid action']);
        }
    }
    
    // Clean up old sessions (older than 4 hours)
    $pdo->exec("DELETE FROM game_sessions WHERE last_update < " . (time() - 14400));
    
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error']);
    error_log("Game session error: " . $e->getMessage());
}
?>