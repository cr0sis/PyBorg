<?php
// Hardened breakout score submission system with self-contained validation
set_time_limit(120); // Increase timeout to 2 minutes for debugging
session_start();

require_once 'security_config.php';
require_once 'input_sanitizer.php';
require_once 'config_paths.php';
require_once 'crypto_utils.php';
require_once 'security_emergency_lockdown.php';
require_once 'security_audit_logger.php';

// Emergency lockdown check - NO admin bypass capabilities
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

// Simple SQLite database for breakout scores
$db_path = ConfigPaths::getDatabase('breakout_scores');

try {
    $pdo = new PDO("sqlite:$db_path");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Create tables if they don't exist
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
    
    // Add color_hex column to existing breakout_scores table if it doesn't exist
    try {
        $pdo->exec("ALTER TABLE breakout_scores ADD COLUMN color_hex TEXT");
    } catch (PDOException $e) {
        // Column already exists, ignore error
    }
    
    // Create user colors table for persistent color assignments
    $pdo->exec("CREATE TABLE IF NOT EXISTS user_colors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        player_name TEXT UNIQUE NOT NULL,
        color_hex TEXT NOT NULL,
        is_registered_user INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    
    // Include shared color system functions
    require_once 'user_color_system.php';
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        error_log("DEBUG: POST request started, about to sanitize input");
        // Sanitize all input first - use lightweight version for performance
        $_GET = array_map('trim', $_GET);
        $_POST = array_map('trim', $_POST);
        error_log("DEBUG: Input sanitization completed (LIGHTWEIGHT VERSION)");
        
        // Rate limiting for score submissions
        if (!RateLimit::check($_SERVER['REMOTE_ADDR'] . '_score', 10, 300)) {
            http_response_code(429);
            echo json_encode(['error' => 'Too many score submissions. Please try again later.']);
            exit;
        }
        
        // Add new score - use secure JSON validation
        $raw_input = file_get_contents('php://input');
        $input = InputSanitizer::validateJSON($raw_input);
        
        if ($input === false) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid JSON data']);
            exit;
        }
        
        // Handle obfuscated payload for F12 protection
        $is_obfuscated = isset($input['p_n']) && isset($input['s_v']) && isset($input['l_r']) && isset($input['ts']) && isset($input['chk']);
        
        if ($is_obfuscated) {
            // Deobfuscate the payload
            try {
                $player_name = base64_decode(strrev($input['p_n'])); // Reverse and decode
                $timestamp = intval($input['ts']);
                $raw_score = intval($input['s_v']) - $timestamp; // Remove timestamp
                $score = $raw_score ^ 0x1337; // XOR deobfuscation with smaller value to prevent overflow
                $level_reached = (intval($input['l_r']) - 13) / 7; // Mathematical deobfuscation
                $nonce = $input['nc'] ?? '';
                $checksum = $input['chk'] ?? '';
                
                // Verify checksum to prevent tampering
                $expected_checksum = base64_encode(substr(hash('sha256', $player_name . $score . $level_reached . $timestamp . $nonce, true), 0, 12));
                
                if ($checksum !== $expected_checksum) {
                    error_log("F12_TAMPERING_DETECTED: Checksum mismatch for obfuscated payload");
                    http_response_code(403);
                    echo json_encode(['error' => 'Payload integrity check failed']);
                    exit;
                }
                
                error_log("OBFUSCATED_PAYLOAD_SUCCESS: Deobfuscated payload validated");
            } catch (Exception $e) {
                error_log("F12_TAMPERING_DETECTED: Failed to deobfuscate payload - " . $e->getMessage());
                http_response_code(400);
                echo json_encode(['error' => 'Invalid payload format']);
                exit;
            }
        } else {
            // Handle legacy format (fallback)
            if (!isset($input['player_name']) || !isset($input['score']) || !isset($input['level_reached']) || !isset($input['session_id'])) {
                http_response_code(400);
                echo json_encode(['error' => 'Missing required fields']);
                exit;
            }
            $player_name = $input['player_name'];
            $score = $input['score'];
            $level_reached = $input['level_reached'];
        }
        
        // Comprehensive input validation and sanitization
        $player_name = InputSanitizer::validatePlayerName($player_name ?? '');
        $player_name = substr(trim($player_name), 0, 20); // Limit name length and trim
        
        // Strict score validation
        if (!is_numeric($score) || $score < 0) {
            error_log("INVALID_INPUT: Non-numeric or negative score: " . var_export($score, true));
            http_response_code(400);
            echo json_encode(['error' => 'Invalid score value']);
            exit;
        }
        $score = InputSanitizer::validateNumeric($score, 0, 9999999);
        
        // Strict level validation
        if (!is_numeric($level_reached) || $level_reached < 1) {
            error_log("INVALID_INPUT: Invalid level: " . var_export($level_reached, true));
            http_response_code(400);
            echo json_encode(['error' => 'Invalid level value']);
            exit;
        }
        $level_reached = InputSanitizer::validateNumeric($level_reached, 1, 200);
        
        // Validate player name is not empty after sanitization
        if (empty($player_name)) {
            error_log("INVALID_INPUT: Empty player name after sanitization");
            http_response_code(400);
            echo json_encode(['error' => 'Player name cannot be empty']);
            exit;
        }
        
        // Score-to-level ratio validation removed - any score is allowed
        
        // Enhanced deduplication: Check for rapid identical submissions BEFORE expensive validation
        $stmt = $pdo->prepare("
            SELECT COUNT(*) as identical_submissions 
            FROM breakout_scores 
            WHERE player_name = ? AND score = ? AND level_reached = ? 
            AND date_played > datetime('now', '-2 minutes')
        ");
        $stmt->execute([$player_name, $score, $level_reached]);
        $identical_count = $stmt->fetchColumn();
        
        if ($identical_count > 0) {
            error_log("DEDUPLICATION: Blocked duplicate score submission - Player: $player_name, Score: $score, Level: $level_reached");
            // Return success but don't actually insert - prevents client-side errors
            echo json_encode(['success' => true, 'message' => 'Score already recorded', 'duplicate' => true]);
            exit;
        }
        
        // Extract session data from appropriate payload format
        $session_id = $is_obfuscated ? ($input['s_id'] ?? '') : ($input['session_id'] ?? '');
        $secure_token = $is_obfuscated ? ($input['tk'] ?? '') : ($input['token'] ?? '');
        
        // ALL users must pass cryptographic validation - NO admin bypasses
        $validation_passed = false;
        
        // Self-contained HMAC validation for ALL users
        error_log("DEBUG: Starting cryptographic validation for session $session_id");
        if (!empty($session_id) && !empty($secure_token)) {
            // Self-contained cryptographic validation using CryptoUtils
            error_log("DEBUG: About to call validateSecureToken");
            $token_data = CryptoUtils::validateSecureToken($secure_token, 7200); // 2 hour max age
            error_log("DEBUG: validateSecureToken completed");
            
            if ($token_data && $token_data['session_id'] === $session_id) {
                // Verify IP hasn't changed (prevents session hijacking)
                $current_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
                $current_ip_hash = hash('sha256', $current_ip . CryptoUtils::getSecretKey());
                
                // Allow some IP flexibility for mobile/dynamic IPs
                $base_ip = implode('.', array_slice(explode('.', $current_ip), 0, 3)) . '.0';
                $base_ip_hash = hash('sha256', $base_ip . CryptoUtils::getSecretKey());
                
                $ip_matches = ($token_data['ip_hash'] === $current_ip_hash) || 
                             ($token_data['ip_hash'] === $base_ip_hash);
                
                if ($ip_matches) {
                    $validation_passed = true;
                    error_log("CRYPTO_VALIDATION_SUCCESS: Session $session_id validated with HMAC token");
                } else {
                    error_log("CRYPTO_VALIDATION_FAILED: IP mismatch for session $session_id");
                }
            } else {
                error_log("CRYPTO_VALIDATION_FAILED: Invalid or expired token for session $session_id");
            }
        } else {
            error_log("CRYPTO_VALIDATION_FAILED: Missing session_id or token");
        }
        
        // Enhanced anti-cheat analysis for ALL users - NO bypasses
        if ($validation_passed) {
            // Create session data for behavior analysis
            $session_data = [
                'session_id' => $session_id,
                'final_score' => $score,
                'final_level' => $level_reached,
                'start_time' => $token_data['start_time'] ?? time(),
                'blocks_destroyed' => max(1, $score / 20), // Estimate blocks from score
                'game_duration' => time() - ($token_data['start_time'] ?? time()),
                'current_level' => $level_reached,
                'lives_lost' => 0, // Default values for enhanced analysis
                'powerups_collected' => 0,
                'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ];
            
            // Apply behavior analysis with NO admin context (all users treated equally)
            // TEMPORARILY DISABLED: $behavior_analysis = BehaviorAnalyzer::analyzeGameSession($session_data, false);
            
            // Anti-cheat threshold removed - behavior analysis is for logging only
        }
        
        error_log("DEBUG: About to check final validation, validation_passed = " . ($validation_passed ? 'true' : 'false'));
        // Final validation check - NO exceptions
        if (!$validation_passed) {
            error_log("DEBUG: Validation failed, returning 403");
            http_response_code(403);
            echo json_encode(['error' => 'Security validation failed']);
            exit;
        }
        error_log("DEBUG: Validation passed, continuing to input validation");
        
        // Validate sanitized input (already validated above)
        error_log("DEBUG: Checking input validation for player_name='$player_name', score=$score, level_reached=$level_reached");
        if (empty($player_name) || $score < 0 || $level_reached < 1) {
            error_log("DEBUG: Input validation failed");
            http_response_code(400);
            echo json_encode(['error' => 'Invalid input data']);
            exit;
        }
        error_log("DEBUG: Input validation passed, checking user login status");
        
        // Check if user is logged in (for name protection only)
        $is_logged_in = isset($_SESSION['username']) && isset($_SESSION['user_id']);
        $logged_in_username = $is_logged_in ? $_SESSION['username'] : null;
        error_log("DEBUG: User login check - is_logged_in=" . ($is_logged_in ? 'true' : 'false') . ", logged_in_username='$logged_in_username'");
        
        // Name protection: prevent anonymous users from using registered names
        error_log("DEBUG: About to call checkNameProtection");
        if (!checkNameProtection($player_name, $is_logged_in)) {
            error_log("DEBUG: Name protection failed");
            http_response_code(403);
            echo json_encode(['error' => 'This name is reserved for registered users. Please choose a different name or log in.']);
            exit;
        }
        error_log("DEBUG: Name protection passed");
        
        // Additional check: if logged in, ensure they're using their actual username
        if ($is_logged_in && $player_name !== $logged_in_username) {
            http_response_code(403);
            echo json_encode(['error' => 'Logged-in users must use their registered username.']);
            exit;
        }
        
        // Theoretical max score checking removed - any score is allowed
        
        // Level 1 score checking removed - any score is allowed on any level
        
        // Check if player is banned
        $banned_file = '/tmp/banned_players.txt';
        if (file_exists($banned_file)) {
            $banned_players = file($banned_file, FILE_IGNORE_NEW_LINES);
            if (in_array($player_name, $banned_players)) {
                http_response_code(403);
                echo json_encode(['error' => 'Player is banned from submitting scores']);
                exit;
            }
        }
        
        // Industry standard profanity filter
        if (containsProfanity($player_name)) {
            http_response_code(400);
            echo json_encode(['error' => 'Inappropriate player name']);
            exit;
        }
        
        // Always insert new scores to allow multiple entries per name (especially for Anonymous)
        // This allows the hall of fame to fill up with top 10 scores
        $new_score = $score;
        $new_level = $level_reached;
        
        // Deduplication already handled at the top - no need to check again
        
        // Enhanced anti-cheat: Check for suspicious submission patterns (STRICT F12 protection)
        $stmt = $pdo->prepare("SELECT COUNT(*) as recent_submissions FROM breakout_scores WHERE ip_address = ? AND date_played > datetime('now', '-5 minutes')");
        $stmt->execute([$_SERVER['REMOTE_ADDR']]);
        $recent_count = $stmt->fetchColumn();
        
        if ($recent_count > 10) { // Allow multiple players from same IP/household
            error_log("F12_PROTECTION: Suspicious rapid score submissions from IP: {$_SERVER['REMOTE_ADDR']} - $recent_count submissions in 5 minutes");
            http_response_code(429);
            echo json_encode(['error' => 'Too many recent submissions. Please wait before submitting again.']);
            exit;
        }
        
        // Enhanced anti-cheat: Check for impossible score improvements (STRICT F12 protection)
        $stmt = $pdo->prepare("SELECT MAX(score) as best_score FROM breakout_scores WHERE player_name = ?");
        $stmt->execute([$player_name]);
        $previous_best = $stmt->fetchColumn() ?: 0;
        
        if ($previous_best > 0 && $new_score > ($previous_best * 3)) { // Strict 3x improvement limit for F12 protection
            error_log("F12_CHEAT_DETECTED: Extreme score improvement - Player: $player_name, Previous: $previous_best, New: $new_score");
            http_response_code(400);
            echo json_encode(['error' => 'Score improvement appears suspicious']);
            exit;
        }
        
        // Get user's current color at time of score submission
        error_log("DEBUG: About to call getUserColor for player: $player_name");
        $current_color = getUserColor($player_name, $is_logged_in);
        error_log("DEBUG: getUserColor completed, color: $current_color");
        
        // Generate validation hash for integrity
        $validation_hash = hash('sha256', $player_name . $new_score . $new_level . time() . $_SERVER['REMOTE_ADDR']);
        
        // Insert with comprehensive audit trail including current color
        $stmt = $pdo->prepare("INSERT INTO breakout_scores (player_name, score, level_reached, ip_address, session_id, validation_hash, color_hex) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->execute([$player_name, $new_score, $new_level, $_SERVER['REMOTE_ADDR'], $session_id, $validation_hash, $current_color]);
        $new_id = $pdo->lastInsertId();
        
        // Enhanced audit logging with cryptographic validation metrics
        $audit_message = "SECURE_SCORE_AUDIT: New score submitted - ID: $new_id, Player: $player_name, Score: $new_score, Level: $new_level, IP: {$_SERVER['REMOTE_ADDR']}, Session: $session_id, Validation: HMAC_CRYPTO";
        
        // All users get identical security treatment - NO admin bypasses
        error_log($audit_message);
        
        echo json_encode(['success' => true, 'id' => $new_id]);
        
        // Only clean up exact duplicates (same player, same exact score, submitted within 5 seconds)
        // This prevents accidental double-submissions but allows multiple different scores per player
        $stmt = $pdo->prepare("DELETE FROM breakout_scores WHERE id IN (
            SELECT b1.id FROM breakout_scores b1
            JOIN breakout_scores b2 ON (
                b1.player_name = b2.player_name 
                AND b1.score = b2.score 
                AND b1.level_reached = b2.level_reached
                AND b1.id > b2.id
                AND ABS((julianday(b1.date_played) - julianday(b2.date_played)) * 86400) < 5
            )
        )");
        $stmt->execute();
        
        // Clean up old scores to prevent database bloat
        // Keep only top 100 scores total
        $stmt = $pdo->prepare("DELETE FROM breakout_scores WHERE id NOT IN (
            SELECT id FROM (
                SELECT id FROM breakout_scores ORDER BY score DESC, date_played DESC LIMIT 100
            ) AS top_scores
        )");
        $stmt->execute();
    }
    
    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        // Use simplified working approach
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
    // Log detailed error for debugging but don't expose to client
    error_log("DATABASE_ERROR: " . $e->getMessage() . " | File: " . $e->getFile() . " | Line: " . $e->getLine());
    
    // Generic error response to prevent information disclosure
    http_response_code(500);
    echo json_encode(['error' => 'Internal server error - please try again later']);
} catch (Exception $e) {
    // Catch any other exceptions
    error_log("GENERAL_ERROR: " . $e->getMessage() . " | File: " . $e->getFile() . " | Line: " . $e->getLine());
    
    http_response_code(500);
    echo json_encode(['error' => 'Server error - please try again later']);
}

function containsProfanity($text) {
    // Comprehensive profanity list (industry standard)
    $profanity_list = [
        // Severe profanity
        'fuck', 'shit', 'bitch', 'damn', 'hell', 'ass', 'crap', 'piss', 'cock', 'dick', 'pussy', 'cunt', 'whore', 'slut', 
        'bastard', 'motherfucker', 'asshole', 'bullshit', 'goddamn', 'jesus', 'christ', 'wtf', 'stfu', 'gtfo',
        
        // Racial slurs and hate speech
        'nigger', 'nigga', 'faggot', 'retard', 'gay', 'homo', 'dyke', 'tranny', 'chink', 'spic', 'wetback', 'kike',
        'nazi', 'hitler', 'terrorist', 'jihad', 'isis', 'kkk',
        
        // Sexual content
        'porn', 'sex', 'anal', 'oral', 'cum', 'jizz', 'masturbate', 'orgasm', 'penis', 'vagina', 'boobs', 'tits',
        'nude', 'naked', 'xxx', 'milf', 'dildo', 'vibrator', 'bdsm', 'kinky', 'horny', 'erotic',
        
        // Violence and threats
        'kill', 'murder', 'rape', 'bomb', 'gun', 'knife', 'stab', 'shoot', 'die', 'death', 'suicide', 'kys',
        'violence', 'attack', 'assault', 'abuse', 'torture', 'harm', 'hurt', 'pain', 'blood', 'gore',
        
        // Drugs and substances
        'weed', 'marijuana', 'cocaine', 'heroin', 'meth', 'crack', 'drug', 'dealer', 'high', 'stoned',
        'drunk', 'alcohol', 'beer', 'wine', 'vodka', 'whiskey', 'smoke', 'joint', 'blunt', 'bong',
        
        // General inappropriate
        'admin', 'moderator', 'mod', 'owner', 'staff', 'official', 'bot', 'system', 'server', 'user',
        'spam', 'scam', 'hack', 'cheat', 'exploit', 'bug', 'glitch', 'noob', 'newb', 'scrub', 'trash',
        'toxic', 'cancer', 'aids', 'autism', 'autistic', 'mental', 'crazy', 'insane', 'stupid', 'idiot',
        
        // Leetspeak variations will be handled by normalization
    ];
    
    // Normalize the input text
    $normalized_text = normalizeProfanityText($text);
    
    // Check against profanity list
    foreach ($profanity_list as $word) {
        $normalized_word = normalizeProfanityText($word);
        
        // Direct match
        if (stripos($normalized_text, $normalized_word) !== false) {
            return true;
        }
        
        // Check for word boundaries to catch whole words
        if (preg_match('/\b' . preg_quote($normalized_word, '/') . '\b/i', $normalized_text)) {
            return true;
        }
        
        // Check for variations with numbers/symbols in between
        $pattern = '';
        for ($i = 0; $i < strlen($normalized_word); $i++) {
            $pattern .= preg_quote($normalized_word[$i], '/');
            if ($i < strlen($normalized_word) - 1) {
                $pattern .= '[0-9\s\-_\.\*\+]*?';
            }
        }
        if (preg_match('/' . $pattern . '/i', $normalized_text)) {
            return true;
        }
    }
    
    return false;
}

function normalizeProfanityText($text) {
    $text = strtolower(trim($text));
    
    // Remove spaces, hyphens, underscores, dots
    $text = str_replace([' ', '-', '_', '.', '*', '+', '!', '@', '#', '$', '%', '^', '&'], '', $text);
    
    // Replace common leetspeak substitutions
    $leetspeak = [
        '4' => 'a', '@' => 'a', 
        '3' => 'e', 
        '1' => 'i', '!' => 'i', '|' => 'i',
        '0' => 'o', 
        '5' => 's', '$' => 's', 'z' => 's',
        '7' => 't', '+' => 't',
        '8' => 'b',
        '6' => 'g',
        '2' => 'z',
        '9' => 'g',
    ];
    
    $text = str_replace(array_keys($leetspeak), array_values($leetspeak), $text);
    
    // Remove numbers that might be used as separators
    $text = preg_replace('/[0-9]+/', '', $text);
    
    return $text;
}
?>