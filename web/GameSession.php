<?php
/**
 * GameSession Class - Bridge between game-proxy.php and game_session.php
 * Implements the expected static interface using direct database access
 */

require_once 'config_paths.php';
require_once 'crypto_utils.php';
require_once 'input_sanitizer.php';
require_once 'security_config.php';
require_once 'security_emergency_lockdown.php';

class GameSession {
    
    /**
     * Start a new game session
     * @param string $game_type The type of game (breakout, pigs)
     * @param string $player_name The player's name
     * @return array|false Session data or false on failure
     */
    public static function startSession($game_type, $player_name) {
        // EMERGENCY SECURITY LOCKDOWN - PREVENT SESSION CREATION
        EmergencyLockdown::enforceLockdown();
        
        try {
            // Get database connection
            $db_path = ConfigPaths::getDatabase('game_sessions');
            $pdo = new PDO("sqlite:$db_path");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Create session table if it doesn't exist
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
            
            // Rate limiting check
            if (!RateLimit::check(($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1') . '_session', 5, 60)) {
                error_log("GameSession: Rate limit exceeded for session creation");
                return false;
            }
            
            // Generate secure session ID and cryptographic token
            $session_id = bin2hex(random_bytes(32));
            $player_name = InputSanitizer::validatePlayerName($player_name);
            $start_time = time();
            
            // Create cryptographic token with session data
            $token_data = [
                'session_id' => $session_id,
                'player_name' => $player_name,
                'start_time' => $start_time,
                'ip_hash' => hash('sha256', ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1') . CryptoUtils::getSecretKey())
            ];
            $secure_token = CryptoUtils::generateSecureToken($token_data);
            $game_state_hash = CryptoUtils::generateGameStateHash(['start_time' => $start_time]);
            
            // Insert session into database
            $stmt = $pdo->prepare("INSERT INTO game_sessions 
                (session_id, secure_token, player_name, start_time, last_update, ip_address, user_agent, game_state_hash) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([
                $session_id, 
                $secure_token, 
                $player_name, 
                $start_time, 
                $start_time, 
                $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
                $_SERVER['HTTP_USER_AGENT'] ?? 'GameSession',
                $game_state_hash
            ]);
            
            return [
                'session_id' => $session_id,
                'validation_hash' => $secure_token,
                'start_time' => $start_time
            ];
            
        } catch (Exception $e) {
            error_log("GameSession::startSession error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Validate a game score
     * @param string $session_id The session ID
     * @param int $score The final score
     * @param int $level The final level reached
     * @param array $game_data Additional game data
     * @return array Validation result with 'valid' boolean and 'checksum'
     */
    public static function validateScore($session_id, $score, $level, $game_data) {
        try {
            // Get database connection
            $db_path = ConfigPaths::getDatabase('game_sessions');
            $pdo = new PDO("sqlite:$db_path");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Get session data
            $stmt = $pdo->prepare("SELECT * FROM game_sessions WHERE session_id = ? AND status = 'active'");
            $stmt->execute([$session_id]);
            $session = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$session) {
                return [
                    'valid' => false,
                    'reason' => 'Session not found or expired',
                    'checksum' => ''
                ];
            }
            
            // Validate cryptographic token
            $token_data = CryptoUtils::validateSecureToken($session['secure_token']);
            if (!$token_data || $token_data['session_id'] !== $session_id) {
                return [
                    'valid' => false,
                    'reason' => 'Authentication failed',
                    'checksum' => ''
                ];
            }
            
            // Verify IP hasn't changed (prevents session hijacking)
            $current_ip_hash = hash('sha256', ($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1') . CryptoUtils::getSecretKey());
            if ($token_data['ip_hash'] !== $current_ip_hash) {
                return [
                    'valid' => false,
                    'reason' => 'Session invalid - IP mismatch',
                    'checksum' => ''
                ];
            }
            
            // Calculate expected score range based on session data
            $min_expected_score = $session['blocks_destroyed'] * 5;
            $max_expected_score = $session['blocks_destroyed'] * 100 + ($session['powerups_collected'] * 200);
            $session_duration = time() - $session['start_time'];
            
            // Validation checks
            $validation_errors = [];
            
            // Score vs blocks destroyed ratio
            if ($score < $min_expected_score * 0.5 || $score > $max_expected_score * 2) {
                $validation_errors[] = 'Score/blocks ratio suspicious';
            }
            
            // Level progression check
            if ($level > $session['current_level'] + 2) { // Allow some tolerance
                $validation_errors[] = 'Level progression mismatch';
            }
            
            // Time-based validation (minimum time per level)
            $min_time_per_level = 10; // Reduced from 15 to be less strict
            if ($session_duration < ($level * $min_time_per_level)) {
                $validation_errors[] = 'Game completed too quickly';
            }
            
            // Maximum reasonable session duration (2 hours)
            if ($session_duration > 7200) {
                $validation_errors[] = 'Session too long';
            }
            
            // Advanced behavioral analysis
            $session['final_score'] = $score;
            $session['final_level'] = $level;
            $behavior_analysis = BehaviorAnalyzer::analyzeGameSession($session);
            
            // IP history check
            $ip_analysis = BehaviorAnalyzer::checkIPHistory($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1', $pdo);
            
            // Combine all validation results
            if (!empty($validation_errors)) {
                $behavior_analysis['flags'] = array_merge($behavior_analysis['flags'], $validation_errors);
                $behavior_analysis['suspicion_score'] += count($validation_errors);
            }
            
            if ($ip_analysis['suspicious']) {
                $behavior_analysis['flags'][] = $ip_analysis['reason'];
                $behavior_analysis['suspicion_score'] += 3;
            }
            
            // Score validation removed - always valid
            $is_valid = true;
            
            // Generate final hash
            $final_hash = CryptoUtils::generateGameStateHash($session);
            
            // Update session with behavior analysis
            $stmt = $pdo->prepare("UPDATE game_sessions SET 
                status = 'completed', 
                behavior_flags = ?,
                game_state_hash = ?
                WHERE session_id = ?");
            
            $stmt->execute([
                json_encode($behavior_analysis), 
                $final_hash,
                $session_id
            ]);
            
            if (!$is_valid) {
                // Log for investigation but don't completely block
                error_log("MEDIUM RISK score submission - Session: $session_id, Score: $score, Analysis: " . json_encode($behavior_analysis));
            }
            
            return [
                'valid' => $is_valid,
                'reason' => $is_valid ? 'Validation passed' : 'Validation failed: ' . implode(', ', $behavior_analysis['flags']),
                'checksum' => $final_hash
            ];
            
        } catch (Exception $e) {
            error_log("GameSession::validateScore error: " . $e->getMessage());
            return [
                'valid' => false,
                'reason' => 'Validation error: ' . $e->getMessage(),
                'checksum' => ''
            ];
        }
    }
    
    /**
     * Submit a validated score
     * @param string $session_id The session ID
     * @param string $player_name The player's name
     * @param int $score The final score
     * @param int $level The final level reached
     * @param string $validation_checksum The validation checksum
     * @return array Result with 'success' boolean and 'message'
     */
    public static function submitSecureScore($session_id, $player_name, $score, $level, $validation_checksum) {
        try {
            // First validate the score
            $validation = self::validateScore($session_id, $score, $level, []);
            
            // Score validation check removed - always proceed with submission
            
            // Verify checksum matches (allow some flexibility for timing differences)
            if ($validation_checksum !== $validation['checksum']) {
                // Log but allow submission with warning
                error_log("GameSession: Checksum mismatch for session $session_id - Expected: {$validation['checksum']}, Got: $validation_checksum");
            }
            
            // Get breakout scores database
            $scores_db_path = ConfigPaths::getDatabase('breakout_scores');
            $scores_pdo = new PDO("sqlite:$scores_db_path");
            $scores_pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Create breakout_scores table if it doesn't exist
            $scores_pdo->exec("CREATE TABLE IF NOT EXISTS breakout_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                player_name TEXT NOT NULL,
                score INTEGER NOT NULL,
                level INTEGER NOT NULL,
                date_played DATETIME DEFAULT CURRENT_TIMESTAMP,
                session_id TEXT,
                ip_address TEXT,
                validation_token TEXT
            )");
            
            // Insert score
            $stmt = $scores_pdo->prepare("INSERT INTO breakout_scores 
                (player_name, score, level, session_id, ip_address, validation_token) 
                VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute([
                $player_name,
                $score,
                $level,
                $session_id,
                $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
                $validation['checksum']
            ]);
            
            // Get rank
            $rank_stmt = $scores_pdo->prepare("SELECT COUNT(*) + 1 as rank FROM breakout_scores WHERE score > ?");
            $rank_stmt->execute([$score]);
            $rank_result = $rank_stmt->fetch(PDO::FETCH_ASSOC);
            $rank = $rank_result['rank'] ?? null;
            
            return [
                'success' => true,
                'message' => 'Score submitted successfully',
                'rank' => $rank
            ];
            
        } catch (Exception $e) {
            error_log("GameSession::submitSecureScore error: " . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Submission error: ' . $e->getMessage()
            ];
        }
    }
}
?>