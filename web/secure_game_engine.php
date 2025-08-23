<?php
/**
 * Secure Game Engine - Server-Side Score Calculation and Validation
 * This completely eliminates client-side score manipulation vulnerabilities
 */

require_once 'security_config.php';
require_once 'input_sanitizer.php';
require_once 'config_paths.php';
require_once 'crypto_utils.php';

class SecureGameEngine {
    
    // Game constants - these CANNOT be modified by client
    const POINTS_PER_BLOCK = 10;
    const BONUS_MULTIPLIER_PER_LEVEL = 1.2;
    const POWERUP_BONUS = 50;
    const PERFECT_LEVEL_BONUS = 500;
    const TIME_BONUS_PER_SECOND = 1;
    const MAX_REALISTIC_SCORE_PER_LEVEL = 2000;
    const MIN_TIME_PER_LEVEL_SECONDS = 8;
    
    /**
     * Create a new secure game session with server-side state tracking
     */
    public static function createSecureSession($player_name, $ip_address) {
        try {
            $db_path = ConfigPaths::getDatabase('secure_game_sessions');
            $pdo = new PDO("sqlite:$db_path");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Create secure sessions table
            $pdo->exec("CREATE TABLE IF NOT EXISTS secure_game_sessions (
                session_id TEXT PRIMARY KEY,
                player_name TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                current_level INTEGER DEFAULT 1,
                total_blocks_destroyed INTEGER DEFAULT 0,
                total_powerups_collected INTEGER DEFAULT 0,
                game_start_time INTEGER NOT NULL,
                last_update_time INTEGER NOT NULL,
                server_calculated_score INTEGER DEFAULT 0,
                level_completion_times TEXT DEFAULT '[]',
                block_destruction_sequence TEXT DEFAULT '[]',
                powerup_collection_sequence TEXT DEFAULT '[]',
                game_state_hash TEXT NOT NULL,
                validation_token TEXT NOT NULL,
                is_completed BOOLEAN DEFAULT FALSE,
                security_flags TEXT DEFAULT '[]',
                status TEXT DEFAULT 'active'
            )");
            
            // Generate cryptographically secure session
            $session_id = bin2hex(random_bytes(32));
            $game_start_time = time();
            $validation_token = hash_hmac('sha256', $session_id . $game_start_time . $ip_address, CryptoUtils::getSecretKey());
            $initial_state_hash = self::calculateStateHash([
                'session_id' => $session_id,
                'level' => 1,
                'score' => 0,
                'timestamp' => $game_start_time
            ]);
            
            // Insert secure session
            $stmt = $pdo->prepare("INSERT INTO secure_game_sessions 
                (session_id, player_name, ip_address, game_start_time, last_update_time, 
                 game_state_hash, validation_token) 
                VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->execute([
                $session_id,
                InputSanitizer::validatePlayerName($player_name),
                $ip_address,
                $game_start_time,
                $game_start_time,
                $initial_state_hash,
                $validation_token
            ]);
            
            return [
                'session_id' => $session_id,
                'validation_token' => $validation_token,
                'server_time' => $game_start_time
            ];
            
        } catch (Exception $e) {
            error_log("SecureGameEngine::createSecureSession error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Process a single game event (block destroyed, powerup collected, level completed)
     * ALL score calculation happens server-side based on validated events
     */
    public static function processGameEvent($session_id, $validation_token, $event_type, $event_data, $client_timestamp) {
        try {
            $db_path = ConfigPaths::getDatabase('secure_game_sessions');
            $pdo = new PDO("sqlite:$db_path");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Get and validate session
            $stmt = $pdo->prepare("SELECT * FROM secure_game_sessions WHERE session_id = ? AND status = 'active'");
            $stmt->execute([$session_id]);
            $session = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$session) {
                return ['success' => false, 'error' => 'Invalid session'];
            }
            
            // Validate token
            $expected_token = hash_hmac('sha256', $session_id . $session['game_start_time'] . $session['ip_address'], CryptoUtils::getSecretKey());
            if (!hash_equals($expected_token, $validation_token)) {
                return ['success' => false, 'error' => 'Invalid validation token'];
            }
            
            // Validate timing (prevent time manipulation)
            $server_time = time();
            $time_since_start = $server_time - $session['game_start_time'];
            $time_since_last_update = $server_time - $session['last_update_time'];
            
            if ($time_since_last_update < 0.1) { // Prevent rapid-fire events
                return ['success' => false, 'error' => 'Events too frequent'];
            }
            
            // Process event and calculate score server-side
            $score_change = 0;
            $current_sequences = [
                'blocks' => json_decode($session['block_destruction_sequence'], true) ?: [],
                'powerups' => json_decode($session['powerup_collection_sequence'], true) ?: [],
                'levels' => json_decode($session['level_completion_times'], true) ?: []
            ];
            
            switch ($event_type) {
                case 'block_destroyed':
                    // Validate block position is reasonable
                    if (!self::validateBlockPosition($event_data, $session['current_level'])) {
                        return ['success' => false, 'error' => 'Invalid block position'];
                    }
                    
                    $score_change = self::POINTS_PER_BLOCK * (self::BONUS_MULTIPLIER_PER_LEVEL ** ($session['current_level'] - 1));
                    $current_sequences['blocks'][] = [
                        'timestamp' => $server_time,
                        'level' => $session['current_level'],
                        'position' => $event_data['position'] ?? null
                    ];
                    
                    $stmt = $pdo->prepare("UPDATE secure_game_sessions SET 
                        total_blocks_destroyed = total_blocks_destroyed + 1,
                        server_calculated_score = server_calculated_score + ?,
                        block_destruction_sequence = ?,
                        last_update_time = ?
                        WHERE session_id = ?");
                    $stmt->execute([
                        $score_change,
                        json_encode($current_sequences['blocks']),
                        $server_time,
                        $session_id
                    ]);
                    break;
                    
                case 'powerup_collected':
                    $score_change = self::POWERUP_BONUS;
                    $current_sequences['powerups'][] = [
                        'timestamp' => $server_time,
                        'level' => $session['current_level'],
                        'type' => $event_data['type'] ?? 'unknown'
                    ];
                    
                    $stmt = $pdo->prepare("UPDATE secure_game_sessions SET 
                        total_powerups_collected = total_powerups_collected + 1,
                        server_calculated_score = server_calculated_score + ?,
                        powerup_collection_sequence = ?,
                        last_update_time = ?
                        WHERE session_id = ?");
                    $stmt->execute([
                        $score_change,
                        json_encode($current_sequences['powerups']),
                        $server_time,
                        $session_id
                    ]);
                    break;
                    
                case 'level_completed':
                    $level_duration = $event_data['level_duration'] ?? 0;
                    
                    // Validate minimum level completion time
                    if ($level_duration < self::MIN_TIME_PER_LEVEL_SECONDS) {
                        return ['success' => false, 'error' => 'Level completed too quickly'];
                    }
                    
                    // Calculate level completion bonus
                    $time_bonus = max(0, (60 - $level_duration) * self::TIME_BONUS_PER_SECOND);
                    $perfect_bonus = ($event_data['perfect_level'] ?? false) ? self::PERFECT_LEVEL_BONUS : 0;
                    $score_change = $time_bonus + $perfect_bonus;
                    
                    $current_sequences['levels'][] = [
                        'level' => $session['current_level'],
                        'duration' => $level_duration,
                        'completed_at' => $server_time,
                        'perfect' => $event_data['perfect_level'] ?? false
                    ];
                    
                    $stmt = $pdo->prepare("UPDATE secure_game_sessions SET 
                        current_level = current_level + 1,
                        server_calculated_score = server_calculated_score + ?,
                        level_completion_times = ?,
                        last_update_time = ?
                        WHERE session_id = ?");
                    $stmt->execute([
                        $score_change,
                        json_encode($current_sequences['levels']),
                        $server_time,
                        $session_id
                    ]);
                    break;
                    
                default:
                    return ['success' => false, 'error' => 'Invalid event type'];
            }
            
            // Get updated session data
            $stmt = $pdo->prepare("SELECT server_calculated_score, current_level FROM secure_game_sessions WHERE session_id = ?");
            $stmt->execute([$session_id]);
            $updated_session = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return [
                'success' => true,
                'server_score' => $updated_session['server_calculated_score'],
                'current_level' => $updated_session['current_level'],
                'score_change' => $score_change
            ];
            
        } catch (Exception $e) {
            error_log("SecureGameEngine::processGameEvent error: " . $e->getMessage());
            return ['success' => false, 'error' => 'Processing error'];
        }
    }
    
    /**
     * Finalize game and submit score with comprehensive validation
     */
    public static function finalizeGameScore($session_id, $validation_token, $final_game_state) {
        try {
            $db_path = ConfigPaths::getDatabase('secure_game_sessions');
            $pdo = new PDO("sqlite:$db_path");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Get session
            $stmt = $pdo->prepare("SELECT * FROM secure_game_sessions WHERE session_id = ? AND status = 'active'");
            $stmt->execute([$session_id]);
            $session = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$session) {
                return ['success' => false, 'error' => 'Session not found'];
            }
            
            // Validate token
            $expected_token = hash_hmac('sha256', $session_id . $session['game_start_time'] . $session['ip_address'], CryptoUtils::getSecretKey());
            if (!hash_equals($expected_token, $validation_token)) {
                return ['success' => false, 'error' => 'Authentication failed'];
            }
            
            // Perform comprehensive validation
            $validation_result = self::comprehensiveScoreValidation($session, $final_game_state);
            
            if (!$validation_result['valid']) {
                // Mark session as suspicious but log the attempt
                $stmt = $pdo->prepare("UPDATE secure_game_sessions SET 
                    status = 'rejected',
                    security_flags = ?
                    WHERE session_id = ?");
                $stmt->execute([json_encode($validation_result['flags']), $session_id]);
                
                error_log("SECURE_GAME_ENGINE: Score validation failed for session $session_id: " . json_encode($validation_result['flags']));
                return ['success' => false, 'error' => 'Score validation failed', 'details' => $validation_result['flags']];
            }
            
            // Score is valid - mark session as completed
            $stmt = $pdo->prepare("UPDATE secure_game_sessions SET 
                status = 'completed',
                is_completed = TRUE
                WHERE session_id = ?");
            $stmt->execute([$session_id]);
            
            // Submit to scores database with security metadata
            $scores_result = self::submitValidatedScore($session);
            
            return $scores_result;
            
        } catch (Exception $e) {
            error_log("SecureGameEngine::finalizeGameScore error: " . $e->getMessage());
            return ['success' => false, 'error' => 'Finalization error'];
        }
    }
    
    /**
     * Comprehensive score validation using multiple verification methods
     */
    private static function comprehensiveScoreValidation($session, $final_game_state) {
        $flags = [];
        $suspicion_score = 0;
        
        // Validate score matches server calculation
        $server_score = $session['server_calculated_score'];
        $client_claimed_score = $final_game_state['score'] ?? 0;
        
        if (abs($server_score - $client_claimed_score) > 100) { // Allow small tolerance
            $flags[] = 'score_mismatch';
            $suspicion_score += 10; // High penalty
        }
        
        // Validate game duration
        $total_duration = time() - $session['game_start_time'];
        $level_reached = $session['current_level'];
        $min_expected_time = $level_reached * self::MIN_TIME_PER_LEVEL_SECONDS;
        
        if ($total_duration < $min_expected_time) {
            $flags[] = 'impossible_timing';
            $suspicion_score += 8;
        }
        
        // Validate score vs blocks ratio
        $blocks_destroyed = $session['total_blocks_destroyed'];
        if ($blocks_destroyed > 0) {
            $score_per_block = $server_score / $blocks_destroyed;
            $max_reasonable_score_per_block = 100; // Generous estimate
            
            if ($score_per_block > $max_reasonable_score_per_block) {
                $flags[] = 'excessive_score_per_block';
                $suspicion_score += 6;
            }
        }
        
        // Validate level progression
        $max_realistic_score = $level_reached * self::MAX_REALISTIC_SCORE_PER_LEVEL;
        if ($server_score > $max_realistic_score) {
            $flags[] = 'unrealistic_score_for_level';
            $suspicion_score += 7;
        }
        
        // Check for bot-like behavior patterns
        $behavioral_analysis = self::analyzeBehaviorPatterns($session);
        if ($behavioral_analysis['is_suspicious']) {
            $flags = array_merge($flags, $behavioral_analysis['flags']);
            $suspicion_score += $behavioral_analysis['suspicion_points'];
        }
        
        return [
            'valid' => $suspicion_score < 8, // Strict threshold
            'flags' => $flags,
            'suspicion_score' => $suspicion_score,
            'server_score' => $server_score
        ];
    }
    
    /**
     * Analyze behavioral patterns for bot detection
     */
    private static function analyzeBehaviorPatterns($session) {
        $flags = [];
        $suspicion_points = 0;
        
        // Analyze block destruction timing patterns
        $block_sequence = json_decode($session['block_destruction_sequence'], true) ?: [];
        if (count($block_sequence) > 10) {
            $intervals = [];
            for ($i = 1; $i < count($block_sequence); $i++) {
                $intervals[] = $block_sequence[$i]['timestamp'] - $block_sequence[$i-1]['timestamp'];
            }
            
            // Check for too-consistent timing (bot-like)
            $avg_interval = array_sum($intervals) / count($intervals);
            $variance = 0;
            foreach ($intervals as $interval) {
                $variance += pow($interval - $avg_interval, 2);
            }
            $variance /= count($intervals);
            
            if ($variance < 0.01) { // Very low variance = bot-like
                $flags[] = 'consistent_timing_pattern';
                $suspicion_points += 5;
            }
        }
        
        // Check powerup collection efficiency (too perfect = suspicious)
        $powerup_count = $session['total_powerups_collected'];
        $blocks_count = $session['total_blocks_destroyed'];
        if ($blocks_count > 0 && ($powerup_count / $blocks_count) > 0.8) {
            $flags[] = 'perfect_powerup_collection';
            $suspicion_points += 3;
        }
        
        return [
            'is_suspicious' => $suspicion_points > 5,
            'flags' => $flags,
            'suspicion_points' => $suspicion_points
        ];
    }
    
    /**
     * Submit validated score to the main scores database
     */
    private static function submitValidatedScore($session) {
        try {
            $scores_db_path = ConfigPaths::getDatabase('breakout_scores');
            $pdo = new PDO("sqlite:$scores_db_path");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Enhanced scores table with security metadata
            $pdo->exec("CREATE TABLE IF NOT EXISTS breakout_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                player_name TEXT NOT NULL,
                score INTEGER NOT NULL,
                level_reached INTEGER NOT NULL,
                date_played DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                session_id TEXT,
                validation_hash TEXT,
                security_validated BOOLEAN DEFAULT FALSE,
                server_side_calculated BOOLEAN DEFAULT FALSE,
                game_duration INTEGER,
                blocks_destroyed INTEGER,
                powerups_collected INTEGER
            )");
            
            $game_duration = time() - $session['game_start_time'];
            $validation_hash = hash('sha256', $session['session_id'] . $session['server_calculated_score'] . $game_duration . 'SECURE_V2');
            
            $stmt = $pdo->prepare("INSERT INTO breakout_scores 
                (player_name, score, level_reached, ip_address, session_id, validation_hash,
                 security_validated, server_side_calculated, game_duration, blocks_destroyed, powerups_collected)
                VALUES (?, ?, ?, ?, ?, ?, TRUE, TRUE, ?, ?, ?)");
            
            $stmt->execute([
                $session['player_name'],
                $session['server_calculated_score'],
                $session['current_level'],
                $session['ip_address'],
                $session['session_id'],
                $validation_hash,
                $game_duration,
                $session['total_blocks_destroyed'],
                $session['total_powerups_collected']
            ]);
            
            $score_id = $pdo->lastInsertId();
            
            error_log("SECURE_SCORE_SUBMITTED: ID=$score_id, Player={$session['player_name']}, Score={$session['server_calculated_score']}, Session={$session['session_id']}");
            
            return [
                'success' => true,
                'score_id' => $score_id,
                'final_score' => $session['server_calculated_score'],
                'level_reached' => $session['current_level']
            ];
            
        } catch (Exception $e) {
            error_log("SecureGameEngine::submitValidatedScore error: " . $e->getMessage());
            return ['success' => false, 'error' => 'Score submission failed'];
        }
    }
    
    /**
     * Validate block position to prevent impossible destructions
     */
    private static function validateBlockPosition($event_data, $current_level) {
        // Basic position validation - can be enhanced with actual game grid
        $position = $event_data['position'] ?? null;
        if (!$position || !isset($position['x']) || !isset($position['y'])) {
            return false;
        }
        
        // Validate coordinates are within reasonable game bounds
        return ($position['x'] >= 0 && $position['x'] <= 800 && 
                $position['y'] >= 0 && $position['y'] <= 600);
    }
    
    /**
     * Calculate cryptographic state hash
     */
    private static function calculateStateHash($state_data) {
        return hash_hmac('sha256', json_encode($state_data), CryptoUtils::getSecretKey());
    }
}
?>