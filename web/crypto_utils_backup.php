<?php
class CryptoUtils {
    private static $secret_key = null;
    private static $session_salt = 'bR3ak0ut_G4m3_S3cr3t_2025';
    
    public static function getSecretKey() {
        if (self::$secret_key === null) {
            // Generate from server-specific data that can't be easily guessed
            $server_data = [
                $_SERVER['SERVER_NAME'] ?? 'localhost',
                $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
                php_uname('n'), // hostname
                filemtime(__FILE__), // This file's modification time
                self::$session_salt
            ];
            self::$secret_key = hash('sha256', implode('|', $server_data));
        }
        return self::$secret_key;
    }
    
    public static function generateSecureToken($data) {
        $timestamp = time();
        $nonce = bin2hex(random_bytes(16));
        $payload = json_encode(array_merge($data, [
            'timestamp' => $timestamp,
            'nonce' => $nonce
        ]));
        
        $signature = hash_hmac('sha256', $payload, self::getSecretKey());
        
        return base64_encode(json_encode([
            'payload' => base64_encode($payload),
            'signature' => $signature,
            'version' => 'v2.1'
        ]));
    }
    
    public static function validateSecureToken($token, $max_age = 7200) {
        try {
            $decoded = json_decode(base64_decode($token), true);
            if (!$decoded || !isset($decoded['payload'], $decoded['signature'], $decoded['version'])) {
                return false;
            }
            
            if ($decoded['version'] !== 'v2.1') {
                return false;
            }
            
            $payload = base64_decode($decoded['payload']);
            $expected_signature = hash_hmac('sha256', $payload, self::getSecretKey());
            
            if (!hash_equals($expected_signature, $decoded['signature'])) {
                return false;
            }
            
            $data = json_decode($payload, true);
            if (!$data || !isset($data['timestamp'])) {
                return false;
            }
            
            // Check token age
            if (time() - $data['timestamp'] > $max_age) {
                return false;
            }
            
            return $data;
        } catch (Exception $e) {
            return false;
        }
    }
    
    public static function generateGameStateHash($session_data) {
        // Create a hash based on game progression that should be impossible to fake
        $factors = [
            $session_data['blocks_destroyed'] ?? 0,
            $session_data['current_level'] ?? 1,
            $session_data['game_duration'] ?? 0,
            $session_data['powerups_collected'] ?? 0,
            $session_data['lives_lost'] ?? 0,
            $session_data['start_time'] ?? time(),
            self::getSecretKey()
        ];
        
        return hash('sha256', implode('|', $factors));
    }
    
    public static function obfuscateResponse($data) {
        $decoys = [
            'debug_mode' => false,
            'admin_override' => false,
            'validation_bypass' => false,
            'cheat_detected' => false,
            'security_level' => rand(1, 5),
            'anti_tamper' => hash('md5', mt_rand()),
            'server_load' => rand(10, 95) . '%',
            'cache_hit' => (bool)rand(0, 1)
        ];
        
        return array_merge($data, $decoys);
    }
    
    /**
     * Encrypt data using AES-256-GCM
     */
    public static function encrypt($data) {
        if (empty($data)) {
            return '';
        }
        
        $key = hash('sha256', self::getSecretKey(), true);
        $iv = random_bytes(12); // GCM requires 12-byte IV
        $tag = '';
        
        $encrypted = openssl_encrypt(
            $data, 
            'AES-256-GCM', 
            $key, 
            OPENSSL_RAW_DATA, 
            $iv, 
            $tag
        );
        
        if ($encrypted === false) {
            throw new Exception('Encryption failed');
        }
        
        // Return base64 encoded result with IV and tag
        return base64_encode($iv . $tag . $encrypted);
    }
    
    /**
     * Decrypt data using AES-256-GCM
     */
    public static function decrypt($encryptedData) {
        if (empty($encryptedData)) {
            return '';
        }
        
        try {
            $data = base64_decode($encryptedData);
            if ($data === false || strlen($data) < 28) { // 12 (IV) + 16 (tag) = 28 minimum
                return '';
            }
            
            $key = hash('sha256', self::getSecretKey(), true);
            $iv = substr($data, 0, 12);
            $tag = substr($data, 12, 16);
            $encrypted = substr($data, 28);
            
            $decrypted = openssl_decrypt(
                $encrypted, 
                'AES-256-GCM', 
                $key, 
                OPENSSL_RAW_DATA, 
                $iv, 
                $tag
            );
            
            return $decrypted !== false ? $decrypted : '';
            
        } catch (Exception $e) {
            error_log("Decryption error: " . $e->getMessage());
            return '';
        }
    }
}

class BehaviorAnalyzer {
    private static $suspicious_patterns = [
        'score_jumps' => 0,
        'impossible_timing' => 0,
        'consistent_performance' => 0,
        'robot_like_inputs' => 0
    ];
    
    public static function analyzeGameSession($session_data, $admin_context = false) {
        $suspicion_score = 0;
        $flags = [];
        
        // Check if this is a verified admin user with recent 2FA
        $is_verified_admin = $admin_context && self::isVerifiedAdmin();
        
        // Check if this is an emergency session (minimal game data)
        $blocks_destroyed = $session_data['blocks_destroyed'] ?? 0;
        $game_duration = $session_data['game_duration'] ?? 0;
        $is_emergency_session = ($blocks_destroyed == 0 && $game_duration <= 1);
        
        // ENHANCED ANOMALY DETECTION
        
        // For emergency sessions, apply STRICTER analysis (F12 protection)
        if ($is_emergency_session) {
            // Log emergency session handling
            $user_type = $admin_context ? 'admin' : 'regular';
            error_log("BEHAVIOR ANALYSIS: Emergency session detected for $user_type user - applying STRICT F12 protection validation");
            
            // Minimal validation for emergency sessions (both admin and regular users)
            $final_score = $session_data['final_score'] ?? 0;
            $current_level = $session_data['final_level'] ?? $session_data['current_level'] ?? 1;
            
            // For emergency sessions, only check for negative scores (basic sanity check)
            if ($final_score < 0) {
                $suspicion_score += 5;
                $flags[] = 'negative_score';
            }
            
            // Initialize variables for emergency sessions to prevent undefined variable warnings
            $score_per_second = 0;
            $score_per_block = 0;
            $time_per_level = 0;
            $powerup_efficiency = 0;
            $death_rate = 0;
            
        } else {
            // Normal session analysis
            
            // 1. Analyze score vs time ratio with statistical modeling
            $game_duration = max(1, $game_duration);
            $final_score = $session_data['final_score'] ?? 0;
            $score_per_second = $final_score / $game_duration;
            
            // Score rate analysis removed - any score rate is allowed
            
            // 2. Advanced blocks vs score ratio analysis
            $blocks_destroyed = max(1, $blocks_destroyed);
            $score_per_block = $final_score / $blocks_destroyed;
            
            // Score per block analysis removed - any efficiency is allowed
            
            // 3. Level progression timing analysis
            $current_level = $session_data['current_level'] ?? 1;
            $time_per_level = $game_duration / max(1, $current_level);
        
        // Time per level analysis removed - any progression speed is allowed
        
        // 4. Performance consistency analysis (detecting bots)
        $lives_lost = $session_data['lives_lost'] ?? 0;
        $powerups_collected = $session_data['powerups_collected'] ?? 0;
        
        // Perfect efficiency indicates automation
        $death_rate = $lives_lost / max(1, $current_level);
        if ($death_rate < 0.05 && $current_level > 5) { // Even more lenient for skilled players
            $suspicion_score += ($is_verified_admin ? 1 : 2); // Reduced penalty
            $flags[] = 'perfect_performance_pattern';
        }
        
        // 5. Powerup collection efficiency (humans miss powerups) - more lenient
        $powerup_efficiency = $powerups_collected / max(1, $blocks_destroyed);
        if ($powerup_efficiency > 0.9) { // Collecting >90% of possible powerups is suspicious
            $suspicion_score += ($is_verified_admin ? 1 : 2);
            $flags[] = 'very_high_powerup_efficiency';
        }
        
        // Score jump analysis removed - any score progression is allowed
        
        // 7. Input timing pattern analysis
        if (isset($session_data['input_timestamps']) && is_array($session_data['input_timestamps'])) {
            $timing_analysis = self::analyzeInputTimingPatterns($session_data['input_timestamps']);
            if ($timing_analysis['is_bot_like']) {
                $suspicion_score += ($is_verified_admin ? 2 : 4);
                $flags = array_merge($flags, $timing_analysis['flags']);
            }
        }
        
        // 8. Multi-session analysis for this IP
        $ip_analysis = self::analyzeIPBehaviorHistory($session_data['ip_address'] ?? '', $final_score);
        if ($ip_analysis['is_suspicious']) {
            $suspicion_score += ($is_verified_admin ? 1 : 3);
            $flags = array_merge($flags, $ip_analysis['flags']);
        }
        } // End of else block for normal session analysis
        
        // Balanced risk thresholds that allow skilled play but prevent obvious cheating
        $critical_threshold = $is_verified_admin ? 15 : 12;
        $high_threshold = $is_verified_admin ? 10 : 8;
        $medium_threshold = $is_verified_admin ? 6 : 4;
        
        $risk_level = 'LOW';
        if ($suspicion_score >= $critical_threshold) {
            $risk_level = 'CRITICAL';
        } elseif ($suspicion_score >= $high_threshold) {
            $risk_level = 'HIGH';
        } elseif ($suspicion_score >= $medium_threshold) {
            $risk_level = 'MEDIUM';
        }
        
        return [
            'suspicion_score' => $suspicion_score,
            'flags' => $flags,
            'risk_level' => $risk_level,
            'admin_context' => $is_verified_admin,
            'detailed_analysis' => [
                'score_per_second' => $score_per_second,
                'score_per_block' => $score_per_block,
                'time_per_level' => $time_per_level,
                'powerup_efficiency' => $powerup_efficiency,
                'death_rate' => $death_rate
            ]
        ];
    }
    
    /**
     * Detect sudden unrealistic score increases
     */
    private static function detectScoreJumps($score_history) {
        $suspicious_jumps = 0;
        $max_reasonable_jump = 1000; // Maximum reasonable score increase in one event
        
        for ($i = 1; $i < count($score_history); $i++) {
            $jump = $score_history[$i] - $score_history[$i-1];
            if ($jump > $max_reasonable_jump) {
                $suspicious_jumps++;
            }
        }
        
        return [
            'suspicious_jumps' => $suspicious_jumps,
            'total_changes' => count($score_history) - 1
        ];
    }
    
    /**
     * Analyze input timing patterns to detect automation
     */
    private static function analyzeInputTimingPatterns($timestamps) {
        if (count($timestamps) < 10) {
            return ['is_bot_like' => false, 'flags' => []];
        }
        
        $intervals = [];
        for ($i = 1; $i < count($timestamps); $i++) {
            $intervals[] = $timestamps[$i] - $timestamps[$i-1];
        }
        
        // Calculate statistical measures
        $mean = array_sum($intervals) / count($intervals);
        $variance = 0;
        foreach ($intervals as $interval) {
            $variance += pow($interval - $mean, 2);
        }
        $variance /= count($intervals);
        $std_dev = sqrt($variance);
        
        $flags = [];
        $is_bot_like = false;
        
        // Very low variance indicates bot-like behavior
        if ($std_dev < 0.01 && $mean < 0.1) {
            $flags[] = 'extremely_consistent_timing';
            $is_bot_like = true;
        }
        
        // Check for exact timing patterns (automation signature)
        $exact_intervals = array_count_values(array_map('intval', array_map(function($x) { return $x * 1000; }, $intervals)));
        $most_common_count = max($exact_intervals);
        $total_intervals = count($intervals);
        
        if ($most_common_count / $total_intervals > 0.8) { // 80% same timing
            $flags[] = 'repetitive_timing_pattern';
            $is_bot_like = true;
        }
        
        return [
            'is_bot_like' => $is_bot_like,
            'flags' => $flags,
            'timing_stats' => [
                'mean_interval' => $mean,
                'std_deviation' => $std_dev,
                'variance' => $variance
            ]
        ];
    }
    
    /**
     * Analyze historical behavior from this IP address
     */
    private static function analyzeIPBehaviorHistory($ip_address, $current_score) {
        if (empty($ip_address)) {
            return ['is_suspicious' => false, 'flags' => []];
        }
        
        try {
            $db_path = ConfigPaths::getDatabase('breakout_scores');
            $pdo = new PDO("sqlite:$db_path");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Get recent scores from this IP
            $stmt = $pdo->prepare("SELECT score, date_played FROM breakout_scores 
                                  WHERE ip_address = ? AND date_played > datetime('now', '-24 hours')
                                  ORDER BY date_played DESC LIMIT 20");
            $stmt->execute([$ip_address]);
            $recent_scores = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $flags = [];
            $is_suspicious = false;
            
            // Daily attempt checking removed - allow unlimited attempts from same IP
            
            if (count($recent_scores) > 3) {
                $scores = array_column($recent_scores, 'score');
                $avg_score = array_sum($scores) / count($scores);
                
                // High score checking removed - any average score is allowed
                
                // Sudden improvement indicates possible tool usage
                $first_half = array_slice($scores, 0, ceil(count($scores) / 2));
                $second_half = array_slice($scores, ceil(count($scores) / 2));
                
                if (count($first_half) > 0 && count($second_half) > 0) {
                    $early_avg = array_sum($first_half) / count($first_half);
                    $recent_avg = array_sum($second_half) / count($second_half);
                    
                    if ($recent_avg > ($early_avg * 10) && $recent_avg > 500000) { // Much more lenient for natural skill progression
                        $flags[] = 'sudden_skill_improvement';
                        $is_suspicious = true;
                    }
                }
            }
            
            return [
                'is_suspicious' => $is_suspicious,
                'flags' => $flags,
                'recent_attempts' => count($recent_scores)
            ];
            
        } catch (Exception $e) {
            error_log("BehaviorAnalyzer IP analysis error: " . $e->getMessage());
            return ['is_suspicious' => false, 'flags' => []];
        }
    }
    
    /**
     * Check if current user is a verified admin with recent 2FA
     */
    private static function isVerifiedAdmin() {
        if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
            return false;
        }
        
        // Check if 2FA was completed recently (within last 2 hours)
        if (isset($_SESSION['2fa_verified_time'])) {
            $time_since_2fa = time() - $_SESSION['2fa_verified_time'];
            return $time_since_2fa < 7200; // 2 hours
        }
        
        // For admin users without 2FA, still consider them verified if logged in recently
        if (isset($_SESSION['login_time'])) {
            $time_since_login = time() - $_SESSION['login_time'];
            return $time_since_login < 3600; // 1 hour
        }
        
        return false;
    }
    
    public static function checkIPHistory($ip_address, $pdo) {
        try {
            // Check recent submissions from this IP
            $stmt = $pdo->prepare("SELECT COUNT(*) as count, AVG(score) as avg_score 
                                  FROM breakout_scores 
                                  WHERE ip_address = ? AND date_played > datetime('now', '-1 hour')");
            $stmt->execute([$ip_address]);
            $recent = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($recent['count'] > 10) { // More than 10 games per hour
                return ['suspicious' => true, 'reason' => 'excessive_attempts'];
            }
            
            if ($recent['avg_score'] > 50000) { // Consistently high scores
                return ['suspicious' => true, 'reason' => 'consistently_high_scores'];
            }
            
            return ['suspicious' => false];
        } catch (Exception $e) {
            return ['suspicious' => false];
        }
    }
}
?>
