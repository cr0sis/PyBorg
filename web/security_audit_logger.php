<?php
/**
 * Security Audit Logger - Comprehensive logging and fraud detection
 */

require_once 'config_paths.php';

class SecurityAuditLogger {
    
    private static $audit_db_path = null;
    
    /**
     * Initialize audit logging system
     */
    private static function initializeAuditDB() {
        if (self::$audit_db_path === null) {
            self::$audit_db_path = ConfigPaths::getDatabase('security_audit');
        }
        
        try {
            $pdo = new PDO("sqlite:" . self::$audit_db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Create comprehensive audit tables
            $pdo->exec("CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                session_id TEXT,
                player_name TEXT,
                event_data TEXT,
                risk_score INTEGER DEFAULT 0,
                action_taken TEXT,
                investigation_status TEXT DEFAULT 'pending'
            )");
            
            $pdo->exec("CREATE TABLE IF NOT EXISTS fraud_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_type TEXT NOT NULL,
                pattern_signature TEXT NOT NULL,
                first_detected DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_detected DATETIME DEFAULT CURRENT_TIMESTAMP,
                occurrence_count INTEGER DEFAULT 1,
                associated_ips TEXT,
                pattern_data TEXT,
                auto_block_enabled BOOLEAN DEFAULT FALSE
            )");
            
            $pdo->exec("CREATE TABLE IF NOT EXISTS ip_reputation (
                ip_address TEXT PRIMARY KEY,
                reputation_score INTEGER DEFAULT 100,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                total_attempts INTEGER DEFAULT 0,
                suspicious_attempts INTEGER DEFAULT 0,
                blocked_attempts INTEGER DEFAULT 0,
                is_banned BOOLEAN DEFAULT FALSE,
                ban_reason TEXT,
                ban_timestamp DATETIME
            )");
            
            return $pdo;
        } catch (Exception $e) {
            error_log("SecurityAuditLogger initialization error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Log a security event
     */
    public static function logSecurityEvent($event_type, $severity, $event_data = [], $risk_score = 0) {
        try {
            $pdo = self::initializeAuditDB();
            if (!$pdo) return false;
            
            $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            $session_id = $event_data['session_id'] ?? '';
            $player_name = $event_data['player_name'] ?? '';
            
            // Determine action taken based on severity
            $action_taken = self::determineSecurityAction($severity, $risk_score, $event_data);
            
            $stmt = $pdo->prepare("INSERT INTO security_events 
                (event_type, severity, ip_address, user_agent, session_id, player_name, 
                 event_data, risk_score, action_taken) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
            
            $stmt->execute([
                $event_type,
                $severity,
                $ip_address,
                $user_agent,
                $session_id,
                $player_name,
                json_encode($event_data),
                $risk_score,
                $action_taken
            ]);
            
            // Update IP reputation
            self::updateIPReputation($ip_address, $severity, $risk_score);
            
            // Check for fraud patterns
            self::detectFraudPatterns($event_type, $event_data, $ip_address);
            
            // Send alerts for high-severity events
            if (in_array($severity, ['HIGH', 'CRITICAL'])) {
                self::sendSecurityAlert($event_type, $severity, $event_data, $ip_address);
            }
            
            return true;
            
        } catch (Exception $e) {
            error_log("SecurityAuditLogger::logSecurityEvent error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Determine appropriate security action
     */
    private static function determineSecurityAction($severity, $risk_score, $event_data) {
        switch ($severity) {
            case 'CRITICAL':
                return 'IP_BANNED_AUTO';
                
            case 'HIGH':
                if ($risk_score > 8) {
                    return 'IP_TEMP_BLOCKED';
                }
                return 'SESSION_INVALIDATED';
                
            case 'MEDIUM':
                return 'SCORE_REJECTED';
                
            case 'LOW':
                return 'LOGGED_ONLY';
                
            default:
                return 'NO_ACTION';
        }
    }
    
    /**
     * Update IP reputation scoring
     */
    private static function updateIPReputation($ip_address, $severity, $risk_score) {
        try {
            $pdo = self::initializeAuditDB();
            if (!$pdo) return;
            
            // Get current reputation
            $stmt = $pdo->prepare("SELECT * FROM ip_reputation WHERE ip_address = ?");
            $stmt->execute([$ip_address]);
            $reputation = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$reputation) {
                // Create new reputation record
                $stmt = $pdo->prepare("INSERT INTO ip_reputation 
                    (ip_address, reputation_score, total_attempts, suspicious_attempts) 
                    VALUES (?, ?, 1, ?)");
                $initial_score = 100 - $risk_score;
                $suspicious = in_array($severity, ['HIGH', 'CRITICAL']) ? 1 : 0;
                $stmt->execute([$ip_address, $initial_score, $suspicious]);
            } else {
                // Update existing reputation
                $reputation_change = 0;
                $suspicious_increment = 0;
                
                switch ($severity) {
                    case 'CRITICAL':
                        $reputation_change = -20;
                        $suspicious_increment = 1;
                        break;
                    case 'HIGH':
                        $reputation_change = -10;
                        $suspicious_increment = 1;
                        break;
                    case 'MEDIUM':
                        $reputation_change = -5;
                        break;
                    case 'LOW':
                        $reputation_change = -1;
                        break;
                }
                
                $new_score = max(0, $reputation['reputation_score'] + $reputation_change);
                
                // Auto-ban only for non-game events
                $is_game_event = in_array($event_type, ['anti_cheat_detection', 'impossible_score_detected', 'score_validation_failed']);
                $should_ban = !$is_game_event && ($new_score <= 10 || $reputation['suspicious_attempts'] + $suspicious_increment >= 5);
                
                $stmt = $pdo->prepare("UPDATE ip_reputation SET 
                    reputation_score = ?,
                    last_activity = CURRENT_TIMESTAMP,
                    total_attempts = total_attempts + 1,
                    suspicious_attempts = suspicious_attempts + ?,
                    is_banned = ?,
                    ban_reason = ?,
                    ban_timestamp = ?
                    WHERE ip_address = ?");
                
                $ban_reason = $should_ban ? "Auto-banned: reputation={$new_score}, suspicious_attempts=" . ($reputation['suspicious_attempts'] + $suspicious_increment) : null;
                $ban_timestamp = $should_ban ? date('Y-m-d H:i:s') : null;
                
                $stmt->execute([
                    $new_score,
                    $suspicious_increment,
                    $should_ban ? 1 : 0,
                    $ban_reason,
                    $ban_timestamp,
                    $ip_address
                ]);
                
                if ($should_ban) {
                    error_log("AUTO-BAN: IP $ip_address banned due to reputation score $new_score");
                }
            }
            
        } catch (Exception $e) {
            error_log("SecurityAuditLogger::updateIPReputation error: " . $e->getMessage());
        }
    }
    
    /**
     * Detect and track fraud patterns
     */
    private static function detectFraudPatterns($event_type, $event_data, $ip_address) {
        try {
            $pdo = self::initializeAuditDB();
            if (!$pdo) return;
            
            // Generate pattern signatures based on event characteristics
            $patterns = [];
            
            // Score manipulation pattern
            if (isset($event_data['score']) && isset($event_data['level'])) {
                $score_per_level = $event_data['score'] / max(1, $event_data['level']);
                if ($score_per_level > 5000) { // Unrealistic score per level
                    $patterns[] = [
                        'type' => 'excessive_score_per_level',
                        'signature' => 'score_level_ratio_' . ceil($score_per_level / 1000)
                    ];
                }
            }
            
            // Timing pattern
            if (isset($event_data['game_duration']) && isset($event_data['level'])) {
                $time_per_level = $event_data['game_duration'] / max(1, $event_data['level']);
                if ($time_per_level < 10) { // Too fast progression
                    $patterns[] = [
                        'type' => 'rapid_progression',
                        'signature' => 'fast_level_' . ceil($time_per_level)
                    ];
                }
            }
            
            // Bot-like behavior pattern
            if (isset($event_data['flags']) && is_array($event_data['flags'])) {
                $bot_indicators = ['extremely_consistent_timing', 'repetitive_timing_pattern', 'perfect_performance_pattern'];
                $bot_flags = array_intersect($event_data['flags'], $bot_indicators);
                if (!empty($bot_flags)) {
                    $patterns[] = [
                        'type' => 'bot_behavior',
                        'signature' => 'bot_' . implode('_', $bot_flags)
                    ];
                }
            }
            
            // Record detected patterns
            foreach ($patterns as $pattern) {
                $stmt = $pdo->prepare("SELECT id FROM fraud_patterns 
                                      WHERE pattern_type = ? AND pattern_signature = ?");
                $stmt->execute([$pattern['type'], $pattern['signature']]);
                $existing = $stmt->fetch();
                
                if ($existing) {
                    // Update existing pattern
                    $stmt = $pdo->prepare("UPDATE fraud_patterns SET 
                        last_detected = CURRENT_TIMESTAMP,
                        occurrence_count = occurrence_count + 1,
                        associated_ips = CASE 
                            WHEN associated_ips LIKE ? THEN associated_ips 
                            ELSE associated_ips || ',' || ?
                        END
                        WHERE id = ?");
                    $ip_search = "%$ip_address%";
                    $stmt->execute([$ip_search, $ip_address, $existing['id']]);
                } else {
                    // Create new pattern
                    $stmt = $pdo->prepare("INSERT INTO fraud_patterns 
                        (pattern_type, pattern_signature, associated_ips, pattern_data) 
                        VALUES (?, ?, ?, ?)");
                    $stmt->execute([
                        $pattern['type'],
                        $pattern['signature'],
                        $ip_address,
                        json_encode($event_data)
                    ]);
                }
            }
            
        } catch (Exception $e) {
            error_log("SecurityAuditLogger::detectFraudPatterns error: " . $e->getMessage());
        }
    }
    
    /**
     * Send security alerts for high-risk events
     */
    private static function sendSecurityAlert($event_type, $severity, $event_data, $ip_address) {
        $alert_message = "SECURITY ALERT: $severity $event_type from IP $ip_address\n";
        $alert_message .= "Event Data: " . json_encode($event_data, JSON_PRETTY_PRINT) . "\n";
        $alert_message .= "Timestamp: " . date('Y-m-d H:i:s') . "\n";
        
        error_log("SECURITY_ALERT: $alert_message");
        
        // Could also send email, webhook, or other notifications here
        // Example: mail('admin@example.com', 'Security Alert', $alert_message);
    }
    
    /**
     * Check if IP address is banned
     */
    public static function isIPBanned($ip_address) {
        try {
            $pdo = self::initializeAuditDB();
            if (!$pdo) return false;
            
            $stmt = $pdo->prepare("SELECT is_banned FROM ip_reputation WHERE ip_address = ?");
            $stmt->execute([$ip_address]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return $result ? (bool)$result['is_banned'] : false;
            
        } catch (Exception $e) {
            error_log("SecurityAuditLogger::isIPBanned error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get IP reputation score
     */
    public static function getIPReputation($ip_address) {
        try {
            $pdo = self::initializeAuditDB();
            if (!$pdo) return 100; // Default good reputation
            
            $stmt = $pdo->prepare("SELECT reputation_score FROM ip_reputation WHERE ip_address = ?");
            $stmt->execute([$ip_address]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return $result ? $result['reputation_score'] : 100;
            
        } catch (Exception $e) {
            error_log("SecurityAuditLogger::getIPReputation error: " . $e->getMessage());
            return 100;
        }
    }
    
    /**
     * Get security events for admin dashboard
     */
    public static function getRecentSecurityEvents($limit = 50) {
        try {
            $pdo = self::initializeAuditDB();
            if (!$pdo) return [];
            
            $stmt = $pdo->prepare("SELECT * FROM security_events 
                                  ORDER BY timestamp DESC LIMIT ?");
            $stmt->execute([$limit]);
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch (Exception $e) {
            error_log("SecurityAuditLogger::getRecentSecurityEvents error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get fraud patterns summary
     */
    public static function getFraudPatternsSummary() {
        try {
            $pdo = self::initializeAuditDB();
            if (!$pdo) return [];
            
            $stmt = $pdo->prepare("SELECT pattern_type, COUNT(*) as pattern_count, 
                                         SUM(occurrence_count) as total_occurrences,
                                         MAX(last_detected) as most_recent
                                  FROM fraud_patterns 
                                  GROUP BY pattern_type 
                                  ORDER BY total_occurrences DESC");
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch (Exception $e) {
            error_log("SecurityAuditLogger::getFraudPatternsSummary error: " . $e->getMessage());
            return [];
        }
    }
}
?>