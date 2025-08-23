<?php
/**
 * Secure Session Manager
 * Moves session storage from temp files to encrypted database storage
 * Prevents session hijacking via file system access
 */

require_once 'config_paths.php';
require_once 'security_config.php';

class SecureSessionManager {
    private static $db_path;
    private static $encryption_key;
    
    public static function init() {
        self::$db_path = ConfigPaths::getDatabase('secure_sessions');
        self::$encryption_key = hash('sha256', ENCRYPTION_KEY . $_SERVER['HTTP_HOST'], true);
        self::initDatabase();
    }
    
    private static function initDatabase() {
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS secure_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    ip_address TEXT NOT NULL,
                    user_agent_hash TEXT NOT NULL,
                    session_data TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    last_activity INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    admin_reauth_time INTEGER DEFAULT NULL,
                    security_flags TEXT DEFAULT '{}'
                )
            ");
            
            // Create indexes separately
            $pdo->exec("CREATE INDEX IF NOT EXISTS idx_secure_sessions_user_id ON secure_sessions(user_id)");
            $pdo->exec("CREATE INDEX IF NOT EXISTS idx_secure_sessions_expires_at ON secure_sessions(expires_at)");
            $pdo->exec("CREATE INDEX IF NOT EXISTS idx_secure_sessions_is_active ON secure_sessions(is_active)");
            
            // Clean up expired sessions
            $pdo->exec("DELETE FROM secure_sessions WHERE expires_at < " . time());
            
        } catch (PDOException $e) {
            error_log("SecureSessionManager init error: " . $e->getMessage());
            throw new Exception("Session storage initialization failed");
        }
    }
    
    /**
     * Encrypt sensitive session data
     */
    private static function encryptData($data) {
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt(
            json_encode($data), 
            'AES-256-CBC', 
            self::$encryption_key, 
            0, 
            $iv
        );
        return base64_encode($iv . $encrypted);
    }
    
    /**
     * Decrypt session data
     */
    private static function decryptData($encryptedData) {
        try {
            $data = base64_decode($encryptedData);
            $iv = substr($data, 0, 16);
            $encrypted = substr($data, 16);
            
            $decrypted = openssl_decrypt(
                $encrypted, 
                'AES-256-CBC', 
                self::$encryption_key, 
                0, 
                $iv
            );
            
            return json_decode($decrypted, true);
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Record new session
     */
    public static function recordSession($user_id, $username, $is_admin = false) {
        self::init();
        
        $session_id = session_id();
        $ip_address = $_SERVER['REMOTE_ADDR'];
        $user_agent_hash = hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? 'unknown');
        $now = time();
        $expires_at = $now + (3600 * 24); // 24 hours
        
        // Session data to encrypt
        $session_data = [
            'login_time' => $now,
            'last_ip' => $ip_address,
            'security_level' => $is_admin ? 'admin' : 'user',
            'login_method' => 'password',
            'browser_fingerprint' => $user_agent_hash
        ];
        
        // Security flags
        $security_flags = [
            'requires_2fa' => $is_admin,
            'ip_locked' => true,
            'suspicious_activity' => false
        ];
        
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Deactivate any existing sessions for this user
            $pdo->prepare("UPDATE secure_sessions SET is_active = 0 WHERE user_id = ? AND is_active = 1")
                ->execute([$user_id]);
            
            // Insert new session
            $stmt = $pdo->prepare("
                INSERT INTO secure_sessions 
                (session_id, user_id, username, is_admin, ip_address, user_agent_hash, 
                 session_data, created_at, last_activity, expires_at, security_flags) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            $stmt->execute([
                $session_id,
                $user_id,
                $username,
                $is_admin ? 1 : 0,
                $ip_address,
                $user_agent_hash,
                self::encryptData($session_data),
                $now,
                $now,
                $expires_at,
                json_encode($security_flags)
            ]);
            
            logSecurityEvent('SESSION_CREATED', 
                "Secure session created for user: $username (Admin: " . ($is_admin ? 'Yes' : 'No') . ")", 
                'LOW');
                
            return true;
            
        } catch (PDOException $e) {
            error_log("SecureSessionManager record error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Validate current session
     */
    public static function validateSession() {
        self::init();
        
        $session_id = session_id();
        if (!$session_id) return false;
        
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $stmt = $pdo->prepare("
                SELECT * FROM secure_sessions 
                WHERE session_id = ? AND is_active = 1 AND expires_at > ?
            ");
            $stmt->execute([$session_id, time()]);
            $session = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$session) {
                return false;
            }
            
            // Validate IP consistency for admin sessions
            if ($session['is_admin'] && $session['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
                logSecurityEvent('SESSION_IP_MISMATCH', 
                    "Admin session IP mismatch: {$session['ip_address']} vs {$_SERVER['REMOTE_ADDR']}", 
                    'HIGH');
                self::invalidateSession($session_id);
                return false;
            }
            
            // Update last activity
            $pdo->prepare("UPDATE secure_sessions SET last_activity = ? WHERE session_id = ?")
                ->execute([time(), $session_id]);
            
            return true;
            
        } catch (PDOException $e) {
            error_log("SecureSessionManager validate error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Remove/invalidate session
     */
    public static function removeSession($session_id = null) {
        self::init();
        
        if (!$session_id) {
            $session_id = session_id();
        }
        
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $pdo->prepare("UPDATE secure_sessions SET is_active = 0 WHERE session_id = ?")
                ->execute([$session_id]);
                
            logSecurityEvent('SESSION_REMOVED', 
                "Session removed: $session_id", 'LOW');
                
        } catch (PDOException $e) {
            error_log("SecureSessionManager remove error: " . $e->getMessage());
        }
    }
    
    /**
     * Invalidate session (security concern)
     */
    public static function invalidateSession($session_id) {
        self::removeSession($session_id);
        
        logSecurityEvent('SESSION_INVALIDATED', 
            "Session invalidated due to security concern: $session_id", 'MEDIUM');
    }
    
    /**
     * Get active admin sessions
     */
    public static function getActiveSessions($admin_only = false) {
        self::init();
        
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $sql = "
                SELECT session_id, user_id, username, is_admin, ip_address, 
                       created_at, last_activity, expires_at
                FROM secure_sessions 
                WHERE is_active = 1 AND expires_at > ?
            ";
            
            if ($admin_only) {
                $sql .= " AND is_admin = 1";
            }
            
            $sql .= " ORDER BY last_activity DESC";
            
            $stmt = $pdo->prepare($sql);
            $stmt->execute([time()]);
            
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
            
        } catch (PDOException $e) {
            error_log("SecureSessionManager get sessions error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Clean up expired sessions
     */
    public static function cleanup() {
        self::init();
        
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $stmt = $pdo->prepare("DELETE FROM secure_sessions WHERE expires_at < ?");
            $stmt->execute([time()]);
            
            $cleaned = $stmt->rowCount();
            if ($cleaned > 0) {
                logSecurityEvent('SESSION_CLEANUP', 
                    "Cleaned up $cleaned expired sessions", 'LOW');
            }
            
        } catch (PDOException $e) {
            error_log("SecureSessionManager cleanup error: " . $e->getMessage());
        }
    }
}

// Initialize and run cleanup
SecureSessionManager::cleanup();
?>