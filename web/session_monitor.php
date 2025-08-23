<?php
/**
 * Session Monitoring System
 * Tracks active sessions and detects concurrent logins
 */

class SessionMonitor {
    // DEPRECATED: Moved to SecureSessionManager for database storage
    private static $session_file = '/tmp/active_sessions.json';
    
    /**
     * Record new session - REDIRECTS TO SECURE MANAGER
     */
    public static function recordSession($user_id, $username, $is_admin = false) {
        require_once 'secure_session_manager.php';
        return SecureSessionManager::recordSession($user_id, $username, $is_admin);
        $sessions = self::loadSessions();
        $session_id = session_id();
        $current_time = time();
        
        // Check for existing sessions by this user
        $existing_sessions = array_filter($sessions, function($s) use ($user_id) {
            return $s['user_id'] == $user_id && ($s['last_activity'] > time() - 3600); // Active in last hour
        });
        
        if (count($existing_sessions) > 0 && $is_admin) {
            // Admin with concurrent session detected
            require_once 'security_config.php';
            logSecurityEvent('CONCURRENT_ADMIN_SESSION', 
                "Admin user $username has multiple active sessions", 'HIGH');
        }
        
        // Add current session
        $sessions[$session_id] = [
            'user_id' => $user_id,
            'username' => $username,
            'is_admin' => $is_admin,
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'login_time' => $current_time,
            'last_activity' => $current_time
        ];
        
        self::saveSessions($sessions);
        
        // Cleanup old sessions
        self::cleanupExpiredSessions();
    }
    
    /**
     * Update session activity
     */
    public static function updateActivity() {
        $sessions = self::loadSessions();
        $session_id = session_id();
        
        if (isset($sessions[$session_id])) {
            $sessions[$session_id]['last_activity'] = time();
            self::saveSessions($sessions);
        }
    }
    
    /**
     * Remove session - REDIRECTS TO SECURE MANAGER
     */
    public static function removeSession($session_id = null) {
        require_once 'secure_session_manager.php';
        return SecureSessionManager::removeSession($session_id);
        if ($session_id === null) {
            $session_id = session_id();
        }
        
        $sessions = self::loadSessions();
        
        if (isset($sessions[$session_id])) {
            require_once 'security_config.php';
            logSecurityEvent('SESSION_ENDED', 
                "Session ended for user: {$sessions[$session_id]['username']}", 'LOW');
            
            unset($sessions[$session_id]);
            self::saveSessions($sessions);
        }
    }
    
    /**
     * Get active sessions for a user
     */
    public static function getUserSessions($user_id) {
        $sessions = self::loadSessions();
        
        return array_filter($sessions, function($session) use ($user_id) {
            return $session['user_id'] == $user_id && 
                   ($session['last_activity'] > time() - 3600);
        });
    }
    
    /**
     * Get all active admin sessions
     */
    public static function getAdminSessions() {
        $sessions = self::loadSessions();
        
        return array_filter($sessions, function($session) {
            return $session['is_admin'] && 
                   ($session['last_activity'] > time() - 3600);
        });
    }
    
    /**
     * Kill all sessions for a user
     */
    public static function killUserSessions($user_id, $except_current = false) {
        $sessions = self::loadSessions();
        $current_session = $except_current ? session_id() : '';
        $killed_count = 0;
        
        foreach ($sessions as $session_id => $session) {
            if ($session['user_id'] == $user_id && $session_id !== $current_session) {
                unset($sessions[$session_id]);
                $killed_count++;
            }
        }
        
        if ($killed_count > 0) {
            self::saveSessions($sessions);
            require_once 'security_config.php';
            logSecurityEvent('SESSIONS_KILLED', 
                "Killed $killed_count sessions for user_id: $user_id", 'MEDIUM');
        }
        
        return $killed_count;
    }
    
    /**
     * Check if session is valid
     */
    public static function isValidSession($session_id = null) {
        if ($session_id === null) {
            $session_id = session_id();
        }
        
        $sessions = self::loadSessions();
        
        if (!isset($sessions[$session_id])) {
            return false;
        }
        
        $session = $sessions[$session_id];
        
        // Check if session has expired (1 hour)
        if ($session['last_activity'] < time() - 3600) {
            unset($sessions[$session_id]);
            self::saveSessions($sessions);
            return false;
        }
        
        // Check IP binding for admin sessions
        if ($session['is_admin'] && $session['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
            require_once 'security_config.php';
            logSecurityEvent('ADMIN_SESSION_IP_MISMATCH', 
                "Admin session IP changed from {$session['ip_address']} to {$_SERVER['REMOTE_ADDR']}", 'CRITICAL');
            
            unset($sessions[$session_id]);
            self::saveSessions($sessions);
            return false;
        }
        
        return true;
    }
    
    /**
     * Load sessions from file
     */
    private static function loadSessions() {
        if (!file_exists(self::$session_file)) {
            return [];
        }
        
        $data = file_get_contents(self::$session_file);
        return json_decode($data, true) ?: [];
    }
    
    /**
     * Save sessions to file
     */
    private static function saveSessions($sessions) {
        file_put_contents(self::$session_file, json_encode($sessions), LOCK_EX);
    }
    
    /**
     * Clean up expired sessions
     */
    private static function cleanupExpiredSessions() {
        $sessions = self::loadSessions();
        $cleaned = false;
        
        foreach ($sessions as $session_id => $session) {
            if ($session['last_activity'] < time() - 3600) {
                unset($sessions[$session_id]);
                $cleaned = true;
            }
        }
        
        if ($cleaned) {
            self::saveSessions($sessions);
        }
    }
    
    /**
     * Get session statistics
     */
    public static function getStats() {
        $sessions = self::loadSessions();
        $active_sessions = array_filter($sessions, function($s) {
            return $s['last_activity'] > time() - 3600;
        });
        
        $admin_sessions = array_filter($active_sessions, function($s) {
            return $s['is_admin'];
        });
        
        return [
            'total_active' => count($active_sessions),
            'admin_active' => count($admin_sessions),
            'unique_users' => count(array_unique(array_column($active_sessions, 'user_id'))),
            'unique_ips' => count(array_unique(array_column($active_sessions, 'ip_address')))
        ];
    }
}
?>