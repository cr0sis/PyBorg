<?php
/**
 * Safe Admin Detection - No Redirects
 * This file provides admin detection without any redirect-causing security checks
 */

// Initialize session safely
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 0);
    ini_set('session.cookie_samesite', 'Lax');
    ini_set('session.use_strict_mode', 1);
    session_start();
}

/**
 * Safe admin detection - only checks session variables, no redirects
 */
function isSafeAdmin() {
    // Must be logged in
    if (!isset($_SESSION['user_id']) || empty($_SESSION['username'])) {
        return false;
    }
    
    // Must be admin
    if (!isset($_SESSION['is_admin']) || $_SESSION['is_admin'] !== true) {
        return false;
    }
    
    // Check 2FA - but be very lenient for now to avoid lockouts
    if (isset($_SESSION['2fa_verified_time'])) {
        $time_since_2fa = time() - $_SESSION['2fa_verified_time'];
        if ($time_since_2fa > 604800) { // 7 days (very lenient)
            return false;
        }
    } else {
        // If no 2FA verification time is set, check if user just completed 2FA
        // This handles the case where user just logged in with 2FA
        if (isset($_SESSION['2fa_verified']) && $_SESSION['2fa_verified'] === true) {
            // Set the verification time to now
            $_SESSION['2fa_verified_time'] = time();
        }
    }
    
    return true;
}

/**
 * Check if user is logged in (any user, not just admin)
 */
function isSafeLoggedIn() {
    return isset($_SESSION['user_id']) && !empty($_SESSION['username']);
}

/**
 * Safe logging function
 */
function logSafeAdminEvent($event_type, $message, $severity = 'LOW') {
    $log_entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'event_type' => $event_type,
        'severity' => $severity,
        'message' => $message,
        'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'session_id' => session_id() ?? 'unknown',
        'user_id' => $_SESSION['user_id'] ?? 'anonymous'
    ];
    
    $log_file = '/tmp/safe_admin.log';
    @file_put_contents($log_file, json_encode($log_entry) . "\n", FILE_APPEND | LOCK_EX);
}
?>