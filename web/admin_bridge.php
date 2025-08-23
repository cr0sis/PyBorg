<?php
/**
 * Admin authentication bridge for website admins
 * Allows website admins to automatically authenticate to admin panel session
 */

require_once 'security_config.php';
require_once 'config_paths.php';

// Initialize session if needed
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

header('Content-Type: application/json');

// Database configuration (web data directory)
$db_path = ConfigPaths::getDatabase('users');

/**
 * Check if user is logged in
 */
function isLoggedIn() {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

/**
 * Check if current user is admin
 */
function isAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'];
}

/**
 * Get current user data
 */
function getCurrentUser() {
    global $db_path;
    
    if (!isLoggedIn()) {
        return null;
    }
    
    try {
        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->prepare("SELECT id, username, email, is_admin FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        
        return $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        return null;
    }
}

// Check authentication
if (!isLoggedIn()) {
    echo json_encode(['success' => false, 'message' => 'Not logged in to website']);
    exit;
}

if (!isAdmin()) {
    echo json_encode(['success' => false, 'message' => 'Website admin privileges required']);
    exit;
}

// MANDATORY 2FA CHECK FOR ALL ADMIN ACCESS
require_once 'two_factor_auth.php';
$user_id = $_SESSION['user_id'];
$username = $_SESSION['username'];

// Check if 2FA is enabled for this admin user
if (!TwoFactorAuth::isEnabledForUser($user_id)) {
    logSecurityEvent('ADMIN_NO_2FA', 
        "Admin user $username attempted panel access without 2FA enabled", 'HIGH');
    echo json_encode([
        'success' => false, 
        'message' => 'Two-Factor Authentication is required for admin panel access',
        'requires_2fa_setup' => true,
        'setup_url' => '/setup_2fa.php'
    ]);
    exit;
}

// Verify recent 2FA authentication (within last hour)
// Allow more lenient check for users who just completed login 2FA
$recently_logged_in = isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) < 300; // 5 minutes
$has_recent_2fa = isset($_SESSION['2fa_verified_time']) && (time() - $_SESSION['2fa_verified_time']) < 3600; // 1 hour

if (!$has_recent_2fa && !$recently_logged_in) {
    logSecurityEvent('ADMIN_2FA_EXPIRED', 
        "Admin user $username needs fresh 2FA verification", 'MEDIUM');
    echo json_encode([
        'success' => false,
        'message' => 'Recent 2FA verification required for admin panel access',
        'requires_2fa_verify' => true
    ]);
    exit;
}

// All security checks passed - grant admin panel access
$_SESSION['admin_authenticated'] = true;
$_SESSION['admin_login_time'] = time();

// Record secure session
require_once 'secure_session_manager.php';
SecureSessionManager::recordSession($user_id, $username, true);

logSecurityEvent('ADMIN_PANEL_ACCESS', 
    "Admin panel access granted to $username with 2FA verification", 'LOW');

echo json_encode([
    'success' => true, 
    'message' => 'Admin panel access granted',
    'user' => $username,
    'security_level' => 'high'
]);
?>