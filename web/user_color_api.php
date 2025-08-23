<?php
/**
 * User Color API - Handles color picker operations for logged-in users
 * Allows users to get and update their Hall of Fame colors
 */

// Start session first for authentication checking
session_start();

require_once 'security_config.php';
require_once 'input_sanitizer.php';
require_once 'config_paths.php';
require_once 'security_emergency_lockdown.php';
require_once 'security_audit_logger.php';
require_once 'user_color_system.php';

// Emergency lockdown check
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

// Check if user is logged in
if (!isset($_SESSION['username']) || !isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Authentication required']);
    exit;
}

$username = $_SESSION['username'];
$user_id = $_SESSION['user_id'];

// Rate limiting for color operations
if (!RateLimit::check($client_ip . '_color_api', 20, 300)) {
    http_response_code(429);
    echo json_encode(['error' => 'Too many requests. Please try again later.']);
    exit;
}

try {
    // Get database connection for color storage
    $scores_db_path = ConfigPaths::getDatabase('breakout_scores');
    $pdo = new PDO("sqlite:$scores_db_path");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Ensure user_colors table exists
    $pdo->exec("CREATE TABLE IF NOT EXISTS user_colors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        player_name TEXT UNIQUE NOT NULL,
        color_hex TEXT NOT NULL,
        is_registered_user INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Sanitize input
        $raw_input = file_get_contents('php://input');
        $input = InputSanitizer::validateJSON($raw_input);
        
        if ($input === false) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid JSON data']);
            exit;
        }
        
        $action = $input['action'] ?? '';
        
        if ($action === 'update_color') {
            $color = $input['color'] ?? '';
            
            // Validate color format (hex color)
            if (!preg_match('/^#[0-9A-Fa-f]{6}$/', $color)) {
                http_response_code(400);
                echo json_encode(['error' => 'Invalid color format. Must be hex format (#RRGGBB)']);
                exit;
            }
            
            // Check if user is registered (they should be since they're logged in)
            $is_registered = isRegisteredUser($username);
            
            // Insert or update user color
            $stmt = $pdo->prepare("INSERT OR REPLACE INTO user_colors (player_name, color_hex, is_registered_user, last_used) VALUES (?, ?, ?, CURRENT_TIMESTAMP)");
            $stmt->execute([$username, $color, $is_registered ? 1 : 0]);
            
            // Log the color change for security monitoring
            SecurityAuditLogger::logSecurityEvent('user_color_change', 'INFO', [
                'username' => $username,
                'user_id' => $user_id,
                'new_color' => $color,
                'client_ip' => $client_ip
            ], 2);
            
            echo json_encode([
                'success' => true,
                'message' => 'Color updated successfully',
                'color' => $color
            ]);
            
        } else {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid action']);
        }
        
    } else if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        // Sanitize input
        $_GET = InputSanitizer::sanitizeAll($_GET);
        
        $action = $_GET['action'] ?? 'get_current';
        
        if ($action === 'get_current') {
            // Get current user's color
            $color = getUserColor($username, true);
            
            echo json_encode([
                'success' => true,
                'color' => $color,
                'username' => $username
            ]);
            
        } else {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid action']);
        }
    }
    
} catch (PDOException $e) {
    SecurityAuditLogger::logSecurityEvent('database_error', 'HIGH', ['error' => $e->getMessage()], 7);
    http_response_code(500);
    echo json_encode(['error' => 'Database error occurred']);
} catch (Exception $e) {
    SecurityAuditLogger::logSecurityEvent('general_error', 'MEDIUM', ['error' => $e->getMessage()], 5);
    http_response_code(500);
    echo json_encode(['error' => 'An error occurred']);
}
?>