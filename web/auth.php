<?php
/**
 * User Authentication System
 * Handles user registration, login, and session management
 * Now with HARDCORE security features for internet exposure
 */

require_once 'security_config.php';
require_once 'security_hardened.php';
require_once 'emergency_security.php';
require_once 'input_sanitizer.php';

// Database configuration (centralized data directory)
require_once 'config_paths.php';
$db_path = ConfigPaths::getDatabase('users');

/**
 * Initialize user database
 */
function initUserDatabase() {
    global $db_path;
    
    try {
        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Create users table
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME DEFAULT NULL,
                is_active INTEGER DEFAULT 1
            )
        ");
        
        // Create user_scores table for game scores
        $pdo->exec("
            CREATE TABLE IF NOT EXISTS user_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                game_name TEXT NOT NULL,
                score INTEGER NOT NULL,
                level_reached INTEGER DEFAULT 1,
                date_played DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, game_name)
            )
        ");
        
        return true;
    } catch (PDOException $e) {
        error_log("Database initialization error: " . $e->getMessage());
        return false;
    }
}

/**
 * Register a new user
 */
function registerUser($username, $email, $password) {
    global $db_path;
    
    // Validate input
    if (empty($username) || empty($email) || empty($password)) {
        return ['success' => false, 'message' => 'All fields are required'];
    }
    
    if (strlen($username) < 3 || strlen($username) > 20) {
        return ['success' => false, 'message' => 'Username must be 3-20 characters'];
    }
    
    if (strlen($password) < 6) {
        return ['success' => false, 'message' => 'Password must be at least 6 characters'];
    }
    
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['success' => false, 'message' => 'Invalid email address'];
    }
    
    // Check for profanity in username
    if (containsProfanity($username)) {
        return ['success' => false, 'message' => 'Username contains inappropriate content'];
    }
    
    try {
        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Check if username or email already exists
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $email]);
        
        if ($stmt->fetchColumn() > 0) {
            return ['success' => false, 'message' => 'Username or email already exists'];
        }
        
        // Hash password
        $password_hash = password_hash($password, PASSWORD_DEFAULT);
        
        // Insert new user
        $stmt = $pdo->prepare("
            INSERT INTO users (username, email, password_hash) 
            VALUES (?, ?, ?)
        ");
        $stmt->execute([$username, $email, $password_hash]);
        
        return ['success' => true, 'message' => 'Account created successfully'];
        
    } catch (PDOException $e) {
        error_log("Registration error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Registration failed. Please try again.'];
    }
}

/**
 * Authenticate user login
 */
function loginUser($username, $password) {
    global $db_path;
    
    if (empty($username) || empty($password)) {
        return ['success' => false, 'message' => 'Username and password are required'];
    }
    
    try {
        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Get user by username or email
        $stmt = $pdo->prepare("
            SELECT id, username, email, password_hash, is_admin, is_active 
            FROM users 
            WHERE (username = ? OR email = ?) AND is_active = 1
        ");
        $stmt->execute([$username, $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$user || !password_verify($password, $user['password_hash'])) {
            return ['success' => false, 'message' => 'Invalid username or password'];
        }
        
        // Update last login (skip if database is read-only)
        try {
            $stmt = $pdo->prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?");
            $stmt->execute([$user['id']]);
        } catch (PDOException $e) {
            // Ignore read-only database errors for last_login update
            error_log("Warning: Could not update last_login: " . $e->getMessage());
        }
        
        // Check if admin user needs 2FA
        require_once 'two_factor_auth.php';
        if ($user['is_admin'] && TwoFactorAuth::isEnabledForUser($user['id'])) {
            // Admin with 2FA - don't set full session yet
            $_SESSION['pending_2fa_user_id'] = $user['id'];
            $_SESSION['pending_2fa_username'] = $user['username'];
            $_SESSION['pending_2fa_is_admin'] = true;
            
            return ['success' => true, 'requires_2fa' => true, 'message' => 'Please enter your 2FA code'];
        }
        
        // Regular login or admin without 2FA
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['email'] = $user['email'];
        $_SESSION['is_admin'] = (bool)$user['is_admin'];
        $_SESSION['login_time'] = time();
        
        // Store login IP for admin session binding
        $login_ip = $_SERVER['REMOTE_ADDR'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? 'unknown';
        if (strpos($login_ip, ',') !== false) {
            $login_ip = trim(explode(',', $login_ip)[0]);
        }
        $_SESSION['login_ip'] = $login_ip;
        
        // Set lockdown override flag for admin users
        if ((bool)$user['is_admin']) {
            $_SESSION['lockdown_override'] = true;
            $_SESSION['lockdown_override_time'] = time();
        }
        
        // Record session for monitoring
        require_once 'session_monitor.php';
        SessionMonitor::recordSession($user['id'], $user['username'], (bool)$user['is_admin']);
        
        // Log successful login
        logSecurityEvent('USER_LOGIN', "User {$user['username']} logged in successfully", 'LOW');
        
        return ['success' => true, 'message' => 'Login successful', 'user' => [
            'id' => $user['id'],
            'username' => $user['username'],
            'email' => $user['email'],
            'is_admin' => (bool)$user['is_admin']
        ], 'csrf_token' => generateCSRFToken()];
        
    } catch (PDOException $e) {
        error_log("Login error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Login failed. Please try again.'];
    }
}

/**
 * Verify 2FA code and complete login
 */
function verify2FA($code, $use_backup = false) {
    if (!isset($_SESSION['pending_2fa_user_id'])) {
        return ['success' => false, 'message' => '2FA verification not pending'];
    }
    
    $user_id = $_SESSION['pending_2fa_user_id'];
    $username = $_SESSION['pending_2fa_username'];
    $is_admin = $_SESSION['pending_2fa_is_admin'];
    
    require_once 'two_factor_auth.php';
    
    $valid = false;
    if ($use_backup) {
        $valid = TwoFactorAuth::verifyBackupCode($user_id, $code);
        if ($valid) {
            logSecurityEvent('2FA_BACKUP_USED', "User $username used backup code for login", 'MEDIUM');
        }
    } else {
        $secret = TwoFactorAuth::getUserSecret($user_id);
        if ($secret) {
            $valid = TwoFactorAuth::verifyTOTP($secret, $code);
        }
    }
    
    if (!$valid) {
        logSecurityEvent('2FA_FAILED', "User $username failed 2FA verification", 'HIGH');
        return ['success' => false, 'message' => 'Invalid 2FA code'];
    }
    
    // Get the email from database for session
    global $db_path;
    try {
        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $stmt = $pdo->prepare("SELECT email FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $user_data = $stmt->fetch(PDO::FETCH_ASSOC);
        $email = $user_data['email'] ?? '';
    } catch (PDOException $e) {
        error_log("Failed to get email for 2FA completion: " . $e->getMessage());
        $email = '';
    }
    
    // Complete the login
    $_SESSION['user_id'] = $user_id;
    $_SESSION['username'] = $username;
    $_SESSION['email'] = $email;
    $_SESSION['is_admin'] = $is_admin;
    $_SESSION['login_time'] = time();
    
    // Store login IP for admin session binding (if not already set)
    if (!isset($_SESSION['login_ip'])) {
        $login_ip = $_SERVER['REMOTE_ADDR'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? 'unknown';
        if (strpos($login_ip, ',') !== false) {
            $login_ip = trim(explode(',', $login_ip)[0]);
        }
        $_SESSION['login_ip'] = $login_ip;
    }
    
    // SET 2FA VERIFICATION TIMESTAMP FOR ADMIN SECURITY
    $_SESSION['2fa_verified_time'] = time();
    
    // Set lockdown override flag for admin users completing 2FA
    if ($is_admin) {
        $_SESSION['lockdown_override'] = true;
        $_SESSION['lockdown_override_time'] = time();
    }
    
    // Record session for monitoring  
    require_once 'session_monitor.php';
    SessionMonitor::recordSession($user_id, $username, $is_admin);
    
    // Clean up pending 2FA data
    unset($_SESSION['pending_2fa_user_id']);
    unset($_SESSION['pending_2fa_username']);
    unset($_SESSION['pending_2fa_is_admin']);
    
    logSecurityEvent('2FA_SUCCESS', "User $username completed 2FA login", 'LOW');
    
    return ['success' => true, 'message' => '2FA verification successful'];
}

/**
 * Logout user
 */
function logoutUser() {
    // Remove from session monitoring
    require_once 'session_monitor.php';
    SessionMonitor::removeSession();
    
    // Clear all session variables
    $_SESSION = array();
    
    // Delete the session cookie
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    
    // Destroy the session
    session_destroy();
    
    return ['success' => true, 'message' => 'Logged out successfully'];
}

/**
 * Check if user is logged in
 */
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

/**
 * Get current user info
 */
function getCurrentUser() {
    if (!isLoggedIn()) {
        return null;
    }
    
    return [
        'id' => $_SESSION['user_id'],
        'username' => $_SESSION['username'],
        'email' => $_SESSION['email'] ?? '',
        'is_admin' => isset($_SESSION['is_admin']) ? (bool)$_SESSION['is_admin'] : false,
        'profile_picture' => $_SESSION['profile_picture'] ?? null
    ];
}

/**
 * Save or update user's game score
 */
function saveUserScore($user_id, $game_name, $score, $level_reached = 1) {
    global $db_path;
    
    try {
        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Check if user already has a score for this game
        $stmt = $pdo->prepare("SELECT score FROM user_scores WHERE user_id = ? AND game_name = ?");
        $stmt->execute([$user_id, $game_name]);
        $existing = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($existing) {
            // Only update if new score is higher
            if ($score > $existing['score']) {
                $stmt = $pdo->prepare("
                    UPDATE user_scores 
                    SET score = ?, level_reached = ?, date_played = CURRENT_TIMESTAMP 
                    WHERE user_id = ? AND game_name = ?
                ");
                $stmt->execute([$score, $level_reached, $user_id, $game_name]);
                return ['success' => true, 'message' => 'New high score saved!', 'updated' => true];
            } else {
                return ['success' => true, 'message' => 'Score not improved', 'updated' => false];
            }
        } else {
            // Insert new score
            $stmt = $pdo->prepare("
                INSERT INTO user_scores (user_id, game_name, score, level_reached) 
                VALUES (?, ?, ?, ?)
            ");
            $stmt->execute([$user_id, $game_name, $score, $level_reached]);
            return ['success' => true, 'message' => 'Score saved!', 'updated' => true];
        }
        
    } catch (PDOException $e) {
        error_log("Score save error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to save score'];
    }
}

/**
 * Get user's scores for all games
 */
function getUserScores($user_id) {
    global $db_path;
    
    try {
        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->prepare("
            SELECT game_name, score, level_reached, date_played
            FROM user_scores 
            WHERE user_id = ?
            ORDER BY score DESC
        ");
        $stmt->execute([$user_id]);
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (PDOException $e) {
        error_log("Get scores error: " . $e->getMessage());
        return [];
    }
}

/**
 * Get all users for admin panel
 */
function getAllUsers() {
    global $db_path;
    
    try {
        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->prepare("
            SELECT id, username, email, is_admin, is_active, created_at, last_login
            FROM users 
            ORDER BY created_at DESC
        ");
        $stmt->execute();
        
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
        
    } catch (PDOException $e) {
        error_log("Get users error: " . $e->getMessage());
        return [];
    }
}

/**
 * Update user admin status
 */
function updateUserAdminStatus($user_id, $is_admin) {
    global $db_path;
    
    try {
        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->prepare("UPDATE users SET is_admin = ? WHERE id = ?");
        $stmt->execute([$is_admin ? 1 : 0, $user_id]);
        
        return ['success' => true, 'message' => 'User admin status updated'];
        
    } catch (PDOException $e) {
        error_log("Update admin status error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to update admin status'];
    }
}

/**
 * Update user active status
 */
function updateUserActiveStatus($user_id, $is_active) {
    global $db_path;
    
    try {
        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->prepare("UPDATE users SET is_active = ? WHERE id = ?");
        $result = $stmt->execute([$is_active ? 1 : 0, $user_id]);
        
        $rowCount = $stmt->rowCount();
        error_log("User status update - ID: $user_id, Active: $is_active, Rows affected: $rowCount");
        
        if ($rowCount > 0) {
            return ['success' => true, 'message' => 'User status updated successfully'];
        } else {
            return ['success' => false, 'message' => 'User not found or status unchanged'];
        }
        
    } catch (PDOException $e) {
        error_log("Update active status error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
    }
}

/**
 * Delete a user completely
 */
function deleteUser($user_id) {
    global $db_path;
    
    try {
        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // First check if user exists and get their username for logging
        $checkStmt = $pdo->prepare("SELECT username FROM users WHERE id = ?");
        $checkStmt->execute([$user_id]);
        $user = $checkStmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$user) {
            return ['success' => false, 'message' => 'User not found'];
        }
        
        // Prevent deletion of admin users for safety
        $adminCheckStmt = $pdo->prepare("SELECT is_admin FROM users WHERE id = ?");
        $adminCheckStmt->execute([$user_id]);
        $adminCheck = $adminCheckStmt->fetch(PDO::FETCH_ASSOC);
        
        if ($adminCheck && $adminCheck['is_admin']) {
            return ['success' => false, 'message' => 'Cannot delete admin users'];
        }
        
        // Prevent users from deleting themselves
        if (isset($_SESSION['user_id']) && $_SESSION['user_id'] == $user_id) {
            return ['success' => false, 'message' => 'Cannot delete your own account'];
        }
        
        // Delete the user
        $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
        $result = $stmt->execute([$user_id]);
        
        $rowCount = $stmt->rowCount();
        error_log("User deletion - ID: $user_id, Username: {$user['username']}, Rows affected: $rowCount");
        
        if ($rowCount > 0) {
            return ['success' => true, 'message' => "User '{$user['username']}' deleted successfully"];
        } else {
            return ['success' => false, 'message' => 'Failed to delete user'];
        }
        
    } catch (PDOException $e) {
        error_log("Delete user error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
    }
}

/**
 * Check if current user is admin
 */
function isAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'];
}

/**
 * Basic profanity filter
 */
function containsProfanity($text) {
    $profanity = [
        'fuck', 'shit', 'damn', 'bitch', 'asshole', 'bastard', 'crap', 'piss',
        'cock', 'dick', 'pussy', 'cunt', 'tits', 'ass', 'fag', 'nigger',
        'retard', 'gay', 'homo', 'nazi', 'hitler', 'porn', 'sex', 'xxx'
    ];
    
    $text_lower = strtolower($text);
    foreach ($profanity as $word) {
        if (strpos($text_lower, $word) !== false) {
            return true;
        }
    }
    return false;
}

// Initialize database on first load
initUserDatabase();

// Handle AJAX requests with HARDCORE security
// Handle auth requests (only when accessed directly, not when included)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && basename($_SERVER['SCRIPT_NAME']) === 'auth.php') {
    header('Content-Type: application/json');
    
    // Use hardcore secure JSON parsing
    $rawInput = file_get_contents('php://input');
    $input = HardcoreSecurityManager::safeJSONParse($rawInput);
    
    if ($input === false) {
        HardcoreSecurityManager::logSecurityEvent('ATTACK', 'Invalid JSON payload', $_SERVER['REMOTE_ADDR']);
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid request format']);
        exit;
    }
    
    $action = $input['action'] ?? '';
    
    // CSRF protection for state-changing operations
    $requiresCSRF = ['register', 'update_admin_status', 'update_user_status', 'delete_user'];
    if (in_array($action, $requiresCSRF)) {
        if (!validateCSRFToken($input['csrf_token'] ?? '')) {
            HardcoreSecurityManager::logSecurityEvent('ATTACK', 'CSRF token validation failed', $_SERVER['REMOTE_ADDR']);
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Security validation failed']);
            exit;
        }
    }
    
    // Enhanced rate limiting for login attempts with IP blocking
    if ($action === 'login') {
        if (!HardcoreSecurityManager::checkRateLimit($_SERVER['REMOTE_ADDR'] . '_login', MAX_LOGIN_ATTEMPTS, 300)) {
            HardcoreSecurityManager::blockIP($_SERVER['REMOTE_ADDR'], 'Too many login attempts');
            http_response_code(429);
            echo json_encode(['success' => false, 'message' => 'Too many login attempts. IP blocked temporarily.']);
            exit;
        }
    }
    
    // Input sanitization (careful with login credentials to avoid breaking authentication)
    if ($action !== 'login') {
        // For non-login actions, sanitize all input
        $input = InputSanitizer::sanitizeAll($input);
    } else {
        // For login, only sanitize non-credential fields
        foreach ($input as $key => $value) {
            if (is_string($value) && !in_array($key, ['username', 'password'])) {
                $input[$key] = InputSanitizer::sanitizeAll([$key => $value])[$key];
            }
        }
        
        // Validate username format (but don't alter it)
        if (isset($input['username'])) {
            $username = $input['username'];
            if (strlen($username) > 100 || strlen($username) < 1) {
                http_response_code(400);
                echo json_encode(['success' => false, 'message' => 'Invalid username length']);
                exit;
            }
        }
    }
    
    switch ($action) {
        case 'register':
            HardcoreSecurityManager::logSecurityEvent('AUTH', 'User registration attempt: ' . ($input['username'] ?? 'unknown'));
            $result = registerUser(
                $input['username'] ?? '',
                $input['email'] ?? '',
                $input['password'] ?? ''
            );
            if ($result['success']) {
                HardcoreSecurityManager::logSecurityEvent('AUTH', 'User registration successful: ' . $input['username']);
            } else {
                HardcoreSecurityManager::logSecurityEvent('WARNING', 'User registration failed: ' . $result['message']);
            }
            echo json_encode($result);
            break;
            
        case 'login':
            HardcoreSecurityManager::logSecurityEvent('AUTH', 'Login attempt: ' . ($input['username'] ?? 'unknown'));
            $result = loginUser(
                $input['username'] ?? '',
                $input['password'] ?? ''
            );
            if ($result['success']) {
                if (isset($result['requires_2fa']) && $result['requires_2fa']) {
                    // Store redirect URL for after 2FA completion - admins go to enhanced index
                    // Check pending admin status since user data isn't returned during 2FA flow
                    if (isset($_SESSION['pending_2fa_is_admin']) && $_SESSION['pending_2fa_is_admin']) {
                        $_SESSION['redirect_after_login'] = $input['redirect'] ?? '/index.php';
                    } else {
                        $_SESSION['redirect_after_login'] = $input['redirect'] ?? '/index.php';
                    }
                    HardcoreSecurityManager::logSecurityEvent('AUTH', '2FA required for: ' . $input['username']);
                    $result['redirect_url'] = '/verify_2fa.php';
                } else {
                    // Direct login without 2FA - redirect admins to enhanced index
                    if (isset($result['user']) && $result['user']['is_admin']) {
                        $result['redirect_url'] = '/index.php';
                    }
                    HardcoreSecurityManager::logSecurityEvent('AUTH', 'Login successful: ' . $input['username']);
                }
            } else {
                HardcoreSecurityManager::logSecurityEvent('WARNING', 'Login failed: ' . $result['message']);
            }
            echo json_encode($result);
            break;
            
        case 'verify_2fa':
            if (!isset($_SESSION['pending_2fa_user_id'])) {
                echo json_encode(['success' => false, 'message' => '2FA verification not pending']);
                break;
            }
            
            $code = $input['code'] ?? '';
            $use_backup = isset($input['use_backup']) && $input['use_backup'];
            
            HardcoreSecurityManager::logSecurityEvent('AUTH', '2FA verification attempt for user: ' . ($_SESSION['pending_2fa_username'] ?? 'unknown'));
            
            $result = verify2FA($code, $use_backup);
            
            if ($result['success']) {
                HardcoreSecurityManager::logSecurityEvent('AUTH', '2FA verification successful for: ' . ($_SESSION['username'] ?? 'unknown'));
            } else {
                HardcoreSecurityManager::logSecurityEvent('WARNING', '2FA verification failed: ' . $result['message']);
            }
            
            echo json_encode($result);
            break;
            
        case 'logout':
            $username = $_SESSION['username'] ?? 'unknown';
            HardcoreSecurityManager::logSecurityEvent('AUTH', 'User logout: ' . $username);
            echo json_encode(logoutUser());
            break;
            
        case 'check_auth':
            echo json_encode([
                'success' => true,
                'logged_in' => isLoggedIn(),
                'user' => getCurrentUser(),
                'csrf_token' => generateCSRFToken()
            ]);
            break;
            
        case 'keepalive':
            // Session keepalive for admin users
            if (isLoggedIn() && isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
                // Update last activity time
                $_SESSION['last_activity'] = time();
                echo json_encode(['success' => true, 'keepalive' => true]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Not admin or not logged in']);
            }
            break;
            
        case 'save_score':
            if (isLoggedIn()) {
                echo json_encode(saveUserScore(
                    $_SESSION['user_id'],
                    $input['game_name'] ?? '',
                    $input['score'] ?? 0,
                    $input['level_reached'] ?? 1
                ));
            } else {
                echo json_encode(['success' => false, 'message' => 'Not logged in']);
            }
            break;
            
        case 'get_scores':
            if (isLoggedIn()) {
                $scores = getUserScores($_SESSION['user_id']);
                echo json_encode(['success' => true, 'scores' => $scores]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Not logged in']);
            }
            break;
            
        case 'get_all_users':
            requireAdmin();
            HardcoreSecurityManager::logSecurityEvent('ADMIN', 'Admin user list requested');
            $users = getAllUsers();
            echo json_encode([
                'success' => true, 
                'users' => $users,
                'current_user_id' => $_SESSION['user_id'],
                'csrf_token' => generateCSRFToken()
            ]);
            break;
            
        case 'update_admin_status':
            requireAdmin();
            $user_id = InputSanitizer::validateID($input['user_id'] ?? 0);
            if ($user_id === false) {
                echo json_encode(['success' => false, 'message' => 'Invalid user ID']);
                break;
            }
            $is_admin = (bool)($input['is_admin'] ?? false);
            HardcoreSecurityManager::logSecurityEvent('ADMIN', "Admin status update: User ID $user_id, Admin: " . ($is_admin ? 'true' : 'false'));
            echo json_encode(updateUserAdminStatus($user_id, $is_admin));
            break;
            
        case 'update_user_status':
            requireAdmin();
            $user_id = InputSanitizer::validateID($input['user_id'] ?? 0);
            if ($user_id === false) {
                echo json_encode(['success' => false, 'message' => 'Invalid user ID']);
                break;
            }
            $is_active = (bool)($input['is_active'] ?? false);
            HardcoreSecurityManager::logSecurityEvent('ADMIN', "User status update: User ID $user_id, Active: " . ($is_active ? 'true' : 'false'));
            echo json_encode(updateUserActiveStatus($user_id, $is_active));
            break;
            
        case 'delete_user':
            requireAdmin();
            $user_id = InputSanitizer::validateID($input['user_id'] ?? 0);
            if ($user_id === false) {
                echo json_encode(['success' => false, 'message' => 'Invalid user ID']);
                break;
            }
            HardcoreSecurityManager::logSecurityEvent('ADMIN', "User deletion request: User ID $user_id");
            $result = deleteUser($user_id);
            if ($result['success']) {
                HardcoreSecurityManager::logSecurityEvent('ADMIN', "User deletion successful: " . $result['message']);
            } else {
                HardcoreSecurityManager::logSecurityEvent('WARNING', "User deletion failed: " . $result['message']);
            }
            echo json_encode($result);
            break;
            
        default:
            echo json_encode(['success' => false, 'message' => 'Invalid action']);
            break;
    }
    exit;
}

// Only handle requests if this file is accessed directly (not included)
if (basename($_SERVER['SCRIPT_NAME']) === 'auth.php' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    $action = $_GET['action'] ?? '';
    
    switch ($action) {
        case 'logout':
            $username = $_SESSION['username'] ?? 'unknown';
            HardcoreSecurityManager::logSecurityEvent('AUTH', 'User logout (GET): ' . $username);
            
            $result = logoutUser();
            
            if ($result['success']) {
                // Redirect to main site root to avoid redirect loops
                header('Location: /?msg=' . urlencode('You have been logged out successfully'));
                exit;
            } else {
                // Redirect with error message
                header('Location: /?error=' . urlencode($result['message'] ?? 'Logout failed'));
                exit;
            }
            break;
            
        default:
            // For any other GET request, just redirect to home
            header('Location: /');
            exit;
            break;
    }
}
?>