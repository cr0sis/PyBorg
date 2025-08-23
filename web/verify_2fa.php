<?php
/**
 * Unified Two-Factor Authentication Verification
 * Handles 2FA verification for both regular and SSO authenticated users
 */

require_once 'security_config.php';
require_once 'two_factor_auth.php';
require_once 'session_monitor.php';
require_once 'sso/SSOManager.php';
require_once 'config_paths.php';

// Initialize security
initSecureSession();
setSecurityHeaders();

// Include additional dependencies for new security system
if (file_exists('secure_session_manager.php')) {
    require_once 'secure_session_manager.php';
}

// Database helper with timeout and retry logic
function getDatabaseConnection($database_name, $max_retries = 3, $timeout = 30) {
    $attempt = 0;
    while ($attempt < $max_retries) {
        try {
            $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase($database_name));
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $pdo->setAttribute(PDO::ATTR_TIMEOUT, $timeout);
            $pdo->exec("PRAGMA busy_timeout = " . ($timeout * 1000)); // Convert to milliseconds
            $pdo->exec("PRAGMA journal_mode = WAL"); // Use Write-Ahead Logging for better concurrency
            return $pdo;
        } catch (Exception $e) {
            $attempt++;
            error_log("Database connection attempt $attempt failed: " . $e->getMessage());
            if ($attempt < $max_retries) {
                usleep(100000 * $attempt); // Exponential backoff: 100ms, 200ms, 300ms
            }
        }
    }
    throw new Exception("Failed to connect to database after $max_retries attempts");
}

// Determine if this is SSO or regular 2FA
$is_sso = isset($_SESSION['pending_sso_2fa_user_id']);

// Local verify2FA function (unified for both regular and SSO)
function verify2FA($code, $use_backup = false, $is_sso = false) {
    error_log("verify2FA function started - code: " . substr($code, 0, 2) . "****, use_backup: " . ($use_backup ? 'true' : 'false') . ", is_sso: " . ($is_sso ? 'true' : 'false'));
    global $is_sso;
    
    if ($is_sso) {
        error_log("verify2FA: SSO path");
        if (!isset($_SESSION['pending_sso_2fa_user_id'])) {
            error_log("verify2FA: No pending SSO 2FA user ID");
            return ['success' => false, 'message' => 'SSO 2FA verification not pending'];
        }
        error_log("verify2FA: SSO user ID found: " . $_SESSION['pending_sso_2fa_user_id']);
        if (!isset($_SESSION['pending_sso_2fa_user_id'])) {
            return ['success' => false, 'message' => 'SSO 2FA verification not pending'];
        }
        $user_id = $_SESSION['pending_sso_2fa_user_id'];
        $username = $_SESSION['pending_sso_2fa_username'];
        $is_admin = $_SESSION['pending_sso_2fa_is_admin'];
        $provider_id = $_SESSION['pending_sso_2fa_provider'];
        $sso_attributes = $_SESSION['pending_sso_2fa_attributes'] ?? [];
    } else {
        if (!isset($_SESSION['pending_2fa_user_id'])) {
            return ['success' => false, 'message' => '2FA verification not pending'];
        }
        $user_id = $_SESSION['pending_2fa_user_id'];
        $username = $_SESSION['pending_2fa_username'];
        $is_admin = $_SESSION['pending_2fa_is_admin'];
    }
    
    $valid = false;
    if ($use_backup) {
        $valid = TwoFactorAuth::verifyBackupCode($user_id, $code);
        if ($valid) {
            $event = $is_sso ? 'SSO_2FA_BACKUP_USED' : '2FA_BACKUP_USED';
            $msg = $is_sso ? "User $username used backup code for SSO login" : "User $username used backup code for login";
            logSecurityEvent($event, $msg, 'MEDIUM');
            if ($is_sso) {
                SSOManager::logSSOEvent('SSO_2FA_BACKUP_USED', $provider_id, $user_id, $msg, 'MEDIUM');
            }
        }
    } else {
        $secret = TwoFactorAuth::getUserSecret($user_id);
        if ($secret) {
            $valid = TwoFactorAuth::verifyTOTP($secret, $code);
        }
    }
    
    if (!$valid) {
        $event = $is_sso ? 'SSO_2FA_FAILED' : '2FA_FAILED';
        $msg = $is_sso ? "User $username failed SSO 2FA verification" : "User $username failed 2FA verification";
        logSecurityEvent($event, $msg, 'HIGH');
        if ($is_sso) {
            SSOManager::logSSOEvent('SSO_2FA_FAILED', $provider_id, $user_id, $msg, 'HIGH');
        }
        return ['success' => false, 'message' => 'Invalid 2FA code'];
    }
    
    // Complete the login
    if ($is_sso) {
        // Get user's email for profile picture storage
        $pdo = getDatabaseConnection('users');
        $stmt = $pdo->prepare("SELECT email FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $user_data = $stmt->fetch(PDO::FETCH_ASSOC);
        $email = $user_data['email'] ?? '';
        
        // Set full session
        $_SESSION['user_id'] = $user_id;
        $_SESSION['username'] = $username;
        $_SESSION['email'] = $email;
        $_SESSION['is_admin'] = $is_admin;
        $_SESSION['login_time'] = time();
        $_SESSION['sso_provider_id'] = $provider_id;
        $_SESSION['sso_attributes'] = $sso_attributes;
        
        // Store Google profile picture if available
        if (isset($sso_attributes['picture']) && !empty($sso_attributes['picture'])) {
            $_SESSION['profile_picture'] = $sso_attributes['picture'];
        }
        
        // Store SSO-specific session data
        if (isset($_SESSION['sso_access_token'])) {
            // Keep OIDC tokens
        }
        if (isset($_SESSION['sso_session_index'])) {
            // Keep SAML session index for logout
        }
        
        // Clean up pending SSO 2FA data
        unset($_SESSION['pending_sso_2fa_user_id']);
        unset($_SESSION['pending_sso_2fa_username']);
        unset($_SESSION['pending_sso_2fa_is_admin']);
        unset($_SESSION['pending_sso_2fa_provider']);
        unset($_SESSION['pending_sso_2fa_attributes']);
    } else {
        // Regular login
        $_SESSION['user_id'] = $user_id;
        $_SESSION['username'] = $username;
        $_SESSION['is_admin'] = $is_admin;
        $_SESSION['login_time'] = time();
        
        // Clean up pending 2FA data
        unset($_SESSION['pending_2fa_user_id']);
        unset($_SESSION['pending_2fa_username']);
        unset($_SESSION['pending_2fa_is_admin']);
    }
    
    // Store login IP for admin session binding
    if (!isset($_SESSION['login_ip'])) {
        $login_ip = $_SERVER['REMOTE_ADDR'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_REAL_IP'] ?? 'unknown';
        if (strpos($login_ip, ',') !== false) {
            $login_ip = trim(explode(',', $login_ip)[0]);
        }
        $_SESSION['login_ip'] = $login_ip;
    }
    
    // SET 2FA VERIFICATION TIMESTAMP FOR NEW SECURITY SYSTEM
    $_SESSION['2fa_verified_time'] = time();
    
    // Set lockdown override flag for admin users completing 2FA
    if ($is_admin) {
        $_SESSION['lockdown_override'] = true;
        $_SESSION['lockdown_override_time'] = time();
    }
    
    // Record session for monitoring  
    SessionMonitor::recordSession($user_id, $username, $is_admin);
    
    // Update user's last login
    $pdo = getDatabaseConnection('users');
    if ($is_sso) {
        $pdo->prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP, sso_last_login = CURRENT_TIMESTAMP WHERE id = ?")
            ->execute([$user_id]);
    } else {
        $pdo->prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?")
            ->execute([$user_id]);
    }
    
    $event = $is_sso ? 'SSO_2FA_SUCCESS' : '2FA_SUCCESS';
    $msg = $is_sso ? "User $username completed SSO 2FA verification" : "User $username completed 2FA login";
    logSecurityEvent($event, $msg, 'LOW');
    if ($is_sso) {
        SSOManager::logSSOEvent('SSO_2FA_SUCCESS', $provider_id, $user_id, $msg, 'LOW');
    }
    
    return ['success' => true, 'message' => '2FA verification successful'];
}

// Check if 2FA is pending (either regular or SSO)
if (!isset($_SESSION['pending_2fa_user_id']) && !isset($_SESSION['pending_sso_2fa_user_id'])) {
    // Clean up any stale session data
    unset($_SESSION['pending_2fa_user_id']);
    unset($_SESSION['pending_2fa_username']);  
    unset($_SESSION['pending_2fa_is_admin']);
    unset($_SESSION['pending_sso_2fa_user_id']);
    unset($_SESSION['pending_sso_2fa_username']);
    unset($_SESSION['pending_sso_2fa_is_admin']);
    unset($_SESSION['pending_sso_2fa_provider']);
    unset($_SESSION['pending_sso_2fa_attributes']);
    header('Location: /auth.php');
    exit;
}

// Check if SSO 2FA session is stale (older than 10 minutes)
if ($is_sso) {
    $sso_start_time = $_SESSION['sso_start_time'] ?? 0;
    if ($sso_start_time && (time() - $sso_start_time) > 600) {
        // Clean up stale session
        unset($_SESSION['pending_sso_2fa_user_id']);
        unset($_SESSION['pending_sso_2fa_username']);
        unset($_SESSION['pending_sso_2fa_is_admin']);
        unset($_SESSION['pending_sso_2fa_provider']);
        unset($_SESSION['pending_sso_2fa_attributes']);
        unset($_SESSION['sso_start_time']);
        header('Location: /auth.php?error=' . urlencode('SSO session expired. Please try again.'));
        exit;
    }
}

$error = '';
$success = '';

// Get user details based on auth type
if ($is_sso) {
    $user_id = $_SESSION['pending_sso_2fa_user_id'];
    $username = $_SESSION['pending_sso_2fa_username'];
    $is_admin = $_SESSION['pending_sso_2fa_is_admin'];
    $provider_id = $_SESSION['pending_sso_2fa_provider'];
    $sso_attributes = $_SESSION['pending_sso_2fa_attributes'] ?? [];
    
    // Get provider information
    $provider = SSOManager::getProvider($provider_id);
    if (!$provider) {
        SSOManager::logSSOEvent('2FA_PROVIDER_ERROR', $provider_id, $user_id,
            "Provider not found during 2FA verification", 'HIGH');
        header('Location: /auth.php?error=' . urlencode('SSO provider configuration error'));
        exit;
    }
} else {
    $user_id = $_SESSION['pending_2fa_user_id'];
    $username = $_SESSION['pending_2fa_username'];
    $is_admin = $_SESSION['pending_2fa_is_admin'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    error_log("2FA POST request received");
    $action = $_POST['action'] ?? '';
    
    if ($action === 'verify_2fa') {
        error_log("2FA verify_2fa action triggered");
        $code = trim($_POST['code'] ?? '');
        $use_backup = isset($_POST['use_backup']) && $_POST['use_backup'];
        
        if (empty($code)) {
            error_log("2FA empty code error");
            $error = 'Please enter your 2FA code';
        } else {
            error_log("2FA calling verify2FA function with code: " . substr($code, 0, 2) . "****");
            $result = verify2FA($code, $use_backup, $is_sso);
            error_log("2FA verify2FA returned: " . json_encode($result));
            
            if ($result['success']) {
                // Determine redirect URL based on auth type and admin status
                if ($is_sso) {
                    $redirect_url = $_SESSION['sso_return_url'] ?? '/index.php';
                    unset($_SESSION['sso_return_url']);
                } else {
                    $redirect_url = $_SESSION['redirect_after_login'] ?? '/index.php';
                    unset($_SESSION['redirect_after_login']);
                }
                
                // Override redirect for admin users - send them to admin index
                if ($is_admin) {
                    $redirect_url = '/index.php';  // Admin version of index
                    error_log("2FA successful for admin, redirecting to admin index");
                } else {
                    // Ensure regular users go to regular index  
                    if ($redirect_url === '/index.php') {
                        $redirect_url = '/index.html';  // Regular user version
                    }
                }
                
                error_log("2FA successful, redirecting to: $redirect_url");
                header("Location: $redirect_url");
                exit;
            } else {
                error_log("2FA failed: " . $result['message']);
                $error = $result['message'];
            }
        }
    }
}

// Get 2FA status
require_once 'two_factor_auth.php';
$has_2fa = TwoFactorAuth::isEnabledForUser($user_id);
$backup_codes_count = TwoFactorAuth::getBackupCodesCount($user_id);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Two-Factor Authentication - <?= $is_sso ? 'SSO' : 'CR0 Bot System' ?></title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #000;
            color: #00ff00;
            padding: 20px;
            line-height: 1.6;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        .container {
            max-width: 400px;
            background: rgba(0, 20, 0, 0.9);
            border: 2px solid #00ff00;
            border-radius: 10px;
            padding: 30px;
            text-align: center;
        }
        h1 {
            color: #00ff00;
            text-shadow: 0 0 10px #00ff00;
            margin-bottom: 30px;
        }
        .error {
            background: rgba(255, 0, 0, 0.2);
            border: 1px solid #ff0000;
            color: #ff6666;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .user-info {
            background: rgba(0, 50, 0, 0.5);
            border: 1px solid #00aa00;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .form-group {
            margin: 20px 0;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #66ff66;
        }
        input[type="text"], input[type="number"] {
            width: 100%;
            padding: 15px;
            background: #001100;
            border: 2px solid #00ff00;
            color: #00ff00;
            border-radius: 5px;
            font-family: monospace;
            font-size: 18px;
            text-align: center;
            letter-spacing: 5px;
            box-sizing: border-box;
        }
        input[type="text"]:focus, input[type="number"]:focus {
            outline: none;
            border-color: #66ff66;
            box-shadow: 0 0 10px rgba(0, 255, 0, 0.3);
        }
        button {
            background: #00ff00;
            color: #000;
            border: none;
            padding: 15px 25px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            margin: 10px 5px;
            font-family: inherit;
            width: 100%;
        }
        button:hover {
            background: #66ff66;
        }
        .backup-btn {
            background: #666;
            color: #fff;
            font-size: 0.9em;
            padding: 10px 15px;
        }
        .backup-btn:hover {
            background: #888;
        }
        .instructions {
            color: #aaffaa;
            font-size: 0.9em;
            margin: 15px 0;
        }
        .nav-links {
            margin-top: 30px;
        }
        .nav-links a {
            color: #888;
            text-decoration: none;
            font-size: 0.9em;
        }
        .nav-links a:hover {
            color: #00ff00;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Two-Factor Authentication</h1>
        
        <div class="user-info">
            <strong>Welcome back, <?= htmlspecialchars($username) ?>!</strong><br>
            <?php if ($is_sso): ?>
                <div style="margin: 10px 0; color: #88ff88;">
                    <i class="fas fa-shield-alt"></i> Signed in with <?= htmlspecialchars($provider['name'] ?? 'SSO Provider') ?><br>
                    <small>Please complete 2FA to finish login</small>
                </div>
            <?php else: ?>
                Please enter your 2FA code to complete login.
            <?php endif; ?>
        </div>
        
        <?php if ($error): ?>
            <div class="error">❌ <?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        
        <form method="POST" id="twofa-form">
            <input type="hidden" name="action" value="verify_2fa">
            <div class="form-group">
                <label for="code">Enter 6-digit code from your authenticator app:</label>
                <input type="number" 
                       id="code" 
                       name="code" 
                       placeholder="123456" 
                       maxlength="6" 
                       required 
                       autofocus
                       oninput="if(this.value.length === 6) this.form.submit();">
            </div>
            
            <button type="submit">Verify Code</button>
        </form>
        
        <div class="instructions">
            💡 The code will auto-submit when you enter 6 digits
        </div>
        
        <?php if ($backup_codes_count > 0): ?>
        <form method="POST" style="margin-top: 20px;">
            <input type="hidden" name="action" value="verify_2fa">
            <div class="form-group">
                <label for="backup_code">Or use a backup recovery code:</label>
                <input type="text" 
                       id="backup_code" 
                       name="code" 
                       placeholder="12345678"
                       maxlength="8">
                <input type="hidden" name="use_backup" value="1">
            </div>
            
            <button type="submit" class="backup-btn">Use Backup Code (<?= $backup_codes_count ?> remaining)</button>
        </form>
        <?php endif; ?>
        
        <div class="nav-links">
            <a href="/">← Back to Main Page</a>
        </div>
    </div>
    
    <script>
        // Auto-focus and auto-submit for better UX
        document.getElementById('code').focus();
        
        // Format input as user types
        document.getElementById('code').addEventListener('input', function(e) {
            let value = e.target.value.replace(/\D/g, ''); // Only digits
            if (value.length > 6) value = value.substr(0, 6);
            e.target.value = value;
            
            // Auto-submit when 6 digits entered
            if (value.length === 6) {
                setTimeout(() => {
                    document.getElementById('twofa-form').submit();
                }, 100);
            }
        });
        
        // Clear error after user starts typing
        document.getElementById('code').addEventListener('input', function() {
            const errorDiv = document.querySelector('.error');
            if (errorDiv) {
                errorDiv.style.display = 'none';
            }
        });
    </script>
</body>
</html>