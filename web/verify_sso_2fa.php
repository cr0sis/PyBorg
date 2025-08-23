<?php
/**
 * SSO Two-Factor Authentication Verification
 * Handles 2FA verification for SSO authenticated users
 * 
 * Security: Same security standards as regular 2FA with SSO session bridging
 */

// Debug - show errors temporarily
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'security_config.php';
require_once 'sso/SSOManager.php';

// Initialize security
initSecureSession();
setSecurityHeaders();

// Debug - log session state
error_log("verify_sso_2fa.php - Session ID: " . session_id());
error_log("verify_sso_2fa.php - Session data: " . json_encode($_SESSION));

// Check if SSO 2FA is pending
if (!isset($_SESSION['pending_sso_2fa_user_id'])) {
    // Clean up any stale SSO session data
    unset($_SESSION['pending_sso_2fa_user_id']);
    unset($_SESSION['pending_sso_2fa_username']);
    unset($_SESSION['pending_sso_2fa_is_admin']);
    unset($_SESSION['pending_sso_2fa_provider']);
    unset($_SESSION['pending_sso_2fa_attributes']);
    header('Location: /auth.php');
    exit;
}

// Check if SSO 2FA session is stale (older than 10 minutes)
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

// Handle form submission
$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'verify_2fa') {
        $code = trim($_POST['code'] ?? '');
        $use_backup = isset($_POST['use_backup']) && $_POST['use_backup'];
        
        if (empty($code)) {
            $error = 'Please enter your 2FA code';
        } else {
            require_once 'two_factor_auth.php';
            
            $valid = false;
            if ($use_backup) {
                $valid = TwoFactorAuth::verifyBackupCode($user_id, $code);
                if ($valid) {
                    SSOManager::logSSOEvent('SSO_2FA_BACKUP_USED', $provider_id, $user_id,
                        "User $username used backup code for SSO login", 'MEDIUM');
                }
            } else {
                $secret = TwoFactorAuth::getUserSecret($user_id);
                if ($secret) {
                    $valid = TwoFactorAuth::verifyTOTP($secret, $code);
                }
            }
            
            if ($valid) {
                // Complete the SSO login with 2FA
                $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
                $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
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
                
                // Store SSO-specific session data
                if (isset($_SESSION['sso_access_token'])) {
                    // Keep OIDC tokens
                }
                if (isset($_SESSION['sso_session_index'])) {
                    // Keep SAML session index for logout
                }
                
                // Store login IP for admin session binding
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
                
                // Update user's last login
                $pdo->prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP, sso_last_login = CURRENT_TIMESTAMP WHERE id = ?")
                    ->execute([$user_id]);
                
                // Clean up pending 2FA data
                unset($_SESSION['pending_sso_2fa_user_id']);
                unset($_SESSION['pending_sso_2fa_username']);
                unset($_SESSION['pending_sso_2fa_is_admin']);
                unset($_SESSION['pending_sso_2fa_provider']);
                unset($_SESSION['pending_sso_2fa_attributes']);
                
                SSOManager::logSSOEvent('SSO_2FA_SUCCESS', $provider_id, $user_id,
                    "User $username completed SSO 2FA verification", 'LOW');
                
                // Redirect to dashboard or intended destination
                $redirect_url = $is_admin ? '/index.php' : '/index.php';
                header("Location: $redirect_url");
                exit;
                
            } else {
                $error = 'Invalid 2FA code';
                SSOManager::logSSOEvent('SSO_2FA_FAILED', $provider_id, $user_id,
                    "User $username failed SSO 2FA verification", 'HIGH');
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
    <title>Two-Factor Authentication - SSO Login</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .auth-container {
            max-width: 450px;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
            padding: 2rem;
        }
        .provider-info {
            background: #f8f9fa;
            border-left: 4px solid #007bff;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1.5rem;
        }
        .form-control:focus {
            border-color: #667eea;
            box-shadow: 0 0 0 0.2rem rgba(102, 126, 234, 0.25);
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            padding: 12px 30px;
            border-radius: 25px;
            font-weight: 500;
        }
        .btn-outline-secondary {
            border-radius: 25px;
            padding: 12px 30px;
        }
        .security-notice {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 5px;
            padding: 1rem;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
        }
        .code-input {
            font-size: 1.2rem;
            text-align: center;
            letter-spacing: 0.2em;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <div class="text-center mb-4">
            <i class="fas fa-shield-alt fa-3x text-primary mb-3"></i>
            <h2 class="fw-bold text-dark">Two-Factor Authentication</h2>
            <p class="text-muted">Complete your secure SSO login</p>
        </div>

        <div class="provider-info">
            <div class="d-flex align-items-center">
                <i class="fas fa-external-link-alt text-primary me-2"></i>
                <div>
                    <strong>SSO Provider:</strong> <?= htmlspecialchars($provider['display_name']) ?><br>
                    <small class="text-muted">User: <?= htmlspecialchars($username) ?></small>
                </div>
            </div>
        </div>

        <div class="security-notice">
            <i class="fas fa-info-circle me-2"></i>
            <strong>Security Notice:</strong> You are logging in via SSO with administrative privileges. 
            Two-factor authentication is required for enhanced security.
        </div>

        <?php if ($error): ?>
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle me-2"></i>
                <?= htmlspecialchars($success) ?>
            </div>
        <?php endif; ?>

        <?php if (!$has_2fa): ?>
            <div class="alert alert-warning">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>2FA Not Set Up:</strong> You need to set up two-factor authentication first.
                <a href="/setup_2fa.php" class="btn btn-sm btn-warning ms-2">Set Up 2FA</a>
            </div>
        <?php else: ?>
            <form method="POST" id="twoFAForm">
                <input type="hidden" name="action" value="verify_2fa">
                
                <div class="mb-4">
                    <label for="code" class="form-label fw-bold">
                        <i class="fas fa-mobile-alt me-1"></i>
                        Authentication Code
                    </label>
                    <input type="text" class="form-control code-input" id="code" name="code" 
                           placeholder="000000" maxlength="6" pattern="\d{6}" 
                           autocomplete="one-time-code" required>
                    <div class="form-text">Enter the 6-digit code from your authenticator app</div>
                </div>

                <div class="d-grid gap-2 mb-3">
                    <button type="submit" class="btn btn-primary btn-lg">
                        <i class="fas fa-shield-alt me-2"></i>
                        Verify & Continue
                    </button>
                </div>
            </form>

            <?php if ($backup_codes_count > 0): ?>
                <div class="text-center mb-3">
                    <button type="button" class="btn btn-link text-muted" onclick="toggleBackupForm()">
                        Use backup code instead
                    </button>
                </div>

                <form method="POST" id="backupForm" style="display: none;">
                    <input type="hidden" name="action" value="verify_2fa">
                    <input type="hidden" name="use_backup" value="1">
                    
                    <div class="mb-3">
                        <label for="backup_code" class="form-label fw-bold">
                            <i class="fas fa-key me-1"></i>
                            Backup Code
                        </label>
                        <input type="text" class="form-control" id="backup_code" name="code" 
                               placeholder="Enter backup code" required>
                        <div class="form-text">You have <?= $backup_codes_count ?> backup codes remaining</div>
                    </div>

                    <div class="d-grid gap-2 mb-3">
                        <button type="submit" class="btn btn-outline-secondary">
                            <i class="fas fa-key me-2"></i>
                            Verify Backup Code
                        </button>
                    </div>
                </form>
            <?php endif; ?>
        <?php endif; ?>

        <div class="text-center mt-4">
            <a href="/auth.php" class="text-muted text-decoration-none">
                <i class="fas fa-arrow-left me-1"></i>
                Back to Login
            </a>
        </div>

        <div class="text-center mt-3">
            <small class="text-muted">
                <i class="fas fa-lock me-1"></i>
                Secured by cr0bot SSO System
            </small>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    <script>
        function toggleBackupForm() {
            const regularForm = document.getElementById('twoFAForm');
            const backupForm = document.getElementById('backupForm');
            
            if (backupForm.style.display === 'none') {
                regularForm.style.display = 'none';
                backupForm.style.display = 'block';
                document.getElementById('backup_code').focus();
            } else {
                backupForm.style.display = 'none';
                regularForm.style.display = 'block';
                document.getElementById('code').focus();
            }
        }

        // Auto-format 2FA code input
        document.getElementById('code').addEventListener('input', function(e) {
            this.value = this.value.replace(/\D/g, '').substring(0, 6);
            if (this.value.length === 6) {
                document.getElementById('twoFAForm').submit();
            }
        });

        // Auto-focus on page load
        document.addEventListener('DOMContentLoaded', function() {
            <?php if ($has_2fa): ?>
                document.getElementById('code').focus();
            <?php endif; ?>
        });
    </script>
</body>
</html>