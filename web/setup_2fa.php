<?php
// Start session first
session_start();

require_once 'two_factor_auth.php';
require_once 'security_config.php';
require_once 'config_paths.php';

// Simple authentication check without the heavy auth.php middleware
if (!isset($_SESSION['user_id'])) {
    header('Location: /auth.php');
    exit;
}

// Function to check if user is admin (simplified)
function isUserAdmin($user_id) {
    try {
        $db_path = ConfigPaths::getDatabase('users');
        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->prepare("SELECT is_admin FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        return $user && $user['is_admin'] == 1;
    } catch (PDOException $e) {
        return false;
    }
}

$user_id = $_SESSION['user_id'];
$error = '';
$success = '';

// Check if user is admin (2FA is recommended for all users but required for admins)
$is_admin = isUserAdmin($user_id);

// Check if 2FA is already enabled
$twofa_enabled = TwoFactorAuth::isEnabledForUser($user_id);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'enable' && !$twofa_enabled) {
        $secret = $_POST['secret'] ?? '';
        $code = $_POST['code'] ?? '';
        
        if (empty($secret) || empty($code)) {
            $error = 'Please enter the verification code from your authenticator app.';
        } else if (TwoFactorAuth::verifyTOTP($secret, $code)) {
            $backup_codes = TwoFactorAuth::enableForUser($user_id, $secret);
            if ($backup_codes) {
                $_SESSION['backup_codes'] = $backup_codes;
                
                // Log successful 2FA setup
                $log_entry = [
                    'timestamp' => date('Y-m-d H:i:s'),
                    'event_type' => '2FA_ENABLED',
                    'severity' => 'MEDIUM', 
                    'message' => "User {$user_id} enabled 2FA successfully",
                    'ip_address' => $_SERVER['REMOTE_ADDR'],
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                    'session_id' => session_id(),
                    'user_id' => $user_id
                ];
                file_put_contents('/tmp/admin_security.log', json_encode($log_entry) . "\n", FILE_APPEND | LOCK_EX);
                
                header('Location: /setup_2fa.php?success=enabled');
                exit;
            } else {
                $error = 'Failed to enable 2FA. Please try again.';
            }
        } else {
            $error = 'Invalid verification code. Please try again.';
            
            // Log failed 2FA setup attempt
            $log_entry = [
                'timestamp' => date('Y-m-d H:i:s'),
                'event_type' => '2FA_SETUP_FAILED',
                'severity' => 'MEDIUM',
                'message' => "User {$user_id} failed 2FA verification during setup",
                'ip_address' => $_SERVER['REMOTE_ADDR'],
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 
                'session_id' => session_id(),
                'user_id' => $user_id
            ];
            file_put_contents('/tmp/admin_security.log', json_encode($log_entry) . "\n", FILE_APPEND | LOCK_EX);
        }
    }
}

// Generate new secret for setup
if (!$twofa_enabled && !isset($_POST['secret'])) {
    $secret = TwoFactorAuth::generateSecret();
} else {
    $secret = $_POST['secret'] ?? '';
}

$success = $_GET['success'] ?? '';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Two-Factor Authentication Setup</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #000;
            color: #00ff00;
            padding: 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background: rgba(0, 20, 0, 0.9);
            border: 2px solid #00ff00;
            border-radius: 10px;
            padding: 30px;
        }
        h1 {
            text-align: center;
            color: #00ff00;
            text-shadow: 0 0 10px #00ff00;
        }
        .error {
            background: rgba(255, 0, 0, 0.2);
            border: 1px solid #ff0000;
            color: #ff6666;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .success {
            background: rgba(0, 255, 0, 0.2);
            border: 1px solid #00ff00;
            color: #66ff66;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .form-group {
            margin: 20px 0;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #66ff66;
        }
        input[type="text"], input[type="number"] {
            width: 100%;
            padding: 10px;
            background: #001100;
            border: 1px solid #00ff00;
            color: #00ff00;
            border-radius: 5px;
            font-family: monospace;
        }
        button {
            background: #00ff00;
            color: #000;
            border: none;
            padding: 12px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            margin: 10px 5px;
        }
        button:hover {
            background: #66ff66;
        }
        .qr-code {
            text-align: center;
            margin: 20px 0;
        }
        .backup-codes {
            background: rgba(255, 255, 0, 0.1);
            border: 1px solid #ffff00;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .backup-codes h3 {
            color: #ffff00;
            margin-top: 0;
        }
        .backup-code {
            font-family: monospace;
            background: #000;
            padding: 5px;
            margin: 5px 0;
            border-radius: 3px;
        }
        .nav-links {
            text-align: center;
            margin-top: 30px;
        }
        .nav-links a {
            color: #00ff00;
            text-decoration: none;
            margin: 0 10px;
        }
        .nav-links a:hover {
            text-shadow: 0 0 5px #00ff00;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Two-Factor Authentication</h1>
        
        <?php if ($error): ?>
            <div class="error">❌ <?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        
        <?php if ($is_admin && !$twofa_enabled): ?>
            <div style="background: rgba(255, 100, 0, 0.2); border: 2px solid #ff6600; color: #ffaa66; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <strong>⚠️ ADMIN ACCOUNT SECURITY WARNING</strong><br>
                As an administrator, you have elevated privileges that require additional protection. Two-Factor Authentication is <strong>strongly recommended</strong> for your account security.
            </div>
        <?php endif; ?>
        
        <?php if ($success === 'enabled'): ?>
            <div class="success">✅ Two-Factor Authentication has been successfully enabled!</div>
            
            <?php if (isset($_SESSION['backup_codes'])): ?>
                <div class="backup-codes">
                    <h3>⚠️ Backup Recovery Codes</h3>
                    <p><strong>IMPORTANT:</strong> Save these backup codes in a secure location. You can use them to access your account if you lose your authenticator device.</p>
                    
                    <?php foreach ($_SESSION['backup_codes'] as $code): ?>
                        <div class="backup-code"><?= htmlspecialchars($code) ?></div>
                    <?php endforeach; ?>
                    
                    <p><em>These codes will only be shown once. Please save them now!</em></p>
                </div>
                <?php unset($_SESSION['backup_codes']); ?>
            <?php endif; ?>
            
        <?php elseif ($twofa_enabled): ?>
            <div class="success">✅ Two-Factor Authentication is already enabled for your account.</div>
            <p>Your account is protected with 2FA. You'll need to enter a code from your authenticator app when logging in.</p>
            
        <?php else: ?>
            <p>Enhance your account security by enabling Two-Factor Authentication (2FA). This adds an extra layer of protection to prevent unauthorized access.</p>
            
            <form method="POST">
                <input type="hidden" name="action" value="enable">
                <input type="hidden" name="secret" value="<?= htmlspecialchars($secret) ?>">
                
                <div class="form-group">
                    <h3>Step 1: Scan QR Code</h3>
                    <p>Use Google Authenticator, Authy, or any compatible TOTP app to scan this QR code:</p>
                    
                    <div class="qr-code">
                        <?php 
                        $username = $_SESSION['username'] ?? 'admin';
                        $qr_url = TwoFactorAuth::getQRCodeURL($secret, 'CR0 Bot System', $username);
                        $otpauth_url = TwoFactorAuth::getOTPAuthURL($secret, 'CR0 Bot System', $username);
                        ?>
                        
                        <img src="<?= htmlspecialchars($qr_url) ?>" 
                             alt="2FA QR Code" 
                             style="border: 2px solid #00ff00;"
                             onerror="this.style.display='none'; document.getElementById('qr-error').style.display='block';">
                        
                        <div id="qr-error" style="display: none; color: #ff6666; margin: 10px 0;">
                            ❌ QR Code failed to load. Please use manual entry below.
                        </div>
                        
                        <p style="margin-top: 15px;">
                            <strong>Alternative QR Services:</strong><br>
                            <a href="https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=<?= urlencode($otpauth_url) ?>" 
                               target="_blank" style="color: #66ff66;">Google Charts QR</a> |
                            <a href="https://qr-server.com/api/v1/create-qr-code/?size=200x200&data=<?= urlencode($otpauth_url) ?>" 
                               target="_blank" style="color: #66ff66;">QR Server</a>
                        </p>
                    </div>
                    
                    <p><strong>Secret Key for Manual Entry:</strong><br>
                    <code style="background: #001100; padding: 10px; display: block; margin: 10px 0; border-radius: 5px; word-break: break-all;"><?= htmlspecialchars($secret) ?></code>
                    </p>
                    
                    <p><strong>Manual Setup Instructions:</strong></p>
                    <ol style="color: #aaffaa; text-align: left; max-width: 500px; margin: 0 auto;">
                        <li>Open your authenticator app</li>
                        <li>Select "Add account" or "+"</li>
                        <li>Choose "Enter key manually"</li>
                        <li>Account name: <code><?= htmlspecialchars($username) ?></code></li>
                        <li>Key: <code><?= htmlspecialchars($secret) ?></code></li>
                        <li>Time-based: Yes</li>
                    </ol>
                    
                    <div style="margin: 20px 0; padding: 15px; background: rgba(0, 50, 50, 0.3); border: 1px solid #0088aa; border-radius: 5px;">
                        <h4 style="color: #66aaff; margin-top: 0;">📱 Manual Entry (Copy & Paste)</h4>
                        <p><strong>Account:</strong> CR0 Bot System (<?= htmlspecialchars($username) ?>)</p>
                        <p><strong>Key:</strong> <span style="font-family: monospace; background: #001100; padding: 5px; border-radius: 3px;"><?= htmlspecialchars($secret) ?></span></p>
                        <p><strong>Type:</strong> Time-based (TOTP)</p>
                        
                        <p style="margin-top: 15px;"><strong>Full OTPAUTH URL (for advanced users):</strong></p>
                        <textarea readonly style="width: 100%; height: 60px; background: #001100; color: #00ff00; border: 1px solid #00aa00; font-family: monospace; font-size: 0.8em; padding: 5px; resize: vertical;"><?= htmlspecialchars($otpauth_url) ?></textarea>
                    </div>
                    
                    <details style="margin: 20px 0; color: #666;">
                        <summary style="color: #888; cursor: pointer;">🔧 Troubleshooting (click if QR code doesn't work)</summary>
                        <div style="background: #001100; padding: 10px; margin: 10px 0; border-radius: 5px; font-size: 0.9em;">
                            <p><strong>If the QR code doesn't load:</strong></p>
                            <ol style="text-align: left; color: #aaffaa;">
                                <li>Try the alternative QR links above</li>
                                <li>Use manual entry with the secret key</li>
                                <li>Check your internet connection</li>
                                <li>Try a different authenticator app</li>
                            </ol>
                            
                            <p><strong>Recommended Apps:</strong></p>
                            <ul style="text-align: left; color: #aaffaa;">
                                <li>Google Authenticator (Android/iOS)</li>
                                <li>Authy (Android/iOS/Desktop)</li>
                                <li>Microsoft Authenticator</li>
                                <li>1Password (Premium)</li>
                            </ul>
                            
                            <p style="margin-top: 15px;"><strong>Debug URLs:</strong></p>
                            <div style="font-size: 0.7em; word-break: break-all;">
                                <strong>Primary QR:</strong> <?= htmlspecialchars($qr_url) ?><br><br>
                                <strong>Google Charts:</strong> https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=<?= urlencode($otpauth_url) ?>
                            </div>
                        </div>
                    </details>
                </div>
                
                <div class="form-group">
                    <h3>Step 2: Enter Verification Code</h3>
                    <label for="code">Enter the 6-digit code from your authenticator app:</label>
                    <input type="number" id="code" name="code" placeholder="123456" maxlength="6" required 
                           style="text-align: center; font-size: 18px; letter-spacing: 5px;">
                </div>
                
                <button type="submit">Enable Two-Factor Authentication</button>
            </form>
        <?php endif; ?>
        
        <div class="nav-links">
            <a href="/admin_panel.php">← Back to Admin Panel</a>
            <a href="/auth.php?action=logout">Logout</a>
        </div>
    </div>
</body>
</html>