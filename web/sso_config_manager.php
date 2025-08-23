<?php
/**
 * SSO Configuration Manager
 * Advanced configuration management for SSO system
 * 
 * Security: Admin-only, encrypted storage, audit logging
 */

require_once 'security_config.php';
require_once 'sso/SSOManager.php';

// Initialize security and require admin
initSecureSession();
setSecurityHeaders();
requireAdmin();

$action = $_GET['action'] ?? 'overview';
$error = '';
$success = '';

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
    } else {
        $post_action = $_POST['action'] ?? '';
        
        switch ($post_action) {
            case 'update_global_config':
                $result = updateGlobalConfig($_POST);
                if ($result['success']) {
                    $success = $result['message'];
                } else {
                    $error = $result['message'];
                }
                break;
                
            case 'backup_config':
                $result = backupConfiguration();
                if ($result['success']) {
                    $success = $result['message'];
                } else {
                    $error = $result['message'];
                }
                break;
                
            case 'restore_config':
                $result = restoreConfiguration($_FILES['backup_file'] ?? null);
                if ($result['success']) {
                    $success = $result['message'];
                } else {
                    $error = $result['message'];
                }
                break;
                
            case 'reset_config':
                $result = resetToDefaults();
                if ($result['success']) {
                    $success = $result['message'];
                } else {
                    $error = $result['message'];
                }
                break;
        }
    }
}

function updateGlobalConfig($data) {
    try {
        $configs = [
            'sso_enabled' => isset($data['sso_enabled']) ? '1' : '0',
            'sso_auto_provision' => isset($data['sso_auto_provision']) ? '1' : '0',
            'sso_require_2fa_admin' => isset($data['sso_require_2fa_admin']) ? '1' : '0',
            'sso_session_timeout' => intval($data['sso_session_timeout'] ?? 3600),
            'sso_max_concurrent_sessions' => intval($data['sso_max_concurrent_sessions'] ?? 5),
            'sso_ip_binding_admin' => isset($data['sso_ip_binding_admin']) ? '1' : '0',
            'sso_audit_retention_days' => intval($data['sso_audit_retention_days'] ?? 365),
        ];
        
        foreach ($configs as $key => $value) {
            SSOManager::setConfigValue($key, $value);
        }
        
        SSOManager::logSSOEvent('CONFIG_UPDATE', null, $_SESSION['user_id'],
            'Global SSO configuration updated', 'MEDIUM');
        
        return ['success' => true, 'message' => 'Global configuration updated successfully'];
        
    } catch (Exception $e) {
        return ['success' => false, 'message' => 'Failed to update configuration: ' . $e->getMessage()];
    }
}

function backupConfiguration() {
    try {
        $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Get all SSO-related data
        $backup_data = [
            'version' => '1.0',
            'timestamp' => date('c'),
            'created_by' => $_SESSION['username'],
            'providers' => [],
            'configuration' => []
        ];
        
        // Export providers (without sensitive data)
        $stmt = $pdo->prepare("SELECT * FROM sso_providers");
        $stmt->execute();
        $providers = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        foreach ($providers as $provider) {
            // Remove sensitive fields from backup
            unset($provider['client_secret']);
            unset($provider['private_key']);
            $backup_data['providers'][] = $provider;
        }
        
        // Export configuration
        $stmt = $pdo->prepare("SELECT * FROM sso_configuration WHERE is_encrypted = 0");
        $stmt->execute();
        $backup_data['configuration'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Create backup file
        $backup_filename = 'sso_backup_' . date('Y-m-d_H-i-s') . '.json';
        $backup_path = '/tmp/' . $backup_filename;
        
        file_put_contents($backup_path, json_encode($backup_data, JSON_PRETTY_PRINT));
        
        // Send file to browser
        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="' . $backup_filename . '"');
        header('Content-Length: ' . filesize($backup_path));
        
        readfile($backup_path);
        unlink($backup_path);
        
        SSOManager::logSSOEvent('CONFIG_BACKUP', null, $_SESSION['user_id'],
            'SSO configuration backup created', 'LOW');
        
        exit;
        
    } catch (Exception $e) {
        return ['success' => false, 'message' => 'Backup failed: ' . $e->getMessage()];
    }
}

function restoreConfiguration($backup_file) {
    try {
        if (!$backup_file || $backup_file['error'] !== UPLOAD_ERR_OK) {
            return ['success' => false, 'message' => 'No valid backup file provided'];
        }
        
        $backup_content = file_get_contents($backup_file['tmp_name']);
        $backup_data = json_decode($backup_content, true);
        
        if (!$backup_data || !isset($backup_data['version'])) {
            return ['success' => false, 'message' => 'Invalid backup file format'];
        }
        
        $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $pdo->beginTransaction();
        
        // Restore configuration
        foreach ($backup_data['configuration'] as $config) {
            $stmt = $pdo->prepare("
                INSERT OR REPLACE INTO sso_configuration 
                (key_name, value, description, category, updated_by)
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                $config['key_name'],
                $config['value'],
                $config['description'],
                $config['category'],
                $_SESSION['user_id']
            ]);
        }
        
        // Note: Providers are not restored automatically for security reasons
        // Administrators must manually recreate providers with their credentials
        
        $pdo->commit();
        
        SSOManager::logSSOEvent('CONFIG_RESTORE', null, $_SESSION['user_id'],
            'SSO configuration restored from backup', 'HIGH');
        
        return ['success' => true, 'message' => 'Configuration restored successfully. Note: Provider credentials must be re-entered manually.'];
        
    } catch (Exception $e) {
        if (isset($pdo)) $pdo->rollback();
        return ['success' => false, 'message' => 'Restore failed: ' . $e->getMessage()];
    }
}

function resetToDefaults() {
    try {
        $defaults = [
            'sso_enabled' => '1',
            'sso_auto_provision' => '1',
            'sso_require_2fa_admin' => '1',
            'sso_session_timeout' => '3600',
            'sso_max_concurrent_sessions' => '5',
            'sso_ip_binding_admin' => '1',
            'sso_audit_retention_days' => '365',
            'sso_emergency_disable' => '0'
        ];
        
        foreach ($defaults as $key => $value) {
            SSOManager::setConfigValue($key, $value);
        }
        
        SSOManager::logSSOEvent('CONFIG_RESET', null, $_SESSION['user_id'],
            'SSO configuration reset to defaults', 'MEDIUM');
        
        return ['success' => true, 'message' => 'Configuration reset to defaults'];
        
    } catch (Exception $e) {
        return ['success' => false, 'message' => 'Reset failed: ' . $e->getMessage()];
    }
}

// Get current configuration
$current_config = [];
$config_keys = [
    'sso_enabled', 'sso_auto_provision', 'sso_require_2fa_admin', 
    'sso_session_timeout', 'sso_max_concurrent_sessions', 
    'sso_ip_binding_admin', 'sso_audit_retention_days', 'sso_emergency_disable'
];

foreach ($config_keys as $key) {
    $current_config[$key] = SSOManager::getConfigValue($key);
}

// Get system statistics
$pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$stats = [];
$stmt = $pdo->prepare("SELECT COUNT(*) FROM sso_providers WHERE is_active = 1");
$stmt->execute();
$stats['active_providers'] = $stmt->fetchColumn();

$stmt = $pdo->prepare("SELECT COUNT(*) FROM sso_user_mappings WHERE is_active = 1");
$stmt->execute();
$stats['sso_users'] = $stmt->fetchColumn();

$stmt = $pdo->prepare("SELECT COUNT(*) FROM sso_security_events WHERE timestamp > datetime('now', '-7 days')");
$stmt->execute();
$stats['recent_events'] = $stmt->fetchColumn();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSO Configuration Manager - cr0bot</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        .sidebar {
            min-height: 100vh;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .nav-link {
            color: rgba(255,255,255,0.8) !important;
            border-radius: 8px;
            margin: 2px 0;
        }
        .nav-link:hover, .nav-link.active {
            color: white !important;
            background: rgba(255,255,255,0.2);
        }
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }
        .card-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px 15px 0 0 !important;
        }
        .stat-card {
            background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%);
            color: white;
            text-align: center;
            padding: 1.5rem;
            border-radius: 15px;
        }
        .danger-zone {
            border: 2px solid #dc3545;
            border-radius: 10px;
            padding: 1.5rem;
            background: #fff5f5;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 sidebar p-0">
                <div class="p-4">
                    <h4 class="text-white mb-4">
                        <i class="fas fa-cogs me-2"></i>
                        SSO Config
                    </h4>
                    <nav class="nav flex-column">
                        <a href="?action=overview" class="nav-link <?= $action === 'overview' ? 'active' : '' ?>">
                            <i class="fas fa-tachometer-alt me-2"></i>Overview
                        </a>
                        <a href="?action=global" class="nav-link <?= $action === 'global' ? 'active' : '' ?>">
                            <i class="fas fa-globe me-2"></i>Global Settings
                        </a>
                        <a href="?action=backup" class="nav-link <?= $action === 'backup' ? 'active' : '' ?>">
                            <i class="fas fa-download me-2"></i>Backup & Restore
                        </a>
                        <a href="?action=advanced" class="nav-link <?= $action === 'advanced' ? 'active' : '' ?>">
                            <i class="fas fa-tools me-2"></i>Advanced
                        </a>
                        <hr class="text-white-50">
                        <a href="/admin_sso.php" class="nav-link">
                            <i class="fas fa-shield-alt me-2"></i>SSO Admin
                        </a>
                        <a href="/sso_security_monitor.php" class="nav-link">
                            <i class="fas fa-chart-line me-2"></i>Security Monitor
                        </a>
                    </nav>
                </div>
            </div>

            <!-- Main Content -->
            <div class="col-md-9 col-lg-10 p-4">
                <?php if ($error): ?>
                    <div class="alert alert-danger alert-dismissible fade show">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        <?= htmlspecialchars($error) ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                <?php endif; ?>

                <?php if ($success): ?>
                    <div class="alert alert-success alert-dismissible fade show">
                        <i class="fas fa-check-circle me-2"></i>
                        <?= htmlspecialchars($success) ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                <?php endif; ?>

                <?php if ($action === 'overview'): ?>
                    <!-- Overview -->
                    <h2><i class="fas fa-tachometer-alt me-2"></i>Configuration Overview</h2>
                    
                    <!-- Statistics Cards -->
                    <div class="row mb-4">
                        <div class="col-md-4 mb-3">
                            <div class="card stat-card">
                                <h3><?= $stats['active_providers'] ?></h3>
                                <p class="mb-0">Active Providers</p>
                            </div>
                        </div>
                        <div class="col-md-4 mb-3">
                            <div class="card stat-card">
                                <h3><?= $stats['sso_users'] ?></h3>
                                <p class="mb-0">SSO Users</p>
                            </div>
                        </div>
                        <div class="col-md-4 mb-3">
                            <div class="card stat-card">
                                <h3><?= $stats['recent_events'] ?></h3>
                                <p class="mb-0">Events (7 days)</p>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Current Configuration Summary -->
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0">Current Configuration</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <h6>System Status</h6>
                                    <ul class="list-unstyled">
                                        <li><i class="fas fa-<?= $current_config['sso_enabled'] === '1' ? 'check text-success' : 'times text-danger' ?> me-2"></i>SSO Enabled</li>
                                        <li><i class="fas fa-<?= $current_config['sso_auto_provision'] === '1' ? 'check text-success' : 'times text-danger' ?> me-2"></i>Auto Provisioning</li>
                                        <li><i class="fas fa-<?= $current_config['sso_require_2fa_admin'] === '1' ? 'check text-success' : 'times text-danger' ?> me-2"></i>Admin 2FA Required</li>
                                        <li><i class="fas fa-<?= $current_config['sso_emergency_disable'] === '0' ? 'check text-success' : 'exclamation-triangle text-danger' ?> me-2"></i>Emergency Status: <?= $current_config['sso_emergency_disable'] === '0' ? 'Normal' : 'DISABLED' ?></li>
                                    </ul>
                                </div>
                                <div class="col-md-6">
                                    <h6>Security Settings</h6>
                                    <ul class="list-unstyled">
                                        <li><i class="fas fa-clock me-2"></i>Session Timeout: <?= intval($current_config['sso_session_timeout']) / 3600 ?> hours</li>
                                        <li><i class="fas fa-users me-2"></i>Max Sessions: <?= $current_config['sso_max_concurrent_sessions'] ?></li>
                                        <li><i class="fas fa-map-marker-alt me-2"></i>IP Binding: <?= $current_config['sso_ip_binding_admin'] === '1' ? 'Enabled' : 'Disabled' ?></li>
                                        <li><i class="fas fa-archive me-2"></i>Log Retention: <?= $current_config['sso_audit_retention_days'] ?> days</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>

                <?php elseif ($action === 'global'): ?>
                    <!-- Global Settings -->
                    <h2><i class="fas fa-globe me-2"></i>Global Settings</h2>
                    
                    <form method="POST">
                        <input type="hidden" name="action" value="update_global_config">
                        <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                        
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">System Configuration</h5>
                            </div>
                            <div class="card-body">
                                <div class="row mb-3">
                                    <div class="col-md-4">
                                        <div class="form-check form-switch">
                                            <input class="form-check-input" type="checkbox" name="sso_enabled" 
                                                   <?= $current_config['sso_enabled'] === '1' ? 'checked' : '' ?>>
                                            <label class="form-check-label">Enable SSO</label>
                                        </div>
                                        <small class="text-muted">Allow SSO authentication</small>
                                    </div>
                                    <div class="col-md-4">
                                        <div class="form-check form-switch">
                                            <input class="form-check-input" type="checkbox" name="sso_auto_provision" 
                                                   <?= $current_config['sso_auto_provision'] === '1' ? 'checked' : '' ?>>
                                            <label class="form-check-label">Auto-provision Users</label>
                                        </div>
                                        <small class="text-muted">Create accounts automatically</small>
                                    </div>
                                    <div class="col-md-4">
                                        <div class="form-check form-switch">
                                            <input class="form-check-input" type="checkbox" name="sso_require_2fa_admin" 
                                                   <?= $current_config['sso_require_2fa_admin'] === '1' ? 'checked' : '' ?>>
                                            <label class="form-check-label">Require Admin 2FA</label>
                                        </div>
                                        <small class="text-muted">Force 2FA for admin SSO users</small>
                                    </div>
                                </div>
                                
                                <div class="row mb-3">
                                    <div class="col-md-6">
                                        <label class="form-label">Session Timeout (seconds)</label>
                                        <input type="number" class="form-control" name="sso_session_timeout" 
                                               value="<?= htmlspecialchars($current_config['sso_session_timeout']) ?>" min="300" max="86400">
                                        <div class="form-text">How long SSO sessions remain valid</div>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label">Max Concurrent Sessions</label>
                                        <input type="number" class="form-control" name="sso_max_concurrent_sessions" 
                                               value="<?= htmlspecialchars($current_config['sso_max_concurrent_sessions']) ?>" min="1" max="50">
                                        <div class="form-text">Maximum sessions per user</div>
                                    </div>
                                </div>
                                
                                <div class="row mb-3">
                                    <div class="col-md-6">
                                        <div class="form-check form-switch">
                                            <input class="form-check-input" type="checkbox" name="sso_ip_binding_admin" 
                                                   <?= $current_config['sso_ip_binding_admin'] === '1' ? 'checked' : '' ?>>
                                            <label class="form-check-label">IP Binding for Admins</label>
                                        </div>
                                        <small class="text-muted">Bind admin sessions to IP address</small>
                                    </div>
                                    <div class="col-md-6">
                                        <label class="form-label">Audit Log Retention (days)</label>
                                        <input type="number" class="form-control" name="sso_audit_retention_days" 
                                               value="<?= htmlspecialchars($current_config['sso_audit_retention_days']) ?>" min="30" max="3650">
                                        <div class="form-text">How long to keep security logs</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="mt-3">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-save me-2"></i>Save Configuration
                            </button>
                            <button type="button" class="btn btn-outline-secondary" onclick="location.reload()">
                                <i class="fas fa-undo me-2"></i>Reset Changes
                            </button>
                        </div>
                    </form>

                <?php elseif ($action === 'backup'): ?>
                    <!-- Backup & Restore -->
                    <h2><i class="fas fa-download me-2"></i>Backup & Restore</h2>
                    
                    <div class="row">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header">
                                    <h5 class="mb-0">Create Backup</h5>
                                </div>
                                <div class="card-body">
                                    <p>Create a backup of your SSO configuration including providers and settings.</p>
                                    <div class="alert alert-warning">
                                        <i class="fas fa-exclamation-triangle me-2"></i>
                                        <strong>Note:</strong> Sensitive data like client secrets are not included in backups for security.
                                    </div>
                                    <form method="POST">
                                        <input type="hidden" name="action" value="backup_config">
                                        <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                        <button type="submit" class="btn btn-primary">
                                            <i class="fas fa-download me-2"></i>Download Backup
                                        </button>
                                    </form>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header">
                                    <h5 class="mb-0">Restore Configuration</h5>
                                </div>
                                <div class="card-body">
                                    <p>Restore SSO configuration from a previously created backup file.</p>
                                    <form method="POST" enctype="multipart/form-data">
                                        <input type="hidden" name="action" value="restore_config">
                                        <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                        <div class="mb-3">
                                            <label class="form-label">Backup File</label>
                                            <input type="file" class="form-control" name="backup_file" accept=".json" required>
                                            <div class="form-text">Select a JSON backup file</div>
                                        </div>
                                        <button type="submit" class="btn btn-warning">
                                            <i class="fas fa-upload me-2"></i>Restore Configuration
                                        </button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>

                <?php elseif ($action === 'advanced'): ?>
                    <!-- Advanced Settings -->
                    <h2><i class="fas fa-tools me-2"></i>Advanced Configuration</h2>
                    
                    <div class="danger-zone">
                        <h5><i class="fas fa-exclamation-triangle me-2"></i>Danger Zone</h5>
                        <p>These actions can significantly impact your SSO system. Use with caution.</p>
                        
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <h6>Reset to Defaults</h6>
                                <p class="small text-muted">Reset all SSO configuration to default values. This will not affect existing providers.</p>
                                <form method="POST" onsubmit="return confirm('Are you sure you want to reset all configuration to defaults?')">
                                    <input type="hidden" name="action" value="reset_config">
                                    <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                    <button type="submit" class="btn btn-outline-danger">
                                        <i class="fas fa-undo me-2"></i>Reset to Defaults
                                    </button>
                                </form>
                            </div>
                            
                            <div class="col-md-6 mb-3">
                                <h6>Emergency Disable</h6>
                                <p class="small text-muted">Immediately disable all SSO functionality system-wide.</p>
                                <?php if ($current_config['sso_emergency_disable'] === '1'): ?>
                                    <form method="POST">
                                        <input type="hidden" name="action" value="update_global_config">
                                        <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                        <input type="hidden" name="sso_emergency_disable" value="0">
                                        <button type="submit" class="btn btn-success">
                                            <i class="fas fa-play me-2"></i>Re-enable SSO
                                        </button>
                                    </form>
                                <?php else: ?>
                                    <button type="button" class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#emergencyModal">
                                        <i class="fas fa-stop me-2"></i>Emergency Disable
                                    </button>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Emergency Disable Modal -->
    <div class="modal fade" id="emergencyModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header bg-danger text-white">
                    <h5 class="modal-title">
                        <i class="fas fa-exclamation-triangle me-2"></i>Emergency SSO Disable
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST" action="/admin_sso.php">
                    <div class="modal-body">
                        <div class="alert alert-danger">
                            <strong>Warning:</strong> This will immediately disable all SSO authentication and invalidate pending sessions.
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Reason for emergency disable</label>
                            <textarea class="form-control" name="reason" rows="3" placeholder="Describe the reason for emergency disable..."></textarea>
                        </div>
                        <input type="hidden" name="action" value="emergency_disable">
                        <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-danger">
                            <i class="fas fa-exclamation-triangle me-1"></i>Emergency Disable
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
</body>
</html>