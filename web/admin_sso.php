<?php
/**
 * SSO Administration Interface
 * Enterprise-grade SSO provider management and monitoring
 * 
 * Security: Admin-only access, comprehensive audit logging, secure configuration
 */

require_once 'security_config.php';
require_once 'sso/SSOManager.php';
require_once 'input_sanitizer.php';

// Initialize security and require admin
initSecureSession();
setSecurityHeaders();
requireAdmin();

$error = '';
$success = '';
$action = $_GET['action'] ?? 'dashboard';

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
    } else {
        $post_action = $_POST['action'] ?? '';
        
        switch ($post_action) {
            case 'create_provider':
                $result = createProvider($_POST);
                if ($result['success']) {
                    $success = $result['message'];
                } else {
                    $error = $result['message'];
                }
                break;
                
            case 'update_provider':
                $result = updateProvider($_POST);
                if ($result['success']) {
                    $success = $result['message'];
                } else {
                    $error = $result['message'];
                }
                break;
                
            case 'delete_provider':
                $result = deleteProvider($_POST['provider_id'] ?? 0);
                if ($result['success']) {
                    $success = $result['message'];
                } else {
                    $error = $result['message'];
                }
                break;
                
            case 'toggle_provider':
                $result = toggleProvider($_POST['provider_id'] ?? 0);
                if ($result['success']) {
                    $success = $result['message'];
                } else {
                    $error = $result['message'];
                }
                break;
                
            case 'emergency_disable':
                $reason = trim($_POST['reason'] ?? 'Manual emergency disable');
                SSOManager::emergencyDisable($reason);
                $success = 'SSO has been emergency disabled';
                break;
                
            case 'enable_sso':
                SSOManager::setConfigValue('sso_emergency_disable', '0');
                $success = 'SSO has been re-enabled';
                break;
        }
    }
}

/**
 * Create new SSO provider
 */
function createProvider($data) {
    try {
        $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Validate required fields
        $name = trim($data['name'] ?? '');
        $type = trim($data['type'] ?? '');
        $display_name = trim($data['display_name'] ?? '');
        $sso_url = trim($data['sso_url'] ?? '');
        
        if (empty($name) || empty($type) || empty($display_name) || empty($sso_url)) {
            return ['success' => false, 'message' => 'Missing required fields'];
        }
        
        if (!in_array($type, ['saml', 'oidc', 'oauth2'])) {
            return ['success' => false, 'message' => 'Invalid provider type'];
        }
        
        // Check if name already exists
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM sso_providers WHERE name = ?");
        $stmt->execute([$name]);
        if ($stmt->fetchColumn() > 0) {
            return ['success' => false, 'message' => 'Provider name already exists'];
        }
        
        // Encrypt sensitive data
        $client_secret = '';
        $private_key = '';
        if (!empty($data['client_secret'])) {
            $client_secret = CryptoUtils::encrypt(trim($data['client_secret']));
        }
        if (!empty($data['private_key'])) {
            $private_key = CryptoUtils::encrypt(trim($data['private_key']));
        }
        
        // Prepare configuration JSON
        $config = [
            'prompt' => trim($data['prompt'] ?? ''),
            'max_age' => intval($data['max_age'] ?? 0),
            'token_endpoint' => trim($data['token_endpoint'] ?? ''),
            'userinfo_endpoint' => trim($data['userinfo_endpoint'] ?? ''),
            'jwks_uri' => trim($data['jwks_uri'] ?? ''),
            'issuer' => trim($data['issuer'] ?? '')
        ];
        $config = array_filter($config); // Remove empty values
        
        $stmt = $pdo->prepare("
            INSERT INTO sso_providers 
            (name, type, display_name, icon_url, entity_id, sso_url, sls_url, metadata_url,
             client_id, client_secret, scope, discovery_url, x509_cert, private_key, config_json,
             auto_provision, require_2fa, admin_only)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        
        $stmt->execute([
            $name, $type, $display_name,
            trim($data['icon_url'] ?? ''),
            trim($data['entity_id'] ?? ''),
            $sso_url,
            trim($data['sls_url'] ?? ''),
            trim($data['metadata_url'] ?? ''),
            trim($data['client_id'] ?? ''),
            $client_secret,
            trim($data['scope'] ?? 'openid profile email'),
            trim($data['discovery_url'] ?? ''),
            trim($data['x509_cert'] ?? ''),
            $private_key,
            json_encode($config),
            isset($data['auto_provision']) ? 1 : 0,
            isset($data['require_2fa']) ? 1 : 0,
            isset($data['admin_only']) ? 1 : 0
        ]);
        
        SSOManager::logSSOEvent('PROVIDER_CREATED', $pdo->lastInsertId(), $_SESSION['user_id'],
            "SSO provider '$display_name' created", 'MEDIUM');
        
        return ['success' => true, 'message' => "Provider '$display_name' created successfully"];
        
    } catch (Exception $e) {
        error_log("Create SSO provider error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to create provider: ' . $e->getMessage()];
    }
}

/**
 * Update existing SSO provider
 */
function updateProvider($data) {
    try {
        $provider_id = intval($data['provider_id'] ?? 0);
        if ($provider_id <= 0) {
            return ['success' => false, 'message' => 'Invalid provider ID'];
        }
        
        $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Get current provider
        $stmt = $pdo->prepare("SELECT * FROM sso_providers WHERE id = ?");
        $stmt->execute([$provider_id]);
        $current = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$current) {
            return ['success' => false, 'message' => 'Provider not found'];
        }
        
        // Update fields
        $display_name = trim($data['display_name'] ?? $current['display_name']);
        $sso_url = trim($data['sso_url'] ?? $current['sso_url']);
        
        // Handle encrypted fields
        $client_secret = $current['client_secret'];
        $private_key = $current['private_key'];
        
        if (isset($data['client_secret']) && trim($data['client_secret']) !== '') {
            $client_secret = CryptoUtils::encrypt(trim($data['client_secret']));
        }
        if (isset($data['private_key']) && trim($data['private_key']) !== '') {
            $private_key = CryptoUtils::encrypt(trim($data['private_key']));
        }
        
        // Update configuration
        $config = json_decode($current['config_json'] ?: '{}', true);
        if (isset($data['prompt'])) $config['prompt'] = trim($data['prompt']);
        if (isset($data['max_age'])) $config['max_age'] = intval($data['max_age']);
        if (isset($data['token_endpoint'])) $config['token_endpoint'] = trim($data['token_endpoint']);
        if (isset($data['userinfo_endpoint'])) $config['userinfo_endpoint'] = trim($data['userinfo_endpoint']);
        
        $stmt = $pdo->prepare("
            UPDATE sso_providers SET
            display_name = ?, icon_url = ?, sso_url = ?, sls_url = ?, metadata_url = ?,
            client_id = ?, client_secret = ?, scope = ?, discovery_url = ?, x509_cert = ?, 
            private_key = ?, config_json = ?, auto_provision = ?, require_2fa = ?, 
            admin_only = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ");
        
        $stmt->execute([
            $display_name,
            trim($data['icon_url'] ?? $current['icon_url']),
            $sso_url,
            trim($data['sls_url'] ?? $current['sls_url']),
            trim($data['metadata_url'] ?? $current['metadata_url']),
            trim($data['client_id'] ?? $current['client_id']),
            $client_secret,
            trim($data['scope'] ?? $current['scope']),
            trim($data['discovery_url'] ?? $current['discovery_url']),
            trim($data['x509_cert'] ?? $current['x509_cert']),
            $private_key,
            json_encode($config),
            isset($data['auto_provision']) ? 1 : 0,
            isset($data['require_2fa']) ? 1 : 0,
            isset($data['admin_only']) ? 1 : 0,
            $provider_id
        ]);
        
        SSOManager::logSSOEvent('PROVIDER_UPDATED', $provider_id, $_SESSION['user_id'],
            "SSO provider '$display_name' updated", 'MEDIUM');
        
        return ['success' => true, 'message' => "Provider '$display_name' updated successfully"];
        
    } catch (Exception $e) {
        error_log("Update SSO provider error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to update provider: ' . $e->getMessage()];
    }
}

/**
 * Delete SSO provider
 */
function deleteProvider($provider_id) {
    try {
        $provider_id = intval($provider_id);
        if ($provider_id <= 0) {
            return ['success' => false, 'message' => 'Invalid provider ID'];
        }
        
        $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Get provider name for logging
        $stmt = $pdo->prepare("SELECT display_name FROM sso_providers WHERE id = ?");
        $stmt->execute([$provider_id]);
        $provider = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$provider) {
            return ['success' => false, 'message' => 'Provider not found'];
        }
        
        // Check if provider has active user mappings
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM sso_user_mappings WHERE provider_id = ? AND is_active = 1");
        $stmt->execute([$provider_id]);
        $active_users = $stmt->fetchColumn();
        
        if ($active_users > 0) {
            return ['success' => false, 'message' => 'Cannot delete provider with active user mappings'];
        }
        
        // Delete the provider
        $stmt = $pdo->prepare("DELETE FROM sso_providers WHERE id = ?");
        $stmt->execute([$provider_id]);
        
        SSOManager::logSSOEvent('PROVIDER_DELETED', $provider_id, $_SESSION['user_id'],
            "SSO provider '{$provider['display_name']}' deleted", 'HIGH');
        
        return ['success' => true, 'message' => "Provider '{$provider['display_name']}' deleted successfully"];
        
    } catch (Exception $e) {
        error_log("Delete SSO provider error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to delete provider: ' . $e->getMessage()];
    }
}

/**
 * Toggle provider active status
 */
function toggleProvider($provider_id) {
    try {
        $provider_id = intval($provider_id);
        if ($provider_id <= 0) {
            return ['success' => false, 'message' => 'Invalid provider ID'];
        }
        
        $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->prepare("SELECT display_name, is_active FROM sso_providers WHERE id = ?");
        $stmt->execute([$provider_id]);
        $provider = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$provider) {
            return ['success' => false, 'message' => 'Provider not found'];
        }
        
        $new_status = $provider['is_active'] ? 0 : 1;
        $stmt = $pdo->prepare("UPDATE sso_providers SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
        $stmt->execute([$new_status, $provider_id]);
        
        $status_text = $new_status ? 'enabled' : 'disabled';
        SSOManager::logSSOEvent('PROVIDER_TOGGLED', $provider_id, $_SESSION['user_id'],
            "SSO provider '{$provider['display_name']}' $status_text", 'MEDIUM');
        
        return ['success' => true, 'message' => "Provider '{$provider['display_name']}' $status_text successfully"];
        
    } catch (Exception $e) {
        error_log("Toggle SSO provider error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to toggle provider: ' . $e->getMessage()];
    }
}

// Get data for dashboard
$sso_enabled = SSOManager::isEnabled();
$emergency_disabled = SSOManager::getConfigValue('sso_emergency_disable', '0') === '1';

$pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Get providers
$providers = [];
$stmt = $pdo->prepare("SELECT * FROM sso_providers ORDER BY created_at DESC");
$stmt->execute();
$providers = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get statistics
$stats = [];
$stmt = $pdo->prepare("SELECT COUNT(*) FROM sso_providers WHERE is_active = 1");
$stmt->execute();
$stats['active_providers'] = $stmt->fetchColumn();

$stmt = $pdo->prepare("SELECT COUNT(*) FROM sso_user_mappings WHERE is_active = 1");
$stmt->execute();
$stats['total_sso_users'] = $stmt->fetchColumn();

$stmt = $pdo->prepare("SELECT COUNT(*) FROM sso_auth_sessions WHERE created_at > ?");
$stmt->execute([time() - 86400]);
$stats['recent_logins'] = $stmt->fetchColumn();

// Get recent security events
$recent_events = [];
$stmt = $pdo->prepare("
    SELECT * FROM sso_security_events 
    ORDER BY timestamp DESC 
    LIMIT 10
");
$stmt->execute();
$recent_events = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Provider being edited
$edit_provider = null;
if ($action === 'edit' && isset($_GET['id'])) {
    $edit_id = intval($_GET['id']);
    $stmt = $pdo->prepare("SELECT * FROM sso_providers WHERE id = ?");
    $stmt->execute([$edit_id]);
    $edit_provider = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($edit_provider) {
        // Decrypt sensitive fields for editing
        if ($edit_provider['client_secret']) {
            $edit_provider['client_secret'] = CryptoUtils::decrypt($edit_provider['client_secret']);
        }
        if ($edit_provider['private_key']) {
            $edit_provider['private_key'] = CryptoUtils::decrypt($edit_provider['private_key']);
        }
        if ($edit_provider['config_json']) {
            $edit_provider['config'] = json_decode($edit_provider['config_json'], true);
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSO Administration - PyBorg</title>
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
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
        }
        .status-badge {
            font-size: 0.75rem;
        }
        .provider-card {
            transition: transform 0.2s;
        }
        .provider-card:hover {
            transform: translateY(-2px);
        }
        .emergency-controls {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
        }
        .stats-card {
            background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%);
            color: white;
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
                        <i class="fas fa-shield-alt me-2"></i>
                        SSO Admin
                    </h4>
                    <nav class="nav flex-column">
                        <a href="?action=dashboard" class="nav-link <?= $action === 'dashboard' ? 'active' : '' ?>">
                            <i class="fas fa-tachometer-alt me-2"></i>Dashboard
                        </a>
                        <a href="?action=providers" class="nav-link <?= $action === 'providers' ? 'active' : '' ?>">
                            <i class="fas fa-plug me-2"></i>Providers
                        </a>
                        <a href="?action=users" class="nav-link <?= $action === 'users' ? 'active' : '' ?>">
                            <i class="fas fa-users me-2"></i>SSO Users
                        </a>
                        <a href="?action=events" class="nav-link <?= $action === 'events' ? 'active' : '' ?>">
                            <i class="fas fa-history me-2"></i>Security Events
                        </a>
                        <a href="?action=settings" class="nav-link <?= $action === 'settings' ? 'active' : '' ?>">
                            <i class="fas fa-cogs me-2"></i>Settings
                        </a>
                        <hr class="text-white-50">
                        <a href="/index.php" class="nav-link">
                            <i class="fas fa-home me-2"></i>Main Dashboard
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

                <?php if ($action === 'dashboard'): ?>
                    <!-- Dashboard -->
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2><i class="fas fa-tachometer-alt me-2"></i>SSO Dashboard</h2>
                        <div class="d-flex gap-2">
                            <?php if ($emergency_disabled): ?>
                                <form method="POST" class="d-inline">
                                    <input type="hidden" name="action" value="enable_sso">
                                    <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                    <button type="submit" class="btn btn-success btn-sm">
                                        <i class="fas fa-play me-1"></i>Re-enable SSO
                                    </button>
                                </form>
                            <?php else: ?>
                                <button type="button" class="btn btn-danger btn-sm" data-bs-toggle="modal" data-bs-target="#emergencyModal">
                                    <i class="fas fa-exclamation-triangle me-1"></i>Emergency Disable
                                </button>
                            <?php endif; ?>
                        </div>
                    </div>

                    <!-- Status Cards -->
                    <div class="row mb-4">
                        <div class="col-md-3 mb-3">
                            <div class="card stats-card">
                                <div class="card-body text-center">
                                    <i class="fas fa-plug fa-2x mb-2"></i>
                                    <h3><?= $stats['active_providers'] ?></h3>
                                    <small>Active Providers</small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3 mb-3">
                            <div class="card stats-card">
                                <div class="card-body text-center">
                                    <i class="fas fa-users fa-2x mb-2"></i>
                                    <h3><?= $stats['total_sso_users'] ?></h3>
                                    <small>SSO Users</small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3 mb-3">
                            <div class="card stats-card">
                                <div class="card-body text-center">
                                    <i class="fas fa-sign-in-alt fa-2x mb-2"></i>
                                    <h3><?= $stats['recent_logins'] ?></h3>
                                    <small>24h Logins</small>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-3 mb-3">
                            <div class="card">
                                <div class="card-body text-center">
                                    <?php if ($sso_enabled && !$emergency_disabled): ?>
                                        <i class="fas fa-check-circle fa-2x mb-2 text-success"></i>
                                        <h5 class="text-success">Active</h5>
                                    <?php else: ?>
                                        <i class="fas fa-times-circle fa-2x mb-2 text-danger"></i>
                                        <h5 class="text-danger">Disabled</h5>
                                    <?php endif; ?>
                                    <small>SSO Status</small>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Recent Events -->
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0"><i class="fas fa-history me-2"></i>Recent Security Events</h5>
                        </div>
                        <div class="card-body">
                            <?php if (empty($recent_events)): ?>
                                <p class="text-muted">No recent security events</p>
                            <?php else: ?>
                                <div class="table-responsive">
                                    <table class="table table-sm">
                                        <thead>
                                            <tr>
                                                <th>Time</th>
                                                <th>Event</th>
                                                <th>Severity</th>
                                                <th>Message</th>
                                                <th>IP</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($recent_events as $event): ?>
                                                <tr>
                                                    <td class="small"><?= date('M j, H:i', strtotime($event['timestamp'])) ?></td>
                                                    <td><code class="small"><?= htmlspecialchars($event['event_type']) ?></code></td>
                                                    <td>
                                                        <span class="badge bg-<?= 
                                                            $event['severity'] === 'CRITICAL' ? 'danger' : (
                                                            $event['severity'] === 'HIGH' ? 'warning' : (
                                                            $event['severity'] === 'MEDIUM' ? 'info' : 'secondary'
                                                        )) ?>"><?= $event['severity'] ?></span>
                                                    </td>
                                                    <td class="small"><?= htmlspecialchars($event['message']) ?></td>
                                                    <td class="small"><?= htmlspecialchars($event['ip_address']) ?></td>
                                                </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>

                <?php elseif ($action === 'providers' || $action === 'create' || $action === 'edit'): ?>
                    <!-- Providers Management -->
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h2><i class="fas fa-plug me-2"></i>SSO Providers</h2>
                        <?php if ($action !== 'create' && $action !== 'edit'): ?>
                            <a href="?action=create" class="btn btn-primary">
                                <i class="fas fa-plus me-1"></i>Add Provider
                            </a>
                        <?php endif; ?>
                    </div>

                    <?php if ($action === 'create' || $action === 'edit'): ?>
                        <!-- Provider Form -->
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">
                                    <i class="fas fa-<?= $action === 'create' ? 'plus' : 'edit' ?> me-2"></i>
                                    <?= ucfirst($action) ?> SSO Provider
                                </h5>
                            </div>
                            <div class="card-body">
                                <form method="POST">
                                    <input type="hidden" name="action" value="<?= $action === 'create' ? 'create_provider' : 'update_provider' ?>">
                                    <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                    <?php if ($edit_provider): ?>
                                        <input type="hidden" name="provider_id" value="<?= $edit_provider['id'] ?>">
                                    <?php endif; ?>

                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Provider Name *</label>
                                            <input type="text" class="form-control" name="name" 
                                                   value="<?= htmlspecialchars($edit_provider['name'] ?? '') ?>"
                                                   <?= $edit_provider ? 'readonly' : 'required' ?>>
                                            <div class="form-text">Internal identifier (cannot be changed)</div>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Display Name *</label>
                                            <input type="text" class="form-control" name="display_name" 
                                                   value="<?= htmlspecialchars($edit_provider['display_name'] ?? '') ?>" required>
                                        </div>
                                    </div>

                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Type *</label>
                                            <select class="form-select" name="type" <?= $edit_provider ? 'disabled' : 'required' ?>>
                                                <option value="">Select Type</option>
                                                <option value="saml" <?= ($edit_provider['type'] ?? '') === 'saml' ? 'selected' : '' ?>>SAML 2.0</option>
                                                <option value="oidc" <?= ($edit_provider['type'] ?? '') === 'oidc' ? 'selected' : '' ?>>OpenID Connect</option>
                                                <option value="oauth2" <?= ($edit_provider['type'] ?? '') === 'oauth2' ? 'selected' : '' ?>>OAuth 2.0</option>
                                            </select>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Icon URL</label>
                                            <input type="url" class="form-control" name="icon_url" 
                                                   value="<?= htmlspecialchars($edit_provider['icon_url'] ?? '') ?>">
                                        </div>
                                    </div>

                                    <div class="mb-3">
                                        <label class="form-label">SSO URL *</label>
                                        <input type="url" class="form-control" name="sso_url" 
                                               value="<?= htmlspecialchars($edit_provider['sso_url'] ?? '') ?>" required>
                                        <div class="form-text">Authorization/SSO endpoint URL</div>
                                    </div>

                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Client ID</label>
                                            <input type="text" class="form-control" name="client_id" 
                                                   value="<?= htmlspecialchars($edit_provider['client_id'] ?? '') ?>">
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <label class="form-label">Client Secret</label>
                                            <input type="password" class="form-control" name="client_secret" 
                                                   value="<?= htmlspecialchars($edit_provider['client_secret'] ?? '') ?>">
                                        </div>
                                    </div>

                                    <div class="row">
                                        <div class="col-md-6 mb-3">
                                            <div class="form-check">
                                                <input class="form-check-input" type="checkbox" name="auto_provision" 
                                                       <?= ($edit_provider['auto_provision'] ?? 1) ? 'checked' : '' ?>>
                                                <label class="form-check-label">Auto-provision users</label>
                                            </div>
                                        </div>
                                        <div class="col-md-6 mb-3">
                                            <div class="form-check">
                                                <input class="form-check-input" type="checkbox" name="require_2fa" 
                                                       <?= ($edit_provider['require_2fa'] ?? 0) ? 'checked' : '' ?>>
                                                <label class="form-check-label">Require 2FA</label>
                                            </div>
                                        </div>
                                    </div>

                                    <div class="mb-3">
                                        <div class="form-check">
                                            <input class="form-check-input" type="checkbox" name="admin_only" 
                                                   <?= ($edit_provider['admin_only'] ?? 0) ? 'checked' : '' ?>>
                                            <label class="form-check-label">Admin users only</label>
                                        </div>
                                    </div>

                                    <div class="d-flex gap-2">
                                        <button type="submit" class="btn btn-primary">
                                            <i class="fas fa-save me-1"></i>
                                            <?= $action === 'create' ? 'Create' : 'Update' ?> Provider
                                        </button>
                                        <a href="?action=providers" class="btn btn-outline-secondary">Cancel</a>
                                    </div>
                                </form>
                            </div>
                        </div>
                    <?php else: ?>
                        <!-- Providers List -->
                        <?php if (empty($providers)): ?>
                            <div class="card">
                                <div class="card-body text-center py-5">
                                    <i class="fas fa-plug fa-3x text-muted mb-3"></i>
                                    <h5 class="text-muted">No SSO Providers</h5>
                                    <p class="text-muted">Add your first SSO provider to get started</p>
                                    <a href="?action=create" class="btn btn-primary">
                                        <i class="fas fa-plus me-1"></i>Add Provider
                                    </a>
                                </div>
                            </div>
                        <?php else: ?>
                            <div class="row">
                                <?php foreach ($providers as $provider): ?>
                                    <div class="col-md-6 col-lg-4 mb-3">
                                        <div class="card provider-card">
                                            <div class="card-body">
                                                <div class="d-flex align-items-center mb-3">
                                                    <?php if ($provider['icon_url']): ?>
                                                        <img src="<?= htmlspecialchars($provider['icon_url']) ?>" 
                                                             alt="<?= htmlspecialchars($provider['display_name']) ?>" 
                                                             width="32" height="32" class="me-2">
                                                    <?php else: ?>
                                                        <i class="fas fa-<?= $provider['type'] === 'saml' ? 'certificate' : 'id-card' ?> fa-2x me-2 text-primary"></i>
                                                    <?php endif; ?>
                                                    <div>
                                                        <h6 class="mb-0"><?= htmlspecialchars($provider['display_name']) ?></h6>
                                                        <small class="text-muted text-uppercase"><?= $provider['type'] ?></small>
                                                    </div>
                                                </div>

                                                <div class="mb-2">
                                                    <span class="badge bg-<?= $provider['is_active'] ? 'success' : 'secondary' ?> status-badge">
                                                        <?= $provider['is_active'] ? 'Active' : 'Inactive' ?>
                                                    </span>
                                                    <?php if ($provider['admin_only']): ?>
                                                        <span class="badge bg-warning status-badge">Admin Only</span>
                                                    <?php endif; ?>
                                                    <?php if ($provider['require_2fa']): ?>
                                                        <span class="badge bg-info status-badge">2FA Required</span>
                                                    <?php endif; ?>
                                                </div>

                                                <div class="btn-group w-100" role="group">
                                                    <a href="?action=edit&id=<?= $provider['id'] ?>" class="btn btn-outline-primary btn-sm">
                                                        <i class="fas fa-edit"></i> Edit
                                                    </a>
                                                    <form method="POST" class="d-inline">
                                                        <input type="hidden" name="action" value="toggle_provider">
                                                        <input type="hidden" name="provider_id" value="<?= $provider['id'] ?>">
                                                        <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                                        <button type="submit" class="btn btn-outline-<?= $provider['is_active'] ? 'warning' : 'success' ?> btn-sm">
                                                            <i class="fas fa-power-off"></i> 
                                                            <?= $provider['is_active'] ? 'Disable' : 'Enable' ?>
                                                        </button>
                                                    </form>
                                                    <form method="POST" class="d-inline" onsubmit="return confirm('Are you sure you want to delete this provider?')">
                                                        <input type="hidden" name="action" value="delete_provider">
                                                        <input type="hidden" name="provider_id" value="<?= $provider['id'] ?>">
                                                        <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                                        <button type="submit" class="btn btn-outline-danger btn-sm">
                                                            <i class="fas fa-trash"></i> Delete
                                                        </button>
                                                    </form>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                    <?php endif; ?>

                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- Emergency Disable Modal -->
    <div class="modal fade" id="emergencyModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header emergency-controls">
                    <h5 class="modal-title text-white">
                        <i class="fas fa-exclamation-triangle me-2"></i>Emergency SSO Disable
                    </h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST">
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