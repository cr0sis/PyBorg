<?php
/**
 * SSO Setup Wizard
 * Guided setup for SSO providers and configuration
 * 
 * Security: Admin-only access with step-by-step validation
 */

require_once 'security_config.php';
require_once 'sso/SSOManager.php';

// Initialize security and require admin
initSecureSession();
setSecurityHeaders();
requireAdmin();

$current_step = $_GET['step'] ?? 'welcome';
$provider_type = $_GET['type'] ?? '';
$error = '';
$success = '';

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'Invalid CSRF token';
    } else {
        $action = $_POST['action'] ?? '';
        
        switch ($action) {
            case 'test_connection':
                $result = testProviderConnection($_POST);
                echo json_encode($result);
                exit;
                
            case 'save_provider':
                $result = saveProviderConfig($_POST);
                if ($result['success']) {
                    header('Location: ?step=complete&provider=' . $result['provider_id']);
                    exit;
                } else {
                    $error = $result['message'];
                }
                break;
        }
    }
}

/**
 * Test provider connection
 */
function testProviderConnection($data) {
    try {
        $type = $data['type'] ?? '';
        $sso_url = trim($data['sso_url'] ?? '');
        
        if (empty($sso_url)) {
            return ['success' => false, 'message' => 'SSO URL is required'];
        }
        
        // Basic connectivity test
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $sso_url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_USERAGENT => 'cr0bot-sso-wizard/1.0'
        ]);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            return ['success' => false, 'message' => "Connection failed: $error"];
        }
        
        if ($http_code >= 400) {
            return ['success' => false, 'message' => "HTTP error: $http_code"];
        }
        
        // Type-specific validation
        if ($type === 'saml') {
            // For SAML, check if response looks like metadata or SAML
            if (stripos($response, 'entitydescriptor') === false && stripos($response, 'saml') === false) {
                return ['success' => false, 'message' => 'URL does not appear to be a SAML endpoint'];
            }
        } elseif (in_array($type, ['oidc', 'oauth2'])) {
            // For OIDC, try to parse as JSON if it's a discovery endpoint
            if (stripos($sso_url, '.well-known') !== false) {
                $json = json_decode($response, true);
                if (!$json || !isset($json['authorization_endpoint'])) {
                    return ['success' => false, 'message' => 'Invalid OIDC discovery document'];
                }
            }
        }
        
        return ['success' => true, 'message' => 'Connection successful', 'http_code' => $http_code];
        
    } catch (Exception $e) {
        return ['success' => false, 'message' => 'Test failed: ' . $e->getMessage()];
    }
}

/**
 * Save provider configuration
 */
function saveProviderConfig($data) {
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
        
        // Encrypt sensitive data
        $client_secret = '';
        $private_key = '';
        if (!empty($data['client_secret'])) {
            $client_secret = CryptoUtils::encrypt(trim($data['client_secret']));
        }
        if (!empty($data['private_key'])) {
            $private_key = CryptoUtils::encrypt(trim($data['private_key']));
        }
        
        $stmt = $pdo->prepare("
            INSERT INTO sso_providers 
            (name, type, display_name, icon_url, sso_url, client_id, client_secret, 
             scope, x509_cert, private_key, auto_provision, require_2fa, admin_only)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        
        $stmt->execute([
            $name, $type, $display_name,
            trim($data['icon_url'] ?? ''),
            $sso_url,
            trim($data['client_id'] ?? ''),
            $client_secret,
            trim($data['scope'] ?? 'openid profile email'),
            trim($data['x509_cert'] ?? ''),
            $private_key,
            isset($data['auto_provision']) ? 1 : 0,
            isset($data['require_2fa']) ? 1 : 0,
            isset($data['admin_only']) ? 1 : 0
        ]);
        
        $provider_id = $pdo->lastInsertId();
        
        SSOManager::logSSOEvent('PROVIDER_CREATED', $provider_id, $_SESSION['user_id'],
            "SSO provider '$display_name' created via setup wizard", 'MEDIUM');
        
        return ['success' => true, 'message' => "Provider '$display_name' created successfully", 'provider_id' => $provider_id];
        
    } catch (Exception $e) {
        error_log("SSO wizard save error: " . $e->getMessage());
        return ['success' => false, 'message' => 'Failed to save provider: ' . $e->getMessage()];
    }
}

// Get existing providers for reference
$pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$stmt = $pdo->prepare("SELECT COUNT(*) FROM sso_providers WHERE is_active = 1");
$stmt->execute();
$existing_providers_count = $stmt->fetchColumn();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSO Setup Wizard - cr0bot</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .wizard-container {
            max-width: 800px;
            margin: 2rem auto;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        
        .wizard-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            text-align: center;
        }
        
        .wizard-content {
            padding: 2rem;
        }
        
        .step-indicator {
            display: flex;
            justify-content: center;
            margin-bottom: 2rem;
        }
        
        .step {
            display: flex;
            align-items: center;
            margin: 0 1rem;
        }
        
        .step-number {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: #e9ecef;
            color: #6c757d;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            margin-right: 0.5rem;
        }
        
        .step.active .step-number {
            background: #667eea;
            color: white;
        }
        
        .step.completed .step-number {
            background: #28a745;
            color: white;
        }
        
        .provider-card {
            border: 2px solid #e9ecef;
            border-radius: 15px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .provider-card:hover, .provider-card.selected {
            border-color: #667eea;
            background: #f8f9ff;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.2);
        }
        
        .provider-icon {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.5rem;
            margin-bottom: 1rem;
        }
        
        .form-floating > label {
            color: #6c757d;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            padding: 12px 30px;
            border-radius: 25px;
        }
        
        .btn-outline-primary {
            border-color: #667eea;
            color: #667eea;
            border-radius: 25px;
            padding: 12px 30px;
        }
        
        .connection-test {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 10px;
            padding: 1rem;
            margin: 1rem 0;
        }
        
        .test-result {
            padding: 0.5rem;
            border-radius: 5px;
            margin-top: 0.5rem;
        }
        
        .test-success {
            background: #d1edff;
            color: #0c5460;
            border: 1px solid #b6d7ff;
        }
        
        .test-error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
    </style>
</head>
<body>
    <div class="wizard-container">
        <div class="wizard-header">
            <h2><i class="fas fa-magic me-2"></i>SSO Setup Wizard</h2>
            <p class="mb-0">Configure Single Sign-On for your organization</p>
        </div>
        
        <div class="wizard-content">
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
            
            <!-- Step Indicator -->
            <div class="step-indicator">
                <div class="step <?= $current_step === 'welcome' ? 'active' : ($current_step !== 'welcome' ? 'completed' : '') ?>">
                    <div class="step-number">1</div>
                    <span>Welcome</span>
                </div>
                <div class="step <?= $current_step === 'provider_type' ? 'active' : (in_array($current_step, ['config', 'test', 'complete']) ? 'completed' : '') ?>">
                    <div class="step-number">2</div>
                    <span>Provider Type</span>
                </div>
                <div class="step <?= $current_step === 'config' ? 'active' : (in_array($current_step, ['test', 'complete']) ? 'completed' : '') ?>">
                    <div class="step-number">3</div>
                    <span>Configuration</span>
                </div>
                <div class="step <?= $current_step === 'test' ? 'active' : ($current_step === 'complete' ? 'completed' : '') ?>">
                    <div class="step-number">4</div>
                    <span>Test</span>
                </div>
                <div class="step <?= $current_step === 'complete' ? 'active' : '' ?>">
                    <div class="step-number">5</div>
                    <span>Complete</span>
                </div>
            </div>
            
            <?php if ($current_step === 'welcome'): ?>
                <!-- Welcome Step -->
                <div class="text-center">
                    <i class="fas fa-shield-alt fa-4x text-primary mb-4"></i>
                    <h3>Welcome to SSO Setup</h3>
                    <p class="lead text-muted mb-4">
                        This wizard will guide you through setting up Single Sign-On (SSO) for your organization.
                        You can configure SAML 2.0, OpenID Connect, or OAuth 2.0 providers.
                    </p>
                    
                    <?php if ($existing_providers_count > 0): ?>
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle me-2"></i>
                            You currently have <?= $existing_providers_count ?> SSO provider(s) configured.
                            This wizard will add a new provider.
                        </div>
                    <?php endif; ?>
                    
                    <div class="d-flex justify-content-center gap-3 mt-4">
                        <a href="?step=provider_type" class="btn btn-primary btn-lg">
                            <i class="fas fa-arrow-right me-2"></i>
                            Start Setup
                        </a>
                        <a href="/admin_sso.php" class="btn btn-outline-secondary btn-lg">
                            <i class="fas fa-arrow-left me-2"></i>
                            Back to Admin
                        </a>
                    </div>
                </div>
                
            <?php elseif ($current_step === 'provider_type'): ?>
                <!-- Provider Type Selection -->
                <h3>Choose Provider Type</h3>
                <p class="text-muted mb-4">Select the type of SSO provider you want to configure:</p>
                
                <div class="row">
                    <div class="col-md-4">
                        <div class="provider-card" onclick="selectProviderType('saml')">
                            <div class="provider-icon">
                                <i class="fas fa-certificate"></i>
                            </div>
                            <h5>SAML 2.0</h5>
                            <p class="text-muted small mb-0">
                                Security Assertion Markup Language. Works with Active Directory, 
                                Azure AD, Okta, OneLogin, and other enterprise identity providers.
                            </p>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="provider-card" onclick="selectProviderType('oidc')">
                            <div class="provider-icon">
                                <i class="fas fa-id-card"></i>
                            </div>
                            <h5>OpenID Connect</h5>
                            <p class="text-muted small mb-0">
                                Modern identity layer on OAuth 2.0. Works with Google, Microsoft, 
                                Auth0, and other OIDC-compliant providers.
                            </p>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="provider-card" onclick="selectProviderType('oauth2')">
                            <div class="provider-icon">
                                <i class="fas fa-key"></i>
                            </div>
                            <h5>OAuth 2.0</h5>
                            <p class="text-muted small mb-0">
                                Authorization framework. Works with GitHub, GitLab, 
                                and other OAuth 2.0 providers.
                            </p>
                        </div>
                    </div>
                </div>
                
                <div class="d-flex justify-content-between mt-4">
                    <a href="?step=welcome" class="btn btn-outline-secondary">
                        <i class="fas fa-arrow-left me-2"></i>
                        Back
                    </a>
                </div>
                
            <?php elseif ($current_step === 'config' && !empty($provider_type)): ?>
                <!-- Configuration Step -->
                <h3>Configure <?= strtoupper($provider_type) ?> Provider</h3>
                <p class="text-muted mb-4">Enter the configuration details for your SSO provider:</p>
                
                <form method="POST" id="config-form">
                    <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                    <input type="hidden" name="type" value="<?= htmlspecialchars($provider_type) ?>">
                    
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <div class="form-floating">
                                <input type="text" class="form-control" id="name" name="name" required>
                                <label for="name">Internal Name *</label>
                                <div class="form-text">Unique identifier (lowercase, no spaces)</div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-floating">
                                <input type="text" class="form-control" id="display_name" name="display_name" required>
                                <label for="display_name">Display Name *</label>
                                <div class="form-text">Name shown to users</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <div class="form-floating">
                            <input type="url" class="form-control" id="sso_url" name="sso_url" required>
                            <label for="sso_url">
                                <?php if ($provider_type === 'saml'): ?>
                                    SSO URL / Single Sign-On Service *
                                <?php else: ?>
                                    Authorization Endpoint URL *
                                <?php endif; ?>
                            </label>
                            <div class="form-text">
                                <?php if ($provider_type === 'saml'): ?>
                                    The SAML SSO endpoint URL from your identity provider
                                <?php else: ?>
                                    The OAuth/OIDC authorization endpoint URL
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                    
                    <?php if ($provider_type === 'oidc' || $provider_type === 'oauth2'): ?>
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <div class="form-floating">
                                    <input type="text" class="form-control" id="client_id" name="client_id" required>
                                    <label for="client_id">Client ID *</label>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-floating">
                                    <input type="password" class="form-control" id="client_secret" name="client_secret">
                                    <label for="client_secret">Client Secret</label>
                                </div>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <div class="form-floating">
                                <input type="text" class="form-control" id="scope" name="scope" value="openid profile email">
                                <label for="scope">Scope</label>
                                <div class="form-text">Requested permissions (space-separated)</div>
                            </div>
                        </div>
                    <?php endif; ?>
                    
                    <?php if ($provider_type === 'saml'): ?>
                        <div class="mb-3">
                            <label for="x509_cert" class="form-label">X.509 Certificate</label>
                            <textarea class="form-control" id="x509_cert" name="x509_cert" rows="6" 
                                      placeholder="-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END CERTIFICATE-----"></textarea>
                            <div class="form-text">Identity provider's public certificate for signature validation</div>
                        </div>
                    <?php endif; ?>
                    
                    <div class="mb-3">
                        <div class="form-floating">
                            <input type="url" class="form-control" id="icon_url" name="icon_url">
                            <label for="icon_url">Icon URL</label>
                            <div class="form-text">Optional icon to display on login button</div>
                        </div>
                    </div>
                    
                    <div class="row mb-4">
                        <div class="col-md-4">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="auto_provision" name="auto_provision" checked>
                                <label class="form-check-label" for="auto_provision">
                                    Auto-provision users
                                </label>
                                <div class="form-text small">Automatically create accounts for new SSO users</div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="require_2fa" name="require_2fa">
                                <label class="form-check-label" for="require_2fa">
                                    Require 2FA
                                </label>
                                <div class="form-text small">Require additional 2FA after SSO login</div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="admin_only" name="admin_only">
                                <label class="form-check-label" for="admin_only">
                                    Admin users only
                                </label>
                                <div class="form-text small">Restrict to admin users only</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="d-flex justify-content-between">
                        <a href="?step=provider_type" class="btn btn-outline-secondary">
                            <i class="fas fa-arrow-left me-2"></i>
                            Back
                        </a>
                        <button type="button" class="btn btn-primary" onclick="nextStep()">
                            Test Configuration
                            <i class="fas fa-arrow-right ms-2"></i>
                        </button>
                    </div>
                </form>
                
            <?php elseif ($current_step === 'complete'): ?>
                <!-- Complete Step -->
                <div class="text-center">
                    <i class="fas fa-check-circle fa-4x text-success mb-4"></i>
                    <h3>SSO Provider Configured!</h3>
                    <p class="lead text-muted mb-4">
                        Your SSO provider has been successfully configured and is ready for use.
                    </p>
                    
                    <div class="alert alert-info">
                        <h6><i class="fas fa-info-circle me-2"></i>Next Steps:</h6>
                        <ul class="list-unstyled mb-0">
                            <li>• Users can now see the SSO option on the login page</li>
                            <li>• Test the SSO login flow with a test user</li>
                            <li>• Monitor SSO activity in the security dashboard</li>
                            <li>• Configure additional providers if needed</li>
                        </ul>
                    </div>
                    
                    <div class="d-flex justify-content-center gap-3 mt-4">
                        <a href="/admin_sso.php" class="btn btn-primary btn-lg">
                            <i class="fas fa-cog me-2"></i>
                            Manage Providers
                        </a>
                        <a href="/sso_security_monitor.php" class="btn btn-outline-primary btn-lg">
                            <i class="fas fa-chart-line me-2"></i>
                            Security Monitor
                        </a>
                        <a href="?step=welcome" class="btn btn-outline-secondary btn-lg">
                            <i class="fas fa-plus me-2"></i>
                            Add Another
                        </a>
                    </div>
                </div>
                
            <?php else: ?>
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    Invalid step or missing provider type.
                    <a href="?step=welcome">Start over</a>
                </div>
            <?php endif; ?>
        </div>
    </div>
    
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    <script>
        function selectProviderType(type) {
            window.location.href = '?step=config&type=' + type;
        }
        
        function nextStep() {
            // Validate form first
            const form = document.getElementById('config-form');
            if (!form.checkValidity()) {
                form.reportValidity();
                return;
            }
            
            // Show test step
            window.location.href = '?step=test&type=<?= htmlspecialchars($provider_type) ?>';
        }
        
        // Auto-generate internal name from display name
        document.getElementById('display_name')?.addEventListener('input', function() {
            const nameField = document.getElementById('name');
            if (!nameField.value) {
                nameField.value = this.value.toLowerCase()
                    .replace(/[^a-z0-9]/g, '_')
                    .replace(/_+/g, '_')
                    .replace(/^_|_$/g, '');
            }
        });
    </script>
</body>
</html>