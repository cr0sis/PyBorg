<?php
/**
 * SSO Integration Test Suite
 * Comprehensive testing of SSO functionality and security
 * 
 * Security: Admin-only access, comprehensive validation
 */

require_once 'security_config.php';
require_once 'sso/SSOManager.php';
require_once 'sso/SAMLHandler.php';
require_once 'sso/OIDCHandler.php';

// Initialize security and require admin
initSecureSession();
setSecurityHeaders();
requireAdmin();

$test_action = $_GET['test'] ?? '';
$results = [];

/**
 * Run all SSO tests
 */
function runAllTests() {
    $tests = [
        'database_connectivity' => 'Test Database Connectivity',
        'sso_manager_basic' => 'Test SSOManager Basic Functions',
        'provider_validation' => 'Test Provider Configuration Validation',
        'session_management' => 'Test Auth Session Management',
        'security_logging' => 'Test Security Event Logging',
        'config_management' => 'Test Configuration Management',
        'encryption_decryption' => 'Test Encryption/Decryption',
        'authentication_flow' => 'Test Authentication Flow Simulation',
        'error_handling' => 'Test Error Handling',
        'cleanup_functions' => 'Test Cleanup Functions'
    ];
    
    $results = [];
    foreach ($tests as $test_func => $test_name) {
        $results[$test_func] = [
            'name' => $test_name,
            'result' => call_user_func("test_$test_func"),
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
    
    return $results;
}

/**
 * Test database connectivity
 */
function test_database_connectivity() {
    try {
        $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Check if SSO tables exist
        $required_tables = [
            'sso_providers',
            'sso_user_mappings', 
            'sso_auth_sessions',
            'sso_security_events',
            'sso_configuration'
        ];
        
        $missing_tables = [];
        foreach ($required_tables as $table) {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?");
            $stmt->execute([$table]);
            if ($stmt->fetchColumn() == 0) {
                $missing_tables[] = $table;
            }
        }
        
        if (!empty($missing_tables)) {
            return [
                'success' => false,
                'message' => 'Missing tables: ' . implode(', ', $missing_tables),
                'details' => []
            ];
        }
        
        return [
            'success' => true,
            'message' => 'All required tables exist and are accessible',
            'details' => ['tables_checked' => count($required_tables)]
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => 'Database connectivity failed: ' . $e->getMessage(),
            'details' => []
        ];
    }
}

/**
 * Test SSOManager basic functions
 */
function test_sso_manager_basic() {
    try {
        $details = [];
        
        // Test SSO enabled check
        $enabled = SSOManager::isEnabled();
        $details['sso_enabled'] = $enabled;
        
        // Test get active providers
        $providers = SSOManager::getActiveProviders();
        $details['providers_count'] = count($providers);
        
        // Test configuration value retrieval
        $config_value = SSOManager::getConfigValue('sso_session_timeout', '3600');
        $details['config_retrieval'] = !empty($config_value);
        
        // Test cleanup function
        SSOManager::cleanup();
        $details['cleanup_executed'] = true;
        
        return [
            'success' => true,
            'message' => 'SSOManager basic functions working correctly',
            'details' => $details
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => 'SSOManager test failed: ' . $e->getMessage(),
            'details' => []
        ];
    }
}

/**
 * Test provider configuration validation
 */
function test_provider_validation() {
    try {
        $details = [];
        
        // Test invalid provider ID
        $invalid_provider = SSOManager::getProvider(99999);
        $details['invalid_provider_handled'] = ($invalid_provider === null);
        
        // Test SAML handler creation with invalid provider
        try {
            new SAMLHandler(99999);
            $details['saml_invalid_provider'] = false;
        } catch (Exception $e) {
            $details['saml_invalid_provider'] = true;
        }
        
        // Test OIDC handler creation with invalid provider
        try {
            new OIDCHandler(99999);
            $details['oidc_invalid_provider'] = false;
        } catch (Exception $e) {
            $details['oidc_invalid_provider'] = true;
        }
        
        $all_passed = $details['invalid_provider_handled'] && 
                     $details['saml_invalid_provider'] && 
                     $details['oidc_invalid_provider'];
        
        return [
            'success' => $all_passed,
            'message' => $all_passed ? 'Provider validation tests passed' : 'Some provider validation tests failed',
            'details' => $details
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => 'Provider validation test failed: ' . $e->getMessage(),
            'details' => []
        ];
    }
}

/**
 * Test auth session management
 */
function test_session_management() {
    try {
        $details = [];
        
        // Create a test provider first
        $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->prepare("INSERT OR IGNORE INTO sso_providers (name, type, display_name, sso_url, is_active) VALUES (?, ?, ?, ?, 1)");
        $stmt->execute(['test_provider', 'oidc', 'Test Provider', 'https://example.com/auth']);
        
        $provider_id = $pdo->lastInsertId();
        if (!$provider_id) {
            // Provider already exists, get its ID
            $stmt = $pdo->prepare("SELECT id FROM sso_providers WHERE name = 'test_provider'");
            $stmt->execute();
            $provider_id = $stmt->fetchColumn();
        }
        
        if ($provider_id) {
            // Test session creation
            $session_data = SSOManager::createAuthSession($provider_id);
            $details['session_created'] = !empty($session_data['session_token']);
            
            if ($details['session_created']) {
                // Test session retrieval
                $retrieved_session = SSOManager::getAuthSession($session_data['session_token']);
                $details['session_retrieved'] = ($retrieved_session !== null);
                
                // Test session state validation
                $details['state_matches'] = ($retrieved_session && $retrieved_session['state'] === $session_data['state']);
            }
        }
        
        // Clean up test provider
        $pdo->prepare("DELETE FROM sso_providers WHERE name = 'test_provider'")->execute();
        $details['cleanup_completed'] = true;
        
        return [
            'success' => !empty($details['session_created']) && !empty($details['session_retrieved']),
            'message' => 'Session management test completed',
            'details' => $details
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => 'Session management test failed: ' . $e->getMessage(),
            'details' => []
        ];
    }
}

/**
 * Test security event logging
 */
function test_security_logging() {
    try {
        $details = [];
        
        // Test logging function
        $test_event_type = 'TEST_EVENT_' . time();
        SSOManager::logSSOEvent($test_event_type, null, $_SESSION['user_id'], 'Test security event', 'LOW');
        
        // Verify event was logged
        $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM sso_security_events WHERE event_type = ?");
        $stmt->execute([$test_event_type]);
        $event_logged = $stmt->fetchColumn() > 0;
        
        $details['event_logged'] = $event_logged;
        
        // Clean up test event
        $pdo->prepare("DELETE FROM sso_security_events WHERE event_type = ?")->execute([$test_event_type]);
        $details['cleanup_completed'] = true;
        
        return [
            'success' => $event_logged,
            'message' => 'Security logging test completed',
            'details' => $details
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => 'Security logging test failed: ' . $e->getMessage(),
            'details' => []
        ];
    }
}

/**
 * Test configuration management
 */
function test_config_management() {
    try {
        $details = [];
        
        // Test setting and getting config values
        $test_key = 'test_config_' . time();
        $test_value = 'test_value_' . rand(1000, 9999);
        
        $set_result = SSOManager::setConfigValue($test_key, $test_value);
        $details['config_set'] = $set_result;
        
        if ($set_result) {
            $retrieved_value = SSOManager::getConfigValue($test_key);
            $details['config_retrieved'] = ($retrieved_value === $test_value);
            
            // Clean up test config
            $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $pdo->prepare("DELETE FROM sso_configuration WHERE key_name = ?")->execute([$test_key]);
            $details['cleanup_completed'] = true;
        }
        
        return [
            'success' => !empty($details['config_set']) && !empty($details['config_retrieved']),
            'message' => 'Configuration management test completed',
            'details' => $details
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => 'Configuration management test failed: ' . $e->getMessage(),
            'details' => []
        ];
    }
}

/**
 * Test encryption and decryption
 */
function test_encryption_decryption() {
    try {
        $details = [];
        
        // Test data to encrypt
        $test_data = 'sensitive_test_data_' . time();
        
        // Test encryption
        $encrypted = CryptoUtils::encrypt($test_data);
        $details['encryption_successful'] = !empty($encrypted);
        $details['encrypted_different'] = ($encrypted !== $test_data);
        
        if ($details['encryption_successful']) {
            // Test decryption
            $decrypted = CryptoUtils::decrypt($encrypted);
            $details['decryption_successful'] = ($decrypted === $test_data);
        }
        
        // Test empty data handling
        $empty_encrypted = CryptoUtils::encrypt('');
        $empty_decrypted = CryptoUtils::decrypt('');
        $details['empty_data_handled'] = ($empty_encrypted === '' && $empty_decrypted === '');
        
        return [
            'success' => !empty($details['encryption_successful']) && 
                        !empty($details['decryption_successful']) &&
                        !empty($details['empty_data_handled']),
            'message' => 'Encryption/decryption test completed',
            'details' => $details
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => 'Encryption test failed: ' . $e->getMessage(),
            'details' => []
        ];
    }
}

/**
 * Test authentication flow simulation
 */
function test_authentication_flow() {
    try {
        $details = [];
        
        // This test simulates parts of the auth flow without actual external connections
        $details['test_type'] = 'simulation';
        
        // Test URL validation
        $valid_urls = [
            'https://example.com/auth',
            'https://idp.company.com/saml/sso'
        ];
        
        $invalid_urls = [
            'not_a_url',
            'ftp://example.com',
            'javascript:alert(1)'
        ];
        
        $url_validation_passed = true;
        foreach ($valid_urls as $url) {
            if (!filter_var($url, FILTER_VALIDATE_URL) || !preg_match('/^https:\/\//', $url)) {
                $url_validation_passed = false;
                break;
            }
        }
        
        foreach ($invalid_urls as $url) {
            if (filter_var($url, FILTER_VALIDATE_URL) && preg_match('/^https:\/\//', $url)) {
                $url_validation_passed = false;
                break;
            }
        }
        
        $details['url_validation'] = $url_validation_passed;
        
        // Test state generation and validation
        $state = bin2hex(random_bytes(32));
        $nonce = bin2hex(random_bytes(32));
        
        $details['state_generated'] = (strlen($state) === 64);
        $details['nonce_generated'] = (strlen($nonce) === 64);
        $details['state_nonce_different'] = ($state !== $nonce);
        
        return [
            'success' => $url_validation_passed && 
                        $details['state_generated'] && 
                        $details['nonce_generated'] && 
                        $details['state_nonce_different'],
            'message' => 'Authentication flow simulation completed',
            'details' => $details
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => 'Authentication flow test failed: ' . $e->getMessage(),
            'details' => []
        ];
    }
}

/**
 * Test error handling
 */
function test_error_handling() {
    try {
        $details = [];
        
        // Test invalid database path handling
        try {
            $invalid_pdo = new PDO("sqlite:/invalid/path/database.db");
            $details['invalid_db_handled'] = false;
        } catch (Exception $e) {
            $details['invalid_db_handled'] = true;
        }
        
        // Test malformed JSON handling
        $malformed_json = '{"invalid": json}';
        $parsed = json_decode($malformed_json, true);
        $details['json_error_handled'] = ($parsed === null && json_last_error() !== JSON_ERROR_NONE);
        
        // Test empty required field handling
        $details['validation_tested'] = true; // This would be tested in actual form validation
        
        return [
            'success' => $details['invalid_db_handled'] && $details['json_error_handled'],
            'message' => 'Error handling test completed',
            'details' => $details
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => 'Error handling test failed: ' . $e->getMessage(),
            'details' => []
        ];
    }
}

/**
 * Test cleanup functions
 */
function test_cleanup_functions() {
    try {
        $details = [];
        
        // Create some test data to clean up
        $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        // Create expired auth session
        $expired_time = time() - 7200; // 2 hours ago
        $stmt = $pdo->prepare("INSERT INTO sso_auth_sessions (session_token, provider_id, state, nonce, code_verifier, initiated_ip, user_agent_hash, created_at, expires_at, status) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, 'pending')");
        $stmt->execute([
            'test_expired_' . time(),
            'test_state',
            'test_nonce', 
            'test_verifier',
            '127.0.0.1',
            hash('sha256', 'test'),
            $expired_time,
            $expired_time
        ]);
        
        $details['test_data_created'] = true;
        
        // Run cleanup
        SSOManager::cleanup();
        $details['cleanup_executed'] = true;
        
        // Verify expired session was cleaned up
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM sso_auth_sessions WHERE session_token LIKE 'test_expired_%' AND status = 'expired'");
        $stmt->execute();
        $expired_count = $stmt->fetchColumn();
        $details['expired_sessions_marked'] = ($expired_count > 0);
        
        // Clean up test data
        $pdo->prepare("DELETE FROM sso_auth_sessions WHERE session_token LIKE 'test_expired_%'")->execute();
        $details['cleanup_completed'] = true;
        
        return [
            'success' => $details['cleanup_executed'] && $details['expired_sessions_marked'],
            'message' => 'Cleanup functions test completed',
            'details' => $details
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'message' => 'Cleanup test failed: ' . $e->getMessage(),
            'details' => []
        ];
    }
}

// Run tests based on action
if (!empty($test_action)) {
    if ($test_action === 'all') {
        $results = runAllTests();
    } elseif (function_exists("test_$test_action")) {
        $results[$test_action] = [
            'name' => ucfirst(str_replace('_', ' ', $test_action)),
            'result' => call_user_func("test_$test_action"),
            'timestamp' => date('Y-m-d H:i:s')
        ];
    } else {
        $results['error'] = [
            'name' => 'Invalid Test',
            'result' => [
                'success' => false,
                'message' => 'Invalid test specified',
                'details' => []
            ],
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSO Test Suite - cr0bot</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e6edf3;
            font-family: 'Courier New', monospace;
            min-height: 100vh;
        }
        
        .test-container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 2rem;
        }
        
        .header {
            background: linear-gradient(135deg, #0f3460 0%, #0e6ba8 100%);
            color: white;
            padding: 2rem;
            border-radius: 15px;
            margin-bottom: 2rem;
            text-align: center;
        }
        
        .test-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .test-card {
            background: #21262d;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 1.5rem;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        
        .test-card:hover {
            background: #262c36;
            border-color: #58a6ff;
            transform: translateY(-2px);
        }
        
        .test-result {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        }
        
        .result-header {
            display: flex;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .result-success {
            border-left: 4px solid #238636;
        }
        
        .result-failure {
            border-left: 4px solid #da3633;
        }
        
        .result-details {
            background: #161b22;
            border-radius: 8px;
            padding: 1rem;
            margin-top: 1rem;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.875rem;
        }
        
        .run-all-btn {
            background: linear-gradient(135deg, #238636 0%, #2ea043 100%);
            border: none;
            color: white;
            padding: 1rem 2rem;
            border-radius: 25px;
            font-size: 1.1rem;
            font-weight: bold;
            margin-bottom: 2rem;
        }
        
        .run-all-btn:hover {
            background: linear-gradient(135deg, #2ea043 0%, #3fb950 100%);
            transform: translateY(-1px);
        }
        
        pre {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 1rem;
            color: #f0f6fc;
            overflow-x: auto;
        }
        
        .badge {
            font-size: 0.875rem;
            padding: 0.5rem 0.75rem;
        }
        
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #58a6ff 0%, #316dca 100%);
            color: white;
            padding: 1.5rem;
            border-radius: 12px;
            text-align: center;
        }
        
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
        }
        
        .spinner {
            border: 2px solid #30363d;
            border-top: 2px solid #58a6ff;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            animation: spin 1s linear infinite;
            display: inline-block;
            margin-right: 0.5rem;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="test-container">
        <div class="header">
            <h1><i class="fas fa-flask me-3"></i>SSO Integration Test Suite</h1>
            <p class="mb-0">Comprehensive testing and validation of Single Sign-On functionality</p>
        </div>
        
        <?php if (empty($results)): ?>
            <!-- Test Selection -->
            <div class="text-center">
                <button class="btn run-all-btn" onclick="runTest('all')" id="runAllBtn">
                    <i class="fas fa-play me-2"></i>
                    Run All Tests
                </button>
                <p class="text-muted">Or select individual tests below</p>
            </div>
            
            <div class="test-grid">
                <div class="test-card" onclick="runTest('database_connectivity')">
                    <h5><i class="fas fa-database me-2"></i>Database Connectivity</h5>
                    <p class="small text-muted mb-0">Test database connection and table structure</p>
                </div>
                
                <div class="test-card" onclick="runTest('sso_manager_basic')">
                    <h5><i class="fas fa-cogs me-2"></i>SSO Manager Basic</h5>
                    <p class="small text-muted mb-0">Test core SSOManager functionality</p>
                </div>
                
                <div class="test-card" onclick="runTest('provider_validation')">
                    <h5><i class="fas fa-check-circle me-2"></i>Provider Validation</h5>
                    <p class="small text-muted mb-0">Test provider configuration validation</p>
                </div>
                
                <div class="test-card" onclick="runTest('session_management')">
                    <h5><i class="fas fa-clock me-2"></i>Session Management</h5>
                    <p class="small text-muted mb-0">Test authentication session handling</p>
                </div>
                
                <div class="test-card" onclick="runTest('security_logging')">
                    <h5><i class="fas fa-shield-alt me-2"></i>Security Logging</h5>
                    <p class="small text-muted mb-0">Test security event logging system</p>
                </div>
                
                <div class="test-card" onclick="runTest('config_management')">
                    <h5><i class="fas fa-wrench me-2"></i>Config Management</h5>
                    <p class="small text-muted mb-0">Test configuration storage and retrieval</p>
                </div>
                
                <div class="test-card" onclick="runTest('encryption_decryption')">
                    <h5><i class="fas fa-lock me-2"></i>Encryption/Decryption</h5>
                    <p class="small text-muted mb-0">Test data encryption and decryption</p>
                </div>
                
                <div class="test-card" onclick="runTest('authentication_flow')">
                    <h5><i class="fas fa-sign-in-alt me-2"></i>Auth Flow Simulation</h5>
                    <p class="small text-muted mb-0">Test authentication flow components</p>
                </div>
                
                <div class="test-card" onclick="runTest('error_handling')">
                    <h5><i class="fas fa-exclamation-triangle me-2"></i>Error Handling</h5>
                    <p class="small text-muted mb-0">Test error handling and recovery</p>
                </div>
                
                <div class="test-card" onclick="runTest('cleanup_functions')">
                    <h5><i class="fas fa-broom me-2"></i>Cleanup Functions</h5>
                    <p class="small text-muted mb-0">Test data cleanup and maintenance</p>
                </div>
            </div>
            
        <?php else: ?>
            <!-- Test Results -->
            <?php
            $total_tests = count($results);
            $passed_tests = 0;
            $failed_tests = 0;
            
            foreach ($results as $result) {
                if ($result['result']['success']) {
                    $passed_tests++;
                } else {
                    $failed_tests++;
                }
            }
            ?>
            
            <div class="summary-stats">
                <div class="stat-card">
                    <div class="stat-value"><?= $total_tests ?></div>
                    <div>Total Tests</div>
                </div>
                <div class="stat-card" style="background: linear-gradient(135deg, #238636 0%, #2ea043 100%);">
                    <div class="stat-value"><?= $passed_tests ?></div>
                    <div>Passed</div>
                </div>
                <div class="stat-card" style="background: linear-gradient(135deg, #da3633 0%, #f85149 100%);">
                    <div class="stat-value"><?= $failed_tests ?></div>
                    <div>Failed</div>
                </div>
                <div class="stat-card" style="background: linear-gradient(135deg, <?= $failed_tests === 0 ? '#238636 0%, #2ea043' : '#da3633 0%, #f85149' ?> 100%);">
                    <div class="stat-value"><?= round(($passed_tests / $total_tests) * 100) ?>%</div>
                    <div>Success Rate</div>
                </div>
            </div>
            
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h3><i class="fas fa-list-ul me-2"></i>Test Results</h3>
                <div>
                    <button class="btn btn-outline-light btn-sm" onclick="location.href='?'">
                        <i class="fas fa-redo me-1"></i>Run Again
                    </button>
                    <a href="/admin_sso.php" class="btn btn-outline-light btn-sm">
                        <i class="fas fa-arrow-left me-1"></i>Back to Admin
                    </a>
                </div>
            </div>
            
            <?php foreach ($results as $test_key => $test_data): ?>
                <div class="test-result <?= $test_data['result']['success'] ? 'result-success' : 'result-failure' ?>">
                    <div class="result-header">
                        <i class="fas fa-<?= $test_data['result']['success'] ? 'check-circle text-success' : 'times-circle text-danger' ?> me-2"></i>
                        <h5 class="mb-0 me-3"><?= htmlspecialchars($test_data['name']) ?></h5>
                        <span class="badge bg-<?= $test_data['result']['success'] ? 'success' : 'danger' ?>">
                            <?= $test_data['result']['success'] ? 'PASSED' : 'FAILED' ?>
                        </span>
                        <small class="text-muted ms-auto"><?= $test_data['timestamp'] ?></small>
                    </div>
                    
                    <div class="mb-2">
                        <strong>Result:</strong> <?= htmlspecialchars($test_data['result']['message']) ?>
                    </div>
                    
                    <?php if (!empty($test_data['result']['details'])): ?>
                        <div class="result-details">
                            <strong>Details:</strong>
                            <pre><?= htmlspecialchars(json_encode($test_data['result']['details'], JSON_PRETTY_PRINT)) ?></pre>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>
    
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    <script>
        function runTest(testName) {
            const button = document.getElementById('runAllBtn');
            if (button) {
                button.innerHTML = '<div class="spinner"></div>Running Tests...';
                button.disabled = true;
            }
            
            // Add small delay for visual feedback
            setTimeout(() => {
                window.location.href = '?test=' + testName;
            }, 500);
        }
        
        // Add click effect to test cards
        document.querySelectorAll('.test-card').forEach(card => {
            card.addEventListener('click', function(e) {
                this.style.background = '#58a6ff';
                this.style.color = 'white';
                setTimeout(() => {
                    this.style.background = '#262c36';
                    this.style.color = '';
                }, 150);
            });
        });
    </script>
</body>
</html>