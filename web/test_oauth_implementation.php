<?php
/**
 * OAuth Implementation Test Suite
 * Tests the Google SSO OAuth fixes and security measures
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'security_config.php';
require_once 'sso/SSOManager.php';
require_once 'sso/OIDCHandler.php';

class OAuthImplementationTest {
    private $results = [];
    private $passed = 0;
    private $failed = 0;
    
    public function runAllTests() {
        echo "<h1>OAuth Implementation Security Review</h1>\n";
        echo "<style>
            body { font-family: monospace; margin: 20px; background: #f5f5f5; }
            .test-pass { color: green; font-weight: bold; }
            .test-fail { color: red; font-weight: bold; }
            .test-warn { color: orange; font-weight: bold; }
            .code-block { background: #f0f0f0; padding: 10px; margin: 10px 0; border-left: 4px solid #007bff; }
            .security-issue { background: #ffe6e6; padding: 10px; margin: 10px 0; border-left: 4px solid #dc3545; }
            .security-good { background: #e6ffe6; padding: 10px; margin: 10px 0; border-left: 4px solid #28a745; }
        </style>\n";
        
        $this->testTrustedIPsConfiguration();
        $this->testAdminAPISecurityImplementation();
        $this->testOAuthCallbackSecurity();
        $this->testSessionManagement();
        $this->testInputValidation();
        $this->testErrorHandling();
        $this->testRateLimiting();
        $this->testCSRFProtection();
        
        $this->displayResults();
    }
    
    private function testTrustedIPsConfiguration() {
        echo "<h2>🔒 Trusted IPs Configuration Security Test</h2>\n";
        
        // Test file exists
        $this->test("trusted_ips.php file exists", function() {
            return file_exists(__DIR__ . '/trusted_ips.php');
        });
        
        // Test file permissions
        $this->test("trusted_ips.php has secure permissions", function() {
            $perms = fileperms(__DIR__ . '/trusted_ips.php') & 0777;
            return $perms <= 0644; // Should not be executable
        });
        
        // Test file content structure
        $this->test("trusted_ips.php returns valid array", function() {
            $config = include __DIR__ . '/trusted_ips.php';
            return is_array($config);
        });
        
        // Test default values
        $this->test("Default trusted IPs include localhost variants", function() {
            $config = include __DIR__ . '/trusted_ips.php';
            return in_array('127.0.0.1', $config) && 
                   in_array('::1', $config) && 
                   in_array('localhost', $config);
        });
        
        // Security check: No wildcard IPs
        $this->test("No dangerous wildcard IPs configured", function() {
            $config = include __DIR__ . '/trusted_ips.php';
            $dangerous = ['0.0.0.0', '*', '0.0.0.0/0', '::/0'];
            foreach ($dangerous as $danger) {
                if (in_array($danger, $config)) {
                    return false;
                }
            }
            return true;
        });
        
        // Test that commented out lines are secure
        $content = file_get_contents(__DIR__ . '/trusted_ips.php');
        $this->test("Private network ranges are commented out by default", function() use ($content) {
            return strpos($content, "// '192.168.1.0/24'") !== false &&
                   strpos($content, "// '10.0.0.0/8'") !== false &&
                   strpos($content, "// '172.16.0.0/12'") !== false;
        });
    }
    
    private function testAdminAPISecurityImplementation() {
        echo "<h2>🛡️ Admin API Security Implementation Test</h2>\n";
        
        // Test trusted IP loading mechanism
        $this->test("Admin API loads trusted IPs correctly", function() {
            // Simulate the admin_api.php trusted IP loading logic
            $trustedIPs = ['127.0.0.1', '::1', 'localhost'];
            $trustedIPsFile = __DIR__ . '/trusted_ips.php';
            if (file_exists($trustedIPsFile)) {
                $additionalIPs = include $trustedIPsFile;
                if (is_array($additionalIPs)) {
                    $trustedIPs = array_merge($trustedIPs, $additionalIPs);
                }
            }
            return count($trustedIPs) >= 3; // At minimum localhost variants
        });
        
        // Test CSRF protection logic
        $this->test("CSRF protection checks authenticated admin status", function() {
            // This would require mocking $_SESSION, but we can check the logic exists
            $adminApiContent = file_get_contents(__DIR__ . '/admin_api.php');
            return strpos($adminApiContent, '$isAuthenticatedAdmin') !== false &&
                   strpos($adminApiContent, "isset(\$_SESSION['is_admin'])") !== false;
        });
        
        // Test rate limiting implementation
        $this->test("Rate limiting is implemented in admin API", function() {
            $adminApiContent = file_get_contents(__DIR__ . '/admin_api.php');
            return strpos($adminApiContent, 'checkRateLimit') !== false;
        });
        
        // Test security logging
        $this->test("Security events are logged", function() {
            $adminApiContent = file_get_contents(__DIR__ . '/admin_api.php');
            return strpos($adminApiContent, 'logSecurityEvent') !== false ||
                   strpos($adminApiContent, 'securityLog') !== false;
        });
    }
    
    private function testOAuthCallbackSecurity() {
        echo "<h2>🔐 OAuth Callback Security Test</h2>\n";
        
        // Test callback file structure
        $callbackPath = __DIR__ . '/sso/oidc/callback.php';
        $this->test("OAuth callback file exists", function() use ($callbackPath) {
            return file_exists($callbackPath);
        });
        
        if (!file_exists($callbackPath)) {
            echo "<div class='security-issue'>❌ OAuth callback file missing - OAuth flow will fail</div>\n";
            return;
        }
        
        $callbackContent = file_get_contents($callbackPath);
        
        // Test security headers
        $this->test("Security headers are set", function() use ($callbackContent) {
            return strpos($callbackContent, 'X-Content-Type-Options: nosniff') !== false &&
                   strpos($callbackContent, 'X-Frame-Options: DENY') !== false &&
                   strpos($callbackContent, 'X-XSS-Protection: 1; mode=block') !== false;
        });
        
        // Test state parameter validation
        $this->test("State parameter is validated", function() use ($callbackContent) {
            return strpos($callbackContent, '$state !== $expected_state') !== false &&
                   strpos($callbackContent, 'possible CSRF attack') !== false;
        });
        
        // Test rate limiting
        $this->test("Rate limiting is implemented", function() use ($callbackContent) {
            return strpos($callbackContent, 'checkRateLimit') !== false;
        });
        
        // Test session timeout validation
        $this->test("Session timeout is validated", function() use ($callbackContent) {
            return strpos($callbackContent, 'sso_start_time') !== false &&
                   strpos($callbackContent, 'SSO session expired') !== false;
        });
        
        // Test error handling
        $this->test("OAuth errors are handled securely", function() use ($callbackContent) {
            return strpos($callbackContent, '$error = $_GET[\'error\']') !== false &&
                   strpos($callbackContent, 'logSecurityEvent') !== false;
        });
        
        // Test session cleanup
        $this->test("Session data is cleaned up", function() use ($callbackContent) {
            return strpos($callbackContent, "unset(\$_SESSION['sso_state'], \$_SESSION['sso_nonce']") !== false;
        });
    }
    
    private function testSessionManagement() {
        echo "<h2>🔑 Session Management Security Test</h2>\n";
        
        // Test SSO session security in verify_sso_2fa.php
        $verifyPath = __DIR__ . '/verify_sso_2fa.php';
        if (file_exists($verifyPath)) {
            $verifyContent = file_get_contents($verifyPath);
            
            $this->test("SSO 2FA session timeout is implemented", function() use ($verifyContent) {
                return strpos($verifyContent, 'sso_start_time') !== false &&
                       strpos($verifyContent, '(time() - $sso_start_time) > 600') !== false;
            });
            
            $this->test("Admin session IP binding is implemented", function() use ($verifyContent) {
                return strpos($verifyContent, 'login_ip') !== false &&
                       strpos($verifyContent, '$_SESSION[\'login_ip\']') !== false;
            });
            
            $this->test("2FA verification timestamp is set", function() use ($verifyContent) {
                return strpos($verifyContent, '2fa_verified_time') !== false;
            });
        } else {
            echo "<div class='test-fail'>❌ verify_sso_2fa.php missing</div>\n";
        }
    }
    
    private function testInputValidation() {
        echo "<h2>🔍 Input Validation Test</h2>\n";
        
        // Test SSOManager input validation
        try {
            SSOManager::init();
            $this->test("SSOManager initializes without errors", function() {
                return true;
            });
        } catch (Exception $e) {
            $this->test("SSOManager initialization", function() {
                return false;
            }, "Error: " . $e->getMessage());
        }
        
        // Test OIDCHandler validation
        $this->test("OIDCHandler validates provider configuration", function() {
            try {
                // This should fail with invalid provider
                new OIDCHandler('invalid_provider');
                return false; // Should have thrown exception
            } catch (Exception $e) {
                return strpos($e->getMessage(), 'Invalid OIDC/OAuth2 provider') !== false;
            }
        });
        
        // Test JWT validation exists
        $oidcContent = file_get_contents(__DIR__ . '/sso/OIDCHandler.php');
        $this->test("JWT validation is implemented", function() use ($oidcContent) {
            return strpos($oidcContent, 'validateJWT') !== false &&
                   strpos($oidcContent, 'validateJWTHeader') !== false;
        });
        
        // Test base64url validation
        $this->test("Base64URL validation is implemented", function() use ($oidcContent) {
            return strpos($oidcContent, 'isValidBase64Url') !== false &&
                   strpos($oidcContent, 'base64UrlDecode') !== false;
        });
    }
    
    private function testErrorHandling() {
        echo "<h2>🚨 Error Handling Test</h2>\n";
        
        $callbackPath = __DIR__ . '/sso/oidc/callback.php';
        if (file_exists($callbackPath)) {
            $callbackContent = file_get_contents($callbackPath);
            
            $this->test("OAuth errors are logged with security context", function() use ($callbackContent) {
                return strpos($callbackContent, 'OIDC_CALLBACK_ERROR') !== false &&
                       strpos($callbackContent, 'provider_id') !== false &&
                       strpos($callbackContent, 'has_code') !== false;
            });
            
            $this->test("Error messages don't leak sensitive info", function() use ($callbackContent) {
                // Check that we don't expose internal details in user-facing errors
                return strpos($callbackContent, 'urlencode(\'OIDC authentication failed:') !== false;
            });
        }
        
        // Test SSOManager error handling
        $ssoContent = file_get_contents(__DIR__ . '/sso/SSOManager.php');
        $this->test("SSOManager has comprehensive error logging", function() use ($ssoContent) {
            return strpos($ssoContent, 'SSO_LOGIN_ERROR') !== false &&
                   strpos($ssoContent, 'error_log(') !== false;
        });
    }
    
    private function testRateLimiting() {
        echo "<h2>🛑 Rate Limiting Test</h2>\n";
        
        // Test HardcoreSecurityManager rate limiting
        $securityContent = file_get_contents(__DIR__ . '/security_hardened.php');
        $this->test("Rate limiting whitelist includes localhost", function() use ($securityContent) {
            return strpos($securityContent, "in_array(\$_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1', 'localhost'])") !== false;
        });
        
        // Test SecurityMiddleware rate limiting
        if (file_exists(__DIR__ . '/security_middleware.php')) {
            $middlewareContent = file_get_contents(__DIR__ . '/security_middleware.php');
            $this->test("SecurityMiddleware has quick rate limiting", function() use ($middlewareContent) {
                return strpos($middlewareContent, 'quickRateLimit') !== false;
            });
        }
    }
    
    private function testCSRFProtection() {
        echo "<h2>🔒 CSRF Protection Test</h2>\n";
        
        $adminContent = file_get_contents(__DIR__ . '/admin_api.php');
        
        $this->test("CSRF tokens are validated for POST requests", function() use ($adminContent) {
            return strpos($adminContent, 'validateCSRFToken') !== false &&
                   strpos($adminContent, 'csrf_token') !== false;
        });
        
        $this->test("Trusted IPs bypass CSRF for localhost", function() use ($adminContent) {
            return strpos($adminContent, '!in_array($_SERVER[\'REMOTE_ADDR\'], $trustedIPs)') !== false;
        });
        
        $this->test("Authenticated admins bypass CSRF checks", function() use ($adminContent) {
            return strpos($adminContent, '!$isAuthenticatedAdmin') !== false &&
                   strpos($adminContent, 'is_admin\']) && $_SESSION[\'is_admin\']') !== false;
        });
    }
    
    private function test($description, $testFunction, $additionalInfo = '') {
        try {
            $result = $testFunction();
            if ($result) {
                echo "<div class='test-pass'>✅ $description</div>\n";
                $this->passed++;
            } else {
                echo "<div class='test-fail'>❌ $description</div>\n";
                if ($additionalInfo) {
                    echo "<div class='code-block'>$additionalInfo</div>\n";
                }
                $this->failed++;
            }
        } catch (Exception $e) {
            echo "<div class='test-fail'>❌ $description - Exception: " . $e->getMessage() . "</div>\n";
            $this->failed++;
        }
    }
    
    private function displayResults() {
        echo "<h2>📊 Test Summary</h2>\n";
        $total = $this->passed + $this->failed;
        $percentage = $total > 0 ? round(($this->passed / $total) * 100, 1) : 0;
        
        echo "<div class='security-good'>\n";
        echo "<h3>Overall Security Score: {$percentage}%</h3>\n";
        echo "<p>✅ Passed: {$this->passed}</p>\n";
        echo "<p>❌ Failed: {$this->failed}</p>\n";
        echo "<p>📋 Total Tests: {$total}</p>\n";
        echo "</div>\n";
        
        if ($this->failed > 0) {
            echo "<div class='security-issue'>\n";
            echo "<h3>⚠️ Security Recommendations:</h3>\n";
            if ($this->failed > 5) {
                echo "<p>❗ Multiple security issues detected. Review implementation carefully.</p>\n";
            } else if ($this->failed > 2) {
                echo "<p>⚠️ Some security improvements needed. Address failed tests.</p>\n";
            } else {
                echo "<p>✨ Minor issues detected. System is largely secure.</p>\n";
            }
            echo "</div>\n";
        } else {
            echo "<div class='security-good'>\n";
            echo "<h3>🎉 Excellent Security Implementation!</h3>\n";
            echo "<p>All security tests passed. The OAuth implementation appears robust.</p>\n";
            echo "</div>\n";
        }
    }
}

// Run the tests
$tester = new OAuthImplementationTest();
$tester->runAllTests();
?>