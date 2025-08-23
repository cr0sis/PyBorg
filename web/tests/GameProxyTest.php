<?php
/**
 * Unit tests for game-proxy.php to identify SecureGame HTTP 400 issues
 */

require_once '/var/www/html/security_config.php';
require_once '/var/www/html/security_hardened.php';
require_once '/var/www/html/crypto_utils.php';

class GameProxyTest {
    
    public function runAllTests() {
        echo "=== Game Proxy Unit Tests ===\n";
        
        $this->testJSONParsing();
        $this->testValidateGameOperation();
        $this->testSecureGameRequests();
        $this->testInputValidation();
        
        echo "=== Tests Complete ===\n";
    }
    
    /**
     * Test JSON parsing with HardcoreSecurityManager::safeJSONParse
     */
    public function testJSONParsing() {
        echo "\n--- Testing JSON Parsing ---\n";
        
        // Test valid JSON
        $validJson = '{"op":"start_session","game_type":"breakout","player_name":"Anonymous"}';
        $result = HardcoreSecurityManager::safeJSONParse($validJson);
        echo "Valid JSON test: " . ($result !== false ? "PASS" : "FAIL") . "\n";
        if ($result !== false) {
            echo "Parsed: " . json_encode($result) . "\n";
        }
        
        // Test SecureGame format (from minified JS)
        $secureGameJson = '{"op":"start_session","data":{"game_type":"breakout","player_name":"Anonymous"},"ts":' . time() . ',"nonce":"test123","sid":null}';
        $result2 = HardcoreSecurityManager::safeJSONParse($secureGameJson);
        echo "SecureGame format test: " . ($result2 !== false ? "PASS" : "FAIL") . "\n";
        if ($result2 !== false) {
            echo "Parsed: " . json_encode($result2) . "\n";
        }
        
        // Test invalid JSON
        $invalidJson = '{"op":"start_session",,,"invalid"}';
        $result3 = HardcoreSecurityManager::safeJSONParse($invalidJson);
        echo "Invalid JSON test: " . ($result3 === false ? "PASS" : "FAIL") . "\n";
        
        // Test empty input
        $result4 = HardcoreSecurityManager::safeJSONParse('');
        echo "Empty input test: " . ($result4 === false ? "PASS" : "FAIL") . "\n";
    }
    
    /**
     * Test validateGameOperation function
     */
    public function testValidateGameOperation() {
        echo "\n--- Testing validateGameOperation ---\n";
        
        // Include the function from game-proxy.php
        $gameProxyContent = file_get_contents('/var/www/html/api/secure/game-proxy.php');
        
        // Extract just the validateGameOperation function
        preg_match('/function validateGameOperation.*?^\}/ms', $gameProxyContent, $matches);
        if (!empty($matches[0])) {
            eval($matches[0]);
        } else {
            echo "Could not extract validateGameOperation function\n";
            return;
        }
        
        // Test valid operations
        $validOps = [
            ['op' => 'start_session', 'expected' => true],
            ['op' => 'validate_score', 'expected' => true],
            ['op' => 'submit_score', 'expected' => true],
            ['op' => 'get_leaderboard', 'expected' => true],
            ['op' => 'health_check', 'expected' => true],
            ['op' => 'invalid_op', 'expected' => false],
            ['op' => '', 'expected' => false],
        ];
        
        foreach ($validOps as $test) {
            $data = ['op' => $test['op']];
            $result = validateGameOperation($test['op'], $data);
            $status = ($result === $test['expected']) ? "PASS" : "FAIL";
            echo "Operation '{$test['op']}': $status\n";
        }
    }
    
    /**
     * Test SecureGame request formats
     */
    public function testSecureGameRequests() {
        echo "\n--- Testing SecureGame Request Formats ---\n";
        
        // Format 1: Direct format (what we expect)
        $directFormat = [
            'op' => 'start_session',
            'game_type' => 'breakout', 
            'player_name' => 'Anonymous'
        ];
        echo "Direct format: " . json_encode($directFormat) . "\n";
        
        // Format 2: Nested data format (what SecureGame.js might send)
        $nestedFormat = [
            'op' => 'start_session',
            'data' => [
                'game_type' => 'breakout',
                'player_name' => 'Anonymous'
            ],
            'ts' => time(),
            'nonce' => 'test123',
            'sid' => null
        ];
        echo "Nested format: " . json_encode($nestedFormat) . "\n";
        
        // Format 3: Base64 encoded format (from minified JS)
        $encodedPayload = base64_encode(json_encode([
            'op' => 'start_session',
            'data' => ['game_type' => 'breakout', 'player_name' => 'Anonymous'],
            'ts' => time(),
            'nonce' => 'test123',
            'sid' => null
        ]));
        echo "Base64 encoded format: $encodedPayload\n";
    }
    
    /**
     * Test input validation scenarios
     */
    public function testInputValidation() {
        echo "\n--- Testing Input Validation ---\n";
        
        // Test scenarios that might cause HTTP 400
        $testInputs = [
            // Missing op field
            ['game_type' => 'breakout', 'player_name' => 'Anonymous'],
            // Empty op field  
            ['op' => '', 'game_type' => 'breakout'],
            // Null op field
            ['op' => null, 'game_type' => 'breakout'],
            // Invalid characters
            ['op' => 'start_session', 'player_name' => "Test\x00User"],
            // Very long strings
            ['op' => 'start_session', 'player_name' => str_repeat('A', 1000)],
        ];
        
        foreach ($testInputs as $i => $input) {
            echo "Test input $i: " . json_encode($input) . "\n";
            $jsonString = json_encode($input);
            $parsed = HardcoreSecurityManager::safeJSONParse($jsonString);
            echo "  Parsing result: " . ($parsed !== false ? "SUCCESS" : "FAILED") . "\n";
            
            if ($parsed !== false) {
                $op = $parsed['op'] ?? '';
                echo "  Operation: '$op'\n";
            }
        }
    }
    
    /**
     * Simulate the exact request the browser is making
     */
    public function simulateBrowserRequest() {
        echo "\n--- Simulating Browser Request ---\n";
        
        // This simulates what the minified SecureGame.js is likely sending
        $browserPayload = [
            'op' => 'start_session',
            'game_type' => 'breakout',
            'player_name' => 'Anonymous'
        ];
        
        $jsonPayload = json_encode($browserPayload);
        echo "Simulated browser payload: $jsonPayload\n";
        
        // Test the full pipeline
        $parsed = HardcoreSecurityManager::safeJSONParse($jsonPayload);
        if ($parsed === false) {
            echo "JSON parsing FAILED\n";
            return;
        }
        
        echo "JSON parsing SUCCESS\n";
        
        $operation = $parsed['op'] ?? '';
        echo "Extracted operation: '$operation'\n";
        
        // Test operation validation
        if (function_exists('validateGameOperation')) {
            $isValid = validateGameOperation($operation, $parsed);
            echo "Operation validation: " . ($isValid ? "PASS" : "FAIL") . "\n";
        } else {
            echo "validateGameOperation function not available\n";
        }
    }
}

// Run the tests
$tester = new GameProxyTest();
$tester->runAllTests();
$tester->simulateBrowserRequest();