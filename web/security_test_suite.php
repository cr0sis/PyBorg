<?php
/**
 * Security Test Suite - Comprehensive F12 Attack Vector Testing
 * Tests all known methods of score manipulation via browser developer tools
 */

require_once 'security_config.php';
require_once 'input_sanitizer.php';
require_once 'config_paths.php';

class SecurityTestSuite {
    
    private static $test_results = [];
    private static $base_url = 'http://localhost';
    
    /**
     * Run all security tests
     */
    public static function runAllTests() {
        echo "=== BREAKOUT GAME SECURITY TEST SUITE ===\n";
        echo "Testing all known F12 attack vectors...\n\n";
        
        self::$test_results = [];
        
        // Test 1: Direct score manipulation via POST
        self::testDirectScoreManipulation();
        
        // Test 2: Session manipulation
        self::testSessionManipulation();
        
        // Test 3: JSON payload manipulation
        self::testJSONPayloadManipulation();
        
        // Test 4: Impossible scores
        self::testImpossibleScores();
        
        // Test 5: Rapid submission attacks
        self::testRapidSubmissionAttacks();
        
        // Test 6: Time manipulation attacks
        self::testTimeManipulationAttacks();
        
        // Test 7: Player name injection
        self::testPlayerNameInjection();
        
        // Test 8: Bypassing rate limits
        self::testRateLimitBypass();
        
        // Print results
        self::printTestResults();
        
        return self::$test_results;
    }
    
    /**
     * Test 1: Direct Score Manipulation via POST (Primary F12 attack)
     */
    private static function testDirectScoreManipulation() {
        echo "Test 1: Direct Score Manipulation via POST\n";
        echo "----------------------------------------\n";
        
        $attack_payloads = [
            ['player_name' => 'Hacker1', 'score' => 999999, 'level_reached' => 1, 'session_id' => 'fake_session'],
            ['player_name' => 'Hacker2', 'score' => 1000000, 'level_reached' => 5, 'session_id' => ''],
            ['player_name' => 'Hacker3', 'score' => 50000, 'level_reached' => 2, 'session_id' => 'invalid_session']
        ];
        
        foreach ($attack_payloads as $i => $payload) {
            $result = self::makePostRequest('/breakout_scores.php', $payload);
            
            $blocked = (
                $result['http_code'] === 503 || // Emergency lockdown
                $result['http_code'] === 403 || // Session validation failed
                $result['http_code'] === 400    // Invalid data
            );
            
            $test_name = "Direct manipulation attack " . ($i + 1);
            echo "  $test_name: " . ($blocked ? "BLOCKED ✓" : "FAILED ✗") . "\n";
            echo "    HTTP Code: {$result['http_code']}\n";
            echo "    Response: " . substr($result['response'], 0, 100) . "\n";
            
            self::$test_results[$test_name] = $blocked;
        }
        echo "\n";
    }
    
    /**
     * Test 2: Session Manipulation
     */
    private static function testSessionManipulation() {
        echo "Test 2: Session Manipulation Attacks\n";
        echo "------------------------------------\n";
        
        $session_attacks = [
            ['session_id' => 'admin_session', 'token' => 'fake_admin_token'],
            ['session_id' => str_repeat('a', 1000), 'token' => 'buffer_overflow_attempt'],
            ['session_id' => '../../../etc/passwd', 'token' => 'path_traversal'],
            ['session_id' => '<script>alert("xss")</script>', 'token' => 'xss_attempt']
        ];
        
        foreach ($session_attacks as $i => $attack) {
            $payload = [
                'player_name' => 'SessionHacker',
                'score' => 10000,
                'level_reached' => 3,
                'session_id' => $attack['session_id'],
                'token' => $attack['token']
            ];
            
            $result = self::makePostRequest('/breakout_scores.php', $payload);
            $blocked = $result['http_code'] !== 200;
            
            $test_name = "Session manipulation " . ($i + 1);
            echo "  $test_name: " . ($blocked ? "BLOCKED ✓" : "FAILED ✗") . "\n";
            
            self::$test_results[$test_name] = $blocked;
        }
        echo "\n";
    }
    
    /**
     * Test 3: JSON Payload Manipulation
     */
    private static function testJSONPayloadManipulation() {
        echo "Test 3: JSON Payload Manipulation\n";
        echo "---------------------------------\n";
        
        $malformed_payloads = [
            '{"player_name":"JSONHacker","score":99999999999999999999,"level_reached":1}', // Integer overflow
            '{"player_name":"SQLInjector","score":"1; DROP TABLE breakout_scores; --","level_reached":1}', // SQL injection
            '{"score":50000}', // Missing required fields
            '{"player_name":"","score":-50000,"level_reached":-1}', // Negative values
            '{"player_name":"NullHacker","score":null,"level_reached":null}', // Null values
        ];
        
        foreach ($malformed_payloads as $i => $payload) {
            $result = self::makeRawPostRequest('/breakout_scores.php', $payload);
            $blocked = $result['http_code'] !== 200;
            
            $test_name = "JSON manipulation " . ($i + 1);
            echo "  $test_name: " . ($blocked ? "BLOCKED ✓" : "FAILED ✗") . "\n";
            
            self::$test_results[$test_name] = $blocked;
        }
        echo "\n";
    }
    
    /**
     * Test 4: Impossible Scores
     */
    private static function testImpossibleScores() {
        echo "Test 4: Impossible Score Detection\n";
        echo "----------------------------------\n";
        
        $impossible_scores = [
            ['score' => 1000000, 'level' => 1], // 1M points on level 1
            ['score' => 500000, 'level' => 2],  // 500K points on level 2
            ['score' => 100000, 'level' => 1],  // 100K points on level 1
            ['score' => 999999999, 'level' => 10] // Nearly 1B points
        ];
        
        foreach ($impossible_scores as $i => $test_case) {
            $payload = [
                'player_name' => 'ImpossibleScorer',
                'score' => $test_case['score'],
                'level_reached' => $test_case['level'],
                'session_id' => 'test_session'
            ];
            
            $result = self::makePostRequest('/breakout_scores.php', $payload);
            $blocked = $result['http_code'] !== 200;
            
            $test_name = "Impossible score " . ($i + 1) . " ({$test_case['score']} pts, level {$test_case['level']})";
            echo "  $test_name: " . ($blocked ? "BLOCKED ✓" : "FAILED ✗") . "\n";
            
            self::$test_results[$test_name] = $blocked;
        }
        echo "\n";
    }
    
    /**
     * Test 5: Rapid Submission Attacks
     */
    private static function testRapidSubmissionAttacks() {
        echo "Test 5: Rapid Submission Attacks\n";
        echo "--------------------------------\n";
        
        $rapid_submissions = 0;
        $blocked_submissions = 0;
        
        // Attempt 10 rapid submissions
        for ($i = 0; $i < 10; $i++) {
            $payload = [
                'player_name' => 'RapidAttacker',
                'score' => 5000 + $i,
                'level_reached' => 2,
                'session_id' => 'rapid_session_' . $i
            ];
            
            $result = self::makePostRequest('/breakout_scores.php', $payload);
            $rapid_submissions++;
            
            if ($result['http_code'] === 429) { // Rate limited
                $blocked_submissions++;
            }
            
            usleep(100000); // 0.1 second delay
        }
        
        $rate_limiting_working = $blocked_submissions > 0;
        echo "  Rapid submissions: $rapid_submissions attempted, $blocked_submissions blocked\n";
        echo "  Rate limiting: " . ($rate_limiting_working ? "WORKING ✓" : "FAILED ✗") . "\n";
        
        self::$test_results['Rate limiting'] = $rate_limiting_working;
        echo "\n";
    }
    
    /**
     * Test 6: Time Manipulation Attacks
     */
    private static function testTimeManipulationAttacks() {
        echo "Test 6: Time Manipulation Attacks\n";
        echo "---------------------------------\n";
        
        // Test backdated timestamps and future timestamps
        $time_attacks = [
            ['timestamp' => time() - 86400, 'desc' => 'Backdated 24h'],
            ['timestamp' => time() + 86400, 'desc' => 'Future 24h'],
            ['timestamp' => 0, 'desc' => 'Unix epoch'],
            ['timestamp' => time() + 999999999, 'desc' => 'Far future']
        ];
        
        foreach ($time_attacks as $i => $attack) {
            $payload = [
                'player_name' => 'TimeManipulator',
                'score' => 15000,
                'level_reached' => 3,
                'session_id' => 'time_session',
                'timestamp' => $attack['timestamp']
            ];
            
            $result = self::makePostRequest('/breakout_scores.php', $payload);
            $blocked = $result['http_code'] !== 200;
            
            $test_name = "Time manipulation: {$attack['desc']}";
            echo "  $test_name: " . ($blocked ? "BLOCKED ✓" : "FAILED ✗") . "\n";
            
            self::$test_results[$test_name] = $blocked;
        }
        echo "\n";
    }
    
    /**
     * Test 7: Player Name Injection
     */
    private static function testPlayerNameInjection() {
        echo "Test 7: Player Name Injection Attacks\n";
        echo "-------------------------------------\n";
        
        $injection_names = [
            '<script>alert("XSS")</script>',
            'admin\'; DROP TABLE breakout_scores; --',
            str_repeat('A', 1000), // Buffer overflow
            '../../../etc/passwd',
            'NULL',
            'admin',
            'administrator',
            'root'
        ];
        
        foreach ($injection_names as $i => $name) {
            $payload = [
                'player_name' => $name,
                'score' => 8000,
                'level_reached' => 2,
                'session_id' => 'injection_session'
            ];
            
            $result = self::makePostRequest('/breakout_scores.php', $payload);
            $blocked = $result['http_code'] !== 200;
            
            $test_name = "Name injection " . ($i + 1);
            echo "  $test_name (" . substr($name, 0, 20) . "...): " . ($blocked ? "BLOCKED ✓" : "FAILED ✗") . "\n";
            
            self::$test_results[$test_name] = $blocked;
        }
        echo "\n";
    }
    
    /**
     * Test 8: Rate Limit Bypass Attempts
     */
    private static function testRateLimitBypass() {
        echo "Test 8: Rate Limit Bypass Attempts\n";
        echo "----------------------------------\n";
        
        // Different IP spoofing attempts
        $bypass_attempts = [
            ['X-Forwarded-For' => '192.168.1.100'],
            ['X-Real-IP' => '10.0.0.1'],
            ['X-Originating-IP' => '172.16.0.1'],
            ['Client-IP' => '203.0.113.1']
        ];
        
        foreach ($bypass_attempts as $i => $headers) {
            $payload = [
                'player_name' => 'BypassAttempt',
                'score' => 12000,
                'level_reached' => 3,
                'session_id' => 'bypass_session'
            ];
            
            $result = self::makePostRequest('/breakout_scores.php', $payload, $headers);
            $blocked = $result['http_code'] !== 200;
            
            $test_name = "Rate limit bypass " . ($i + 1);
            echo "  $test_name: " . ($blocked ? "BLOCKED ✓" : "FAILED ✗") . "\n";
            
            self::$test_results[$test_name] = $blocked;
        }
        echo "\n";
    }
    
    /**
     * Make POST request
     */
    private static function makePostRequest($endpoint, $data, $extra_headers = []) {
        $url = self::$base_url . $endpoint;
        $json_data = json_encode($data);
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        
        $headers = ['Content-Type: application/json'];
        foreach ($extra_headers as $key => $value) {
            $headers[] = "$key: $value";
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return [
            'response' => $response ?: '',
            'http_code' => $http_code
        ];
    }
    
    /**
     * Make raw POST request with malformed JSON
     */
    private static function makeRawPostRequest($endpoint, $raw_data) {
        $url = self::$base_url . $endpoint;
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $raw_data);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return [
            'response' => $response ?: '',
            'http_code' => $http_code
        ];
    }
    
    /**
     * Print comprehensive test results
     */
    private static function printTestResults() {
        echo "=== SECURITY TEST RESULTS SUMMARY ===\n";
        echo "=====================================\n";
        
        $total_tests = count(self::$test_results);
        $passed_tests = array_sum(self::$test_results);
        $failed_tests = $total_tests - $passed_tests;
        
        echo "Total Tests: $total_tests\n";
        echo "Passed (Blocked): $passed_tests\n";
        echo "Failed (Not Blocked): $failed_tests\n";
        echo "Success Rate: " . round(($passed_tests / $total_tests) * 100, 1) . "%\n\n";
        
        if ($failed_tests > 0) {
            echo "FAILED TESTS (SECURITY VULNERABILITIES):\n";
            foreach (self::$test_results as $test_name => $passed) {
                if (!$passed) {
                    echo "  ✗ $test_name\n";
                }
            }
            echo "\n";
        }
        
        if ($passed_tests === $total_tests) {
            echo "🎉 ALL SECURITY TESTS PASSED! 🎉\n";
            echo "The system successfully blocked all known F12 attack vectors.\n";
        } else {
            echo "⚠️  SECURITY VULNERABILITIES DETECTED ⚠️\n";
            echo "Some attack vectors were not properly blocked.\n";
        }
        
        echo "\nDetailed test breakdown available in test results array.\n";
    }
}

// Run tests if called directly
if (basename(__FILE__) === basename($_SERVER['SCRIPT_NAME'])) {
    SecurityTestSuite::runAllTests();
}
?>