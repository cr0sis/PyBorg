<?php
/**
 * Unit Tests for Breakout Performance Issues
 * Tests for duplicate submissions and bottlenecks
 */

require_once 'PHPUnit/Autoload.php';

class BreakoutPerformanceTest extends PHPUnit\Framework\TestCase {
    
    /**
     * Test that score submission has deduplication
     */
    public function testScoreDeduplication() {
        // Simulate multiple rapid score submissions
        $player_name = 'TestPlayer';
        $score = 12345;
        $level = 5;
        $session_id = 'test_session_' . time();
        
        // Submit same score multiple times rapidly
        $results = [];
        for ($i = 0; $i < 3; $i++) {
            $result = $this->simulateScoreSubmission($player_name, $score, $level, $session_id);
            $results[] = $result;
            usleep(100000); // 100ms delay
        }
        
        // Check that only one score was actually recorded
        $this->assertEquals(1, $this->countScoresInDB($player_name, $score), 
            'Score should only be recorded once despite multiple submissions');
    }
    
    /**
     * Test bot status API performance
     */
    public function testBotStatusPerformance() {
        $start_time = microtime(true);
        
        // Simulate multiple concurrent bot status requests
        $requests = [];
        for ($i = 0; $i < 5; $i++) {
            $requests[] = $this->simulateBotStatusRequest();
        }
        
        $end_time = microtime(true);
        $total_time = $end_time - $start_time;
        
        // Should complete within reasonable time even with multiple requests
        $this->assertLessThan(2.0, $total_time, 
            'Bot status requests should complete within 2 seconds');
    }
    
    /**
     * Test that game completion doesn't trigger multiple score submissions
     */
    public function testGameCompletionSingleSubmission() {
        // Mock game completion scenario
        $player_name = 'CompletionTester';
        $final_score = 50000;
        $session_id = 'completion_test_' . time();
        
        // Simulate the sequence of events during game completion:
        // 1. Level completion
        // 2. Game over detection  
        // 3. Ultimate victory (if applicable)
        // 4. Hall of fame display
        
        $initial_count = $this->countScoresInDB($player_name, $final_score);
        
        // Each of these should be idempotent (not create duplicate submissions)
        $this->simulateGameCompletion($player_name, $final_score, $session_id);
        
        $final_count = $this->countScoresInDB($player_name, $final_score);
        
        $this->assertEquals($initial_count + 1, $final_count,
            'Game completion should result in exactly one score submission');
    }
    
    private function simulateScoreSubmission($player_name, $score, $level, $session_id) {
        // Simulate the AJAX request to breakout_scores.php
        $data = [
            'player_name' => $player_name,
            'score' => $score,
            'level_reached' => $level,
            'session_id' => $session_id
        ];
        
        // Use curl to simulate the request
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'http://localhost/breakout_scores.php');
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        
        $result = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return ['result' => $result, 'http_code' => $http_code];
    }
    
    private function simulateBotStatusRequest() {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'http://localhost/api/bot_status.php?action=full');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        
        $start = microtime(true);
        $result = curl_exec($ch);
        $end = microtime(true);
        
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return [
            'result' => $result,
            'http_code' => $http_code,
            'duration' => $end - $start
        ];
    }
    
    private function simulateGameCompletion($player_name, $score, $session_id) {
        // This simulates the JavaScript game completion logic
        // Multiple events that could trigger score submission
        
        // Event 1: Level completion
        $this->simulateScoreSubmission($player_name, $score, 100, $session_id);
        
        // Event 2: Game over detection
        usleep(50000); // 50ms delay
        $this->simulateScoreSubmission($player_name, $score, 100, $session_id);
        
        // Event 3: Hall of fame display
        usleep(50000); // 50ms delay  
        $this->simulateScoreSubmission($player_name, $score, 100, $session_id);
    }
    
    private function countScoresInDB($player_name, $score) {
        $db_path = '/data/cr0_system/databases/breakout_scores.db';
        $pdo = new PDO("sqlite:$db_path");
        
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM breakout_scores WHERE player_name = ? AND score = ?");
        $stmt->execute([$player_name, $score]);
        
        return (int)$stmt->fetchColumn();
    }
}

// Simple test runner if executed directly
if (basename($_SERVER['SCRIPT_NAME']) === basename(__FILE__)) {
    echo "Running Breakout Performance Tests...\n\n";
    
    $test = new BreakoutPerformanceTest();
    
    try {
        echo "Test 1: Score Deduplication\n";
        $test->testScoreDeduplication();
        echo "✓ PASSED\n\n";
    } catch (Exception $e) {
        echo "✗ FAILED: " . $e->getMessage() . "\n\n";
    }
    
    try {
        echo "Test 2: Bot Status Performance\n";
        $test->testBotStatusPerformance();
        echo "✓ PASSED\n\n";
    } catch (Exception $e) {
        echo "✗ FAILED: " . $e->getMessage() . "\n\n";
    }
    
    try {
        echo "Test 3: Game Completion Single Submission\n";
        $test->testGameCompletionSingleSubmission();
        echo "✓ PASSED\n\n";
    } catch (Exception $e) {
        echo "✗ FAILED: " . $e->getMessage() . "\n\n";
    }
}
?>