<?php
/**
 * Test Score Submission Performance
 */

echo "Testing score submission performance fix...\n\n";

// Test data
$testData = [
    'player_name' => 'TestUser',
    'score' => 12345,
    'level_reached' => 1,
    'session_id' => 'test_session_' . time()
];

// Test 1: Normal submission (should work)
echo "Test 1: Normal submission\n";
$start = microtime(true);
$result1 = simulateScoreSubmission($testData);
$duration1 = (microtime(true) - $start) * 1000;
echo "Duration: {$duration1}ms\n";
echo "Result: " . ($result1['success'] ? 'SUCCESS' : 'FAILED') . "\n\n";

// Test 2: Duplicate submission (should be fast due to early deduplication)
echo "Test 2: Duplicate submission (should be very fast)\n";
$start = microtime(true);
$result2 = simulateScoreSubmission($testData);
$duration2 = (microtime(true) - $start) * 1000;
echo "Duration: {$duration2}ms\n";
echo "Result: " . ($result2['success'] ? 'SUCCESS (Duplicate)' : 'FAILED') . "\n";
echo "Duplicate flag: " . ($result2['duplicate'] ? 'YES' : 'NO') . "\n\n";

// Performance improvement check
if ($duration2 < $duration1 / 2) {
    echo "✓ Performance improved! Duplicate submission was " . round($duration1/$duration2, 1) . "x faster\n";
} else {
    echo "✗ Performance not improved. Duplicate took {$duration2}ms vs original {$duration1}ms\n";
}

function simulateScoreSubmission($data) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'http://localhost/breakout_scores.php');
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode === 200 && $response) {
        $result = json_decode($response, true);
        return $result ?: ['success' => false, 'error' => 'Invalid JSON'];
    }
    
    return ['success' => false, 'error' => "HTTP $httpCode"];
}
?>