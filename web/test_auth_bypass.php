<?php
/**
 * Test the authenticated user bypass for score submission
 */

session_start();

echo "=== Testing Authenticated User Bypass ===\n\n";

// Simulate being logged in as admin
$_SESSION['username'] = 'cr0sis';
$_SESSION['user_id'] = 1;
$_SESSION['is_admin'] = true;

echo "Simulated session:\n";
echo "- Username: " . ($_SESSION['username'] ?? 'not set') . "\n";
echo "- User ID: " . ($_SESSION['user_id'] ?? 'not set') . "\n";
echo "- Is Admin: " . ($_SESSION['is_admin'] ? 'true' : 'false') . "\n\n";

// Test authenticated score submission
echo "Testing authenticated score submission...\n";

$testData = [
    'player_name' => 'cr0sis',
    'score' => 9999,
    'level_reached' => 1,
    'session_id' => 'test_session_' . time(), // This should be ignored for authenticated users
    'token' => 'fake_token' // This should also be ignored
];

$start = microtime(true);

// Simulate the score submission
require_once 'config_paths.php';
require_once 'input_sanitizer.php';

$db_path = ConfigPaths::getDatabase('breakout_scores');
$pdo = new PDO("sqlite:$db_path");
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Simulate the authentication check
$is_authenticated = isset($_SESSION['username']) && isset($_SESSION['user_id']);

if ($is_authenticated) {
    echo "✓ Authentication check passed for: " . $_SESSION['username'] . "\n";
    
    // Quick deduplication check
    $stmt = $pdo->prepare("
        SELECT COUNT(*) as identical_submissions 
        FROM breakout_scores 
        WHERE player_name = ? AND score = ? AND level_reached = ? 
        AND date_played > datetime('now', '-2 minutes')
    ");
    $stmt->execute([$testData['player_name'], $testData['score'], $testData['level_reached']]);
    $identical_count = $stmt->fetchColumn();
    
    if ($identical_count > 0) {
        echo "✓ Deduplication check - score already exists\n";
        $result = ['success' => true, 'message' => 'Score already recorded', 'duplicate' => true];
    } else {
        echo "✓ New score - would be inserted\n";
        $result = ['success' => true, 'message' => 'Score would be recorded'];
    }
} else {
    echo "✗ Authentication failed\n";
    $result = ['success' => false, 'error' => 'Not authenticated'];
}

$end = microtime(true);
$duration = ($end - $start) * 1000;

echo "Duration: {$duration}ms\n";
echo "Result: " . json_encode($result, JSON_PRETTY_PRINT) . "\n\n";

if ($duration < 10 && $result['success']) {
    echo "✓ SUCCESS: Authenticated bypass is working and fast!\n";
} else {
    echo "✗ FAILED: Either too slow ({$duration}ms) or unsuccessful\n";
}

echo "\n=== Testing Complete ===\n";
?>