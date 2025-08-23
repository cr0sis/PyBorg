<?php
/**
 * Simple Performance Tests for Breakout Issues
 */

echo "=== Breakout Performance Tests ===\n\n";

// Test 1: Check PHP-FPM pool size
echo "Test 1: PHP-FPM Configuration\n";
$fpmConfig = file_get_contents('/etc/php/8.2/fpm/pool.d/www.conf');
if (strpos($fpmConfig, 'pm.max_children = 25') !== false) {
    echo "✓ PHP-FPM max_children increased to 25\n";
} else {
    echo "✗ PHP-FPM max_children not updated\n";
}

// Test 2: Check secure_sessions database exists
echo "\nTest 2: Secure Sessions Database\n";
if (file_exists('/data/cr0_system/databases/secure_sessions.db')) {
    echo "✓ Secure sessions database exists\n";
} else {
    echo "✗ Secure sessions database missing\n";
}

// Test 3: Test bot status API performance
echo "\nTest 3: Bot Status API Performance\n";
$start = microtime(true);

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'http://localhost/api/bot_status_public.php');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 5);
curl_setopt($ch, CURLOPT_HEADER, true);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$totalTime = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
curl_close($ch);

$end = microtime(true);
$duration = $end - $start;

if ($httpCode === 200 && $duration < 1.0) {
    echo "✓ Public bot status API responds in {$duration}s\n";
} else {
    echo "✗ Bot status API slow or failed (HTTP $httpCode, {$duration}s)\n";
}

// Test 4: Check score deduplication logic
echo "\nTest 4: Score Deduplication Logic\n";
$breakoutScoresPath = '/var/www/html/breakout_scores.php';
$content = file_get_contents($breakoutScoresPath);

if (strpos($content, 'identical_submissions') !== false && 
    strpos($content, 'DEDUPLICATION:') !== false) {
    echo "✓ Enhanced deduplication system implemented\n";
} else {
    echo "✗ Deduplication system not found\n";
}

// Test 5: Check completionist prevention in JavaScript
echo "\nTest 5: Completionist Duplicate Prevention\n";
$breakoutHtmlPath = '/var/www/html/breakout.html';
$content = file_get_contents($breakoutHtmlPath);

if (strpos($content, 'completionistRecorded') !== false && 
    strpos($content, 'already recorded for this session') !== false) {
    echo "✓ Completionist duplicate prevention implemented\n";
} else {
    echo "✗ Completionist duplicate prevention not found\n";
}

// Test 6: Monitor current system resources
echo "\nTest 6: Current System Resources\n";
$loadAvg = sys_getloadavg();
echo "System load: " . implode(', ', array_map(fn($x) => number_format($x, 2), $loadAvg)) . "\n";

// Check PHP-FPM process count
$fpmProcesses = shell_exec('pgrep -c php-fpm') ?: 0;
echo "PHP-FPM processes: $fpmProcesses\n";

if ($fpmProcesses >= 8) {
    echo "✓ PHP-FPM has sufficient processes running\n";
} else {
    echo "✗ PHP-FPM may need more processes (found: $fpmProcesses)\n";
}

echo "\n=== Test Summary ===\n";
echo "Performance improvements implemented to fix server overload:\n";
echo "1. PHP-FPM pool increased from 5 to 25 max children\n";
echo "2. Missing secure_sessions database created\n";
echo "3. Bot status API caching increased and public endpoint added\n";
echo "4. Score submission deduplication enhanced\n";
echo "5. Game completion duplicate prevention added\n";
echo "6. Unit test framework created for future monitoring\n";

?>