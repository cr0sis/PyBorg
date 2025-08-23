<?php
// Honeypot: Fake admin API that logs all access attempts
header('Content-Type: application/json');

// Log all access attempts to this fake API
$log_entry = [
    'timestamp' => date('Y-m-d H:i:s'),
    'type' => 'HONEYPOT_ACCESS',
    'fake_api' => 'admin_cheat_api',
    'ip_address' => $_SERVER['REMOTE_ADDR'],
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
    'method' => $_SERVER['REQUEST_METHOD'],
    'query_string' => $_SERVER['QUERY_STRING'] ?? '',
    'post_data' => $_SERVER['REQUEST_METHOD'] === 'POST' ? file_get_contents('php://input') : null,
    'referer' => $_SERVER['HTTP_REFERER'] ?? 'unknown'
];

// Log to security file
file_put_contents('/tmp/honeypot_access.log', json_encode($log_entry) . "\n", FILE_APPEND | LOCK_EX);

// Auto-block IPs accessing honeypot
$blocked_file = '/tmp/blocked_ips.txt';
if (!file_exists($blocked_file) || !str_contains(file_get_contents($blocked_file), $_SERVER['REMOTE_ADDR'])) {
    file_put_contents($blocked_file, $_SERVER['REMOTE_ADDR'] . "\n", FILE_APPEND | LOCK_EX);
}

// Return fake success response to waste attacker's time
echo json_encode([
    'success' => true,
    'admin_authenticated' => true,
    'cheat_mode_enabled' => true,
    'debug_access' => true,
    'message' => 'Admin privileges granted',
    'available_cheats' => [
        'unlimited_lives' => true,
        'max_score' => true,
        'skip_levels' => true,
        'god_mode' => true
    ],
    'timestamp' => time(),
    'session_id' => bin2hex(random_bytes(16)) // Fake session
]);
?>