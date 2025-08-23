<?php
require_once 'security_config.php';
require_once 'input_sanitizer.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

try {
    $raw_input = file_get_contents('php://input');
    $input = InputSanitizer::validateJSON($raw_input);
    
    if ($input === false) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON data']);
        exit;
    }
    
    $type = $input['type'] ?? 'unknown';
    $session_id = $input['session_id'] ?? 'unknown';
    $timestamp = date('Y-m-d H:i:s');
    $ip_address = $_SERVER['REMOTE_ADDR'];
    
    // Log to security file
    $log_entry = [
        'timestamp' => $timestamp,
        'type' => 'CLIENT_TAMPERING',
        'subtype' => $type,
        'session_id' => $session_id,
        'ip_address' => $ip_address,
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'data' => $input
    ];
    
    $log_file = '/tmp/security_tampering.log';
    file_put_contents($log_file, json_encode($log_entry) . "\n", FILE_APPEND | LOCK_EX);
    
    // Add to high-priority monitoring
    $alert_entry = [
        'timestamp' => $timestamp,
        'severity' => 'HIGH',
        'source_ip' => $ip_address,
        'session_id' => $session_id,
        'description' => "Client-side tampering detected: $type",
        'details' => $input
    ];
    
    $alert_file = '/tmp/security_alerts.log';
    file_put_contents($alert_file, json_encode($alert_entry) . "\n", FILE_APPEND | LOCK_EX);
    
    // Check for admin bypass before auto-blocking
    $is_admin_ip = false;
    if (isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true) {
        $is_admin_ip = true;
        error_log("ADMIN IP BYPASS: Not blocking IP $ip_address (admin session detected)");
    }
    
    // If this is the third offense from this IP, auto-block (unless admin)
    if (!$is_admin_ip) {
        $recent_logs = file_get_contents($log_file);
        $ip_count = substr_count($recent_logs, '"ip_address":"' . $ip_address . '"');
        
        if ($ip_count >= 3) {
            $blocked_file = '/tmp/blocked_ips.txt';
            if (!file_exists($blocked_file) || !str_contains(file_get_contents($blocked_file), $ip_address)) {
                file_put_contents($blocked_file, $ip_address . "\n", FILE_APPEND | LOCK_EX);
                
                // Log the auto-block
                $block_entry = [
                    'timestamp' => $timestamp,
                    'action' => 'AUTO_BLOCK',
                    'ip_address' => $ip_address,
                    'reason' => 'Multiple tampering attempts',
                    'offense_count' => $ip_count
                ];
                
                file_put_contents('/tmp/auto_blocks.log', json_encode($block_entry) . "\n", FILE_APPEND | LOCK_EX);
            }
        }
    }
    
    // Always return success to avoid revealing security measures
    echo json_encode(['status' => 'received']);
    
} catch (Exception $e) {
    // Log error but don't reveal details
    error_log("Tampering report error: " . $e->getMessage());
    echo json_encode(['status' => 'received']);
}
?>