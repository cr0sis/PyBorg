<?php
/**
 * Public Bot Status API - Lightweight version
 * Provides basic bot online/offline status without admin authentication
 * Used by bot_status_manager.js to reduce server load
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');

// Super lightweight cache - just stores basic online/offline status
$cacheFile = '/tmp/bot_status_public_cache.json';
$cacheLifetime = 60; // 1 minute cache for public endpoint

// Check cache first
if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < $cacheLifetime) {
    echo file_get_contents($cacheFile);
    exit;
}

// Generate fresh status with minimal overhead
try {
    $status = [
        'timestamp' => time(),
        'rizon' => false,
        'libera' => false,
        'cached' => false
    ];
    
    // Ultra-lightweight status check - just check if screen sessions exist
    // This avoids expensive process scanning that was causing timeouts
    $screen_sessions = glob('/var/run/screen/S-*/?????.rizon-bot') ?: [];
    $status['rizon'] = !empty($screen_sessions);
    
    $screen_sessions = glob('/var/run/screen/S-*/?????.libera-bot') ?: [];
    $status['libera'] = !empty($screen_sessions);
    
    $status['any_online'] = $status['rizon'] || $status['libera'];
    $status['all_online'] = $status['rizon'] && $status['libera'];
    
    $json = json_encode($status);
    file_put_contents($cacheFile, $json);
    echo $json;
    
} catch (Exception $e) {
    // Fallback response
    echo json_encode([
        'timestamp' => time(),
        'rizon' => false,
        'libera' => false,
        'any_online' => false,
        'all_online' => false,
        'error' => 'Status check failed',
        'cached' => false
    ]);
}
?>