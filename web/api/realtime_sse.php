<?php
/**
 * Real-time Server-Sent Events Handler
 * Optimized SSE implementation with connection pooling to prevent PHP-FPM exhaustion
 */

require_once '../security_config.php';
require_once '../auth.php';
require_once '../config_paths.php';

class SSEConnectionManager {
    private static $maxConnections = 10;
    private static $connectionFile = '/tmp/sse_connections.json';
    private static $eventQueueDir = '/data/cr0_system/realtime_events/';
    
    /**
     * Check if we can accept a new SSE connection
     */
    public static function canAcceptConnection() {
        $connections = self::getActiveConnections();
        return count($connections) < self::$maxConnections;
    }
    
    /**
     * Register a new SSE connection
     */
    public static function registerConnection($sessionId, $clientIp) {
        $connections = self::getActiveConnections();
        $connections[$sessionId] = [
            'ip' => $clientIp,
            'started' => time(),
            'last_ping' => time()
        ];
        
        file_put_contents(self::$connectionFile, json_encode($connections));
        return true;
    }
    
    /**
     * Cleanup expired connections
     */
    public static function cleanupConnections() {
        $connections = self::getActiveConnections();
        $timeout = 300; // 5 minutes
        $now = time();
        
        foreach ($connections as $sessionId => $info) {
            if (($now - $info['last_ping']) > $timeout) {
                unset($connections[$sessionId]);
            }
        }
        
        file_put_contents(self::$connectionFile, json_encode($connections));
        return count($connections);
    }
    
    /**
     * Get active connections
     */
    private static function getActiveConnections() {
        if (!file_exists(self::$connectionFile)) {
            return [];
        }
        
        $data = file_get_contents(self::$connectionFile);
        return json_decode($data, true) ?: [];
    }
    
    /**
     * Get pending events from queue
     */
    public static function getPendingEvents($lastEventId = 0) {
        $events = [];
        $eventDirs = ['bot_status', 'commands', 'security', 'games'];
        
        foreach ($eventDirs as $dir) {
            $dirPath = self::$eventQueueDir . $dir;
            if (!is_dir($dirPath)) continue;
            
            $files = glob($dirPath . '/*.json');
            foreach ($files as $file) {
                $eventId = basename($file, '.json');
                if ($eventId <= $lastEventId) continue;
                
                $eventData = json_decode(file_get_contents($file), true);
                if ($eventData) {
                    $eventData['id'] = $eventId;
                    $eventData['type'] = $dir;
                    $events[] = $eventData;
                    
                    // Clean up processed events older than 1 minute
                    if (time() - filemtime($file) > 60) {
                        unlink($file);
                    }
                }
            }
        }
        
        // Sort by event ID
        usort($events, function($a, $b) {
            return $a['id'] - $b['id'];
        });
        
        return $events;
    }
}

// Authentication check
if (!isLoggedIn() || !isAdmin()) {
    http_response_code(403);
    exit('Access denied');
}

// Verify 2FA
if (!isset($_SESSION['2fa_verified_time']) || (time() - $_SESSION['2fa_verified_time']) > 3600) {
    http_response_code(403);
    exit('2FA verification required');
}

// Check IP binding
if (!isset($_SESSION['bound_ip']) || $_SESSION['bound_ip'] !== $_SERVER['REMOTE_ADDR']) {
    http_response_code(403);
    exit('IP binding verification failed');
}

// Check connection limit
if (!SSEConnectionManager::canAcceptConnection()) {
    http_response_code(503);
    exit('Server busy - too many connections');
}

// Set SSE headers
header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('Connection: keep-alive');
header('Access-Control-Allow-Origin: *');

// Prevent timeout
set_time_limit(0);
ini_set('auto_detect_line_endings', 1);

// Register connection
$sessionId = session_id();
$clientIp = $_SERVER['REMOTE_ADDR'];
SSEConnectionManager::registerConnection($sessionId, $clientIp);

// Initialize
$lastEventId = isset($_GET['lastEventId']) ? (int)$_GET['lastEventId'] : 0;
$heartbeatInterval = 30; // seconds
$lastHeartbeat = time();

// Send initial connection event
echo "id: 0\n";
echo "event: connected\n";
echo "data: " . json_encode(['status' => 'connected', 'timestamp' => time()]) . "\n\n";
flush();

// Main event loop
while (connection_status() == CONNECTION_NORMAL) {
    // Cleanup old connections periodically
    if (rand(1, 100) == 1) {
        SSEConnectionManager::cleanupConnections();
    }
    
    // Get and send events
    $events = SSEConnectionManager::getPendingEvents($lastEventId);
    
    foreach ($events as $event) {
        echo "id: {$event['id']}\n";
        echo "event: {$event['type']}\n";
        echo "data: " . json_encode($event) . "\n\n";
        flush();
        
        $lastEventId = max($lastEventId, $event['id']);
    }
    
    // Send heartbeat
    if (time() - $lastHeartbeat > $heartbeatInterval) {
        echo "id: " . time() . "\n";
        echo "event: heartbeat\n";
        echo "data: " . json_encode(['timestamp' => time()]) . "\n\n";
        flush();
        $lastHeartbeat = time();
    }
    
    // Short sleep to prevent excessive CPU usage
    usleep(500000); // 0.5 seconds
    
    // Check if client disconnected
    if (connection_aborted()) {
        break;
    }
}

// Cleanup on disconnect
$connections = SSEConnectionManager::getActiveConnections();
unset($connections[$sessionId]);
file_put_contents('/tmp/sse_connections.json', json_encode($connections));
?>