<?php
/**
 * Real-time Bot Status API
 * Replaces polling-based bot status with real-time event-driven updates
 */

require_once '../security_config.php';
require_once '../secure_admin_functions.php';
require_once '../security_middleware.php';
require_once '../input_sanitizer.php';
require_once 'realtime_events_core.php';

// Initialize security
$authenticated = false;
try {
    SecurityMiddleware::validateAdminAccess();
    $authenticated = true;
} catch (Exception $e) {
    // For non-admin endpoints, allow limited access
    if ($_GET['action'] === 'public_status') {
        $authenticated = 'public';
    } else {
        header('HTTP/1.1 403 Forbidden');
        echo json_encode(['error' => 'Admin access required']);
        exit;
    }
}

header('Content-Type: application/json');

// Secure CORS implementation
if ($authenticated === true) {
    SecurityMiddleware::generateSecureCORS();
}
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type');

class RealtimeBotStatusAPI {
    private $eventsCore;
    private $eventDbPath;
    private $statusDir;
    
    public function __construct() {
        $this->eventsCore = new RealtimeEventsCore();
        $this->eventDbPath = '/data/cr0_system/databases/realtime_events.db';
        $this->statusDir = '/data/cr0_system/bot_status';
    }
    
    /**
     * Get comprehensive real-time bot status
     */
    public function getRealtimeStatus() {
        try {
            // Get current status from event database
            $db = new SQLite3($this->eventDbPath);
            $db->enableExceptions(true);
            
            $networks = ['rizon', 'libera'];
            $status = [
                'timestamp' => time(),
                'networks' => [],
                'overall' => [
                    'bots_online' => 0,
                    'total_bots' => 2,
                    'all_online' => false,
                    'any_online' => false,
                    'last_events' => []
                ],
                'realtime' => [
                    'enabled' => true,
                    'event_source' => '/api/sse_connection_manager.php',
                    'last_event_check' => time()
                ]
            ];
            
            foreach ($networks as $network) {
                $networkStatus = $this->getCurrentNetworkStatus($db, $network);
                $status['networks'][$network] = $networkStatus;
                
                if ($networkStatus['online']) {
                    $status['overall']['bots_online']++;
                }
            }
            
            $status['overall']['all_online'] = $status['overall']['bots_online'] === $status['overall']['total_bots'];
            $status['overall']['any_online'] = $status['overall']['bots_online'] > 0;
            $status['overall']['status_text'] = $this->getOverallStatusText($status['overall']['bots_online']);
            $status['overall']['status_color'] = $this->getOverallStatusColor($status['overall']['bots_online']);
            
            // Get recent events for debugging
            $status['overall']['last_events'] = $this->getRecentEvents($db, 5);
            
            $db->close();
            return $status;
            
        } catch (Exception $e) {
            error_log("Realtime status error: " . $e->getMessage());
            return $this->getFallbackStatus();
        }
    }
    
    /**
     * Get current status for a specific network from event database
     */
    private function getCurrentNetworkStatus($db, $network) {
        try {
            // Get latest status from bot_status_events
            $stmt = $db->prepare('
                SELECT status, pid, uptime, timestamp, change_type
                FROM bot_status_events 
                WHERE network = ? 
                ORDER BY timestamp DESC 
                LIMIT 1
            ');
            $stmt->bindValue(1, $network, SQLITE3_TEXT);
            $result = $stmt->execute();
            
            $latestEvent = $result->fetchArray(SQLITE3_ASSOC);
            
            if ($latestEvent) {
                $online = $latestEvent['status'] === 'online';
                
                return [
                    'online' => $online,
                    'pid' => $latestEvent['pid'],
                    'uptime' => $latestEvent['uptime'],
                    'uptime_formatted' => $this->formatUptime($latestEvent['uptime']),
                    'last_update' => $latestEvent['timestamp'],
                    'last_change' => $latestEvent['change_type'],
                    'status_color' => $online ? '#059669' : '#dc2626',
                    'status_icon' => $online ? '🟢' : '🔴',
                    'status_text' => $online ? 'Online' : 'Offline',
                    'data_source' => 'realtime_events'
                ];
            } else {
                // Fallback to status file if no events
                return $this->getStatusFromFile($network);
            }
            
        } catch (Exception $e) {
            error_log("Error getting network status for $network: " . $e->getMessage());
            return $this->getStatusFromFile($network);
        }
    }
    
    /**
     * Fallback to reading status from JSON files
     */
    private function getStatusFromFile($network) {
        $statusFile = $this->statusDir . "/{$network}_status.json";
        
        if (file_exists($statusFile)) {
            $data = json_decode(file_get_contents($statusFile), true);
            if ($data) {
                $online = $data['status'] === 'online';
                return [
                    'online' => $online,
                    'pid' => $data['pid'],
                    'uptime' => $data['uptime'],
                    'uptime_formatted' => $this->formatUptime($data['uptime']),
                    'last_update' => $data['last_update'],
                    'last_change' => 'file_read',
                    'status_color' => $online ? '#059669' : '#dc2626',
                    'status_icon' => $online ? '🟢' : '🔴',
                    'status_text' => $online ? 'Online' : 'Offline',
                    'data_source' => 'status_file'
                ];
            }
        }
        
        return [
            'online' => false,
            'pid' => null,
            'uptime' => 0,
            'uptime_formatted' => '0s',
            'last_update' => time(),
            'last_change' => 'unknown',
            'status_color' => '#dc2626',
            'status_icon' => '🔴',
            'status_text' => 'Offline',
            'data_source' => 'default'
        ];
    }
    
    /**
     * Get recent events for debugging
     */
    private function getRecentEvents($db, $limit = 5) {
        try {
            $stmt = $db->prepare('
                SELECT event_type, data, timestamp
                FROM realtime_events 
                WHERE event_type = "bot_status_change"
                ORDER BY timestamp DESC 
                LIMIT ?
            ');
            $stmt->bindValue(1, $limit, SQLITE3_INTEGER);
            $result = $stmt->execute();
            
            $events = [];
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $events[] = [
                    'type' => $row['event_type'],
                    'data' => json_decode($row['data'], true),
                    'timestamp' => $row['timestamp'],
                    'time_ago' => $this->timeAgo($row['timestamp'])
                ];
            }
            
            return $events;
            
        } catch (Exception $e) {
            error_log("Error getting recent events: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get fallback status when event system fails
     */
    private function getFallbackStatus() {
        return [
            'timestamp' => time(),
            'networks' => [
                'rizon' => $this->getStatusFromFile('rizon'),
                'libera' => $this->getStatusFromFile('libera')
            ],
            'overall' => [
                'bots_online' => 0,
                'total_bots' => 2,
                'all_online' => false,
                'any_online' => false,
                'status_text' => 'Status Unknown',
                'status_color' => '#f59e0b'
            ],
            'realtime' => [
                'enabled' => false,
                'error' => 'Event system unavailable, using fallback',
                'event_source' => null
            ]
        ];
    }
    
    /**
     * Get public status (limited information)
     */
    public function getPublicStatus() {
        $status = $this->getRealtimeStatus();
        
        // Remove sensitive information for public access
        return [
            'timestamp' => $status['timestamp'],
            'networks' => [
                'rizon' => [
                    'online' => $status['networks']['rizon']['online'],
                    'status_text' => $status['networks']['rizon']['status_text'],
                    'status_icon' => $status['networks']['rizon']['status_icon']
                ],
                'libera' => [
                    'online' => $status['networks']['libera']['online'],
                    'status_text' => $status['networks']['libera']['status_text'],
                    'status_icon' => $status['networks']['libera']['status_icon']
                ]
            ],
            'overall' => [
                'bots_online' => $status['overall']['bots_online'],
                'total_bots' => $status['overall']['total_bots'],
                'status_text' => $status['overall']['status_text'],
                'status_color' => $status['overall']['status_color']
            ]
        ];
    }
    
    /**
     * Get event system statistics
     */
    public function getEventStats() {
        return $this->eventsCore->getEventStats();
    }
    
    /**
     * Trigger a manual status check (for testing)
     */
    public function triggerStatusCheck() {
        // This would normally be called by the Python monitor
        // For now, just return current status
        return [
            'message' => 'Manual status check triggered',
            'timestamp' => time(),
            'note' => 'Real-time monitoring handles this automatically'
        ];
    }
    
    private function formatUptime($seconds) {
        if (!$seconds || $seconds < 0) return '0s';
        
        if ($seconds < 60) return $seconds . 's';
        if ($seconds < 3600) return floor($seconds/60) . 'm ' . ($seconds%60) . 's';
        if ($seconds < 86400) return floor($seconds/3600) . 'h ' . floor(($seconds%3600)/60) . 'm';
        return floor($seconds/86400) . 'd ' . floor(($seconds%86400)/3600) . 'h';
    }
    
    private function timeAgo($timestamp) {
        $diff = time() - $timestamp;
        
        if ($diff < 60) return $diff . 's ago';
        if ($diff < 3600) return floor($diff/60) . 'm ago';
        if ($diff < 86400) return floor($diff/3600) . 'h ago';
        return floor($diff/86400) . 'd ago';
    }
    
    private function getOverallStatusText($onlineCount) {
        if ($onlineCount === 2) return 'All Bots Online';
        if ($onlineCount === 1) return 'Partial Service';
        return 'All Bots Offline';
    }
    
    private function getOverallStatusColor($onlineCount) {
        if ($onlineCount === 2) return '#059669';
        if ($onlineCount === 1) return '#f59e0b';
        return '#dc2626';
    }
}

// Handle API request
try {
    // Sanitize all input
    $_GET = InputSanitizer::sanitizeAll($_GET);
    $_POST = InputSanitizer::sanitizeAll($_POST);
    
    // Validate action parameter
    $action = InputSanitizer::validateAction($_GET['action'] ?? $_POST['action'] ?? 'status');
    $statusAPI = new RealtimeBotStatusAPI();
    
    switch ($action) {
        case 'status':
        case 'realtime':
            echo json_encode($statusAPI->getRealtimeStatus());
            break;
            
        case 'public_status':
            echo json_encode($statusAPI->getPublicStatus());
            break;
            
        case 'events':
        case 'stats':
            if ($authenticated !== true) {
                echo json_encode(['error' => 'Admin access required for event stats']);
                break;
            }
            echo json_encode($statusAPI->getEventStats());
            break;
            
        case 'trigger_check':
            if ($authenticated !== true) {
                echo json_encode(['error' => 'Admin access required']);
                break;
            }
            echo json_encode($statusAPI->triggerStatusCheck());
            break;
            
        default:
            echo json_encode(['error' => 'Unknown action']);
    }
    
} catch (Exception $e) {
    error_log("Realtime Bot Status API Error: " . $e->getMessage());
    echo json_encode(['error' => 'API request failed']);
}
?>