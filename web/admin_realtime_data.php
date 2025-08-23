<?php
/**
 * Real-time Admin Data API
 * Provides live data updates for the comprehensive admin panel
 */

session_start();
require_once 'security_config.php';
require_once 'auth.php';
require_once 'advanced_admin_functions.php';

// Check admin authentication
if (!isLoggedIn() || !isAdmin()) {
    http_response_code(403);
    echo json_encode(['error' => 'Access denied']);
    exit;
}

// Verify 2FA
if (!isset($_SESSION['2fa_verified_time']) || (time() - $_SESSION['2fa_verified_time']) > 3600) {
    http_response_code(403);
    echo json_encode(['error' => '2FA verification required']);
    exit;
}

// Set headers for JSON response
header('Content-Type: application/json');
header('Cache-Control: no-cache, no-store, must-revalidate');

$action = $_GET['action'] ?? $_POST['action'] ?? '';

switch ($action) {
    case 'bot_stats':
        echo json_encode([
            'success' => true,
            'data' => AdvancedAdmin::getBotStatistics()
        ]);
        break;
        
    case 'recent_commands':
        $limit = (int)($_GET['limit'] ?? 20);
        echo json_encode([
            'success' => true,
            'data' => AdvancedAdmin::getRecentCommands($limit)
        ]);
        break;
        
    case 'game_stats':
        echo json_encode([
            'success' => true,
            'data' => AdvancedAdmin::getGameStatistics()
        ]);
        break;
        
    case 'user_analytics':
        echo json_encode([
            'success' => true,
            'data' => AdvancedAdmin::getUserAnalytics()
        ]);
        break;
        
    case 'security_events':
        $limit = (int)($_GET['limit'] ?? 20);
        echo json_encode([
            'success' => true,
            'data' => AdvancedAdmin::getSecurityEvents($limit)
        ]);
        break;
        
    case 'db_health':
        echo json_encode([
            'success' => true,
            'data' => AdvancedAdmin::getDatabaseHealth()
        ]);
        break;
        
    case 'command_performance':
        echo json_encode([
            'success' => true,
            'data' => AdvancedAdmin::getCommandPerformance()
        ]);
        break;
        
    case 'live_feed':
        // Combined data for activity feed
        echo json_encode([
            'success' => true,
            'data' => [
                'commands' => AdvancedAdmin::getRecentCommands(10),
                'security' => AdvancedAdmin::getSecurityEvents(5),
                'bot_stats' => AdvancedAdmin::getBotStatistics(),
                'game_stats' => AdvancedAdmin::getGameStatistics(),
                'user_analytics' => AdvancedAdmin::getUserAnalytics()
            ]
        ]);
        break;
        
    case 'system_health':
        // System resource monitoring
        $stats = [
            'cpu' => 0,
            'memory' => 0,
            'disk' => 0,
            'load' => [0, 0, 0],
            'processes' => 0
        ];
        
        try {
            // CPU load
            $load = sys_getloadavg();
            $stats['load'] = $load;
            $stats['cpu'] = round($load[0] * 100 / 4, 1); // Assuming 4 cores
            
            // Memory usage
            $free = shell_exec('free');
            if ($free) {
                preg_match_all('/\s+(\d+)/', $free, $matches);
                if (count($matches[1]) >= 6) {
                    $stats['memory'] = round(($matches[1][0] - $matches[1][1]) / $matches[1][0] * 100, 1);
                }
            }
            
            // Disk usage
            $disk_free = disk_free_space('/');
            $disk_total = disk_total_space('/');
            if ($disk_free && $disk_total) {
                $stats['disk'] = round((1 - $disk_free / $disk_total) * 100, 1);
            }
            
            // Process count
            $processes = shell_exec('ps aux | wc -l');
            $stats['processes'] = (int)trim($processes) - 1; // Subtract header line
            
        } catch (Exception $e) {
            error_log("Error getting system health: " . $e->getMessage());
        }
        
        echo json_encode([
            'success' => true,
            'data' => $stats
        ]);
        break;
        
    case 'network_status':
        // Network connectivity and bot status
        echo json_encode([
            'success' => true,
            'data' => AdvancedAdmin::getBotStatus()
        ]);
        break;
        
    case 'live_logs':
        $network = $_GET['network'] ?? 'rizon';
        $lines = (int)($_GET['lines'] ?? 50);
        echo json_encode([
            'success' => true,
            'data' => AdvancedAdmin::getLiveLogs($network, $lines)
        ]);
        break;
        
    case 'system_resources':
        echo json_encode([
            'success' => true,
            'data' => AdvancedAdmin::getSystemResources()
        ]);
        break;
        
    case 'bot_management':
        $action = $_POST['bot_action'] ?? '';
        if (empty($action)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'No action specified']);
            break;
        }
        
        $result = AdvancedAdmin::manageBots($action);
        echo json_encode($result);
        break;
        
    case 'system_health':
        // Get combined system status 
        echo json_encode([
            'success' => true,
            'data' => [
                'bot_stats' => AdvancedAdmin::getBotStatistics(),
                'system_resources' => AdvancedAdmin::getSystemResources(),
                'network_status' => AdvancedAdmin::getBotStatus()
            ]
        ]);
        break;
        
    default:
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'Invalid action specified'
        ]);
        break;
}
?>