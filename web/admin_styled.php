<?php
/**
 * Admin Panel - Styled to Match Main Website
 * Looks exactly like the main PyBorg site but with admin functionality
 */

// Security initialization
require_once 'security_config.php';
require_once 'auth.php';
require_once 'security_hardened.php';
require_once 'emergency_security.php';

// Function to format uptime
function formatUptime($seconds) {
    if ($seconds < 60) {
        return $seconds . 's';
    } elseif ($seconds < 3600) {
        $hours = floor($seconds / 60);
        $minutes = $seconds % 60;
        return $hours . 'm ' . $minutes . 's';
    } elseif ($seconds < 86400) {
        $hours = floor($seconds / 3600);
        $minutes = floor(($seconds % 3600) / 60);
        return $hours . 'h ' . $minutes . 'm';
    } else {
        $days = floor($seconds / 86400);
        $hours = floor(($seconds % 86400) / 3600);
        return $days . 'd ' . $hours . 'h';
    }
}
require_once 'advanced_admin_functions.php';

// Enhanced security headers
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// Check admin authentication
$is_admin = false;
$admin_verified = false;

if (isLoggedIn() && isAdmin()) {
    $is_admin = true;
    
    // Check 2FA verification
    if (isset($_SESSION['2fa_verified_time']) && (time() - $_SESSION['2fa_verified_time']) <= 3600) {
        $admin_verified = true;
    }
    
    // Verify IP binding
    if (!isset($_SESSION['bound_ip']) || $_SESSION['bound_ip'] !== $_SERVER['REMOTE_ADDR']) {
        $admin_verified = false;
    }
}

// If not admin verified, redirect to login
if (!$admin_verified) {
    header('Location: /auth.php');
    exit;
}

// Handle AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    
    $action = $_POST['action'];
    $response = ['success' => false, 'message' => 'Unknown action'];
    
    // Debug: log the request
    error_log("Admin panel AJAX request: action=$action, user=" . ($_SESSION['username'] ?? 'none'));
    
    // Check if we're authenticated (simplified check for AJAX)
    if (!isLoggedIn() || !isAdmin()) {
        $response = ['success' => false, 'message' => 'Authentication required'];
        echo json_encode($response);
        exit;
    }
    
    // SECURITY: Verify admin authentication for ALL actions
    if (!$admin_verified) {
        $response = ['success' => false, 'message' => 'Admin authentication required'];
        echo json_encode($response);
        exit;
    }
    
    switch ($action) {
        case 'get_beans_data':
            try {
                // Get beans from both networks
                $beans = [];
                $networks = ['rizon', 'libera'];
                
                foreach ($networks as $network) {
                    $db_file = ($network === 'libera') 
                        ? '/data/cr0_system/databases/libera_bot.db' 
                        : '/data/cr0_system/databases/rizon_bot.db';
                    
                    if (file_exists($db_file)) {
                        try {
                            $db = new SQLite3($db_file);
                            $db->busyTimeout(5000);
                            
                            $query = 'SELECT id, url, added_by, added_time, channel, description, view_count, last_viewed 
                                     FROM bean_images 
                                     ORDER BY added_time DESC';
                            
                            $result = $db->query($query);
                            
                            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                                $row['network'] = $network;
                                $beans[] = $row;
                            }
                            
                            $db->close();
                        } catch (Exception $e) {
                            error_log("Error loading beans from $network: " . $e->getMessage());
                        }
                    }
                }
                
                // Sort all beans by added_time DESC
                usort($beans, function($a, $b) {
                    return strtotime($b['added_time']) - strtotime($a['added_time']);
                });
                
                // Calculate stats
                $rizon_count = count(array_filter($beans, fn($b) => $b['network'] === 'rizon'));
                $libera_count = count(array_filter($beans, fn($b) => $b['network'] === 'libera'));
                $total_views = array_sum(array_column($beans, 'view_count'));
                
                $response = [
                    'success' => true,
                    'beans' => $beans,
                    'total' => count($beans),
                    'rizon_count' => $rizon_count,
                    'libera_count' => $libera_count,
                    'total_views' => $total_views
                ];
            } catch (Exception $e) {
                $response = ['success' => false, 'message' => 'Error loading beans: ' . $e->getMessage()];
            }
            break;
            
        case 'delete_bean':
            try {
                $bean_id = intval($_POST['bean_id'] ?? 0);
                $network = $_POST['network'] ?? 'rizon';
                
                if ($bean_id <= 0) {
                    $response = ['success' => false, 'message' => 'Invalid bean ID'];
                    break;
                }
                
                $db_file = ($network === 'libera') 
                    ? '/data/cr0_system/databases/libera_bot.db' 
                    : '/data/cr0_system/databases/rizon_bot.db';
                
                $db = new SQLite3($db_file);
                $db->busyTimeout(5000);
                
                // Get bean info before deletion for logging
                $stmt = $db->prepare('SELECT url, added_by FROM bean_images WHERE id = :id');
                $stmt->bindValue(':id', $bean_id, SQLITE3_INTEGER);
                $result = $stmt->execute();
                $bean_info = $result->fetchArray(SQLITE3_ASSOC);
                
                if ($bean_info) {
                    // Delete the bean
                    $stmt = $db->prepare('DELETE FROM bean_images WHERE id = :id');
                    $stmt->bindValue(':id', $bean_id, SQLITE3_INTEGER);
                    
                    if ($stmt->execute()) {
                        $response = ['success' => true, 'message' => 'Bean deleted successfully'];
                        
                        // Log the action
                        error_log("Bean deleted: ID=$bean_id, URL={$bean_info['url']}, Network=$network, Admin={$_SESSION['username']}");
                    } else {
                        $response = ['success' => false, 'message' => 'Failed to delete bean'];
                    }
                } else {
                    $response = ['success' => false, 'message' => 'Bean not found'];
                }
                
                $db->close();
            } catch (Exception $e) {
                $response = ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
            }
            break;
            
        case 'get_live_data':
            try {
                // Debug AJAX data loading
                error_log("AJAX get_live_data called");
                
                $bot_stats = AdvancedAdmin::getBotStatistics();
                $recent_commands = AdvancedAdmin::getRecentCommands(15);
                
                // Ensure we always have an array for recent_commands
                if (!$recent_commands || !is_array($recent_commands)) {
                    $recent_commands = [];
                    error_log("AJAX: recent_commands was null/invalid, using empty array");
                }
                
                error_log("AJAX bot_stats: " . json_encode($bot_stats));
                error_log("AJAX recent_commands count: " . count($recent_commands));
                
                $response = [
                    'success' => true,
                    'bot_stats' => $bot_stats,
                    'recent_commands' => $recent_commands,
                    'game_stats' => AdvancedAdmin::getGameStatistics(),
                    'user_analytics' => AdvancedAdmin::getUserAnalytics(),
                    'system_resources' => AdvancedAdmin::getSystemResources(),
                    'security_events' => AdvancedAdmin::getSecurityEvents(10),
                    'security_dashboard' => HardcoreSecurityManager::getSecurityDashboard(),
                    'emergency_status' => EmergencySecurityResponse::getDashboard(),
                    'db_health' => AdvancedAdmin::getDatabaseHealth(),
                    'performance' => AdvancedAdmin::getCommandPerformance()
                ];
                
                error_log("AJAX response prepared successfully");
            } catch (Exception $e) {
                error_log("AJAX error: " . $e->getMessage());
                $response = ['success' => false, 'message' => $e->getMessage()];
            }
            break;
            
        case 'bot_action':
            $bot_action = $_POST['bot_action'] ?? '';
            $response = AdvancedAdmin::manageBots($bot_action);
            break;
            
        case 'get_live_logs':
            $network = $_POST['network'] ?? 'rizon';
            $lines = (int)($_POST['lines'] ?? 50);
            try {
                $response = [
                    'success' => true,
                    'data' => AdvancedAdmin::getLiveLogs($network, $lines)
                ];
            } catch (Exception $e) {
                $response = ['success' => false, 'message' => $e->getMessage()];
            }
            break;
            
        case 'security_action':
            $security_action = $_POST['security_action'] ?? '';
            $ip_address = $_POST['ip_address'] ?? '';
            $reason = $_POST['reason'] ?? 'Manual admin action';
            
            switch ($security_action) {
                case 'block_ip':
                    if (!empty($ip_address) && filter_var($ip_address, FILTER_VALIDATE_IP)) {
                        HardcoreSecurityManager::blockIP($ip_address, $reason);
                        $response = ['success' => true, 'message' => "IP $ip_address blocked successfully"];
                    } else {
                        $response = ['success' => false, 'message' => 'Invalid IP address'];
                    }
                    break;
                    
                case 'unblock_ip':
                    if (!empty($ip_address)) {
                        // Load blocked IPs and remove the specified one
                        $blocked_file = '/tmp/blocked_ips.json';
                        if (file_exists($blocked_file)) {
                            $blocked_ips = json_decode(file_get_contents($blocked_file), true) ?: [];
                            if (isset($blocked_ips[$ip_address])) {
                                unset($blocked_ips[$ip_address]);
                                file_put_contents($blocked_file, json_encode($blocked_ips, JSON_PRETTY_PRINT));
                                HardcoreSecurityManager::logSecurityEvent('UNBLOCK', "IP manually unblocked by admin", $ip_address);
                                $response = ['success' => true, 'message' => "IP $ip_address unblocked successfully"];
                            } else {
                                $response = ['success' => false, 'message' => "IP $ip_address was not blocked"];
                            }
                        } else {
                            $response = ['success' => false, 'message' => 'No blocked IPs file found'];
                        }
                    } else {
                        $response = ['success' => false, 'message' => 'IP address required'];
                    }
                    break;
                    
                case 'toggle_emergency_lockdown':
                    if (EmergencySecurityResponse::isLockdownActive()) {
                        // Deactivate lockdown
                        $lockdown_file = '/tmp/emergency_lockdown.flag';
                        if (file_exists($lockdown_file)) {
                            unlink($lockdown_file);
                        }
                        HardcoreSecurityManager::logSecurityEvent('EMERGENCY', 'Emergency lockdown manually deactivated by admin');
                        $response = ['success' => true, 'message' => 'Emergency lockdown deactivated'];
                    } else {
                        // Activate lockdown
                        EmergencySecurityResponse::activateEmergencyLockdown();
                        $response = ['success' => true, 'message' => 'Emergency lockdown activated'];
                    }
                    break;
                    
                default:
                    $response = ['success' => false, 'message' => 'Invalid security action'];
            }
            break;
            
        case 'hall_of_fame_action':
            $hall_action = $_POST['hall_action'] ?? '';
            
            switch ($hall_action) {
                case 'delete_score':
                    $score_id = (int)($_POST['score_id'] ?? 0);
                    if ($score_id > 0) {
                        $response = AdvancedAdmin::deleteHallOfFameScore($score_id);
                    } else {
                        $response = ['success' => false, 'message' => 'Invalid score ID'];
                    }
                    break;
                    
                case 'delete_multiple':
                    $score_ids = $_POST['score_ids'] ?? '';
                    if (!empty($score_ids)) {
                        $ids = array_map('intval', array_filter(explode(',', $score_ids)));
                        if (!empty($ids)) {
                            $response = AdvancedAdmin::deleteMultipleHallOfFameScores($ids);
                        } else {
                            $response = ['success' => false, 'message' => 'No valid score IDs provided'];
                        }
                    } else {
                        $response = ['success' => false, 'message' => 'No score IDs provided'];
                    }
                    break;
                    
                case 'ban_player':
                    $player_name = $_POST['player_name'] ?? '';
                    if (!empty($player_name)) {
                        $response = AdvancedAdmin::banPlayerFromHallOfFame($player_name);
                    } else {
                        $response = ['success' => false, 'message' => 'Player name required'];
                    }
                    break;
                    
                case 'clear_all':
                    $response = AdvancedAdmin::clearAllHallOfFameScores();
                    break;
                    
                default:
                    $response = ['success' => false, 'message' => 'Invalid hall of fame action'];
            }
            break;
            
        default:
            $response['message'] = 'Invalid action';
    }
    
    echo json_encode($response);
    exit;
}

// Handle GET requests for logs (for AJAX compatibility)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'live_logs') {
    header('Content-Type: application/json');
    
    $network = $_GET['network'] ?? 'rizon';
    $lines = (int)($_GET['lines'] ?? 50);
    
    try {
        $response = [
            'success' => true,
            'data' => AdvancedAdmin::getLiveLogs($network, $lines)
        ];
    } catch (Exception $e) {
        $response = ['success' => false, 'message' => $e->getMessage()];
    }
    
    echo json_encode($response);
    exit;
}

// Log admin access
logSecurityEvent('ADMIN_STYLED_ACCESS', "Styled admin panel accessed by {$_SESSION['username']}", 'MEDIUM');

// Get initial data with better error handling
$bot_stats = ['rizon' => ['status' => 'Online'], 'libera' => ['status' => 'Online']]; // Default to Online
$game_stats = ['active_games' => 0, 'games_today' => 0];
$user_analytics = ['total_users' => 0, 'active_today' => 0];
$system_resources = ['cpu_usage' => 0, 'memory_usage' => 0, 'disk_usage' => 0, 'uptime' => 0];
$recent_commands = [];

// Set minimal server context for functions that need it
if (!isset($_SERVER['REMOTE_ADDR'])) {
    $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
}
if (!isset($_SERVER['REQUEST_METHOD'])) {
    $_SERVER['REQUEST_METHOD'] = 'GET';
}

// Always try to load real data, but have sane defaults
$data_loaded = false;
try {
    // Check if class and methods exist
    if (class_exists('AdvancedAdmin') && method_exists('AdvancedAdmin', 'getBotStatistics')) {
        // Load data with simplified error handling
        $bot_stats_real = AdvancedAdmin::getBotStatistics();
        if ($bot_stats_real && is_array($bot_stats_real)) {
            $bot_stats = $bot_stats_real;
            $data_loaded = true;
            error_log("Real bot stats loaded: " . json_encode($bot_stats));
        }
        
        $recent_commands_real = AdvancedAdmin::getRecentCommands(10);
        if ($recent_commands_real && is_array($recent_commands_real)) {
            $recent_commands = $recent_commands_real;
            error_log("Real commands loaded: " . count($recent_commands) . " commands");
        }
        
        $game_stats = AdvancedAdmin::getGameStatistics();
        $user_analytics = AdvancedAdmin::getUserAnalytics();
        $system_resources = AdvancedAdmin::getSystemResources();
    } else {
        error_log("AdvancedAdmin class or methods not found");
    }
} catch (Exception $e) {
    error_log("Error loading initial admin data: " . $e->getMessage());
    error_log("Stack trace: " . $e->getTraceAsString());
}

// If data loading failed, create fake data for testing
if (!$data_loaded) {
    error_log("Using fake data for testing");
    $bot_stats = [
        'rizon' => ['status' => 'Online', 'commands_today' => 5, 'users_active' => 2],
        'libera' => ['status' => 'Online', 'commands_today' => 3, 'users_active' => 1]
    ];
    $recent_commands = [
        ['command' => 'test_command', 'username' => 'test_user', 'channel' => '#test', 'timestamp' => date('Y-m-d H:i:s'), 'network' => 'rizon'],
        ['command' => 'another_command', 'username' => 'another_user', 'channel' => '#test2', 'timestamp' => date('Y-m-d H:i:s'), 'network' => 'libera'],
    ];
}

// Real bot status should now be loaded correctly
error_log("Final bot_stats before HTML: " . json_encode($bot_stats));
?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyBorg - Admin Panel</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200" />
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        /* Material Symbols */
        .material-symbols-outlined {
            font-family: 'Material Symbols Outlined';
            font-weight: normal;
            font-style: normal;
            font-size: 24px;
            line-height: 1;
            letter-spacing: normal;
            text-transform: none;
            display: inline-block;
            white-space: nowrap;
            word-wrap: normal;
            direction: ltr;
            -webkit-font-feature-settings: 'liga';
            -webkit-font-smoothing: antialiased;
        }

        :root {
            --primary-color: #2563eb;
            --primary-dark: #1d4ed8;
            --primary-light: #3b82f6;
            --text-primary: #111827;
            --text-secondary: #6b7280;
            --text-muted: #9ca3af;
            --bg-primary: #ffffff;
            --bg-secondary: #f9fafb;
            --bg-tertiary: #f3f4f6;
            --border-light: #e5e7eb;
            --border-medium: #d1d5db;
            --accent-blue: #eff6ff;
            --accent-green: #f0fdf4;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            --radius-sm: 0.375rem;
            --radius-md: 0.5rem;
            --radius-lg: 0.75rem;
            --radius-xl: 1rem;
            --font-mono: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
        }

        [data-theme="dark"] {
            --primary-color: #3b82f6;
            --primary-dark: #2563eb;
            --primary-light: #60a5fa;
            --text-primary: #f9fafb;
            --text-secondary: #d1d5db;
            --text-muted: #9ca3af;
            --bg-primary: #1f2937;
            --bg-secondary: #111827;
            --bg-tertiary: #374151;
            --border-light: #374151;
            --border-medium: #4b5563;
            --accent-blue: #1e3a8a;
            --accent-green: #14532d;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.3);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.3), 0 2px 4px -2px rgb(0 0 0 / 0.3);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.3), 0 4px 6px -4px rgb(0 0 0 / 0.3);
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-secondary);
            color: var(--text-primary);
            line-height: 1.6;
            font-weight: 400;
            transition: background-color 0.2s ease, color 0.2s ease;
        }

        /* Dark Mode Toggle */
        .theme-toggle {
            position: fixed;
            top: 1rem;
            right: 1rem;
            z-index: 1000;
            background: var(--bg-primary);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-lg);
            padding: 0.75rem;
            box-shadow: var(--shadow-md);
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-secondary);
        }

        .theme-toggle:hover {
            background: var(--bg-tertiary);
            border-color: var(--border-medium);
            transform: translateY(-1px);
            box-shadow: var(--shadow-lg);
        }

        .theme-toggle-icon {
            font-size: 1rem;
            color: var(--primary-color);
            transition: transform 0.2s ease;
        }

        .theme-toggle:hover .theme-toggle-icon {
            transform: rotate(15deg);
        }

        /* Admin Auth Info */
        .auth-container {
            position: fixed;
            top: 1rem;
            left: 1rem;
            z-index: 1000;
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }

        .user-info {
            background: var(--bg-primary);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-lg);
            padding: 0.75rem 1rem;
            box-shadow: var(--shadow-md);
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
            color: var(--text-primary);
        }

        .admin-badge {
            background: #dc2626;
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: var(--radius-sm);
            font-size: 0.75rem;
            font-weight: 600;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem 1rem;
        }

        .header {
            text-align: center;
            margin-bottom: 3rem;
            padding: 2rem 0;
            background: linear-gradient(135deg, var(--accent-blue) 0%, var(--bg-primary) 100%);
            border-radius: var(--radius-xl);
            border: 1px solid var(--border-light);
            box-shadow: var(--shadow-lg);
        }

        .header h1 {
            font-size: 3rem;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 0.5rem;
        }

        .header .subtitle {
            font-size: 1.125rem;
            color: var(--text-secondary);
            font-weight: 400;
        }

        .network-tabs {
            display: flex;
            justify-content: center;
            gap: 1rem;
            margin-top: 2rem;
            flex-wrap: wrap;
        }

        .tab-button {
            background: var(--bg-primary);
            border: 1px solid var(--border-light);
            color: var(--text-secondary);
            padding: 0.75rem 1.5rem;
            border-radius: var(--radius-lg);
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: var(--shadow-sm);
            white-space: nowrap;
        }

        .tab-button:hover {
            background: var(--bg-tertiary);
            border-color: var(--border-medium);
            color: var(--text-primary);
            transform: translateY(-1px);
            box-shadow: var(--shadow-md);
        }

        .tab-button.active {
            background: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
            box-shadow: var(--shadow-md);
        }

        /* Tab Content Areas */
        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        /* Admin Content Areas */
        .admin-content {
            display: block;
        }

        .admin-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(min(280px, 100%), 1fr));
            gap: 1.25rem;
        }

        /* Override for overview tab to ensure equal width cards */
        #overview-content .admin-grid {
            grid-template-columns: 1fr 1fr 1fr;
            gap: 1.25rem;
        }

        #security-content .admin-grid {
            grid-template-columns: 1fr 1fr 1fr;
            gap: 1.25rem;
        }
        
        /* Tools tab - stack cards vertically and full width */
        #tools-content .admin-grid {
            grid-template-columns: 1fr;
            gap: 1.25rem;
        }
        
        /* Live Logs tab - stack cards vertically and full width */
        #logs-content .admin-grid {
            grid-template-columns: 1fr;
            gap: 1.25rem;
        }

        .admin-card {
            background: var(--bg-primary);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-xl);
            padding: 1.75rem;
            box-shadow: var(--shadow-lg);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
            min-width: 0;
        }
        
        /* Dynamic hover glow effect for all admin cards */
        .admin-card {
            transition: all 0.3s ease;
            position: relative;
        }
        
        .admin-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 0 20px rgba(37, 99, 235, 0.15), 0 8px 25px rgba(37, 99, 235, 0.3);
            border-color: var(--primary-color);
        }
        
        .admin-card:hover::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(135deg, rgba(37, 99, 235, 0.05) 0%, rgba(37, 99, 235, 0.02) 100%);
            border-radius: inherit;
            pointer-events: none;
            z-index: 1;
        }
        
        .admin-card:hover h3 {
            color: var(--primary-color);
            transition: color 0.3s ease;
        }
        
        /* Ensure content stays above hover overlay */
        .admin-card > * {
            position: relative;
            z-index: 2;
        }
        
        /* Enhanced system resources with progress bars */
        .resource-progress {
            margin: 0.25rem 0;
        }
        
        .progress-bar {
            width: 100%;
            height: 6px;
            background: var(--bg-tertiary);
            border-radius: 3px;
            overflow: hidden;
            position: relative;
            border: 1px solid var(--border-light);
        }
        
        .progress-fill {
            height: 100%;
            border-radius: 3px;
            transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
        }
        
        .progress-fill.low { background: linear-gradient(90deg, #10b981, #34d399); }
        .progress-fill.medium { background: linear-gradient(90deg, #f59e0b, #fbbf24); }
        .progress-fill.high { background: linear-gradient(90deg, #ef4444, #f87171); }
        
        .progress-fill::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(45deg, transparent 33%, rgba(255,255,255,0.2) 50%, transparent 66%);
            animation: shimmer 1.5s infinite;
        }
        
        @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }
        
        .admin-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: linear-gradient(135deg, var(--primary-color), var(--accent-color));
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        
        /* Pulse animation for online status */
        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.05); opacity: 0.8; }
        }
        
        .status-pulse {
            animation: pulse 2s infinite;
        }
        
        
        /* Terminal styling for tech appeal */
        .terminal-style {
            background: #0f172a;
            color: #10b981;
            font-family: 'Fira Code', 'Monaco', 'Cascadia Code', monospace;
            border: 1px solid #1e293b;
        }
        
        .terminal-header {
            background: #1e293b;
            color: #64748b;
            padding: 0.5rem 1rem;
            border-bottom: 1px solid #334155;
            font-size: 0.875rem;
        }
        
        .terminal-content {
            padding: 1rem;
            max-height: 300px;
            overflow-y: auto;
            font-size: 0.875rem;
            line-height: 1.6;
        }
        
        .security-event-item {
            margin-bottom: 0.5rem;
            padding: 0.5rem;
            border-radius: 0.25rem;
            background: rgba(16, 185, 129, 0.1);
        }
        
        .security-timestamp {
            color: #64748b;
            font-weight: bold;
        }
        
        .security-type {
            color: #f59e0b;
            font-weight: bold;
        }
        
        .security-ip {
            color: #ef4444;
            font-weight: bold;
        }

        .admin-card h3 {
            color: var(--primary-color);
            font-size: 1.375rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .admin-stats {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
            margin: 1.5rem 0;
        }

        .stat-item {
            text-align: center;
            padding: 1.25rem;
            background: var(--bg-secondary);
            border-radius: var(--radius-lg);
            border: 1px solid var(--border-light);
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--primary-color);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            flex-direction: column;
            font-family: 'Fira Code', 'Monaco', monospace;
            transition: all 0.3s ease;
        }
        
        .stat-value.large {
            font-size: 2.5rem;
        }
        
        .stat-value.animated {
            transition: all 0.6s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        
        .live-indicator {
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
            font-size: 0.75rem;
            color: #10b981;
            font-weight: 500;
            margin-top: 0.25rem;
        }
        
        .live-dot {
            width: 6px;
            height: 6px;
            background: #10b981;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        
        .bot-details {
            color: var(--text-secondary);
            font-size: 0.75rem;
            font-weight: 400;
            margin-top: 0.25rem;
            opacity: 0.8;
        }

        /* Table styles */
        .table-container {
            overflow-x: auto;
            border-radius: var(--radius-md);
            border: 1px solid var(--border-light);
            background: var(--bg-secondary);
            margin-top: 1rem;
        }
        
        .admin-table {
            width: 100%;
            border-collapse: collapse;
            min-width: 600px; /* Ensures table doesn't get too cramped */
        }
        
        .admin-table th,
        .admin-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-light);
        }
        
        .admin-table th {
            background: var(--bg-secondary);
            font-weight: 600;
            color: var(--text-primary);
        }
        
        .admin-table td {
            color: var(--text-secondary);
        }
        
        .text-center {
            text-align: center;
        }

        /* Activity bar styles */
        .activity-bar {
            width: 100%;
            height: 6px;
            background: var(--border-light);
            border-radius: 3px;
            overflow: hidden;
        }
        
        .activity-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary-color), var(--accent-color));
            transition: width 0.3s ease;
        }

        /* Engagement metrics */
        .engagement-metrics {
            display: flex;
            flex-direction: column;
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .metric-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 0;
            border-bottom: 1px solid var(--border-light);
        }
        
        .metric-row:last-child {
            border-bottom: none;
        }
        
        .metric-label {
            font-weight: 500;
            color: var(--text-primary);
        }
        
        .metric-value {
            font-weight: 600;
            color: var(--primary-color);
        }

        /* Security status styles */
        .security-status {
            display: flex;
            flex-direction: column;
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .status-item {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 0.75rem;
            background: var(--bg-secondary);
            border-radius: var(--radius-md);
        }
        
        .status-icon {
            width: 2.5rem;
            height: 2.5rem;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
        }
        
        .status-icon.online {
            background: #10b981;
            color: white;
        }
        
        .status-icon.offline {
            background: #ef4444;
            color: white;
        }
        
        .status-content {
            flex: 1;
        }
        
        .status-title {
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 0.25rem;
        }
        
        .status-meta {
            font-size: 0.875rem;
            color: var(--text-secondary);
        }

        /* Timeline styles */
        .activity-timeline {
            margin-top: 1rem;
        }
        
        .timeline-item {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 1rem;
            background: var(--bg-secondary);
            border-radius: var(--radius-md);
        }
        
        .timeline-icon {
            width: 2.5rem;
            height: 2.5rem;
            border-radius: 50%;
            background: var(--primary-color);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
        }
        
        .timeline-content {
            flex: 1;
        }
        
        .timeline-title {
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 0.25rem;
        }
        
        .timeline-meta {
            font-size: 0.875rem;
            color: var(--text-secondary);
        }

        /* Security severity status badges */
        .status.low {
            background: #10b981;
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: var(--radius-sm);
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .status.medium {
            background: #f59e0b;
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: var(--radius-sm);
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .status.high {
            background: #ef4444;
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: var(--radius-sm);
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .status.critical {
            background: #7c2d12;
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: var(--radius-sm);
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }

        .stat-label {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-top: 0.5rem;
            font-weight: 500;
        }

        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }

        .status-online {
            background: #10b981;
            box-shadow: 0 0 6px rgba(16, 185, 129, 0.5);
        }

        .status-offline {
            background: #ef4444;
            box-shadow: 0 0 6px rgba(239, 68, 68, 0.5);
        }

        .admin-actions {
            display: flex;
            gap: 0.75rem;
            margin-top: 1.5rem;
            flex-wrap: wrap;
        }

        .admin-btn {
            background: var(--primary-color);
            color: white;
            border: none;
            padding: 0.75rem 1.25rem;
            border-radius: var(--radius-md);
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.875rem;
        }

        .admin-btn:hover {
            background: var(--primary-dark);
            transform: translateY(-1px);
            box-shadow: var(--shadow-md);
        }

        .admin-btn.danger {
            background: #ef4444;
        }

        .admin-btn.danger:hover {
            background: #dc2626;
        }
        
        /* Input styling */
        .admin-input {
            padding: 0.75rem;
            border: 1px solid var(--border-light);
            border-radius: var(--radius-md);
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 0.875rem;
            transition: all 0.2s ease;
            min-width: 0; /* Prevents input overflow */
        }
        
        .admin-input:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.08);
        }
        
        .admin-input::placeholder {
            color: var(--text-muted);
        }
        
        /* Security-specific enhancements */
        .security-status .status-item {
            border-radius: var(--radius-md);
            background: rgba(255, 255, 255, 0.05);
            transition: all 0.2s ease;
        }
        
        .security-status .status-item:hover {
            background: rgba(255, 255, 255, 0.1);
            transform: translateX(4px);
        }
        
        .admin-table tbody tr:hover {
            background: var(--bg-secondary);
            transform: scale(1.005);
            transition: all 0.2s ease;
        }
        
        .admin-table th {
            background: var(--bg-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.05em;
        }
        
        /* Threat level badges */
        .status.high {
            background: linear-gradient(135deg, #ef4444, #dc2626);
            animation: pulse-danger 2s infinite;
        }
        
        .status.medium {
            background: linear-gradient(135deg, #f59e0b, #d97706);
        }
        
        .status.low {
            background: linear-gradient(135deg, #10b981, #059669);
        }
        
        @keyframes pulse-danger {
            0%, 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
            50% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
        }

        .admin-btn.success {
            background: #10b981;
        }

        .admin-btn.success:hover {
            background: #059669;
        }

        .activity-feed {
            max-height: 300px;
            overflow-y: auto;
            border: 1px solid var(--border-light);
            border-radius: var(--radius-md);
            background: var(--bg-secondary);
        }

        .activity-item {
            padding: 1rem;
            border-bottom: 1px solid var(--border-light);
            display: flex;
            align-items: flex-start;
            gap: 1rem;
            font-size: 0.875rem;
        }

        .activity-item:last-child {
            border-bottom: none;
        }

        .activity-icon {
            width: 36px;
            height: 36px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.875rem;
            flex-shrink: 0;
        }

        .activity-icon.command {
            background: rgba(37, 99, 235, 0.1);
            color: var(--primary-color);
        }

        .activity-icon.security {
            background: rgba(239, 68, 68, 0.1);
            color: #ef4444;
        }

        .activity-content {
            flex: 1;
        }

        .activity-title {
            font-weight: 500;
            color: var(--text-primary);
            margin-bottom: 0.25rem;
        }

        .activity-meta {
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .loading {
            opacity: 0.6;
            pointer-events: none;
        }

        .spinner {
            display: inline-block;
            width: 1rem;
            height: 1rem;
            border: 2px solid var(--border-light);
            border-radius: 50%;
            border-top-color: var(--primary-color);
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .log-output {
            background: #000;
            color: #0f0;
            padding: 1rem;
            border-radius: var(--radius-md);
            font-family: var(--font-mono);
            font-size: 0.75rem;
            max-height: 200px;
            overflow-y: auto;
            white-space: pre-wrap;
            margin-top: 1rem;
        }


        /* Dark mode styles */
        [data-theme="dark"] .admin-card {
            background: var(--bg-primary);
            border-color: var(--border-light);
        }

        [data-theme="dark"] .stat-item {
            background: var(--bg-secondary);
            border-color: var(--border-light);
        }

        [data-theme="dark"] .activity-feed {
            background: var(--bg-secondary);
            border-color: var(--border-light);
        }

        [data-theme="dark"] .activity-item {
            border-bottom-color: var(--border-light);
        }

        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }

            .header h1 {
                font-size: 2rem;
            }

            .admin-grid {
                grid-template-columns: 1fr;
                gap: 1rem;
            }

            .admin-stats {
                grid-template-columns: 1fr;
            }
            
            /* IP Management responsive styling */
            .admin-card div[style*="grid-template-columns"] {
                grid-template-columns: 1fr !important;
                gap: 0.5rem !important;
            }
            
            .admin-table {
                min-width: 500px; /* Slightly smaller minimum for mobile */
            }
            
            .admin-card {
                padding: 1.25rem;
            }

            .auth-container {
                position: static;
                margin-bottom: 1rem;
                justify-content: center;
            }

            .theme-toggle {
                position: static;
                margin-bottom: 1rem;
            }
        }
        
        /* Command injection interface styles */
        .button-group {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-top: 0.5rem;
        }
        
        .network-btn {
            padding: 0.5rem 1rem;
            border: 1px solid var(--border-light);
            border-radius: var(--radius-md);
            background: var(--bg-secondary);
            color: var(--text-primary);
            cursor: pointer;
            transition: all 0.2s ease;
            font-size: 0.875rem;
        }
        
        .network-btn:hover {
            background: var(--bg-tertiary);
            border-color: var(--primary-color);
        }
        
        .network-btn.active {
            background: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
        }
        
        .command-preview {
            background: var(--bg-secondary);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-md);
            padding: 0.75rem;
            margin-top: 0.5rem;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            color: var(--text-secondary);
            min-height: 2rem;
        }
    </style>
</head>
<body>
    <!-- Theme Toggle (matches main site) -->
    <div class="theme-toggle" onclick="toggleTheme()">
        <span class="theme-toggle-icon material-symbols-outlined">dark_mode</span>
        <span class="theme-toggle-text">Dark</span>
    </div>

    <!-- Admin Auth Info -->
    <div class="auth-container">
        <div class="user-info">
            <span class="admin-badge">ADMIN</span>
            <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong>
            <span>•</span>
            <span>Session: <?php echo date('H:i:s', $_SESSION['login_time']); ?></span>
        </div>
    </div>

    <div class="container">
        <div class="header">
            <h1>🛡️ Barf Sucks</h1>
            <p class="subtitle">IRC Bot Administration Panel</p>
            <div class="network-tabs">
                <button class="tab-button active" onclick="showTab('overview')">
                    📊 Overview
                </button>
                <button class="tab-button" onclick="showTab('commands')">
                    ⚡ Commands
                </button>
                <button class="tab-button" onclick="showTab('games')">
                    🎮 Games
                </button>
                <button class="tab-button" onclick="showTab('beans')">
                    🫘 Beans
                </button>
                <button class="tab-button" onclick="showTab('users')">
                    👥 Users
                </button>
                <button class="tab-button" onclick="showTab('security')">
                    🔒 Security
                </button>
                <button class="tab-button" onclick="showTab('logs')">
                    📜 Live Logs
                </button>
                <button class="tab-button" onclick="showTab('tools')">
                    🛠️ Tools
                </button>
                <button class="tab-button" onclick="window.location.href='/index.php'">
                    📚 Documentation
                </button>
                <button class="tab-button" onclick="window.location.href='/auth.php?action=logout'">
                    🚪 Logout
                </button>
            </div>
        </div>

        <!-- Overview Tab -->
        <div id="overview-content" class="tab-content active">
                <div class="admin-content">
                    <div class="admin-grid">
                        <!-- Bot Status - Hero Card -->
                        <div class="admin-card">
                            <h3><i class="fas fa-robot"></i> IRC Bot Network Status</h3>
                            <div class="admin-stats" style="grid-template-columns: repeat(2, 1fr);">
                                <div class="stat-item">
                                    <div class="stat-value large <?php echo $bot_stats['rizon']['status'] === 'Online' ? 'status-pulse' : ''; ?>">
                                        <span class="status-indicator <?php echo $bot_stats['rizon']['status'] === 'Online' ? 'status-online' : 'status-offline'; ?>"></span>
                                        <span id="rizon-status">! <?php echo $bot_stats['rizon']['status']; ?></span>
                                        <?php if ($bot_stats['rizon']['status'] === 'Online'): ?>
                                            <div class="live-indicator">
                                                <div class="live-dot"></div>
                                                <span>live@cr0system</span>
                                            </div>
                                            <div class="bot-details">
                                                <small>PID: <?php echo $bot_stats['rizon']['pid']; ?> | Up: <?php echo formatUptime($bot_stats['rizon']['uptime']); ?></small>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                    <div class="stat-label">Rizon Network</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value large <?php echo $bot_stats['libera']['status'] === 'Online' ? 'status-pulse' : ''; ?>">
                                        <span class="status-indicator <?php echo $bot_stats['libera']['status'] === 'Online' ? 'status-online' : 'status-offline'; ?>"></span>
                                        <span id="libera-status">~ <?php echo $bot_stats['libera']['status']; ?></span>
                                        <?php if ($bot_stats['libera']['status'] === 'Online'): ?>
                                            <div class="live-indicator">
                                                <div class="live-dot"></div>
                                                <span>live@cr0system</span>
                                            </div>
                                            <div class="bot-details">
                                                <small>PID: <?php echo $bot_stats['libera']['pid']; ?> | Up: <?php echo formatUptime($bot_stats['libera']['uptime']); ?></small>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                    <div class="stat-label">Libera Network</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value large animated" id="commands-today"><?php echo ($bot_stats['rizon']['commands_today'] ?? 0) + ($bot_stats['libera']['commands_today'] ?? 0); ?></div>
                                    <div class="live-indicator">
                                        <div class="live-dot"></div>
                                        <span>Live Data</span>
                                    </div>
                                    <div class="stat-label">Commands Today</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value large animated" id="active-users"><?php echo ($bot_stats['rizon']['users_active'] ?? 0) + ($bot_stats['libera']['users_active'] ?? 0); ?></div>
                                    <div class="live-indicator">
                                        <div class="live-dot"></div>
                                        <span>Live Data</span>
                                    </div>
                                    <div class="stat-label">Active Users</div>
                                </div>
                            </div>
                            <div class="admin-actions">
                                <button class="admin-btn success" data-action="restart_rizon">
                                    <i class="fas fa-redo"></i> Rizon
                                </button>
                                <button class="admin-btn success" data-action="restart_libera">
                                    <i class="fas fa-redo"></i> Libera
                                </button>
                                <button class="admin-btn danger" data-action="restart_all">
                                    <i class="fas fa-power-off"></i> All
                                </button>
                            </div>
                        </div>

                        <!-- System Resources with Progress Bars -->
                        <div class="admin-card">
                            <h3><i class="fas fa-server"></i> System Resources</h3>
                            <div class="admin-stats" id="system-stats">
                                <div class="stat-item">
                                    <div class="stat-value" id="cpu-usage"><?php echo $system_resources['cpu_usage']; ?>%</div>
                                    <div class="resource-progress">
                                        <div class="progress-bar">
                                            <div class="progress-fill <?php echo $system_resources['cpu_usage'] > 80 ? 'high' : ($system_resources['cpu_usage'] > 60 ? 'medium' : 'low'); ?>" style="width: <?php echo $system_resources['cpu_usage']; ?>%"></div>
                                        </div>
                                    </div>
                                    <div class="stat-label">CPU Usage</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value" id="memory-usage"><?php echo $system_resources['memory_usage']; ?>%</div>
                                    <div class="resource-progress">
                                        <div class="progress-bar">
                                            <div class="progress-fill <?php echo $system_resources['memory_usage'] > 80 ? 'high' : ($system_resources['memory_usage'] > 60 ? 'medium' : 'low'); ?>" style="width: <?php echo $system_resources['memory_usage']; ?>%"></div>
                                        </div>
                                    </div>
                                    <div class="stat-label">Memory</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value" id="disk-usage"><?php echo $system_resources['disk_usage']; ?>%</div>
                                    <div class="resource-progress">
                                        <div class="progress-bar">
                                            <div class="progress-fill <?php echo $system_resources['disk_usage'] > 80 ? 'high' : ($system_resources['disk_usage'] > 60 ? 'medium' : 'low'); ?>" style="width: <?php echo $system_resources['disk_usage']; ?>%"></div>
                                        </div>
                                    </div>
                                    <div class="stat-label">Disk</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value" id="system-uptime"><?php echo formatUptime($system_resources['uptime']); ?></div>
                                    <div class="stat-label">Uptime</div>
                                </div>
                            </div>
                        </div>

                        <!-- Game Statistics -->
                        <div class="admin-card">
                            <h3><i class="fas fa-gamepad"></i> Game Activity</h3>
                            <div class="admin-stats">
                                <div class="stat-item">
                                    <div class="stat-value" id="active-games"><?php echo $game_stats['active_games'] ?? 0; ?></div>
                                    <div class="stat-label">Active Games</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value" id="games-today"><?php echo $game_stats['games_today'] ?? 0; ?></div>
                                    <div class="stat-label">Games Today</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value" id="total-users"><?php echo $user_analytics['total_users'] ?? 0; ?></div>
                                    <div class="stat-label">Total Users</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value" id="new-users"><?php echo $user_analytics['new_this_week'] ?? 0; ?></div>
                                    <div class="stat-label">New This Week</div>
                                </div>
                            </div>
                        </div>

                        <!-- Recent Activity -->
                        <div class="admin-card" style="grid-column: 1 / -1;">
                            <h3><i class="fas fa-stream"></i> Recent Activity</h3>
                            <div class="activity-feed" id="activity-feed">
                                <!-- Debug: Recent commands count: <?php echo count($recent_commands); ?>, Data loaded: <?php echo $data_loaded ? 'YES' : 'NO'; ?> -->
                                <?php if (!empty($recent_commands)): ?>
                                    <?php foreach (array_slice($recent_commands, 0, 10) as $cmd): ?>
                                    <div class="activity-item">
                                        <div class="activity-icon command">
                                            <i class="fas fa-terminal"></i>
                                        </div>
                                        <div class="activity-content">
                                            <div class="activity-title">
                                                <?php echo htmlspecialchars($cmd['display_command'] ?? $cmd['command']); ?> executed by <?php echo htmlspecialchars($cmd['username']); ?>
                                            </div>
                                            <div class="activity-meta">
                                                <?php echo htmlspecialchars($cmd['network']); ?> • 
                                                <?php echo htmlspecialchars($cmd['channel'] ?? 'DM'); ?> • 
                                                <?php echo date('H:i:s', strtotime($cmd['timestamp'])); ?>
                                            </div>
                                        </div>
                                    </div>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <div class="activity-item">
                                        <div class="activity-icon command">
                                            <i class="fas fa-info-circle"></i>
                                        </div>
                                        <div class="activity-content">
                                            <div class="activity-title">No recent activity</div>
                                            <div class="activity-meta">Waiting for commands...</div>
                                        </div>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Commands Tab -->
            <div id="commands-content" class="tab-content">
                <div class="admin-content">
                    <div class="admin-grid">
                        <div class="admin-card">
                            <h3><i class="fas fa-terminal"></i> Command Analytics</h3>
                            <div class="admin-stats">
                                <div class="stat-item">
                                    <div class="stat-value" id="total-commands"><?php echo ($bot_stats['rizon']['commands_today'] ?? 0) + ($bot_stats['libera']['commands_today'] ?? 0); ?></div>
                                    <div class="stat-label">Commands Today</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value" id="command-active-users"><?php echo ($bot_stats['rizon']['users_active'] ?? 0) + ($bot_stats['libera']['users_active'] ?? 0); ?></div>
                                    <div class="stat-label">Active Users</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value" id="avg-response-time">-</div>
                                    <div class="stat-label">Avg Response</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value" id="error-rate">-</div>
                                    <div class="stat-label">Error Rate</div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="admin-card">
                            <h3><i class="fas fa-chart-bar"></i> Most Used Commands</h3>
                            <div class="table-container">
                                <table class="admin-table">
                                    <thead>
                                        <tr>
                                            <th>Command</th>
                                            <th>Uses</th>
                                            <th>Network</th>
                                            <th>Avg Time</th>
                                        </tr>
                                    </thead>
                                    <tbody id="most-used-commands">
                                        <tr>
                                            <td colspan="4" class="text-center">Loading...</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                
                        <div class="admin-card">
                            <h3><i class="fas fa-clock"></i> Slowest Commands</h3>
                            <div class="table-container">
                                <table class="admin-table">
                                    <thead>
                                        <tr>
                                            <th>Command</th>
                                            <th>Avg Time</th>
                                            <th>Uses</th>
                                            <th>Network</th>
                                        </tr>
                                    </thead>
                                    <tbody id="slowest-commands">
                                        <tr>
                                            <td colspan="4" class="text-center">Loading...</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>


            <!-- Security Tab -->
            <div id="security-content" class="tab-content">
                <div class="admin-content">
                    <div class="admin-grid">
                <div class="admin-card">
                    <h3><i class="fas fa-shield-alt"></i> Threat Analysis Dashboard</h3>
                    <div class="admin-stats">
                        <div class="stat-item">
                            <div class="stat-value animated" id="security-events-count">-</div>
                            <div class="live-indicator">
                                <div class="live-dot"></div>
                                <span>Live Monitoring</span>
                            </div>
                            <div class="stat-label">Security Events (24h)</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value animated" id="failed-logins">-</div>
                            <div class="live-indicator">
                                <div class="live-dot"></div>
                                <span>Real-time</span>
                            </div>
                            <div class="stat-label">Failed Login Attempts</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value animated" id="blocked-ips-count">-</div>
                            <div class="stat-label">Blocked IP Addresses</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value large" id="threat-level">
                                <span class="status low status-pulse">LOW</span>
                            </div>
                            <div class="stat-label">Current Threat Level</div>
                        </div>
                    </div>
                </div>
                
                <div class="admin-card">
                    <h3><i class="fas fa-lock"></i> Security Status</h3>
                    <div class="security-status" id="security-systems-status">
                        <div class="status-item">
                            <div class="status-icon online" id="auth-status-icon">
                                <i class="fas fa-check-circle"></i>
                            </div>
                            <div class="status-content">
                                <div class="status-title">Authentication System</div>
                                <div class="status-meta" id="auth-status-meta">Active - 2FA enabled</div>
                            </div>
                        </div>
                        <div class="status-item">
                            <div class="status-icon online" id="rate-limit-status-icon">
                                <i class="fas fa-shield-alt"></i>
                            </div>
                            <div class="status-content">
                                <div class="status-title">Rate Limiting</div>
                                <div class="status-meta" id="rate-limit-status-meta">Active - Bot protection enabled</div>
                            </div>
                        </div>
                        <div class="status-item">
                            <div class="status-icon online" id="network-status-icon">
                                <i class="fas fa-globe"></i>
                            </div>
                            <div class="status-content">
                                <div class="status-title">Network Security</div>
                                <div class="status-meta" id="network-status-meta">Secured - SSL/TLS connections</div>
                            </div>
                        </div>
                        <div class="status-item">
                            <div class="status-icon online" id="db-status-icon">
                                <i class="fas fa-database"></i>
                            </div>
                            <div class="status-content">
                                <div class="status-title">Database Security</div>
                                <div class="status-meta" id="db-status-meta">Protected - Parameterized queries</div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="admin-card">
                    <h3><i class="fas fa-exclamation-triangle"></i> Emergency Controls</h3>
                    <div class="security-status" style="margin-bottom: 1rem;">
                        <div class="status-item" id="emergency-status-indicator">
                            <div class="status-icon online">
                                <i class="fas fa-check-circle"></i>
                            </div>
                            <div class="status-content">
                                <div class="status-title" id="emergency-status-title">System Normal</div>
                                <div class="status-meta" id="emergency-status-meta">No emergency lockdown active</div>
                            </div>
                        </div>
                    </div>
                    <div class="admin-actions">
                        <button class="admin-btn danger" id="emergency-lockdown-btn" data-action="toggle_emergency_lockdown">
                            <i class="fas fa-lock"></i> <span id="lockdown-btn-text">Activate Emergency Lockdown</span>
                        </button>
                        <button class="admin-btn" onclick="refreshSecurityData()">
                            <i class="fas fa-sync"></i> Refresh Security Data
                        </button>
                    </div>
                    <div id="threat-recommendations" style="margin-top: 1rem;">
                        <h4 style="color: var(--text-primary); margin-bottom: 0.5rem;">Recommended Actions:</h4>
                        <ul id="recommendations-list" style="color: var(--text-secondary); margin-left: 1rem;">
                            <li>System operating normally</li>
                        </ul>
                    </div>
                </div>
                
                <div class="admin-card" style="grid-column: 1 / -1;">
                    <h3><i class="fas fa-terminal"></i> Security Command Center</h3>
                    <div style="display: flex; gap: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap; align-items: center;">
                        <button class="admin-btn" onclick="toggleTerminalMode()" id="terminal-mode-btn">
                            <i class="fas fa-terminal"></i> Terminal Mode
                        </button>
                        <select id="event-filter" onchange="filterSecurityEvents()" class="admin-input" style="min-width: 150px;">
                            <option value="">All Events</option>
                            <option value="ATTACK">Attacks</option>
                            <option value="BLOCKED">Blocked Access</option>
                            <option value="RATE_LIMIT">Rate Limits</option>
                            <option value="EMERGENCY">Emergency</option>
                        </select>
                        <button class="admin-btn" onclick="exportSecurityEvents()" style="white-space: nowrap;">
                            <i class="fas fa-download"></i> Export
                        </button>
                        <button class="admin-btn" onclick="refreshSecurityEvents()">
                            <i class="fas fa-sync"></i> Refresh
                        </button>
                        <button class="admin-btn" onclick="clearSecurityDisplay()">
                            <i class="fas fa-trash"></i> Clear
                        </button>
                    </div>
                    
                    <!-- Terminal View -->
                    <div id="security-terminal" class="terminal-style" style="display: none;">
                        <div class="terminal-header">
                            <span>cr0@security-monitor:~$ tail -f /var/log/security/events.log</span>
                        </div>
                        <div class="terminal-content" id="terminal-output">
                            <div class="security-event-item">
                                <span class="security-timestamp">[<?php echo date('H:i:s'); ?>]</span>
                                <span class="security-type">INFO</span>
                                <span>Security monitoring initialized</span>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Table View -->
                    <div id="security-table-view" class="table-container">
                        <table class="admin-table">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Event Type</th>
                                    <th>IP Address</th>
                                    <th>Description</th>
                                    <th>Severity</th>
                                </tr>
                            </thead>
                            <tbody id="security-events-table">
                                <tr>
                                    <td colspan="5" class="text-center">Loading security events...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="admin-card" style="grid-column: 1 / -1;">
                    <h3><i class="fas fa-ban"></i> IP Management</h3>
                    <div style="margin-bottom: 1.5rem;">
                        <div style="display: grid; grid-template-columns: 1fr 1fr auto; gap: 0.75rem; margin-bottom: 1rem;">
                            <input type="text" id="ip-address-input" placeholder="Enter IP address" class="admin-input">
                            <input type="text" id="block-reason-input" placeholder="Reason (optional)" class="admin-input">
                            <button class="admin-btn danger" data-action="block_ip" style="white-space: nowrap;">
                                <i class="fas fa-ban"></i> Block IP
                            </button>
                        </div>
                    </div>
                    <div class="table-container">
                        <table class="admin-table">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Blocked At</th>
                                    <th>Reason</th>
                                    <th>Expires</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="blocked-ips-table">
                                <tr>
                                    <td colspan="5" class="text-center">Loading blocked IPs...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

            </div>

            <!-- Logs Tab -->
            <div id="logs-content" class="tab-content">
                <div class="admin-content">
                    <div class="admin-grid">
                <div class="admin-card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                        <h3><i class="fas fa-terminal"></i> Live IRC Logs</h3>
                        <div style="display: flex; gap: 0.5rem;">
                            <select id="log-network" onchange="switchLogNetwork()" style="padding: 0.5rem; border-radius: var(--radius-md); border: 1px solid var(--border-light); background: var(--bg-primary); color: var(--text-primary);">
                                <option value="rizon">Rizon Network</option>
                                <option value="libera">Libera Network</option>
                            </select>
                            <button class="admin-btn" onclick="toggleAutoRefresh()" id="auto-refresh-btn">
                                <i class="fas fa-pause"></i> Auto-refresh: ON
                            </button>
                            <button class="admin-btn" onclick="refreshLogs()">
                                <i class="fas fa-sync"></i> Refresh
                            </button>
                            <button class="admin-btn" onclick="clearLogs()">
                                <i class="fas fa-trash"></i> Clear
                            </button>
                        </div>
                    </div>
                    <div id="log-container" style="background: var(--bg-secondary); border: 1px solid var(--border-light); border-radius: var(--radius-md); padding: 1rem; height: 400px; overflow-y: auto; font-family: var(--font-mono); font-size: 0.875rem; line-height: 1.4;">
                        <div id="log-content">Loading logs...</div>
                    </div>
                    <div style="margin-top: 0.5rem; font-size: 0.75rem; color: var(--text-muted);">
                        Auto-refreshes every 5 seconds • Last updated: <span id="log-timestamp">Never</span>
                    </div>
                </div>  <!-- Close admin-card -->

                        <!-- Logs Manual Command Interface -->
                        <div class="admin-card">
                            <h3><i class="fas fa-terminal"></i> Send Command to Logs Network</h3>
                            
                            <!-- Network Selection for Logs -->
                            <div class="admin-field">
                                <label>Network</label>
                                <div class="button-group">
                                    <button class="network-btn" data-network="both" onclick="selectLogsNetwork('both')">Both Networks</button>
                                    <button class="network-btn active" data-network="rizon" onclick="selectLogsNetwork('rizon')">Rizon</button>
                                    <button class="network-btn" data-network="libera" onclick="selectLogsNetwork('libera')">Libera</button>
                                </div>
                            </div>

                            <!-- Channel Selection for Logs -->
                            <div class="admin-field">
                                <label>Channel</label>
                                <select id="logs-channel-select" onchange="selectLogsChannel(this.value)" class="admin-input">
                                    <option value="#8BitVape">#8BitVape</option>
                                    <option value="#temp">#temp</option>
                                    <option value="#bots">#bots</option>
                                </select>
                            </div>

                            <!-- Command Input for Logs -->
                            <div class="admin-field" style="margin-top: 1rem;">
                                <label>Command/Message</label>
                                <input type="text" id="logs-manual-command" placeholder="Enter command or message..." class="admin-input">
                                <div id="logs-command-preview" class="command-preview"></div>
                                <button onclick="sendLogsManualCommand()" class="admin-btn" style="margin-top: 0.5rem;">
                                    <i class="fas fa-paper-plane"></i> Send Command
                                </button>
                            </div>
                        </div>

                    </div>  <!-- Close admin-grid -->
                </div>  <!-- Close admin-content -->
            </div>  <!-- Close logs-content -->

            <!-- Tools Tab -->
            <div id="tools-content" class="tab-content">
                <div class="admin-content">
                    <div class="admin-grid">
                        <div class="admin-card">
                            <h3><i class="fas fa-tools"></i> Admin Tools</h3>
                            <div class="admin-actions">
                                <button class="admin-btn" onclick="window.open('/debug_admin.php', '_blank')">
                                    <i class="fas fa-bug"></i> Debug Panel
                                </button>
                                <button class="admin-btn" data-action="status">
                                    <i class="fas fa-info-circle"></i> Bot Status
                                </button>
                                <button class="admin-btn danger" data-action="stop_all" data-confirm="Stop all bots?">
                                    <i class="fas fa-stop"></i> Emergency Stop
                                </button>
                            </div>
                            <div id="tool-output" class="log-output" style="display: none;"></div>
                        </div>
                        
                        <!-- Bot Command Injection Card -->
                        <div class="admin-card">
                            <h3><i class="fas fa-terminal"></i> Bot Command Injection</h3>
                            
                            <!-- Network Selection -->
                            <div class="admin-field">
                                <label>Network</label>
                                <div class="button-group">
                                    <button class="network-btn active" data-network="both">Both Networks</button>
                                    <button class="network-btn" data-network="rizon">🔴 Rizon</button>
                                    <button class="network-btn" data-network="libera">🔵 Libera</button>
                                </div>
                            </div>
                            
                            <!-- Channel Selection -->
                            <div class="admin-field" style="margin-top: 1rem;">
                                <label>Channel</label>
                                <div class="button-group" id="channel-buttons">
                                    <!-- Channels populated by JavaScript -->
                                </div>
                            </div>
                            
                            <!-- Manual Command Input -->
                            <div class="admin-field" style="margin-top: 1rem;">
                                <label>Command/Message</label>
                                <input type="text" id="manual-command" placeholder="Enter command or message..." class="admin-input">
                                <div id="command-preview" class="command-preview"></div>
                                <button onclick="sendManualCommand()" class="admin-btn" style="margin-top: 0.5rem;">
                                    <i class="fas fa-paper-plane"></i> Send Command
                                </button>
                            </div>
                        </div>

                        <!-- Text Tools Card -->
                        <div class="admin-card">
                            <h3><i class="fas fa-text-width"></i> Text Tools</h3>
                            
                            <!-- Base64 Encoder/Decoder -->
                            <div class="text-tool-section">
                                <h4><i class="fas fa-code"></i> Base64 Encoder/Decoder</h4>
                                <div class="admin-field">
                                    <textarea id="base64-input" placeholder="Enter text to encode or Base64 to decode..." class="admin-input" rows="3"></textarea>
                                </div>
                                <div class="admin-actions">
                                    <button onclick="encodeBase64()" class="admin-btn">
                                        <i class="fas fa-arrow-up"></i> Encode
                                    </button>
                                    <button onclick="decodeBase64()" class="admin-btn">
                                        <i class="fas fa-arrow-down"></i> Decode
                                    </button>
                                </div>
                                <div class="admin-field">
                                    <textarea id="base64-output" placeholder="Result will appear here..." class="admin-input" rows="3" readonly></textarea>
                                </div>
                            </div>

                            <!-- URL Encoder/Decoder -->
                            <div class="text-tool-section" style="margin-top: 2rem;">
                                <h4><i class="fas fa-link"></i> URL Encoder/Decoder</h4>
                                <div class="admin-field">
                                    <textarea id="url-input" placeholder="Enter text to URL encode or encoded URL to decode..." class="admin-input" rows="3"></textarea>
                                </div>
                                <div class="admin-actions">
                                    <button onclick="encodeURL()" class="admin-btn">
                                        <i class="fas fa-arrow-up"></i> Encode
                                    </button>
                                    <button onclick="decodeURL()" class="admin-btn">
                                        <i class="fas fa-arrow-down"></i> Decode
                                    </button>
                                </div>
                                <div class="admin-field">
                                    <textarea id="url-output" placeholder="Result will appear here..." class="admin-input" rows="3" readonly></textarea>
                                </div>
                            </div>

                            <!-- Hash Generator -->
                            <div class="text-tool-section" style="margin-top: 2rem;">
                                <h4><i class="fas fa-shield-alt"></i> Hash Generator</h4>
                                <div class="admin-field">
                                    <textarea id="hash-input" placeholder="Enter text to hash..." class="admin-input" rows="3"></textarea>
                                </div>
                                <div class="admin-actions">
                                    <button onclick="generateHash('md5')" class="admin-btn">
                                        <i class="fas fa-key"></i> MD5
                                    </button>
                                    <button onclick="generateHash('sha1')" class="admin-btn">
                                        <i class="fas fa-key"></i> SHA1
                                    </button>
                                    <button onclick="generateHash('sha256')" class="admin-btn">
                                        <i class="fas fa-key"></i> SHA256
                                    </button>
                                </div>
                                <div class="admin-field">
                                    <textarea id="hash-output" placeholder="Hash will appear here..." class="admin-input" rows="3" readonly></textarea>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Games Tab -->
            <div id="games-content" class="tab-content">
                <div class="admin-content">
                    <div class="admin-grid">
                        <div class="admin-card">
                            <h3><i class="fas fa-gamepad"></i> Game Statistics</h3>
                            <div class="admin-stats">
                                <div class="stat-item">
                                    <div class="stat-value" id="active-games"><?php echo $game_stats['active_games'] ?? 0; ?></div>
                                    <div class="stat-label">Active Games</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value" id="games-today"><?php echo $game_stats['games_today'] ?? 0; ?></div>
                                    <div class="stat-label">Games Today</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value" id="total-users"><?php echo $user_analytics['total_users'] ?? 0; ?></div>
                                    <div class="stat-label">Total Users</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value" id="new-users"><?php echo $user_analytics['new_this_week'] ?? 0; ?></div>
                                    <div class="stat-label">New This Week</div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="admin-card" style="grid-column: 1 / -1;">
                            <h3><i class="fas fa-gamepad"></i> Game Configuration</h3>
                            <div style="display: flex; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; align-items: center;">
                                <a href="admin_game_config_realistic.php" target="_blank" class="admin-btn" style="text-decoration: none; display: inline-flex; background: #28a745;">
                                    <i class="fas fa-bullseye"></i> Realistic Values Config
                                </a>
                                <a href="admin_game_config_cleaned.php" target="_blank" class="admin-btn" style="text-decoration: none; display: inline-flex;">
                                    <i class="fas fa-cog"></i> Scale-Based Config
                                </a>
                                <button class="admin-btn" onclick="window.open('/breakout.html?config=realistic', '_blank')" style="background: #28a745;">
                                    <i class="fas fa-play"></i> Test Realistic Config
                                </button>
                                <button class="admin-btn" onclick="window.open('/breakout.html?config=live', '_blank')">
                                    <i class="fas fa-play"></i> Test Scale Config
                                </button>
                            </div>
                            <p style="color: #6c757d; margin-top: 0.5rem;">
                                <strong>Realistic Values:</strong> Shows actual game units (px/frame, seconds, etc.) for transparent configuration.<br>
                                <strong>Scale-Based:</strong> Uses 1-10 scales that map to game values behind the scenes.
                            </p>
                        </div>
                        
                        <div class="admin-card" style="grid-column: 1 / -1;">
                            <h3><i class="fas fa-trophy"></i> Hall of Fame Moderation</h3>
                            <div style="display: flex; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; align-items: center;">
                                <button class="admin-btn" onclick="refreshHallOfFame()">
                                    <i class="fas fa-sync"></i> Refresh Scores
                                </button>
                                <button class="admin-btn danger" onclick="deleteSelectedScores()">
                                    <i class="fas fa-trash"></i> Delete Selected
                                </button>
                                <button class="admin-btn danger" onclick="banPlayerFromScores()">
                                    <i class="fas fa-ban"></i> Ban Player
                                </button>
                                <input type="text" id="score-search" placeholder="Search player name..." class="admin-input" style="max-width: 200px;" onkeyup="filterScores()">
                            </div>
                            
                            <div class="table-container">
                                <table class="admin-table">
                                    <thead>
                                        <tr>
                                            <th style="width: 40px;">
                                                <input type="checkbox" id="select-all-scores" onchange="toggleAllScores()">
                                            </th>
                                            <th>ID</th>
                                            <th>Player Name</th>
                                            <th>Score</th>
                                            <th>Level</th>
                                            <th>Date</th>
                                            <th>IP Address</th>
                                            <th>Session ID</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody id="hall-of-fame-table">
                                        <tr>
                                            <td colspan="9" class="text-center">Loading hall of fame scores...</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                            
                            <div style="margin-top: 1rem; padding: 1rem; background: var(--bg-secondary); border-radius: var(--radius-md); border: 1px solid var(--border-light);">
                                <h4 style="color: var(--text-primary); margin-bottom: 0.5rem;">Security Actions</h4>
                                <div style="display: grid; grid-template-columns: 1fr auto; gap: 0.75rem; margin-bottom: 0.5rem;">
                                    <input type="text" id="ban-player-name" placeholder="Player name to ban" class="admin-input">
                                    <button class="admin-btn danger" onclick="addPlayerBan()">
                                        <i class="fas fa-ban"></i> Add Ban
                                    </button>
                                </div>
                                <div style="margin-top: 1rem;">
                                    <button class="admin-btn danger" onclick="if(confirm('This will delete ALL scores from the database. This action cannot be undone!')) clearAllScores()">
                                        <i class="fas fa-exclamation-triangle"></i> Clear All Scores
                                    </button>
                                    <button class="admin-btn" onclick="exportScores()">
                                        <i class="fas fa-download"></i> Export Scores
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Beans Tab -->
            <div id="beans-content" class="tab-content">
                <div class="admin-content">
                    <div class="admin-grid">
                        <div class="admin-card" style="grid-column: 1 / -1;">
                            <h3>🫘 Beans Management</h3>
                            <div class="admin-stats" style="margin-bottom: 1rem;">
                                <div class="stat-item">
                                    <div class="stat-value animated" id="total-beans">Loading...</div>
                                    <div class="stat-label">Total Beans</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value animated" id="rizon-beans">Loading...</div>
                                    <div class="stat-label">Rizon Beans</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value animated" id="libera-beans">Loading...</div>
                                    <div class="stat-label">Libera Beans</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-value animated" id="total-bean-views">Loading...</div>
                                    <div class="stat-label">Total Views</div>
                                </div>
                            </div>
                            
                            <div style="margin-bottom: 1rem;">
                                <input type="text" id="bean-search" placeholder="Search URLs, users, descriptions..." class="admin-input" style="width: 300px; margin-right: 1rem;" onkeyup="filterBeans()">
                                <select id="bean-network-filter" class="admin-input" style="width: 150px;" onchange="filterBeans()">
                                    <option value="">All Networks</option>
                                    <option value="rizon">Rizon Only</option>
                                    <option value="libera">Libera Only</option>
                                </select>
                                <button class="admin-btn" onclick="refreshBeans()" style="margin-left: 1rem;">
                                    <i class="fas fa-sync"></i> Refresh
                                </button>
                            </div>
                            
                            <div class="table-container">
                                <table class="admin-table" id="beans-table">
                                    <thead>
                                        <tr>
                                            <th>Preview</th>
                                            <th>Network</th>
                                            <th>URL</th>
                                            <th>Added By</th>
                                            <th>Channel</th>
                                            <th>Added Time</th>
                                            <th>Views</th>
                                            <th>Description</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody id="beans-tbody">
                                        <tr>
                                            <td colspan="9" style="text-align: center; padding: 2rem;">
                                                Loading beans data...
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Users Tab -->
            <div id="users-content" class="tab-content">
                <div class="admin-content">
                    <div class="admin-grid">
                        <div class="admin-card" style="grid-column: 1 / -1;">
                            <h3><i class="fas fa-users"></i> User Management</h3>
                            <p style="color: var(--text-secondary); margin-bottom: 1rem;">User management features coming soon...</p>
                        </div>
                    </div>
                </div>
            </div>
    </div>

    

    <script>
        // Theme toggle functionality (matches main site exactly)
        function toggleTheme() {
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            html.setAttribute('data-theme', newTheme);
            
            const icon = document.querySelector('.theme-toggle-icon');
            const text = document.querySelector('.theme-toggle-text');
            
            if (newTheme === 'dark') {
                icon.className = 'theme-toggle-icon material-symbols-outlined';
                icon.textContent = 'light_mode';
                text.textContent = 'Light';
            } else {
                icon.className = 'theme-toggle-icon material-symbols-outlined';
                icon.textContent = 'dark_mode';
                text.textContent = 'Dark';
            }
            
            localStorage.setItem('theme', newTheme);
        }

        // Apply saved theme
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        
        if (savedTheme === 'dark') {
            const icon = document.querySelector('.theme-toggle-icon');
            icon.className = 'theme-toggle-icon material-symbols-outlined';
            icon.textContent = 'light_mode';
            document.querySelector('.theme-toggle-text').textContent = 'Light';
        }

        // Tab management
        function showTab(tabName) {
            // Hide all tab content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active from all tab buttons
            document.querySelectorAll('.tab-button').forEach(button => {
                button.classList.remove('active');
            });
            
            // Show selected content
            const targetContent = document.getElementById(tabName + '-content');
            if (targetContent) {
                targetContent.classList.add('active');
            }
            
            // Set active tab button
            document.querySelectorAll('.tab-button').forEach(button => {
                if (button.getAttribute('onclick') && button.getAttribute('onclick').includes("showTab('" + tabName + "')")) {
                    button.classList.add('active');
                }
            });
            
            // Initialize logs if logs tab is shown
            if (tabName === 'logs') {
                setTimeout(() => {
                    refreshLogs();
                    if (logAutoRefresh) startLogAutoRefresh();
                }, 100);
            } else {
                // Stop log auto-refresh when not on logs tab
                clearInterval(logRefreshInterval);
            }
        }


        // Refresh data
        function refreshData() {
            console.log('refreshData() called');
            
            return new Promise((resolve, reject) => {
            
            // Fetch live data using self-hosted endpoint
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: 'action=get_live_data'
            })
            .then(response => {
                console.log('Response received:', response.status, response.statusText);
                return response.text();
            })
            .then(text => {
                console.log('Response text:', text);
                try {
                    const data = JSON.parse(text);
                    console.log('Parsed data:', data);
                    if (data.success) {
                        console.log('AJAX success - data keys:', Object.keys(data));
                        updateData(data);
                        resolve(data);
                    } else {
                        console.error('Failed to fetch data:', data.message);
                        console.log('AJAX returned success=false - keeping existing data');
                        reject(new Error(data.message || 'API returned success=false'));
                    }
                } catch (e) {
                    console.error('JSON parse error:', e, 'Text:', text);
                    // Show user-friendly error
                    document.getElementById('rizon-status').textContent = 'Error';
                    document.getElementById('libera-status').textContent = 'Error';
                    reject(e);
                }
            })
            .catch(error => {
                console.error('Error fetching data:', error);
                console.log('AJAX failed - keeping existing data intact');
                reject(error);
            });
            });
        }

        // Update data on page
        function formatUptime(seconds) {
            if (seconds < 60) {
                return seconds + 's';
            } else if (seconds < 3600) {
                const hours = Math.floor(seconds / 60);
                const minutes = seconds % 60;
                return hours + 'm ' + minutes + 's';
            } else if (seconds < 86400) {
                const hours = Math.floor(seconds / 3600);
                const minutes = Math.floor((seconds % 3600) / 60);
                return hours + 'h ' + minutes + 'm';
            } else {
                const days = Math.floor(seconds / 86400);
                const hours = Math.floor((seconds % 86400) / 3600);
                return days + 'd ' + hours + 'h';
            }
        }

        // Helper function to update command tables
        function updateCommandTables(performance) {
            // Update most used commands
            const mostUsedTable = document.getElementById('most-used-commands');
            if (mostUsedTable && performance.most_used) {
                let html = '';
                performance.most_used.slice(0, 10).forEach(cmd => {
                    html += `
                        <tr>
                            <td>${cmd.display_command || cmd.command || 'Unknown'}</td>
                            <td>${cmd.uses || 0}</td>
                            <td>${cmd.network || 'Unknown'}</td>
                            <td>${Math.round(cmd.avg_time || 0)}ms</td>
                        </tr>
                    `;
                });
                if (html === '') {
                    html = '<tr><td colspan="4" class="text-center">No command data available</td></tr>';
                }
                mostUsedTable.innerHTML = html;
            }
            
            // Update slowest commands
            const slowestTable = document.getElementById('slowest-commands');
            if (slowestTable && performance.slowest_commands) {
                let html = '';
                performance.slowest_commands.slice(0, 10).forEach(cmd => {
                    html += `
                        <tr>
                            <td>${cmd.display_command || cmd.command || 'Unknown'}</td>
                            <td>${Math.round(cmd.avg_time || 0)}ms</td>
                            <td>${cmd.uses || 0}</td>
                            <td>${cmd.network || 'Unknown'}</td>
                        </tr>
                    `;
                });
                if (html === '') {
                    html = '<tr><td colspan="4" class="text-center">No performance data available</td></tr>';
                }
                slowestTable.innerHTML = html;
            }
        }
        
        // Helper function to update security events table
        function updateSecurityTable(events) {
            const securityTable = document.getElementById('security-events-table');
            if (securityTable && events) {
                let html = '';
                events.slice(0, 10).forEach(event => {
                    const time = new Date(event.timestamp || Date.now()).toLocaleString();
                    const severity = event.severity || 'LOW';
                    const severityClass = severity.toLowerCase();
                    html += `
                        <tr>
                            <td>${time}</td>
                            <td>${event.event_type || event.type || 'Unknown'}</td>
                            <td>${event.ip_address || event.ip || 'Unknown'}</td>
                            <td>${event.message || event.description || 'No description'}</td>
                            <td><span class="status ${severityClass}">${severity}</span></td>
                        </tr>
                    `;
                });
                if (html === '') {
                    html = '<tr><td colspan="5" class="text-center">No security events</td></tr>';
                }
                securityTable.innerHTML = html;
            }
        }
        
        // Helper function to update blocked IPs table
        function updateBlockedIPsTable(activeBlocks) {
            const blockedTable = document.getElementById('blocked-ips-table');
            if (blockedTable) {
                let html = '';
                Object.entries(activeBlocks || {}).forEach(([ip, info]) => {
                    const blockedAt = new Date(info.blocked_at * 1000).toLocaleString();
                    const expiresAt = new Date(info.until * 1000).toLocaleString();
                    const reason = info.reason || 'No reason specified';
                    html += `
                        <tr>
                            <td>${ip}</td>
                            <td>${blockedAt}</td>
                            <td>${reason}</td>
                            <td>${expiresAt}</td>
                            <td>
                                <button class="admin-btn" onclick="unblockIP('${ip}')" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;">
                                    <i class="fas fa-unlock"></i> Unblock
                                </button>
                            </td>
                        </tr>
                    `;
                });
                if (html === '') {
                    html = '<tr><td colspan="5" class="text-center">No blocked IPs</td></tr>';
                }
                blockedTable.innerHTML = html;
            }
        }
        
        // Helper function to update emergency status
        function updateEmergencyStatus(emergencyData) {
            const statusIndicator = document.getElementById('emergency-status-indicator');
            const statusTitle = document.getElementById('emergency-status-title');
            const statusMeta = document.getElementById('emergency-status-meta');
            const lockdownBtn = document.getElementById('emergency-lockdown-btn');
            const lockdownBtnText = document.getElementById('lockdown-btn-text');
            const recommendationsList = document.getElementById('recommendations-list');
            
            if (emergencyData.lockdown_active) {
                // Lockdown is active
                statusIndicator.querySelector('.status-icon').className = 'status-icon offline';
                statusIndicator.querySelector('.status-icon i').className = 'fas fa-exclamation-triangle';
                statusTitle.textContent = 'Emergency Lockdown Active';
                statusMeta.textContent = 'System is in lockdown mode';
                lockdownBtn.className = 'admin-btn success';
                lockdownBtnText.textContent = 'Deactivate Emergency Lockdown';
            } else {
                // Normal operation
                statusIndicator.querySelector('.status-icon').className = 'status-icon online';
                statusIndicator.querySelector('.status-icon i').className = 'fas fa-check-circle';
                statusTitle.textContent = 'System Normal';
                statusMeta.textContent = 'No emergency lockdown active';
                lockdownBtn.className = 'admin-btn danger';
                lockdownBtnText.textContent = 'Activate Emergency Lockdown';
            }
            
            // Update threat level
            const threatLevelEl = document.getElementById('threat-level');
            if (threatLevelEl && emergencyData.threat_level) {
                const level = emergencyData.threat_level.toLowerCase();
                threatLevelEl.innerHTML = `<span class="status ${level}">${emergencyData.threat_level}</span>`;
            }
            
            // Update recommendations
            if (recommendationsList && emergencyData.recommended_actions) {
                recommendationsList.innerHTML = '';
                emergencyData.recommended_actions.forEach(action => {
                    const li = document.createElement('li');
                    li.textContent = action;
                    recommendationsList.appendChild(li);
                });
            }
        }

        function updateData(data) {
            // Update bot status
            if (data.bot_stats && data.bot_stats.rizon && data.bot_stats.libera) {
                const rizonStatus = document.getElementById('rizon-status');
                const liberaStatus = document.getElementById('libera-status');
                
                // Update text content
                if (rizonStatus) rizonStatus.textContent = data.bot_stats.rizon.status || 'Unknown';
                if (liberaStatus) liberaStatus.textContent = data.bot_stats.libera.status || 'Unknown';
                
                // Update PID and uptime for each bot
                ['rizon', 'libera'].forEach(network => {
                    const statusElement = document.getElementById(network + '-status');
                    if (statusElement) {
                        const statValue = statusElement.parentElement;
                        let botDetails = statValue.querySelector('.bot-details');
                        
                        if (data.bot_stats[network].status === 'Online') {
                            const pid = data.bot_stats[network].pid || 'unknown';
                            const uptime = formatUptime(data.bot_stats[network].uptime || 0);
                            
                            if (!botDetails) {
                                botDetails = document.createElement('div');
                                botDetails.className = 'bot-details';
                                statValue.appendChild(botDetails);
                            }
                            botDetails.innerHTML = '<small>PID: ' + pid + ' | Up: ' + uptime + '</small>';
                        } else if (botDetails) {
                            botDetails.remove();
                        }
                    }
                });
                
                // Update status indicator classes
                const rizonIndicator = rizonStatus ? rizonStatus.previousElementSibling : null;
                const liberaIndicator = liberaStatus ? liberaStatus.previousElementSibling : null;
                
                if (rizonIndicator && rizonIndicator.classList.contains('status-indicator')) {
                    rizonIndicator.className = 'status-indicator ' + (data.bot_stats.rizon.status === 'Online' ? 'status-online' : 'status-offline');
                }
                
                if (liberaIndicator && liberaIndicator.classList.contains('status-indicator')) {
                    liberaIndicator.className = 'status-indicator ' + (data.bot_stats.libera.status === 'Online' ? 'status-online' : 'status-offline');
                }
                
                const commandsToday = (data.bot_stats.rizon.commands_today || 0) + (data.bot_stats.libera.commands_today || 0);
                const activeUsers = (data.bot_stats.rizon.users_active || 0) + (data.bot_stats.libera.users_active || 0);
                
                // Update overview stats
                const commandsEl = document.getElementById('commands-today');
                const usersEl = document.getElementById('active-users');
                
                if (commandsEl) commandsEl.textContent = commandsToday;
                if (usersEl) usersEl.textContent = activeUsers;
                
                // Update command analytics (same data for consistency)
                const totalCommandsEl = document.getElementById('total-commands');
                const commandActiveUsersEl = document.getElementById('command-active-users');
                
                if (totalCommandsEl) totalCommandsEl.textContent = commandsToday;
                if (commandActiveUsersEl) commandActiveUsersEl.textContent = activeUsers;
            }
            
            
            // Update game statistics
            if (data.game_stats) {
                const activeGamesEl = document.getElementById('active-games');
                const gamesTodayEl = document.getElementById('games-today');
                const totalPlayersEl = document.getElementById('total-players');
                const popularGamesCountEl = document.getElementById('popular-games-count');
                
                if (activeGamesEl) activeGamesEl.textContent = data.game_stats.active_games || 0;
                if (gamesTodayEl) gamesTodayEl.textContent = data.game_stats.games_today || 0;
                if (totalPlayersEl) totalPlayersEl.textContent = data.game_stats.total_players || 0;
                if (popularGamesCountEl) popularGamesCountEl.textContent = (data.game_stats.popular_games ? data.game_stats.popular_games.length : 0);
            }
            
            // Update user analytics
            if (data.user_analytics) {
                const totalUsersEl = document.getElementById('total-users');
                const activeTodayEl = document.getElementById('active-today');
                const newUsersEl = document.getElementById('new-users');
                const topUsersCountEl = document.getElementById('top-users-count');
                
                if (totalUsersEl) totalUsersEl.textContent = data.user_analytics.total_users || 0;
                if (activeTodayEl) activeTodayEl.textContent = data.user_analytics.active_today || 0;
                if (newUsersEl) newUsersEl.textContent = data.user_analytics.new_this_week || 0;
                if (topUsersCountEl) topUsersCountEl.textContent = (data.user_analytics.top_users ? Object.keys(data.user_analytics.top_users).length : 0);
            }
            
            // Update command analytics
            if (data.performance) {
                // Update command tables
                updateCommandTables(data.performance);
                
                // Calculate average response time
                const avgResponseEl = document.getElementById('avg-response-time');
                if (avgResponseEl && data.performance.slowest_commands && data.performance.slowest_commands.length > 0) {
                    const avgTime = data.performance.slowest_commands.reduce((sum, cmd) => sum + (parseFloat(cmd.avg_time) || 0), 0) / data.performance.slowest_commands.length;
                    avgResponseEl.textContent = Math.round(avgTime) + 'ms';
                }
            }
            
            // Update security events
            if (data.security_events) {
                const securityCountEl = document.getElementById('security-events-count');
                if (securityCountEl) securityCountEl.textContent = data.security_events.length || 0;
                
                updateSecurityTable(data.security_events);
            }
            
            // Update security dashboard
            if (data.security_dashboard) {
                const blockedIpsCountEl = document.getElementById('blocked-ips-count');
                if (blockedIpsCountEl) {
                    blockedIpsCountEl.textContent = data.security_dashboard.blocked_ips || 0;
                }
                
                // Update blocked IPs table
                updateBlockedIPsTable(data.security_dashboard.active_blocks);
                
                // Count failed logins from recent events
                let failedLogins = 0;
                if (data.security_dashboard.recent_events) {
                    failedLogins = data.security_dashboard.recent_events.filter(event => 
                        event.type === 'LOGIN_FAILED' || event.event_type === 'LOGIN_FAILED'
                    ).length;
                }
                const failedLoginsEl = document.getElementById('failed-logins');
                if (failedLoginsEl) failedLoginsEl.textContent = failedLogins;
            }
            
            // Update emergency status
            if (data.emergency_status) {
                updateEmergencyStatus(data.emergency_status);
            }
            
            // Update system resources
            if (data.system_resources) {
                const cpuEl = document.getElementById('cpu-usage');
                const memoryEl = document.getElementById('memory-usage');
                const diskEl = document.getElementById('disk-usage');
                const uptimeEl = document.getElementById('system-uptime');
                
                if (cpuEl) cpuEl.textContent = data.system_resources.cpu_usage + '%';
                if (memoryEl) memoryEl.textContent = data.system_resources.memory_usage + '%';
                if (diskEl) diskEl.textContent = data.system_resources.disk_usage + '%';
                if (uptimeEl) uptimeEl.textContent = formatUptime(data.system_resources.uptime || 0);
            }
            
            // Update activity feed - only if we have valid data with commands
            console.log('Checking recent commands:', data.recent_commands);
            if (data.recent_commands !== undefined && Array.isArray(data.recent_commands) && data.recent_commands.length > 0) {
                console.log('Updating activity feed with', data.recent_commands.length, 'commands');
                updateActivityFeed(data.recent_commands);
            } else {
                console.log('Skipping activity feed update - no valid command data');
            }
        }

        // Update activity feed
        function updateActivityFeed(commands) {
            console.log('updateActivityFeed called with:', commands);
            const feed = document.getElementById('activity-feed');
            
            // Only update if we have valid command data
            if (!commands || !Array.isArray(commands) || commands.length === 0) {
                console.log('No valid commands to display, keeping existing feed content');
                return;
            }
            
            // Clear and rebuild with new data
            console.log('Rebuilding activity feed with', commands.length, 'commands');
            feed.innerHTML = '';
            
            commands.slice(0, 10).forEach(cmd => {
                const item = document.createElement('div');
                item.className = 'activity-item';
                item.innerHTML = `
                    <div class="activity-icon command">
                        <i class="fas fa-terminal"></i>
                    </div>
                    <div class="activity-content">
                        <div class="activity-title">
                            ${cmd.display_command || cmd.command} executed by ${cmd.username}
                        </div>
                        <div class="activity-meta">
                            ${cmd.network} • ${cmd.channel || 'DM'} • ${new Date(cmd.timestamp).toLocaleTimeString()}
                        </div>
                    </div>
                `;
                feed.appendChild(item);
            });
        }

        // Secure admin action handler
        function executeSecureAction(action, button, confirmMsg = null) {
            if (confirmMsg && !confirm(confirmMsg)) {
                return;
            }
            
            const originalHTML = button.innerHTML;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Working...';
            button.disabled = true;
            
            const body = action.startsWith('block_ip') || action.startsWith('toggle_emergency') 
                ? `action=security_action&security_action=${action}` 
                : `action=bot_action&bot_action=${action}`;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                credentials: 'same-origin',
                body: body
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    if (data.output) {
                        const output = document.getElementById('tool-output');
                        if (output) {
                            output.style.display = 'block';
                            output.textContent = data.output;
                        }
                    }
                    alert('Success: ' + data.message);
                    setTimeout(refreshData, 2000);
                } else {
                    alert('Action failed: ' + (data.message || 'Unknown error'));
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Network error: ' + error.message);
            })
            .finally(() => {
                button.innerHTML = originalHTML;
                button.disabled = false;
            });
        }

        // Live log functionality
        let logAutoRefresh = true;
        let logRefreshInterval;
        let currentLogNetwork = 'rizon';

        function refreshLogs() {
            const network = document.getElementById('log-network').value;
            
            fetch(`?action=live_logs&network=${network}&lines=50`, {
                method: 'GET',
                credentials: 'same-origin',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    updateLogDisplay(data.data);
                    document.getElementById('log-timestamp').textContent = new Date().toLocaleTimeString();
                } else {
                    console.error('Failed to fetch logs:', data.error);
                    document.getElementById('log-content').innerHTML = '<div style="color: var(--text-secondary);">Error: ' + (data.error || 'Unknown error') + '</div>';
                }
            })
            .catch(error => {
                console.error('Error fetching logs:', error);
                document.getElementById('log-content').innerHTML = '<div style="color: var(--text-secondary);">Connection error: ' + error.message + '</div>';
            });
        }

        function updateLogDisplay(logs) {
            const container = document.getElementById('log-content');
            const wasAtBottom = container.scrollTop >= (container.scrollHeight - container.clientHeight - 10);
            
            if (logs.length === 0) {
                container.innerHTML = '<div style="color: var(--text-secondary);">No logs available</div>';
                return;
            }
            
            container.innerHTML = logs.map(log => {
                const timestamp = new Date(log.timestamp).toLocaleTimeString();
                const level = log.level.toLowerCase();
                const levelColor = level === 'error' ? '#dc2626' : 
                                 level === 'warning' ? '#d97706' : 
                                 level === 'info' ? '#059669' : 
                                 'var(--text-secondary)';
                
                return `<div style="margin-bottom: 0.25rem; word-wrap: break-word;">
                    <span style="color: var(--text-muted); font-size: 0.8em;">[${timestamp}]</span>
                    <span style="color: ${levelColor}; font-weight: 500;">[${log.level}]</span>
                    <span style="color: var(--text-secondary);">[${log.source}]</span>
                    <span style="color: var(--text-primary);">${log.message}</span>
                </div>`;
            }).join('');
            
            // Scroll to bottom if user was already at bottom
            if (wasAtBottom) {
                container.scrollTop = container.scrollHeight;
            }
        }

        function toggleAutoRefresh() {
            logAutoRefresh = !logAutoRefresh;
            const btn = document.getElementById('auto-refresh-btn');
            
            if (logAutoRefresh) {
                btn.innerHTML = '<i class="fas fa-pause"></i> Auto-refresh: ON';
                startLogAutoRefresh();
            } else {
                btn.innerHTML = '<i class="fas fa-play"></i> Auto-refresh: OFF';
                clearInterval(logRefreshInterval);
            }
        }

        function startLogAutoRefresh() {
            clearInterval(logRefreshInterval);
            logRefreshInterval = setInterval(refreshLogs, 5000); // Refresh every 5 seconds
        }

        function switchLogNetwork() {
            currentLogNetwork = document.getElementById('log-network').value;
            document.getElementById('log-content').innerHTML = 'Loading logs...';
            refreshLogs();
        }

        function clearLogs() {
            document.getElementById('log-content').innerHTML = '<div style="color: var(--text-secondary);">Logs cleared</div>';
        }

        // Security management functions
        function blockIP() {
            const ipInput = document.getElementById('ip-address-input');
            const reasonInput = document.getElementById('block-reason-input');
            const ip = ipInput.value.trim();
            const reason = reasonInput.value.trim() || 'Manual admin block';
            
            if (!ip) {
                alert('Please enter an IP address');
                return;
            }
            
            if (!confirm(`Block IP ${ip}?\nReason: ${reason}`)) {
                return;
            }
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `action=security_action&security_action=block_ip&ip_address=${encodeURIComponent(ip)}&reason=${encodeURIComponent(reason)}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert(data.message);
                    ipInput.value = '';
                    reasonInput.value = '';
                    refreshSecurityData();
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Network error: ' + error.message);
            });
        }
        
        function unblockIP(ip) {
            if (!confirm(`Unblock IP ${ip}?`)) {
                return;
            }
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `action=security_action&security_action=unblock_ip&ip_address=${encodeURIComponent(ip)}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert(data.message);
                    refreshSecurityData();
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Network error: ' + error.message);
            });
        }
        
        function toggleEmergencyLockdown() {
            const isActive = document.getElementById('emergency-lockdown-btn').className.includes('success');
            const action = isActive ? 'deactivate' : 'activate';
            
            if (!confirm(`Are you sure you want to ${action} emergency lockdown?`)) {
                return;
            }
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: 'action=security_action&security_action=toggle_emergency_lockdown'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert(data.message);
                    refreshSecurityData();
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Network error: ' + error.message);
            });
        }
        
        function refreshSecurityData() {
            refreshData(); // Use the existing refresh function
        }
        
        // Terminal mode toggle
        let terminalMode = false;
        
        function toggleTerminalMode() {
            terminalMode = !terminalMode;
            const terminal = document.getElementById('security-terminal');
            const tableView = document.getElementById('security-table-view');
            const btn = document.getElementById('terminal-mode-btn');
            
            if (terminalMode) {
                terminal.style.display = 'block';
                tableView.style.display = 'none';
                btn.innerHTML = '<i class="fas fa-table"></i> Table Mode';
                btn.classList.add('active');
                startTerminalUpdates();
            } else {
                terminal.style.display = 'none';
                tableView.style.display = 'block';
                btn.innerHTML = '<i class="fas fa-terminal"></i> Terminal Mode';
                btn.classList.remove('active');
                stopTerminalUpdates();
            }
        }
        
        let terminalUpdateInterval;
        
        function startTerminalUpdates() {
            terminalUpdateInterval = setInterval(() => {
                addRandomSecurityEvent();
            }, 3000);
        }
        
        function stopTerminalUpdates() {
            if (terminalUpdateInterval) {
                clearInterval(terminalUpdateInterval);
            }
        }
        
        function addRandomSecurityEvent() {
            const events = [
                { type: 'INFO', msg: 'User authentication successful from 192.168.1.100' },
                { type: 'WARN', msg: 'Rate limit exceeded for IP 203.0.113.42' },
                { type: 'INFO', msg: 'Bot command executed: !weather' },
                { type: 'INFO', msg: 'Database query completed in 0.023s' },
                { type: 'WARN', msg: 'Failed login attempt detected' }
            ];
            
            const event = events[Math.floor(Math.random() * events.length)];
            const timestamp = new Date().toLocaleTimeString();
            
            const output = document.getElementById('terminal-output');
            const eventDiv = document.createElement('div');
            eventDiv.className = 'security-event-item';
            eventDiv.innerHTML = `
                <span class="security-timestamp">[${timestamp}]</span>
                <span class="security-type">${event.type}</span>
                <span>${event.msg}</span>
            `;
            
            output.appendChild(eventDiv);
            
            // Keep only last 20 events
            const events_list = output.children;
            if (events_list.length > 20) {
                output.removeChild(events_list[0]);
            }
            
            // Auto-scroll to bottom
            output.scrollTop = output.scrollHeight;
        }
        
        function clearSecurityDisplay() {
            if (terminalMode) {
                document.getElementById('terminal-output').innerHTML = `
                    <div class="security-event-item">
                        <span class="security-timestamp">[${new Date().toLocaleTimeString()}]</span>
                        <span class="security-type">INFO</span>
                        <span>Terminal cleared by admin</span>
                    </div>
                `;
            }
        }
        
        function refreshSecurityEvents() {
            refreshData();
        }
        
        // Animated counter function
        function animateCounter(element, targetValue) {
            const currentValue = parseInt(element.textContent) || 0;
            const increment = Math.ceil((targetValue - currentValue) / 20);
            
            if (currentValue < targetValue) {
                element.textContent = currentValue + increment;
                element.style.transform = 'scale(1.05)';
                setTimeout(() => {
                    element.style.transform = 'scale(1)';
                    animateCounter(element, targetValue);
                }, 50);
            } else {
                element.textContent = targetValue;
            }
        }
        
        function filterSecurityEvents() {
            const filter = document.getElementById('event-filter').value;
            const table = document.getElementById('security-events-table');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 0; i < rows.length; i++) {
                const eventTypeCell = rows[i].getElementsByTagName('td')[1];
                if (eventTypeCell) {
                    const eventType = eventTypeCell.textContent;
                    if (filter === '' || eventType.includes(filter)) {
                        rows[i].style.display = '';
                    } else {
                        rows[i].style.display = 'none';
                    }
                }
            }
        }
        
        function exportSecurityEvents() {
            // Get current security events data
            const table = document.getElementById('security-events-table');
            const rows = table.getElementsByTagName('tr');
            let csvContent = "Time,Event Type,IP Address,Description,Severity\n";
            
            for (let i = 0; i < rows.length; i++) {
                const cells = rows[i].getElementsByTagName('td');
                if (cells.length >= 5 && rows[i].style.display !== 'none') {
                    const rowData = [];
                    for (let j = 0; j < 5; j++) {
                        rowData.push('"' + cells[j].textContent.replace(/"/g, '""') + '"');
                    }
                    csvContent += rowData.join(',') + '\n';
                }
            }
            
            // Create download
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', 'security_events_' + new Date().toISOString().slice(0,10) + '.csv');
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        // Real-time Server-Sent Events client
        let eventSource = null;
        let reconnectAttempts = 0;
        let maxReconnectAttempts = 5;
        let reconnectDelay = 1000; // Start with 1 second
        
        function initializeSSE() {
            if (eventSource) {
                eventSource.close();
            }
            
            console.log('Initializing SSE connection...');
            eventSource = new EventSource('/api/realtime_sse.php');
            
            eventSource.onopen = function(event) {
                console.log('SSE connection opened');
                reconnectAttempts = 0;
                reconnectDelay = 1000;
            };
            
            eventSource.onmessage = function(event) {
                console.log('SSE message received:', event.data);
            };
            
            eventSource.addEventListener('connected', function(event) {
                console.log('SSE connected:', event.data);
            });
            
            eventSource.addEventListener('bot_status', function(event) {
                const data = JSON.parse(event.data);
                console.log('Bot status update:', data);
                updateBotStatus(data.data);
            });
            
            eventSource.addEventListener('commands', function(event) {
                const data = JSON.parse(event.data);
                console.log('Command update:', data);
                updateRecentActivity(data.data);
            });
            
            eventSource.addEventListener('security', function(event) {
                const data = JSON.parse(event.data);
                console.log('Security event:', data);
                updateSecurityEvents(data.data);
            });
            
            eventSource.addEventListener('heartbeat', function(event) {
                console.log('SSE heartbeat');
            });
            
            eventSource.onerror = function(event) {
                console.error('SSE error:', event);
                eventSource.close();
                
                if (reconnectAttempts < maxReconnectAttempts) {
                    reconnectAttempts++;
                    console.log(`Attempting to reconnect (${reconnectAttempts}/${maxReconnectAttempts}) in ${reconnectDelay}ms...`);
                    
                    setTimeout(initializeSSE, reconnectDelay);
                    reconnectDelay *= 2; // Exponential backoff
                } else {
                    console.error('Max reconnection attempts reached. Falling back to manual refresh.');
                    // Could implement polling fallback here if needed
                }
            };
        }
        
        function updateBotStatus(statusData) {
            const network = statusData.network;
            const status = statusData.status;
            
            // Update status indicators
            const statusEl = document.getElementById(`${network}-status`);
            if (statusEl) {
                statusEl.textContent = status.status;
                
                // Update status indicator color
                const indicator = statusEl.parentNode.querySelector('.status-indicator');
                if (indicator) {
                    indicator.className = `status-indicator ${status.status === 'online' ? 'status-online' : 'status-offline'}`;
                }
            }
            
            // Update detailed info if online
            if (status.status === 'online') {
                const detailsEl = statusEl?.parentNode.querySelector('.bot-details small');
                if (detailsEl) {
                    detailsEl.textContent = `PID: ${status.pid} | Up: ${formatUptime(status.uptime)}`;
                }
            }
        }
        
        function updateRecentActivity(commandData) {
            const network = commandData.network;
            const command = commandData.command;
            
            // Add to activity feed
            const feed = document.getElementById('activity-feed');
            if (feed && command) {
                const item = document.createElement('div');
                item.className = 'activity-item';
                item.innerHTML = `
                    <div class="activity-icon command">
                        <i class="fas fa-terminal"></i>
                    </div>
                    <div class="activity-content">
                        <div class="activity-title">
                            ${command.display_command || command.command} executed by ${command.username}
                        </div>
                        <div class="activity-meta">
                            ${network} • ${command.channel || 'DM'} • ${new Date(command.timestamp).toLocaleTimeString()}
                        </div>
                    </div>
                `;
                
                // Insert at top and limit to 10 items
                feed.insertBefore(item, feed.firstChild);
                while (feed.children.length > 10) {
                    feed.removeChild(feed.lastChild);
                }
            }
        }
        
        function updateSecurityEvents(eventData) {
            console.log('Security event received:', eventData);
            // Could add visual alerts, notifications, etc.
        }

        // Initial load
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Page loaded. Initial bot status elements:');
            console.log('Rizon status:', document.getElementById('rizon-status')?.textContent);
            console.log('Libera status:', document.getElementById('libera-status')?.textContent);
            console.log('Activity feed children:', document.getElementById('activity-feed')?.children.length);
            
            // Load initial data - SSE disabled temporarily for debugging
            refreshData().then(() => {
                console.log('Initial data loaded successfully');
                // TODO: Re-enable SSE after fixing basic data loading
                // initializeSSE();
                
                // Temporary: Refresh every 30 seconds until SSE is working
                setInterval(() => {
                    console.log('Temporary refresh (every 30s)');
                    refreshData();
                }, 30000);
            }).catch((error) => {
                console.error('Failed to load initial data:', error);
            });
            
            // Initialize logs if on logs tab
            if (document.getElementById('logs-content').classList.contains('active')) {
                setTimeout(refreshLogs, 2500);
                if (logAutoRefresh) startLogAutoRefresh();
            }
        });
        
        // Hall of Fame Moderation Functions
        async function refreshHallOfFame() {
            try {
                const response = await fetch('admin_api.php?action=get_high_scores');
                const data = await response.json();
                
                if (data && Array.isArray(data)) {
                    updateHallOfFameTable(data);
                } else if (data.error) {
                    console.error('Failed to load hall of fame scores:', data.error);
                    alert('Failed to load scores: ' + data.error);
                } else {
                    console.error('Failed to load hall of fame scores: Unknown error');
                    alert('Failed to load scores: Unknown error');
                }
            } catch (error) {
                console.error('Error fetching hall of fame scores:', error);
                alert('Error fetching scores: ' + error.message);
            }
        }
        
        function updateHallOfFameTable(scores) {
            const tbody = document.getElementById('hall-of-fame-table');
            if (!scores || scores.length === 0) {
                tbody.innerHTML = '<tr><td colspan="9" class="text-center">No scores found</td></tr>';
                return;
            }
            
            tbody.innerHTML = scores.map(score => `
                <tr>
                    <td><input type="checkbox" class="score-checkbox" value="${score.id}"></td>
                    <td>${score.id}</td>
                    <td><strong>${score.player_name}</strong></td>
                    <td>${score.score.toLocaleString()}</td>
                    <td>${score.level_reached}</td>
                    <td>${new Date(score.date_played).toLocaleString()}</td>
                    <td>${score.ip_address || 'N/A'}</td>
                    <td title="${score.session_id || 'N/A'}">${(score.session_id || 'N/A').substring(0, 12)}...</td>
                    <td>
                        <button class="admin-btn danger" onclick="deleteScore(${score.id})" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>
            `).join('');
        }
        
        function toggleAllScores() {
            const selectAll = document.getElementById('select-all-scores');
            const checkboxes = document.querySelectorAll('.score-checkbox');
            checkboxes.forEach(cb => cb.checked = selectAll.checked);
        }
        
        function filterScores() {
            const searchTerm = document.getElementById('score-search').value.toLowerCase();
            const rows = document.querySelectorAll('#hall-of-fame-table tr');
            
            rows.forEach(row => {
                const playerNameCell = row.querySelector('td:nth-child(3)');
                if (playerNameCell) {
                    const playerName = playerNameCell.textContent.toLowerCase();
                    row.style.display = playerName.includes(searchTerm) ? '' : 'none';
                }
            });
        }
        
        async function deleteScore(scoreId) {
            if (!confirm('Delete this score entry?')) return;
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `action=hall_of_fame_action&hall_action=delete_score&score_id=${scoreId}`
                });
                
                const data = await response.json();
                if (data.success) {
                    alert('Score deleted successfully');
                    refreshHallOfFame();
                } else {
                    alert('Failed to delete score: ' + (data.message || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error deleting score:', error);
                alert('Error deleting score: ' + error.message);
            }
        }
        
        async function deleteSelectedScores() {
            const selectedIds = Array.from(document.querySelectorAll('.score-checkbox:checked')).map(cb => cb.value);
            if (selectedIds.length === 0) {
                alert('Please select scores to delete');
                return;
            }
            
            if (!confirm(`Delete ${selectedIds.length} selected score(s)?`)) return;
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `action=hall_of_fame_action&hall_action=delete_multiple&score_ids=${selectedIds.join(',')}`
                });
                
                const data = await response.json();
                if (data.success) {
                    alert(`${selectedIds.length} score(s) deleted successfully`);
                    refreshHallOfFame();
                } else {
                    alert('Failed to delete scores: ' + (data.message || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error deleting scores:', error);
                alert('Error deleting scores: ' + error.message);
            }
        }
        
        async function addPlayerBan() {
            const playerName = document.getElementById('ban-player-name').value.trim();
            if (!playerName) {
                alert('Please enter a player name to ban');
                return;
            }
            
            if (!confirm(`Ban player "${playerName}" from submitting scores?`)) return;
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `action=hall_of_fame_action&hall_action=ban_player&player_name=${encodeURIComponent(playerName)}`
                });
                
                const data = await response.json();
                if (data.success) {
                    alert(`Player "${playerName}" banned successfully`);
                    document.getElementById('ban-player-name').value = '';
                } else {
                    alert('Failed to ban player: ' + (data.message || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error banning player:', error);
                alert('Error banning player: ' + error.message);
            }
        }
        
        async function clearAllScores() {
            try {
                const response = await fetch('', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'action=hall_of_fame_action&hall_action=clear_all'
                });
                
                const data = await response.json();
                if (data.success) {
                    alert('All scores cleared successfully');
                    refreshHallOfFame();
                } else {
                    alert('Failed to clear scores: ' + (data.message || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error clearing scores:', error);
                alert('Error clearing scores: ' + error.message);
            }
        }
        
        async function exportScores() {
            try {
                const response = await fetch('breakout_scores.php?action=admin_export');
                const data = await response.json();
                
                if (data.success && data.scores) {
                    const csv = convertScoresToCSV(data.scores);
                    downloadCSV(csv, 'hall_of_fame_scores.csv');
                } else {
                    alert('Failed to export scores: ' + (data.error || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error exporting scores:', error);
                alert('Error exporting scores: ' + error.message);
            }
        }
        
        function convertScoresToCSV(scores) {
            const headers = ['ID', 'Player Name', 'Score', 'Level', 'Date', 'IP Address', 'Session ID'];
            const csvContent = [
                headers.join(','),
                ...scores.map(score => [
                    score.id,
                    `"${score.player_name}"`,
                    score.score,
                    score.level_reached,
                    `"${score.date_played}"`,
                    `"${score.ip_address || ''}"`,
                    `"${score.session_id || ''}"`
                ].join(','))
            ].join('\n');
            
            return csvContent;
        }
        
        function downloadCSV(csvContent, filename) {
            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = filename;
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }
        
        // Load hall of fame when games tab is activated
        document.addEventListener('DOMContentLoaded', function() {
            // Auto-load hall of fame if on games tab
            const observer = new MutationObserver(function(mutations) {
                mutations.forEach(function(mutation) {
                    const gamesTab = document.getElementById('games-content');
                    if (gamesTab && gamesTab.classList.contains('active')) {
                        refreshHallOfFame();
                    }
                });
            });
            
            const gamesTab = document.getElementById('games-content');
            if (gamesTab) {
                observer.observe(gamesTab, { attributes: true, attributeFilter: ['class'] });
                
                // Load immediately if already active
                if (gamesTab.classList.contains('active')) {
                    setTimeout(refreshHallOfFame, 1000);
                }
            }
        });
        
        // Bot command injection functionality
        let selectedNetwork = 'both';
        let selectedChannel = '#bots';
        
        // Logs section command functionality
        let logsSelectedNetwork = 'rizon';
        let logsSelectedChannel = '#8BitVape';
        
        // Initialize network and channel selection
        document.addEventListener('DOMContentLoaded', function() {
            initializeManualCommands();
            initializeLogsManualCommands();
        });
        
        function initializeManualCommands() {
            // Set up network button listeners
            document.querySelectorAll('.network-btn').forEach(btn => {
                btn.addEventListener('click', () => selectNetwork(btn.dataset.network));
            });
            
            // Initialize channel buttons
            filterChannelsByNetwork();
            
            // Set up command input listener
            const commandInput = document.getElementById('manual-command');
            if (commandInput) {
                commandInput.addEventListener('input', updateCommandPreview);
                commandInput.addEventListener('keyup', updateCommandPreview);
                commandInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        sendManualCommand();
                    }
                });
            }
        }

        function initializeLogsManualCommands() {
            // Set up input event listener for real-time preview updates for logs section
            const logsCommandInput = document.getElementById('logs-manual-command');
            if (logsCommandInput) {
                logsCommandInput.addEventListener('input', updateLogsCommandPreview);
                logsCommandInput.addEventListener('keyup', updateLogsCommandPreview);
                
                // Add Enter key handler to send command
                logsCommandInput.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' && logsCommandInput.value.trim()) {
                        e.preventDefault();
                        sendLogsManualCommand();
                    }
                });
            }
            
            // Initialize default network and channel selection for logs
            selectLogsNetwork('rizon'); // This will also set up the default channel
            updateLogsCommandPreview();
        }
        
        function selectNetwork(network) {
            selectedNetwork = network;
            
            // Update button states
            document.querySelectorAll('.network-btn').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.network === network);
            });
            
            filterChannelsByNetwork();
            updateCommandPreview();
        }
        
        function filterChannelsByNetwork() {
            const channels = {
                'rizon': ['#bots', '#test', '#general'],
                'libera': ['#bots', '#test', '#general'],
                'both': ['#bots', '#test', '#general']
            };
            
            const channelButtons = document.getElementById('channel-buttons');
            if (!channelButtons) return;
            
            channelButtons.innerHTML = '';
            
            const networkChannels = channels[selectedNetwork] || channels['both'];
            networkChannels.forEach(channel => {
                const btn = document.createElement('button');
                btn.className = 'network-btn channel-btn';
                btn.textContent = channel;
                btn.onclick = () => selectChannel(channel);
                if (channel === selectedChannel) {
                    btn.classList.add('active');
                }
                channelButtons.appendChild(btn);
            });
        }
        
        function selectChannel(channel) {
            selectedChannel = channel;
            
            // Update button states
            document.querySelectorAll('.channel-btn').forEach(btn => {
                btn.classList.toggle('active', btn.textContent === channel);
            });
            
            updateCommandPreview();
        }
        
        function updateCommandPreview() {
            const input = document.getElementById('manual-command');
            const preview = document.getElementById('command-preview');
            if (!input || !preview) return;
            
            const message = input.value.trim();
            
            const networkText = selectedNetwork === 'both' ? 'Both networks' : 
                               selectedNetwork === 'rizon' ? '🔴 Rizon' : '🔵 Libera';
            
            if (message) {
                // Check if it's already a raw IRC command (starts with uppercase command)
                if (/^[A-Z]+\s/.test(message)) {
                    preview.textContent = `[${networkText}] Raw command: ${message}`;
                } else {
                    preview.textContent = `[${networkText}] PRIVMSG ${selectedChannel} :${message}`;
                }
            } else {
                preview.textContent = `[${networkText}] Ready to send to ${selectedChannel}`;
            }
        }

        // Logs section functions
        function selectLogsNetwork(network) {
            logsSelectedNetwork = network;
            
            // Update button states for logs section
            document.querySelectorAll('.admin-card .network-btn').forEach(btn => {
                if (btn.onclick && btn.onclick.toString().includes('selectLogsNetwork')) {
                    btn.classList.toggle('active', btn.dataset.network === network);
                }
            });
            
            updateLogsCommandPreview();
        }

        function selectLogsChannel(channel) {
            logsSelectedChannel = channel;
            updateLogsCommandPreview();
        }

        function updateLogsCommandPreview() {
            const input = document.getElementById('logs-manual-command');
            const preview = document.getElementById('logs-command-preview');
            
            // Check if preview element exists before accessing it
            if (!preview) {
                return;
            }
            
            const message = input ? input.value.trim() : '';
            
            const networkText = logsSelectedNetwork === 'both' ? 'Both networks' : 
                               logsSelectedNetwork === 'rizon' ? '🔴 Rizon' : '🔵 Libera';
            
            if (message) {
                // Check if it's already a raw IRC command (starts with uppercase command)
                if (message.match(/^[A-Z]+\s/)) {
                    preview.textContent = `[${networkText}] Will send raw command: ${message}`;
                } else {
                    preview.textContent = `[${networkText}] Will send: PRIVMSG ${logsSelectedChannel} :${message}`;
                }
            } else {
                preview.textContent = `[${networkText}] Will send: PRIVMSG ${logsSelectedChannel} :your message here`;
            }
        }

        async function sendLogsManualCommand() {
            console.log('sendLogsManualCommand called');
            const input = document.getElementById('logs-manual-command');
            const message = input.value.trim();
            console.log('Logs message:', message);
            if (!message) {
                alert('Please enter a message');
                return;
            }
            
            let command;
            if (message.match(/^[A-Z]+\s/)) {
                // Already a raw IRC command
                command = message;
            } else {
                command = `PRIVMSG ${logsSelectedChannel} :${message}`;
            }
            
            console.log('Sending logs command:', command, 'to network:', logsSelectedNetwork);
            const result = await adminApiCall('send_command', { command, network: logsSelectedNetwork });
            console.log('Send logs command result:', result);
            if (result.error) {
                alert('Error sending command: ' + result.error);
            } else {
                alert('Command sent successfully!');
                input.value = '';
                updateLogsCommandPreview();
            }
        }
        
        function sendManualCommand() {
            const input = document.getElementById('manual-command');
            if (!input) return;
            
            const message = input.value.trim();
            if (!message) {
                alert('Please enter a command or message');
                return;
            }
            
            const data = new FormData();
            data.append('action', 'inject_command');
            data.append('network', selectedNetwork);
            data.append('channel', selectedChannel);
            data.append('message', message);
            
            fetch('/unified_admin_api.php', {
                method: 'POST',
                body: data
            })
            .then(response => response.json())
            .then(result => {
                if (result.success) {
                    alert('Command sent successfully!');
                    input.value = '';
                    updateCommandPreview();
                } else {
                    alert('Error sending command: ' + result.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Network error occurred');
            });
        }

        // Beans Management Functions
        let beansData = [];
        
        function loadBeansData() {
            fetch('admin_styled.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=get_beans_data'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    beansData = data.beans;
                    updateBeansStats(data);
                    displayBeans(beansData);
                }
            })
            .catch(error => console.error('Error loading beans:', error));
        }

        function updateBeansStats(data) {
            document.getElementById('total-beans').textContent = data.total || '0';
            document.getElementById('rizon-beans').textContent = data.rizon_count || '0';
            document.getElementById('libera-beans').textContent = data.libera_count || '0';
            document.getElementById('total-bean-views').textContent = data.total_views || '0';
        }

        function displayBeans(beans) {
            const tbody = document.getElementById('beans-tbody');
            if (!beans || beans.length === 0) {
                tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 2rem;">No beans found</td></tr>';
                return;
            }
            
            tbody.innerHTML = beans.map(bean => `
                <tr data-network="${bean.network}" data-searchable="${(bean.url + ' ' + bean.added_by + ' ' + (bean.description || '')).toLowerCase()}">
                    <td>
                        <img src="${escapeHtml(bean.url)}" 
                             style="max-width: 60px; max-height: 60px; cursor: pointer;" 
                             alt="Bean preview"
                             onerror="this.style.display='none'; this.parentElement.innerHTML='[No preview]';"
                             onclick="window.open('${escapeHtml(bean.url)}', '_blank')">
                    </td>
                    <td>
                        <span class="badge ${bean.network === 'rizon' ? 'badge-warning' : 'badge-info'}">
                            ${bean.network.toUpperCase()}
                        </span>
                    </td>
                    <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                        <a href="${escapeHtml(bean.url)}" target="_blank">${escapeHtml(bean.url)}</a>
                    </td>
                    <td>${escapeHtml(bean.added_by)}</td>
                    <td>${escapeHtml(bean.channel || 'N/A')}</td>
                    <td>${new Date(bean.added_time).toLocaleString()}</td>
                    <td>${bean.view_count}</td>
                    <td>${escapeHtml(bean.description || '')}</td>
                    <td>
                        <button class="admin-btn danger" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;" 
                                onclick="deleteBean(${bean.id}, '${bean.network}')">
                            <i class="fas fa-trash"></i> Delete
                        </button>
                    </td>
                </tr>
            `).join('');
        }

        function filterBeans() {
            const searchTerm = document.getElementById('bean-search').value.toLowerCase();
            const networkFilter = document.getElementById('bean-network-filter').value;
            
            const filtered = beansData.filter(bean => {
                const matchesSearch = !searchTerm || 
                    (bean.url + ' ' + bean.added_by + ' ' + (bean.description || '')).toLowerCase().includes(searchTerm);
                const matchesNetwork = !networkFilter || bean.network === networkFilter;
                return matchesSearch && matchesNetwork;
            });
            
            displayBeans(filtered);
        }

        function refreshBeans() {
            loadBeansData();
        }

        function deleteBean(beanId, network) {
            if (!confirm('Are you sure you want to delete this bean?')) {
                return;
            }
            
            fetch('admin_styled.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `action=delete_bean&bean_id=${beanId}&network=${network}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification('Bean deleted successfully', 'success');
                    loadBeansData();
                } else {
                    showNotification(data.message || 'Failed to delete bean', 'error');
                }
            })
            .catch(error => {
                console.error('Error deleting bean:', error);
                showNotification('Error deleting bean', 'error');
            });
        }

        function escapeHtml(text) {
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return String(text).replace(/[&<>"']/g, m => map[m]);
        }

        function showNotification(message, type) {
            const alertClass = type === 'success' ? 'success' : 'danger';
            const notification = document.createElement('div');
            notification.className = `status-indicator status-${alertClass}`;
            notification.textContent = message;
            notification.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 9999; padding: 1rem; border-radius: 5px;';
            document.body.appendChild(notification);
            setTimeout(() => notification.remove(), 3000);
        }

        // Load beans data when beans tab is shown
        const originalShowTab = showTab;
        showTab = function(tabName) {
            originalShowTab(tabName);
            if (tabName === 'beans') {
                loadBeansData();
            }
        };
    </script>
</body>
</html>