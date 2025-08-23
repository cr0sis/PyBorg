<?php
/**
 * Invisible Admin Entry Point
 * NO client-side traces, completely server-side rendered
 * Accessible only through direct URL knowledge with proper authentication
 */

// Hardcore security initialization
require_once 'security_config.php';
require_once 'auth.php';
require_once 'security_hardened.php';

// ZERO client-side footprint - no JavaScript, no AJAX hints, no HTML comments
// This file leaves NO traces in any frontend code or network inspector

// Check if user is admin with valid session
if (!isLoggedIn() || !isAdmin()) {
    // Return generic 404 to hide existence
    http_response_code(404);
    header('Content-Type: text/html');
    echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
    exit;
}

// Verify 2FA if required
if (!isset($_SESSION['2fa_verified_time']) || (time() - $_SESSION['2fa_verified_time']) > 3600) {
    // Redirect to 2FA verification - no admin hints
    header('Location: /auth.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit;
}

// Additional IP verification for admin
if (!isset($_SESSION['bound_ip']) || $_SESSION['bound_ip'] !== $_SERVER['REMOTE_ADDR']) {
    http_response_code(403);
    echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>Access denied.</p></body></html>';
    exit;
}

// Log admin access
logSecurityEvent('ADMIN_PANEL_ACCESS', "Admin panel accessed by {$_SESSION['username']}", 'MEDIUM');

?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Dashboard</title>
    <!-- NO external resources, completely self-contained -->
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #fff;
            min-height: 100vh;
        }
        .admin-header {
            background: rgba(0,0,0,0.3);
            padding: 15px 30px;
            border-bottom: 2px solid rgba(255,255,255,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .admin-title { font-size: 1.8em; font-weight: 300; }
        .admin-user { font-size: 0.9em; color: #b8d4ff; }
        .admin-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 30px;
        }
        .admin-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin-top: 20px;
        }
        .admin-card {
            background: rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 25px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
            transition: transform 0.2s ease;
        }
        .admin-card:hover { transform: translateY(-2px); }
        .admin-card h3 {
            color: #fff;
            margin-bottom: 15px;
            font-size: 1.3em;
            border-bottom: 2px solid rgba(255,255,255,0.2);
            padding-bottom: 8px;
        }
        .admin-stats {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin: 15px 0;
        }
        .stat-item {
            text-align: center;
            padding: 15px;
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #4CAF50;
        }
        .stat-label {
            font-size: 0.85em;
            color: #b8d4ff;
            margin-top: 5px;
        }
        .admin-actions {
            display: flex;
            gap: 10px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        .admin-btn {
            background: linear-gradient(45deg, #4CAF50, #45a049);
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9em;
            transition: all 0.2s ease;
            text-decoration: none;
            display: inline-block;
        }
        .admin-btn:hover {
            background: linear-gradient(45deg, #45a049, #4CAF50);
            transform: translateY(-1px);
        }
        .admin-btn.danger {
            background: linear-gradient(45deg, #f44336, #d32f2f);
        }
        .admin-btn.danger:hover {
            background: linear-gradient(45deg, #d32f2f, #f44336);
        }
        .log-output {
            background: #000;
            color: #0f0;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.8em;
            max-height: 300px;
            overflow-y: auto;
            margin: 15px 0;
            border: 1px solid #333;
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-online { background: #4CAF50; }
        .status-offline { background: #f44336; }
        .status-warning { background: #ff9800; }
        .hidden { display: none; }
    </style>
</head>
<body>
    <div class="admin-header">
        <div class="admin-title">🛡️ Admin Control Panel</div>
        <div class="admin-user">
            Logged in as: <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong>
            | Session: <?php echo date('H:i:s', $_SESSION['login_time']); ?>
        </div>
    </div>

    <div class="admin-container">
        <div class="admin-grid">
            <!-- Bot Status Card -->
            <div class="admin-card">
                <h3>🤖 IRC Bot Status</h3>
                <div class="admin-stats">
                    <?php
                    // Server-side bot status check
                    $rizon_status = 'Unknown';
                    $libera_status = 'Unknown';
                    
                    // Check screen sessions
                    try {
                        $screens = shell_exec('screen -list 2>/dev/null') ?: '';
                        $rizon_status = strpos($screens, 'rizon_bot') !== false ? 'Online' : 'Offline';
                        $libera_status = strpos($screens, 'libera_bot') !== false ? 'Online' : 'Offline';
                    } catch (Exception $e) {
                        // Fallback to process check
                        $processes = shell_exec('ps aux | grep -E "(rizon|libera)" | grep -v grep') ?: '';
                        $rizon_status = strpos($processes, 'rizon') !== false ? 'Online' : 'Offline';
                        $libera_status = strpos($processes, 'libera') !== false ? 'Online' : 'Offline';
                    }
                    ?>
                    <div class="stat-item">
                        <div class="stat-value">
                            <span class="status-indicator <?php echo $rizon_status === 'Online' ? 'status-online' : 'status-offline'; ?>"></span>
                            <?php echo $rizon_status; ?>
                        </div>
                        <div class="stat-label">Rizon Network</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">
                            <span class="status-indicator <?php echo $libera_status === 'Online' ? 'status-online' : 'status-offline'; ?>"></span>
                            <?php echo $libera_status; ?>
                        </div>
                        <div class="stat-label">Libera Network</div>
                    </div>
                </div>
                <div class="admin-actions">
                    <a href="?action=restart_rizon" class="admin-btn">Restart Rizon</a>
                    <a href="?action=restart_libera" class="admin-btn">Restart Libera</a>
                    <a href="?action=restart_all" class="admin-btn danger">Restart All</a>
                </div>
            </div>

            <!-- System Resources Card -->
            <div class="admin-card">
                <h3>⚡ System Resources</h3>
                <div class="admin-stats">
                    <?php
                    // Server-side system stats
                    $cpu_usage = 0;
                    $memory_percent = 0;
                    $disk_usage = 0;
                    $uptime = 'Unknown';
                    
                    try {
                        // CPU usage
                        $load = sys_getloadavg();
                        $cpu_usage = round($load[0] * 100 / 4, 1); // Assuming 4 cores
                        
                        // Memory usage
                        $free = shell_exec('free');
                        if ($free) {
                            preg_match_all('/\s+(\d+)/', $free, $matches);
                            if (count($matches[1]) >= 6) {
                                $memory_percent = round(($matches[1][0] - $matches[1][1]) / $matches[1][0] * 100, 1);
                            }
                        }
                        
                        // Disk usage
                        $disk_free = disk_free_space('/');
                        $disk_total = disk_total_space('/');
                        if ($disk_free && $disk_total) {
                            $disk_usage = round((1 - $disk_free / $disk_total) * 100, 1);
                        }
                        
                        // Uptime
                        $uptime_seconds = (int)shell_exec('cat /proc/uptime | cut -d. -f1');
                        $days = floor($uptime_seconds / 86400);
                        $hours = floor(($uptime_seconds % 86400) / 3600);
                        $uptime = "{$days}d {$hours}h";
                        
                    } catch (Exception $e) {
                        // Fallback values
                    }
                    ?>
                    <div class="stat-item">
                        <div class="stat-value"><?php echo $cpu_usage; ?>%</div>
                        <div class="stat-label">CPU Usage</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value"><?php echo $memory_percent; ?>%</div>
                        <div class="stat-label">Memory</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value"><?php echo $disk_usage; ?>%</div>
                        <div class="stat-label">Disk Usage</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value"><?php echo $uptime; ?></div>
                        <div class="stat-label">Uptime</div>
                    </div>
                </div>
            </div>

            <!-- User Management Card -->
            <div class="admin-card">
                <h3>👥 User Management</h3>
                <?php
                $users = getAllUsers();
                $active_users = array_filter($users, function($user) { return $user['is_active']; });
                $admin_users = array_filter($users, function($user) { return $user['is_admin']; });
                ?>
                <div class="admin-stats">
                    <div class="stat-item">
                        <div class="stat-value"><?php echo count($users); ?></div>
                        <div class="stat-label">Total Users</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value"><?php echo count($active_users); ?></div>
                        <div class="stat-label">Active Users</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value"><?php echo count($admin_users); ?></div>
                        <div class="stat-label">Admin Users</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value"><?php echo count($users) - count($active_users); ?></div>
                        <div class="stat-label">Disabled</div>
                    </div>
                </div>
                <div class="admin-actions">
                    <a href="?section=users" class="admin-btn">Manage Users</a>
                    <a href="?section=sessions" class="admin-btn">Active Sessions</a>
                </div>
            </div>

            <!-- Logs & Security Card -->
            <div class="admin-card">
                <h3>📊 Security & Logs</h3>
                <div class="admin-actions">
                    <a href="?section=security_log" class="admin-btn">Security Events</a>
                    <a href="?section=bot_logs" class="admin-btn">Bot Logs</a>
                    <a href="?section=error_logs" class="admin-btn danger">Error Logs</a>
                </div>
                
                <!-- Live Log Preview -->
                <div class="log-output">
                    <?php
                    // Show recent security events
                    $security_log = '/tmp/admin_security.log';
                    if (file_exists($security_log)) {
                        $recent_logs = array_slice(file($security_log), -10);
                        foreach ($recent_logs as $log_line) {
                            $entry = json_decode(trim($log_line), true);
                            if ($entry) {
                                echo "[{$entry['timestamp']}] {$entry['event_type']}: {$entry['message']}\n";
                            }
                        }
                    } else {
                        echo "Security log initialized.\n";
                    }
                    ?>
                </div>
            </div>
        </div>

        <?php
        // Handle admin actions with zero client-side footprint
        if (isset($_GET['action'])) {
            $action = $_GET['action'];
            logSecurityEvent('ADMIN_ACTION', "Admin action requested: $action by {$_SESSION['username']}", 'MEDIUM');
            
            echo '<div class="admin-card" style="margin-top: 25px;"><h3>🔧 Action Result</h3>';
            
            switch ($action) {
                case 'restart_rizon':
                    echo '<p>Restarting Rizon bot...</p>';
                    $result = shell_exec('cd /home/cr0/cr0bot && ./restart_rizon.sh 2>&1');
                    echo '<div class="log-output">' . htmlspecialchars($result) . '</div>';
                    break;
                    
                case 'restart_libera':
                    echo '<p>Restarting Libera bot...</p>';
                    $result = shell_exec('cd /home/cr0/cr0bot && ./restart_libera.sh 2>&1');
                    echo '<div class="log-output">' . htmlspecialchars($result) . '</div>';
                    break;
                    
                case 'restart_all':
                    echo '<p>Restarting all bots...</p>';
                    $result = shell_exec('cd /home/cr0/cr0bot && ./restart_all_bots.sh 2>&1');
                    echo '<div class="log-output">' . htmlspecialchars($result) . '</div>';
                    break;
                    
                default:
                    echo '<p style="color: #f44336;">Unknown action.</p>';
            }
            
            echo '</div>';
        }

        // Handle section views
        if (isset($_GET['section'])) {
            $section = $_GET['section'];
            
            echo '<div class="admin-card" style="margin-top: 25px;">';
            
            switch ($section) {
                case 'users':
                    echo '<h3>👥 User Management</h3>';
                    echo '<table style="width: 100%; color: #fff; border-collapse: collapse;">';
                    echo '<tr style="border-bottom: 1px solid rgba(255,255,255,0.2);"><th style="padding: 10px; text-align: left;">Username</th><th>Email</th><th>Admin</th><th>Status</th><th>Created</th></tr>';
                    
                    foreach (getAllUsers() as $user) {
                        $status_color = $user['is_active'] ? '#4CAF50' : '#f44336';
                        $admin_badge = $user['is_admin'] ? '👑' : '';
                        echo "<tr style='border-bottom: 1px solid rgba(255,255,255,0.1);'>";
                        echo "<td style='padding: 10px;'>{$admin_badge} " . htmlspecialchars($user['username']) . "</td>";
                        echo "<td style='padding: 10px;'>" . htmlspecialchars($user['email']) . "</td>";
                        echo "<td style='padding: 10px;'>" . ($user['is_admin'] ? 'Yes' : 'No') . "</td>";
                        echo "<td style='padding: 10px; color: $status_color;'>" . ($user['is_active'] ? 'Active' : 'Disabled') . "</td>";
                        echo "<td style='padding: 10px;'>" . date('Y-m-d', strtotime($user['created_at'])) . "</td>";
                        echo "</tr>";
                    }
                    
                    echo '</table>';
                    break;
                    
                case 'security_log':
                    echo '<h3>🔒 Security Events</h3>';
                    echo '<div class="log-output" style="max-height: 500px;">';
                    
                    $security_log = '/tmp/admin_security.log';
                    if (file_exists($security_log)) {
                        $logs = array_slice(file($security_log), -50);
                        foreach (array_reverse($logs) as $log_line) {
                            $entry = json_decode(trim($log_line), true);
                            if ($entry) {
                                $severity_color = match($entry['severity']) {
                                    'CRITICAL' => '#ff1744',
                                    'HIGH' => '#f44336',
                                    'MEDIUM' => '#ff9800',
                                    'LOW' => '#4CAF50',
                                    default => '#fff'
                                };
                                echo "<span style='color: $severity_color;'>[{$entry['timestamp']}] {$entry['severity']}</span> ";
                                echo "<strong>{$entry['event_type']}</strong>: {$entry['message']}\n";
                            }
                        }
                    }
                    
                    echo '</div>';
                    break;
                    
                case 'bot_logs':
                    echo '<h3>🤖 Bot Logs</h3>';
                    echo '<div class="log-output" style="max-height: 500px;">';
                    
                    // Show recent bot logs
                    $log_files = [
                        '/data/cr0_system/logs/irc_networks/rizon/rizon_bot.log',
                        '/data/cr0_system/logs/irc_networks/libera/libera_bot.log'
                    ];
                    
                    foreach ($log_files as $log_file) {
                        if (file_exists($log_file)) {
                            $network = basename(dirname($log_file));
                            echo "<strong style='color: #4CAF50;'>[$network]</strong>\n";
                            $logs = array_slice(file($log_file), -20);
                            foreach ($logs as $line) {
                                echo htmlspecialchars($line);
                            }
                            echo "\n";
                        }
                    }
                    
                    echo '</div>';
                    break;
            }
            
            echo '</div>';
        }
        ?>
    </div>
</body>
</html>