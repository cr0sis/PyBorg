<?php
/**
 * Seamlessly Integrated Admin Panel
 * Looks exactly like main site but only appears for authenticated admins
 * ZERO client-side footprint - completely invisible to F12
 */

// Security initialization
require_once 'security_config.php';
require_once 'auth.php';
require_once 'security_hardened.php';

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

// If not admin verified, show regular site (no traces of admin functionality)
if (!$admin_verified) {
    // Redirect to regular index.php (will serve HTML to non-admins) - zero admin traces
    header('Location: /index.php');
    exit;
}

// Log admin access
logSecurityEvent('INTEGRATED_ADMIN_ACCESS', "Integrated admin panel accessed by {$_SESSION['username']}", 'MEDIUM');

// Get bot status for dashboard
function getBotStatus() {
    $status = ['rizon' => 'Unknown', 'libera' => 'Unknown'];
    
    try {
        $screens = shell_exec('screen -list 2>/dev/null') ?: '';
        $status['rizon'] = strpos($screens, 'rizon_bot') !== false ? 'Online' : 'Offline';
        $status['libera'] = strpos($screens, 'libera_bot') !== false ? 'Online' : 'Offline';
    } catch (Exception $e) {
        // Fallback to process check
        $processes = shell_exec('ps aux | grep -E "(rizon|libera)" | grep -v grep') ?: '';
        $status['rizon'] = strpos($processes, 'rizon') !== false ? 'Online' : 'Offline';
        $status['libera'] = strpos($processes, 'libera') !== false ? 'Online' : 'Offline';
    }
    
    return $status;
}

// Get system stats
function getSystemStats() {
    $stats = [
        'cpu' => 0,
        'memory' => 0,
        'disk' => 0,
        'uptime' => 'Unknown'
    ];
    
    try {
        // CPU usage
        $load = sys_getloadavg();
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
        
        // Uptime
        $uptime_seconds = (int)shell_exec('cat /proc/uptime | cut -d. -f1');
        $days = floor($uptime_seconds / 86400);
        $hours = floor(($uptime_seconds % 86400) / 3600);
        $stats['uptime'] = "{$days}d {$hours}h";
        
    } catch (Exception $e) {
        // Use fallback values
    }
    
    return $stats;
}

$bot_status = getBotStatus();
$system_stats = getSystemStats();

// Handle admin actions
$action_result = '';
if (isset($_GET['admin_action']) && $_GET['admin_action']) {
    $action = $_GET['admin_action'];
    logSecurityEvent('ADMIN_ACTION', "Admin action requested: $action by {$_SESSION['username']}", 'MEDIUM');
    
    switch ($action) {
        case 'restart_rizon':
            $result = shell_exec('cd /home/cr0/cr0bot && ./restart_rizon.sh 2>&1');
            $action_result = "Rizon bot restart initiated.<br><pre>" . htmlspecialchars($result) . "</pre>";
            break;
            
        case 'restart_libera':
            $result = shell_exec('cd /home/cr0/cr0bot && ./restart_libera.sh 2>&1');
            $action_result = "Libera bot restart initiated.<br><pre>" . htmlspecialchars($result) . "</pre>";
            break;
            
        case 'restart_all':
            $result = shell_exec('cd /home/cr0/cr0bot && ./restart_all_bots.sh 2>&1');
            $action_result = "All bots restart initiated.<br><pre>" . htmlspecialchars($result) . "</pre>";
            break;
    }
}
?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PyBorg - IRC Bot Documentation</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
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

        /* Admin Dashboard Styles - Seamlessly Integrated */
        .admin-dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 2rem;
            margin-top: 2rem;
        }

        .admin-card {
            background: var(--bg-primary);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-xl);
            padding: 2rem;
            box-shadow: var(--shadow-lg);
            transition: all 0.2s ease;
        }

        .admin-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
            border-color: var(--border-medium);
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

        .action-result {
            margin-top: 1.5rem;
            padding: 1rem;
            background: var(--accent-green);
            border: 1px solid #10b981;
            border-radius: var(--radius-md);
            color: #065f46;
            font-family: var(--font-mono);
            font-size: 0.875rem;
        }

        .admin-indicator {
            position: fixed;
            bottom: 1rem;
            right: 1rem;
            background: var(--primary-color);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: var(--radius-lg);
            font-size: 0.75rem;
            font-weight: 600;
            box-shadow: var(--shadow-md);
            z-index: 1000;
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

        [data-theme="dark"] .action-result {
            background: var(--accent-green);
            border-color: #10b981;
            color: #10b981;
        }
    </style>
</head>
<body>
    <div class="theme-toggle" onclick="toggleTheme()">
        <i class="theme-toggle-icon fas fa-moon"></i>
        <span class="theme-toggle-text">Dark</span>
    </div>

    <div class="container">
        <div class="header">
            <h1>🤖 PyBorg</h1>
            <p class="subtitle">IRC Bot Administration Panel</p>
            <div class="network-tabs">
                <button class="tab-button active">
                    🛡️ Admin Dashboard
                </button>
                <button class="tab-button" onclick="window.location.href='/index.php'">
                    📚 Documentation
                </button>
                <button class="tab-button" onclick="window.location.href='/auth.php?action=logout'">
                    🚪 Logout
                </button>
            </div>
        </div>

        <div class="admin-dashboard">
            <!-- IRC Bot Status -->
            <div class="admin-card">
                <h3><i class="fas fa-robot"></i> IRC Bot Status</h3>
                <div class="admin-stats">
                    <div class="stat-item">
                        <div class="stat-value">
                            <span class="status-indicator <?php echo $bot_status['rizon'] === 'Online' ? 'status-online' : 'status-offline'; ?>"></span>
                            <?php echo $bot_status['rizon']; ?>
                        </div>
                        <div class="stat-label">Rizon Network</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value">
                            <span class="status-indicator <?php echo $bot_status['libera'] === 'Online' ? 'status-online' : 'status-offline'; ?>"></span>
                            <?php echo $bot_status['libera']; ?>
                        </div>
                        <div class="stat-label">Libera Network</div>
                    </div>
                </div>
                <div class="admin-actions">
                    <a href="?admin_action=restart_rizon" class="admin-btn">
                        <i class="fas fa-redo"></i> Restart Rizon
                    </a>
                    <a href="?admin_action=restart_libera" class="admin-btn">
                        <i class="fas fa-redo"></i> Restart Libera
                    </a>
                    <a href="?admin_action=restart_all" class="admin-btn danger">
                        <i class="fas fa-power-off"></i> Restart All
                    </a>
                </div>
            </div>

            <!-- System Resources -->
            <div class="admin-card">
                <h3><i class="fas fa-server"></i> System Resources</h3>
                <div class="admin-stats">
                    <div class="stat-item">
                        <div class="stat-value"><?php echo $system_stats['cpu']; ?>%</div>
                        <div class="stat-label">CPU Usage</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value"><?php echo $system_stats['memory']; ?>%</div>
                        <div class="stat-label">Memory</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value"><?php echo $system_stats['disk']; ?>%</div>
                        <div class="stat-label">Disk Usage</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value"><?php echo $system_stats['uptime']; ?></div>
                        <div class="stat-label">Uptime</div>
                    </div>
                </div>
            </div>

            <!-- User Management -->
            <div class="admin-card">
                <h3><i class="fas fa-users"></i> User Management</h3>
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
            </div>

            <!-- Security Events -->
            <div class="admin-card">
                <h3><i class="fas fa-shield-alt"></i> Security Monitor</h3>
                <div style="background: #000; color: #0f0; padding: 1rem; border-radius: var(--radius-md); font-family: var(--font-mono); font-size: 0.75rem; max-height: 200px; overflow-y: auto;">
                    <?php
                    $security_log = '/tmp/admin_security.log';
                    if (file_exists($security_log)) {
                        $recent_logs = array_slice(file($security_log), -10);
                        foreach (array_reverse($recent_logs) as $log_line) {
                            $entry = json_decode(trim($log_line), true);
                            if ($entry) {
                                echo "[{$entry['timestamp']}] {$entry['event_type']}: {$entry['message']}\n";
                            }
                        }
                    } else {
                        echo "Security monitoring active...\n";
                    }
                    ?>
                </div>
            </div>
        </div>

        <?php if ($action_result): ?>
        <div class="admin-card" style="margin-top: 2rem;">
            <h3><i class="fas fa-terminal"></i> Action Result</h3>
            <div class="action-result"><?php echo $action_result; ?></div>
        </div>
        <?php endif; ?>
    </div>

    <div class="admin-indicator">
        👤 Admin: <?php echo htmlspecialchars($_SESSION['username']); ?>
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
                icon.className = 'theme-toggle-icon fas fa-sun';
                text.textContent = 'Light';
            } else {
                icon.className = 'theme-toggle-icon fas fa-moon';
                text.textContent = 'Dark';
            }
            
            localStorage.setItem('theme', newTheme);
        }

        // Apply saved theme
        const savedTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        
        if (savedTheme === 'dark') {
            document.querySelector('.theme-toggle-icon').className = 'theme-toggle-icon fas fa-sun';
            document.querySelector('.theme-toggle-text').textContent = 'Light';
        }
    </script>
</body>
</html>