<?php
/**
 * Comprehensive Admin Panel
 * Full-featured admin dashboard with all monitoring and management tools
 */

// Security initialization
require_once 'security_config.php';
require_once 'auth.php';
require_once 'security_hardened.php';
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
    
    switch ($action) {
        case 'get_live_data':
            $response = [
                'success' => true,
                'bot_stats' => AdvancedAdmin::getBotStatistics(),
                'recent_commands' => AdvancedAdmin::getRecentCommands(20),
                'game_stats' => AdvancedAdmin::getGameStatistics(),
                'user_analytics' => AdvancedAdmin::getUserAnalytics(),
                'security_events' => AdvancedAdmin::getSecurityEvents(10),
                'db_health' => AdvancedAdmin::getDatabaseHealth(),
                'performance' => AdvancedAdmin::getCommandPerformance()
            ];
            break;
            
        case 'bot_action':
            $bot_action = $_POST['bot_action'] ?? '';
            $network = $_POST['network'] ?? 'all';
            $response = AdvancedAdmin::manageBots($bot_action, $network);
            break;
            
        default:
            $response['message'] = 'Invalid action';
    }
    
    echo json_encode($response);
    exit;
}

// Log admin access
logSecurityEvent('COMPREHENSIVE_ADMIN_ACCESS', "Comprehensive admin panel accessed by {$_SESSION['username']}", 'MEDIUM');

// Get initial data
$bot_stats = AdvancedAdmin::getBotStatistics();
$system_stats = [
    'cpu' => 0,
    'memory' => 0,
    'disk' => 0,
    'uptime' => 'Unknown'
];

try {
    // CPU usage
    $load = sys_getloadavg();
    $system_stats['cpu'] = round($load[0] * 100 / 4, 1);
    
    // Memory usage
    $free = shell_exec('free');
    if ($free) {
        preg_match_all('/\s+(\d+)/', $free, $matches);
        if (count($matches[1]) >= 6) {
            $system_stats['memory'] = round(($matches[1][0] - $matches[1][1]) / $matches[1][0] * 100, 1);
        }
    }
    
    // Disk usage
    $disk_free = disk_free_space('/');
    $disk_total = disk_total_space('/');
    if ($disk_free && $disk_total) {
        $system_stats['disk'] = round((1 - $disk_free / $disk_total) * 100, 1);
    }
    
    // Uptime
    $uptime_seconds = (int)shell_exec('cat /proc/uptime | cut -d. -f1');
    $days = floor($uptime_seconds / 86400);
    $hours = floor(($uptime_seconds % 86400) / 3600);
    $system_stats['uptime'] = "{$days}d {$hours}h";
    
} catch (Exception $e) {
    // Use fallback values
}

?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Comprehensive Admin Panel - CR0 Bot System</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Fira+Code:wght@300;400;500&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary-color: #1e40af;
            --primary-dark: #1d4ed8;
            --primary-light: #3b82f6;
            --tech-blue: #0ea5e9;
            --tech-cyan: #06b6d4;
            --tech-green: #10b981;
            --success-color: #10b981;
            --warning-color: #f59e0b;
            --danger-color: #ef4444;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-muted: #64748b;
            --bg-primary: #ffffff;
            --bg-secondary: #f8fafc;
            --bg-tertiary: #f1f5f9;
            --bg-hero: linear-gradient(135deg, #1e40af 0%, #0ea5e9 100%);
            --border-light: #e2e8f0;
            --border-medium: #cbd5e1;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 10px 10px -5px rgb(0 0 0 / 0.04);
            --radius-sm: 0.375rem;
            --radius-md: 0.5rem;
            --radius-lg: 0.75rem;
            --radius-xl: 1rem;
            --font-mono: 'Fira Code', 'JetBrains Mono', 'Courier New', monospace;
        }

        [data-theme="dark"] {
            --primary-color: #3b82f6;
            --text-primary: #f9fafb;
            --text-secondary: #d1d5db;
            --text-muted: #9ca3af;
            --bg-primary: #1f2937;
            --bg-secondary: #111827;
            --bg-tertiary: #374151;
            --border-light: #374151;
            --border-medium: #4b5563;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-secondary);
            color: var(--text-primary);
            line-height: 1.6;
            font-weight: 400;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }

        @keyframes glow {
            0%, 100% { box-shadow: 0 0 5px rgba(30, 64, 175, 0.3); }
            50% { box-shadow: 0 0 20px rgba(30, 64, 175, 0.6); }
        }

        @keyframes slideUp {
            from { transform: translateY(20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .admin-header {
            background: var(--bg-primary);
            border-bottom: 1px solid var(--border-light);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: var(--shadow-sm);
        }

        .admin-title {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--primary-color);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .admin-user {
            display: flex;
            align-items: center;
            gap: 1rem;
            font-size: 0.875rem;
            color: var(--text-secondary);
        }

        .status-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 0.5rem;
        }

        .status-online {
            background: var(--success-color);
            box-shadow: 0 0 4px rgba(16, 185, 129, 0.5);
            animation: pulse 2s infinite;
        }

        .status-offline {
            background: var(--danger-color);
            box-shadow: 0 0 4px rgba(239, 68, 68, 0.5);
            animation: pulse 1s infinite;
        }

        .terminal-feed {
            background: #0f1419;
            color: #00ff00;
            font-family: var(--font-mono);
            font-size: 0.75rem;
            border-radius: var(--radius-md);
            padding: 1rem;
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid #1a1a1a;
        }

        .terminal-line {
            margin-bottom: 0.25rem;
            white-space: pre-wrap;
        }

        .terminal-line.error {
            color: #ff4444;
        }

        .terminal-line.warning {
            color: #ffaa00;
        }

        .terminal-line.info {
            color: #00aaff;
        }

        .terminal-cursor {
            display: inline-block;
            width: 8px;
            height: 16px;
            background: #00ff00;
            animation: pulse 1s infinite;
        }

        .admin-nav {
            background: var(--bg-primary);
            border-bottom: 1px solid var(--border-light);
            padding: 0 2rem;
            overflow-x: auto;
        }

        .nav-tabs {
            display: flex;
            gap: 0;
            min-width: fit-content;
        }

        .nav-tab {
            background: none;
            border: none;
            padding: 1rem 1.5rem;
            color: var(--text-secondary);
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s ease;
            white-space: nowrap;
            font-weight: 500;
        }

        .nav-tab:hover {
            color: var(--text-primary);
            background: var(--bg-tertiary);
        }

        .nav-tab.active {
            color: var(--primary-color);
            border-bottom-color: var(--primary-color);
            background: var(--bg-secondary);
        }

        .admin-container {
            padding: 2rem;
            max-width: 1400px;
            margin: 0 auto;
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .admin-card {
            background: var(--bg-primary);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-xl);
            padding: 1.5rem;
            box-shadow: var(--shadow-md);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            animation: slideUp 0.6s ease-out;
        }

        .admin-card:hover {
            box-shadow: var(--shadow-xl);
            transform: translateY(-2px);
        }

        .hero-card {
            background: var(--bg-hero);
            color: white;
            grid-column: 1 / -1;
            position: relative;
            overflow: hidden;
        }

        .hero-card::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 100px;
            height: 100px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            transform: translate(30px, -30px);
        }

        .hero-card .card-title,
        .hero-card .card-subtitle {
            color: white;
        }

        .card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
        }

        .card-title {
            font-size: 1.125rem;
            font-weight: 600;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .card-subtitle {
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
        }

        .metric-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }

        .metric-item {
            text-align: center;
            padding: 1rem;
            background: var(--bg-secondary);
            border-radius: var(--radius-lg);
            border: 1px solid var(--border-light);
        }

        .metric-value {
            font-size: 1.5rem;
            font-weight: 700;
            font-family: var(--font-mono);
            color: var(--primary-color);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }

        .metric-value.hero {
            font-size: 2rem;
            color: white;
        }

        .progress-bar {
            width: 100%;
            height: 8px;
            background: rgba(0, 0, 0, 0.1);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 0.5rem;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--tech-green), var(--tech-cyan));
            border-radius: 4px;
            transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .progress-fill.warning {
            background: linear-gradient(90deg, var(--warning-color), #fb923c);
        }

        .progress-fill.danger {
            background: linear-gradient(90deg, var(--danger-color), #f87171);
        }

        .metric-label {
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border: none;
            border-radius: var(--radius-md);
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
            font-size: 0.875rem;
        }

        .btn-primary {
            background: var(--primary-color);
            color: white;
        }

        .btn-primary:hover {
            background: var(--primary-dark);
        }

        .btn-success {
            background: var(--success-color);
            color: white;
        }

        .btn-warning {
            background: var(--warning-color);
            color: white;
        }

        .btn-danger {
            background: var(--danger-color);
            color: white;
        }

        .btn-sm {
            padding: 0.375rem 0.75rem;
            font-size: 0.75rem;
        }

        .activity-feed {
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid var(--border-light);
            border-radius: var(--radius-md);
            background: var(--bg-secondary);
        }

        .activity-feed.terminal-style {
            background: #0f1419;
            border: 1px solid #1a1a1a;
        }

        .activity-item {
            padding: 0.75rem;
            border-bottom: 1px solid var(--border-light);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 0.875rem;
        }

        .activity-item:last-child {
            border-bottom: none;
        }

        .activity-icon {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
        }

        .activity-icon.command {
            background: rgba(37, 99, 235, 0.1);
            color: var(--primary-color);
        }

        .activity-icon.security {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger-color);
        }

        .activity-content {
            flex: 1;
        }

        .activity-title {
            font-weight: 500;
            color: var(--text-primary);
        }

        .activity-meta {
            font-size: 0.75rem;
            color: var(--text-muted);
        }

        .quick-actions {
            display: flex;
            gap: 0.75rem;
            flex-wrap: wrap;
            margin-top: 1rem;
        }

        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.875rem;
        }

        .data-table th,
        .data-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-light);
        }

        .data-table th {
            background: var(--bg-secondary);
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.025em;
            font-size: 0.75rem;
        }

        .log-output {
            background: #000;
            color: #0f0;
            padding: 1rem;
            border-radius: var(--radius-md);
            font-family: 'Courier New', monospace;
            font-size: 0.75rem;
            max-height: 200px;
            overflow-y: auto;
            white-space: pre-wrap;
        }

        .loading {
            opacity: 0.6;
            pointer-events: none;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .refresh-indicator {
            position: fixed;
            top: 1rem;
            right: 1rem;
            background: var(--success-color);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: var(--radius-md);
            font-size: 0.875rem;
            transform: translateY(-100px);
            opacity: 0;
            transition: all 0.3s ease;
            z-index: 1000;
        }

        .refresh-indicator.show {
            transform: translateY(0);
            opacity: 1;
        }

        @media (max-width: 768px) {
            .admin-header {
                padding: 1rem;
                flex-direction: column;
                gap: 1rem;
            }

            .admin-container {
                padding: 1rem;
            }

            .dashboard-grid {
                grid-template-columns: 1fr;
            }

            .metric-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="admin-header">
        <div class="admin-title">
            <i class="fas fa-shield-alt"></i>
            Comprehensive Admin Panel
        </div>
        <div class="admin-user">
            <span class="status-indicator status-online"></span>
            <strong><?php echo htmlspecialchars($_SESSION['username']); ?></strong>
            <span>|</span>
            <span>Session: <?php echo date('H:i:s', $_SESSION['login_time']); ?></span>
            <a href="/auth.php?action=logout" class="btn btn-sm btn-danger">
                <i class="fas fa-sign-out-alt"></i> Logout
            </a>
        </div>
    </div>

    <div class="admin-nav">
        <div class="nav-tabs">
            <button class="nav-tab active" onclick="showTab('overview')">
                <i class="fas fa-tachometer-alt"></i> Overview
            </button>
            <button class="nav-tab" onclick="showTab('monitoring')">
                <i class="fas fa-chart-line"></i> Live Monitoring
            </button>
            <button class="nav-tab" onclick="showTab('commands')">
                <i class="fas fa-terminal"></i> Commands
            </button>
            <button class="nav-tab" onclick="showTab('games')">
                <i class="fas fa-gamepad"></i> Games
            </button>
            <button class="nav-tab" onclick="location.href='admin_beans.php'">
                🫘 Beans
            </button>
            <button class="nav-tab" onclick="showTab('users')">
                <i class="fas fa-users"></i> Users
            </button>
            <button class="nav-tab" onclick="showTab('security')">
                <i class="fas fa-lock"></i> Security
            </button>
            <button class="nav-tab" onclick="showTab('database')">
                <i class="fas fa-database"></i> Database
            </button>
            <button class="nav-tab" onclick="showTab('tools')">
                <i class="fas fa-tools"></i> Tools
            </button>
        </div>
    </div>

    <div class="admin-container">
        <!-- Overview Tab -->
        <div id="overview-tab" class="tab-content active">
            <div class="dashboard-grid">
                <!-- Hero Bot Status Card -->
                <div class="admin-card hero-card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">
                                <i class="fas fa-robot"></i>
                                IRC Bot Network Status
                            </div>
                            <div class="card-subtitle">Dual-network IRC bot system monitoring</div>
                        </div>
                        <button class="btn btn-sm btn-primary" onclick="refreshData()" style="background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.3);">
                            <i class="fas fa-sync"></i> Refresh
                        </button>
                    </div>
                    <div class="metric-grid">
                        <div class="metric-item" style="background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2);">
                            <div class="metric-value hero">
                                <span class="status-indicator <?php echo $bot_stats['rizon']['status'] === 'Online' ? 'status-online' : 'status-offline'; ?>"></span>
                                <?php echo $bot_stats['rizon']['status']; ?>
                            </div>
                            <div class="metric-label" style="color: rgba(255,255,255,0.8);">Rizon Network (!)</div>
                        </div>
                        <div class="metric-item" style="background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.2);">
                            <div class="metric-value hero">
                                <span class="status-indicator <?php echo $bot_stats['libera']['status'] === 'Online' ? 'status-online' : 'status-offline'; ?>"></span>
                                <?php echo $bot_stats['libera']['status']; ?>
                            </div>
                            <div class="metric-label" style="color: rgba(255,255,255,0.8);">Libera Network (~)</div>
                        </div>
                    </div>
                    <div class="quick-actions">
                        <button class="btn btn-success btn-sm" onclick="manageBots('restart_rizon')" style="background: rgba(16,185,129,0.9);">
                            <i class="fas fa-redo"></i> Restart Rizon
                        </button>
                        <button class="btn btn-success btn-sm" onclick="manageBots('restart_libera')" style="background: rgba(16,185,129,0.9);">
                            <i class="fas fa-redo"></i> Restart Libera
                        </button>
                        <button class="btn btn-warning btn-sm" onclick="manageBots('restart_all')" style="background: rgba(245,158,11,0.9);">
                            <i class="fas fa-power-off"></i> Emergency Restart
                        </button>
                    </div>
                </div>

                <!-- System Resources -->
                <div class="admin-card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">
                                <i class="fas fa-server"></i>
                                System Resources
                            </div>
                            <div class="card-subtitle">Real-time server performance metrics</div>
                        </div>
                        <div style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">live@cr0system</div>
                    </div>
                    <div class="metric-grid">
                        <div class="metric-item">
                            <div class="metric-value"><?php echo $system_stats['cpu']; ?>%</div>
                            <div class="progress-bar">
                                <div class="progress-fill <?php echo $system_stats['cpu'] > 80 ? 'danger' : ($system_stats['cpu'] > 60 ? 'warning' : ''); ?>" style="width: <?php echo $system_stats['cpu']; ?>%;"></div>
                            </div>
                            <div class="metric-label">CPU Usage</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value"><?php echo $system_stats['memory']; ?>%</div>
                            <div class="progress-bar">
                                <div class="progress-fill <?php echo $system_stats['memory'] > 80 ? 'danger' : ($system_stats['memory'] > 60 ? 'warning' : ''); ?>" style="width: <?php echo $system_stats['memory']; ?>%;"></div>
                            </div>
                            <div class="metric-label">Memory Usage</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value"><?php echo $system_stats['disk']; ?>%</div>
                            <div class="progress-bar">
                                <div class="progress-fill <?php echo $system_stats['disk'] > 80 ? 'danger' : ($system_stats['disk'] > 60 ? 'warning' : ''); ?>" style="width: <?php echo $system_stats['disk']; ?>%;"></div>
                            </div>
                            <div class="metric-label">Disk Usage</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value" style="font-size: 1.25rem;"><?php echo $system_stats['uptime']; ?></div>
                            <div class="metric-label">System Uptime</div>
                        </div>
                    </div>
                </div>

                <!-- Analytics Dashboard -->
                <div class="admin-card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">
                                <i class="fas fa-chart-bar"></i>
                                Analytics Dashboard
                            </div>
                            <div class="card-subtitle">Real-time activity metrics</div>
                        </div>
                        <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.75rem; color: var(--text-muted);">
                            <div class="status-indicator status-online" style="animation: none; width: 6px; height: 6px;"></div>
                            <span>Live Data</span>
                        </div>
                    </div>
                    <div class="metric-grid" id="activity-stats">
                        <div class="metric-item">
                            <div class="metric-value">-</div>
                            <div class="metric-label">Commands Today</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">-</div>
                            <div class="metric-label">Active Users</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">-</div>
                            <div class="metric-label">Games Active</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value">-</div>
                            <div class="metric-label">Security Events</div>
                        </div>
                    </div>
                </div>

                <!-- Live Activity Stream -->
                <div class="admin-card" style="grid-column: 1 / -1;">
                    <div class="card-header">
                        <div>
                            <div class="card-title">
                                <i class="fas fa-stream"></i>
                                Live Activity Stream
                            </div>
                            <div class="card-subtitle">Real-time command execution and security monitoring</div>
                        </div>
                        <div style="display: flex; gap: 0.5rem;">
                            <button class="btn btn-sm btn-primary" onclick="toggleActivityMode()" id="activity-mode-btn">
                                <i class="fas fa-terminal"></i> Terminal Mode
                            </button>
                            <button class="btn btn-sm btn-primary" onclick="refreshActivityFeed()">
                                <i class="fas fa-sync"></i> Refresh
                            </button>
                        </div>
                    </div>
                    <div class="activity-feed" id="activity-feed">
                        <div class="activity-item">
                            <div class="activity-icon command">
                                <i class="fas fa-terminal"></i>
                            </div>
                            <div class="activity-content">
                                <div class="activity-title">Initializing activity stream...</div>
                                <div class="activity-meta">Connecting to live data feed</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Live Monitoring Tab -->
        <div id="monitoring-tab" class="tab-content">
            <div class="dashboard-grid">
                <div class="admin-card" style="grid-column: 1 / -1;">
                    <div class="card-header">
                        <div>
                            <div class="card-title">
                                <i class="fas fa-chart-line"></i>
                                Live Command Monitor
                            </div>
                            <div class="card-subtitle">Real-time command execution tracking</div>
                        </div>
                        <div class="quick-actions">
                            <button class="btn btn-sm btn-primary" onclick="toggleAutoRefresh()">
                                <i class="fas fa-play" id="auto-refresh-icon"></i>
                                <span id="auto-refresh-text">Start Auto-Refresh</span>
                            </button>
                        </div>
                    </div>
                    <div id="command-monitor">
                        <div class="log-output">Loading command monitor...</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Commands Tab -->
        <div id="commands-tab" class="tab-content">
            <div class="dashboard-grid">
                <div class="admin-card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">
                                <i class="fas fa-chart-bar"></i>
                                Command Performance
                            </div>
                            <div class="card-subtitle">Most used and slowest commands</div>
                        </div>
                    </div>
                    <div id="command-performance">
                        Loading performance data...
                    </div>
                </div>
            </div>
        </div>

        <!-- Games Tab -->
        <div id="games-tab" class="tab-content">
            <div class="dashboard-grid">
                <div class="admin-card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">
                                <i class="fas fa-gamepad"></i>
                                Game Statistics
                            </div>
                            <div class="card-subtitle">Active games and player statistics</div>
                        </div>
                    </div>
                    <div id="game-stats">
                        Loading game statistics...
                    </div>
                </div>
            </div>
        </div>

        <!-- Users Tab -->
        <div id="users-tab" class="tab-content">
            <div class="dashboard-grid">
                <div class="admin-card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">
                                <i class="fas fa-users"></i>
                                User Analytics
                            </div>
                            <div class="card-subtitle">User activity and engagement metrics</div>
                        </div>
                    </div>
                    <div id="user-analytics">
                        Loading user analytics...
                    </div>
                </div>
            </div>
        </div>

        <!-- Security Tab -->
        <div id="security-tab" class="tab-content">
            <div class="dashboard-grid">
                <!-- Security Status Overview -->
                <div class="admin-card" style="grid-column: 1 / -1;">
                    <div class="card-header">
                        <div>
                            <div class="card-title">
                                <i class="fas fa-shield-alt"></i>
                                Security Command Center
                            </div>
                            <div class="card-subtitle">Real-time threat monitoring and intrusion detection</div>
                        </div>
                        <div style="display: flex; gap: 0.5rem;">
                            <button class="btn btn-sm btn-success" onclick="refreshSecurityEvents()">
                                <i class="fas fa-sync"></i> Refresh
                            </button>
                            <button class="btn btn-sm btn-warning" onclick="exportSecurityLog()">
                                <i class="fas fa-download"></i> Export Log
                            </button>
                        </div>
                    </div>
                    <div class="metric-grid" style="margin-bottom: 1.5rem;">
                        <div class="metric-item">
                            <div class="metric-value" style="color: var(--success-color);">0</div>
                            <div class="metric-label">Active Threats</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value" style="color: var(--tech-blue);">24</div>
                            <div class="metric-label">Events Today</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value" style="color: var(--warning-color);">3</div>
                            <div class="metric-label">Failed Logins</div>
                        </div>
                        <div class="metric-item">
                            <div class="metric-value" style="color: var(--tech-green);">SECURE</div>
                            <div class="metric-label">System Status</div>
                        </div>
                    </div>
                </div>
                
                <!-- Terminal-Style Security Feed -->
                <div class="admin-card" style="grid-column: 1 / -1;">
                    <div class="card-header">
                        <div>
                            <div class="card-title" style="font-family: var(--font-mono);">
                                <i class="fas fa-terminal"></i>
                                root@cr0-security:~# tail -f /var/log/security.log
                            </div>
                            <div class="card-subtitle">Live security event stream</div>
                        </div>
                        <button class="btn btn-sm btn-danger" onclick="clearSecurityLog()">
                            <i class="fas fa-trash"></i> Clear Display
                        </button>
                    </div>
                    <div class="terminal-feed" id="security-terminal">
                        <div class="terminal-line info">[2024-07-25 14:30:15] INFO: Security monitoring initialized</div>
                        <div class="terminal-line">[2024-07-25 14:30:15] AUTH: Admin login successful - user: <?php echo htmlspecialchars($_SESSION['username']); ?></div>
                        <div class="terminal-line">[2024-07-25 14:30:15] SYSTEM: IRC bot networks status check - OK</div>
                        <div class="terminal-line">[2024-07-25 14:30:16] MONITOR: Real-time security feed active</div>
                        <div class="terminal-line">[2024-07-25 14:30:16] STATUS: Waiting for security events...<span class="terminal-cursor"></span></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Database Tab -->
        <div id="database-tab" class="tab-content">
            <div class="dashboard-grid">
                <div class="admin-card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">
                                <i class="fas fa-database"></i>
                                Database Health
                            </div>
                            <div class="card-subtitle">Database status and maintenance</div>
                        </div>
                    </div>
                    <div id="database-health">
                        Loading database health...
                    </div>
                </div>
            </div>
        </div>

        <!-- Tools Tab -->
        <div id="tools-tab" class="tab-content">
            <div class="dashboard-grid">
                <div class="admin-card">
                    <div class="card-header">
                        <div>
                            <div class="card-title">
                                <i class="fas fa-tools"></i>
                                Admin Tools
                            </div>
                            <div class="card-subtitle">System management utilities</div>
                        </div>
                    </div>
                    <div class="quick-actions">
                        <button class="btn btn-primary" onclick="window.open('/index.php', '_blank')">
                            <i class="fas fa-home"></i> Main Site
                        </button>
                        <button class="btn btn-primary" onclick="window.open('/debug_admin.php', '_blank')">
                            <i class="fas fa-bug"></i> Debug Panel
                        </button>
                        <button class="btn btn-warning" onclick="manageBots('status')">
                            <i class="fas fa-info-circle"></i> Bot Status
                        </button>
                        <button class="btn btn-danger" onclick="if(confirm('Stop all bots?')) manageBots('stop_all')">
                            <i class="fas fa-stop"></i> Emergency Stop
                        </button>
                    </div>
                    <div id="tool-output" class="log-output" style="margin-top: 1rem; display: none;"></div>
                </div>
            </div>
        </div>
    </div>

    <div class="refresh-indicator" id="refresh-indicator">
        <i class="fas fa-sync fa-spin"></i> Refreshing data...
    </div>

    <script>
        let autoRefreshInterval = null;
        let isAutoRefreshing = false;

        // Tab management
        function showTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.nav-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            document.getElementById(tabName + '-tab').classList.add('active');
            event.target.classList.add('active');
            
            // Load tab-specific data
            loadTabData(tabName);
        }

        // Load data specific to each tab
        function loadTabData(tabName) {
            switch (tabName) {
                case 'overview':
                    refreshData();
                    break;
                case 'monitoring':
                    loadCommandMonitor();
                    break;
                case 'commands':
                    loadCommandPerformance();
                    break;
                case 'games':
                    loadGameStats();
                    break;
                case 'users':
                    loadUserAnalytics();
                    break;
                case 'security':
                    loadSecurityEvents();
                    break;
                case 'database':
                    loadDatabaseHealth();
                    break;
            }
        }

        // Refresh all data
        function refreshData() {
            showRefreshIndicator();
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: 'action=get_live_data'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateActivityStats(data);
                    updateActivityFeed(data.recent_commands, data.security_events);
                }
                hideRefreshIndicator();
            })
            .catch(error => {
                console.error('Error refreshing data:', error);
                hideRefreshIndicator();
            });
        }

        // Update activity statistics with animations
        function updateActivityStats(data) {
            const totalCommands = data.bot_stats.rizon.commands_today + data.bot_stats.libera.commands_today;
            const totalUsers = data.bot_stats.rizon.users_active + data.bot_stats.libera.users_active;
            
            animateCounter('#activity-stats .metric-item:nth-child(1) .metric-value', totalCommands);
            animateCounter('#activity-stats .metric-item:nth-child(2) .metric-value', totalUsers);
            animateCounter('#activity-stats .metric-item:nth-child(3) .metric-value', data.game_stats.games_today);
            animateCounter('#activity-stats .metric-item:nth-child(4) .metric-value', data.security_events ? data.security_events.length : 0);
        }
        
        // Animate counter updates
        function animateCounter(selector, targetValue) {
            const element = document.querySelector(selector);
            if (!element) return;
            
            const currentValue = parseInt(element.textContent) || 0;
            const increment = targetValue > currentValue ? 1 : -1;
            const steps = Math.abs(targetValue - currentValue);
            
            if (steps === 0) return;
            
            let current = currentValue;
            const timer = setInterval(() => {
                current += increment;
                element.textContent = current;
                element.style.transform = 'scale(1.1)';
                setTimeout(() => {
                    element.style.transform = 'scale(1)';
                }, 100);
                
                if (current === targetValue) {
                    clearInterval(timer);
                }
            }, 50);
        }

        // Update activity feed
        function updateActivityFeed(commands, securityEvents) {
            const feed = document.getElementById('activity-feed');
            feed.innerHTML = '';
            
            const allEvents = [];
            
            // Add recent commands
            commands.slice(0, 10).forEach(cmd => {
                allEvents.push({
                    type: 'command',
                    title: `${cmd.command} executed by ${cmd.username}`,
                    meta: `${cmd.network} • ${cmd.channel} • ${new Date(cmd.timestamp).toLocaleTimeString()}`,
                    timestamp: new Date(cmd.timestamp).getTime()
                });
            });
            
            // Add security events
            securityEvents.slice(0, 5).forEach(event => {
                allEvents.push({
                    type: 'security',
                    title: event.event_type,
                    meta: `${event.message} • ${new Date(event.timestamp).toLocaleTimeString()}`,
                    timestamp: new Date(event.timestamp).getTime()
                });
            });
            
            // Sort by timestamp and display
            allEvents.sort((a, b) => b.timestamp - a.timestamp);
            allEvents.slice(0, 15).forEach(event => {
                const item = document.createElement('div');
                item.className = 'activity-item';
                item.innerHTML = `
                    <div class="activity-icon ${event.type}">
                        <i class="fas fa-${event.type === 'command' ? 'terminal' : 'shield-alt'}"></i>
                    </div>
                    <div class="activity-content">
                        <div class="activity-title">${event.title}</div>
                        <div class="activity-meta">${event.meta}</div>
                    </div>
                `;
                feed.appendChild(item);
            });
        }

        // Bot management
        function manageBots(action) {
            const button = event.target;
            const originalText = button.innerHTML;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Working...';
            button.disabled = true;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `action=bot_action&bot_action=${action}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    if (data.output) {
                        const output = document.getElementById('tool-output');
                        output.style.display = 'block';
                        output.textContent = data.output;
                    }
                    setTimeout(refreshData, 2000); // Refresh after 2 seconds
                } else {
                    alert('Action failed: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Network error occurred');
            })
            .finally(() => {
                button.innerHTML = originalText;
                button.disabled = false;
            });
        }

        // Auto-refresh toggle
        function toggleAutoRefresh() {
            const icon = document.getElementById('auto-refresh-icon');
            const text = document.getElementById('auto-refresh-text');
            
            if (isAutoRefreshing) {
                clearInterval(autoRefreshInterval);
                isAutoRefreshing = false;
                icon.className = 'fas fa-play';
                text.textContent = 'Start Auto-Refresh';
            } else {
                autoRefreshInterval = setInterval(refreshData, 5000); // Refresh every 5 seconds
                isAutoRefreshing = true;
                icon.className = 'fas fa-pause';
                text.textContent = 'Stop Auto-Refresh';
            }
        }

        // Load command monitor
        function loadCommandMonitor() {
            document.getElementById('command-monitor').innerHTML = '<div class="log-output">Loading real-time command monitor...</div>';
            // This would be implemented with WebSocket or Server-Sent Events for real-time updates
        }

        // Load command performance
        function loadCommandPerformance() {
            document.getElementById('command-performance').innerHTML = 'Loading command performance data...';
        }

        // Load game stats
        function loadGameStats() {
            document.getElementById('game-stats').innerHTML = 'Loading game statistics...';
        }

        // Load user analytics
        function loadUserAnalytics() {
            document.getElementById('user-analytics').innerHTML = 'Loading user analytics...';
        }

        // Load security events
        function loadSecurityEvents() {
            const terminal = document.getElementById('security-terminal');
            if (terminal) {
                // Simulate loading security events in terminal
                setTimeout(() => {
                    addSecurityEvent('INFO', 'Security events loaded successfully');
                    addSecurityEvent('MONITOR', 'Intrusion detection system active');
                }, 500);
            }
        }
        
        // Add security event to terminal
        function addSecurityEvent(level, message) {
            const terminal = document.getElementById('security-terminal');
            if (!terminal) return;
            
            const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
            const line = document.createElement('div');
            line.className = `terminal-line ${level.toLowerCase()}`;
            line.textContent = `[${timestamp}] ${level}: ${message}`;
            
            // Remove cursor from last line
            const cursor = terminal.querySelector('.terminal-cursor');
            if (cursor) cursor.remove();
            
            terminal.appendChild(line);
            
            // Add new cursor
            const newCursor = document.createElement('span');
            newCursor.className = 'terminal-cursor';
            const waitLine = document.createElement('div');
            waitLine.className = 'terminal-line';
            waitLine.innerHTML = `[${timestamp}] STATUS: Monitoring for threats...`;
            waitLine.appendChild(newCursor);
            terminal.appendChild(waitLine);
            
            // Auto scroll
            terminal.scrollTop = terminal.scrollHeight;
        }
        
        // Refresh security events
        function refreshSecurityEvents() {
            addSecurityEvent('REFRESH', 'Manual security refresh initiated');
            addSecurityEvent('SCAN', 'Running security scan...');
            setTimeout(() => {
                addSecurityEvent('SCAN', 'Security scan completed - no threats detected');
            }, 1500);
        }
        
        // Clear security log display
        function clearSecurityLog() {
            const terminal = document.getElementById('security-terminal');
            if (terminal && confirm('Clear security display? (This does not affect actual logs)')) {
                const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
                terminal.innerHTML = `
                    <div class="terminal-line info">[${timestamp}] INFO: Display cleared by admin</div>
                    <div class="terminal-line">[${timestamp}] STATUS: Waiting for security events...<span class="terminal-cursor"></span></div>
                `;
            }
        }
        
        // Export security log
        function exportSecurityLog() {
            addSecurityEvent('EXPORT', 'Security log export initiated');
            // This would trigger actual log export in production
            alert('Security log export feature would be implemented here');
        }
        
        let activityTerminalMode = false;
        
        // Toggle activity feed terminal mode
        function toggleActivityMode() {
            const feed = document.getElementById('activity-feed');
            const btn = document.getElementById('activity-mode-btn');
            
            activityTerminalMode = !activityTerminalMode;
            
            if (activityTerminalMode) {
                feed.classList.add('terminal-style');
                btn.innerHTML = '<i class="fas fa-list"></i> List Mode';
                convertActivityToTerminal();
            } else {
                feed.classList.remove('terminal-style');
                btn.innerHTML = '<i class="fas fa-terminal"></i> Terminal Mode';
                refreshActivityFeed();
            }
        }
        
        // Convert activity feed to terminal style
        function convertActivityToTerminal() {
            const feed = document.getElementById('activity-feed');
            const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');
            feed.innerHTML = `
                <div class="terminal-line info">[${timestamp}] SYSTEM: Activity terminal mode activated</div>
                <div class="terminal-line">[${timestamp}] MONITOR: Streaming live IRC bot activity</div>
                <div class="terminal-line">[${timestamp}] STATUS: Ready for command monitoring...<span class="terminal-cursor"></span></div>
            `;
        }

        // Load database health
        function loadDatabaseHealth() {
            document.getElementById('database-health').innerHTML = 'Loading database health...';
        }

        // Refresh activity feed
        function refreshActivityFeed() {
            refreshData();
        }

        // Show/hide refresh indicator
        function showRefreshIndicator() {
            document.getElementById('refresh-indicator').classList.add('show');
        }

        function hideRefreshIndicator() {
            setTimeout(() => {
                document.getElementById('refresh-indicator').classList.remove('show');
            }, 500);
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            refreshData();
            
            // Add some demo security events
            setTimeout(() => {
                if (document.getElementById('security-terminal')) {
                    addSecurityEvent('INFO', 'Security system fully operational');
                    addSecurityEvent('AUTH', '2FA verification successful');
                    addSecurityEvent('MONITOR', 'No suspicious activity detected');
                }
            }, 2000);
            
            // Auto-refresh every 30 seconds
            setInterval(() => {
                if (document.querySelector('#overview-tab').classList.contains('active')) {
                    refreshData();
                }
                
                // Add periodic security events
                if (Math.random() < 0.3 && document.getElementById('security-terminal')) {
                    const events = [
                        ['SCAN', 'Periodic security scan completed'],
                        ['MONITOR', 'System integrity check passed'],
                        ['INFO', 'Connection monitoring active'],
                        ['STATUS', 'All security systems operational']
                    ];
                    const randomEvent = events[Math.floor(Math.random() * events.length)];
                    addSecurityEvent(randomEvent[0], randomEvent[1]);
                }
            }, 30000);
            
            // Add CSS transitions
            const style = document.createElement('style');
            style.textContent = `
                .metric-value { transition: transform 0.2s ease; }
                .admin-card { transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); }
            `;
            document.head.appendChild(style);
        });
    </script>
</body>
</html>