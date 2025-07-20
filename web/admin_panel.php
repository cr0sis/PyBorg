<?php
session_start();

// Check authentication
if (!isset($_SESSION['admin_authenticated']) || !$_SESSION['admin_authenticated']) {
    header('Location: admin_login.php');
    exit;
}

// Session timeout (30 minutes)
if (time() - $_SESSION['admin_login_time'] > 1800) {
    session_destroy();
    header('Location: admin_login.php');
    exit;
}

// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: https://cr0s.is/');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - CR0SIS Bot Management</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
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
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-secondary);
            color: var(--text-primary);
            line-height: 1.6;
            transition: background-color 0.2s ease, color 0.2s ease;
        }
        
        .admin-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .admin-title h1 {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .admin-title p {
            opacity: 0.9;
            font-size: 0.9rem;
        }
        
        .admin-actions {
            display: flex;
            gap: 1rem;
            align-items: center;
        }
        
        .theme-toggle {
            background: rgba(255,255,255,0.2);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 5px;
            cursor: pointer;
            transition: background 0.3s;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .theme-toggle:hover {
            background: rgba(255,255,255,0.3);
        }
        
        .logout-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 5px;
            text-decoration: none;
            transition: background 0.3s;
        }
        
        .logout-btn:hover {
            background: rgba(255,255,255,0.3);
        }
        
        .admin-container {
            max-width: 1400px;
            margin: 2rem auto;
            padding: 0 2rem;
        }
        
        .admin-nav {
            background: var(--bg-primary);
            border-radius: var(--radius-lg);
            padding: 1rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow-md);
            border: 1px solid var(--border-light);
        }
        
        .nav-tabs {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .nav-tab {
            padding: 0.75rem 1.5rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-md);
            cursor: pointer;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--text-secondary);
        }
        
        .nav-tab.active {
            background: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
        }
        
        .nav-tab:hover {
            background: var(--bg-primary);
            border-color: var(--border-medium);
        }
        
        .nav-tab.active:hover {
            background: var(--primary-dark);
        }
        
        .admin-section {
            display: none;
            background: var(--bg-primary);
            border-radius: var(--radius-lg);
            padding: 2rem;
            box-shadow: var(--shadow-md);
            border: 1px solid var(--border-light);
        }
        
        .admin-section.active {
            display: block;
        }
        
        .section-header {
            border-bottom: 2px solid var(--border-light);
            padding-bottom: 1rem;
            margin-bottom: 2rem;
        }
        
        .section-header h2 {
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .section-header p {
            color: var(--text-secondary);
            margin-top: 0.5rem;
        }
        
        .admin-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .admin-card {
            border: 1px solid var(--border-light);
            border-radius: var(--radius-md);
            padding: 1.5rem;
            background: var(--bg-tertiary);
        }
        
        .admin-card h3 {
            color: var(--text-primary);
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.3s;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .btn-primary {
            background: var(--primary-color);
            color: white;
        }
        
        .btn-primary:hover {
            background: var(--primary-dark);
        }
        
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        
        .btn-danger:hover {
            background: #c82333;
        }
        
        .btn-success {
            background: #28a745;
            color: white;
        }
        
        .btn-success:hover {
            background: #218838;
        }
        
        .btn-warning {
            background: #ffc107;
            color: #212529;
        }
        
        .btn-warning:hover {
            background: #e0a800;
        }
        
        .status-indicator {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
        }
        
        .status-online {
            background: var(--accent-green);
            color: #155724;
        }
        
        [data-theme="dark"] .status-online {
            color: #4ade80;
        }
        
        .status-offline {
            background: #fee;
            color: #dc2626;
        }
        
        [data-theme="dark"] .status-offline {
            color: #f87171;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        
        .data-table th,
        .data-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        .data-table th {
            background: var(--bg-tertiary);
            font-weight: 600;
            color: var(--text-primary);
            border-bottom: 1px solid var(--border-light);
        }
        
        .data-table td {
            border-bottom: 1px solid var(--border-light);
            color: var(--text-primary);
        }
        
        .data-table tr:hover {
            background: var(--bg-tertiary);
        }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: var(--text-primary);
            font-weight: 500;
        }
        
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid var(--border-light);
            border-radius: var(--radius-sm);
            font-size: 0.9rem;
            background: var(--bg-primary);
            color: var(--text-primary);
        }
        
        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: var(--primary-color);
        }
        
        .alert {
            padding: 0.75rem 1rem;
            margin-bottom: 1rem;
            border-radius: 5px;
        }
        
        .alert-success {
            background: var(--accent-green);
            color: var(--text-primary);
            border: 1px solid var(--border-light);
        }
        
        .alert-danger {
            background: #fee;
            color: var(--text-primary);
            border: 1px solid var(--border-light);
        }
        
        .log-viewer {
            background: #000;
            color: #00ff00;
            padding: 1rem;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
        }
    </style>
</head>
<body>
    <div class="admin-header">
        <div class="admin-title">
            <h1><i class="fas fa-cogs"></i> CR0SIS Admin Panel</h1>
            <p>Bot & Game Management Dashboard</p>
        </div>
        <div class="admin-actions">
            <div class="theme-toggle" onclick="toggleTheme()">
                <i id="theme-icon" class="fas fa-sun"></i>
                <span id="theme-text">Light</span>
            </div>
            <span><i class="fas fa-user"></i> Administrator</span>
            <a href="?logout=1" class="logout-btn"><i class="fas fa-sign-out-alt"></i> Logout</a>
        </div>
    </div>
    
    <div class="admin-container">
        <div class="admin-nav">
            <div class="nav-tabs">
                <button class="nav-tab active" onclick="showSection('overview')">
                    <i class="fas fa-tachometer-alt"></i> Overview
                </button>
                <button class="nav-tab" onclick="showSection('breakout')">
                    <i class="fas fa-gamepad"></i> Breakout Game
                </button>
                <button class="nav-tab" onclick="showSection('bot-status')">
                    <i class="fas fa-robot"></i> Bot Status
                </button>
                <button class="nav-tab" onclick="showSection('bot-control')">
                    <i class="fas fa-play"></i> Bot Control
                </button>
                <button class="nav-tab" onclick="showSection('user-management')">
                    <i class="fas fa-users"></i> User Management
                </button>
                <button class="nav-tab" onclick="showSection('logs')">
                    <i class="fas fa-file-alt"></i> Logs & Monitoring
                </button>
                <button class="nav-tab" onclick="showSection('database')">
                    <i class="fas fa-database"></i> Database
                </button>
                <button class="nav-tab" onclick="showSection('settings')">
                    <i class="fas fa-cog"></i> Settings
                </button>
            </div>
        </div>
        
        <!-- Overview Section -->
        <div id="overview" class="admin-section active">
            <div class="section-header">
                <h2><i class="fas fa-tachometer-alt"></i> System Overview</h2>
                <p>Quick overview of bot status and game statistics</p>
            </div>
            
            <div class="admin-grid">
                <div class="admin-card">
                    <h3><i class="fas fa-robot"></i> Bot Status</h3>
                    <div id="bot-status-overview">Loading...</div>
                </div>
                
                <div class="admin-card">
                    <h3><i class="fas fa-gamepad"></i> Breakout Stats</h3>
                    <div id="breakout-stats-overview">Loading...</div>
                </div>
                
                <div class="admin-card">
                    <h3><i class="fas fa-chart-line"></i> Recent Activity</h3>
                    <div id="recent-activity">Loading...</div>
                </div>
                
                <div class="admin-card">
                    <h3><i class="fas fa-server"></i> System Health</h3>
                    <div id="system-health">Loading...</div>
                </div>
            </div>
        </div>
        
        <!-- Breakout Game Section -->
        <div id="breakout" class="admin-section">
            <div class="section-header">
                <h2><i class="fas fa-gamepad"></i> Breakout Game Management</h2>
                <p>Manage high scores, players, and game settings</p>
            </div>
            
            <div class="admin-grid">
                <div class="admin-card">
                    <h3><i class="fas fa-trophy"></i> Score Management</h3>
                    <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1rem;">
                        <button class="btn btn-primary" onclick="loadHighScores()">
                            <i class="fas fa-refresh"></i> Refresh Scores
                        </button>
                        <button class="btn btn-danger" onclick="resetAllScores()">
                            <i class="fas fa-trash"></i> Reset All Scores
                        </button>
                        <button class="btn btn-warning" onclick="testFunction()">
                            <i class="fas fa-bug"></i> Test Click
                        </button>
                    </div>
                    <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                        <button class="btn btn-warning" onclick="resetLocalStorageScores()">
                            <i class="fas fa-eraser"></i> Reset Local Scores
                        </button>
                        <button class="btn btn-primary" onclick="viewLocalStorageScores()">
                            <i class="fas fa-eye"></i> View Local Scores
                        </button>
                    </div>
                </div>
                
                <div class="admin-card">
                    <h3><i class="fas fa-user-times"></i> Player Moderation</h3>
                    <div class="form-group">
                        <label>Ban Player by Name:</label>
                        <input type="text" id="ban-player-name" placeholder="Enter player name">
                    </div>
                    <button class="btn btn-danger" onclick="banPlayer()">
                        <i class="fas fa-ban"></i> Ban Player
                    </button>
                </div>
            </div>
            
            <div id="high-scores-table">
                <!-- High scores will be loaded here -->
            </div>
        </div>
        
        <!-- Bot Status Section -->
        <div id="bot-status" class="admin-section">
            <div class="section-header">
                <h2><i class="fas fa-robot"></i> Bot Status & Information</h2>
                <p>Real-time bot status and network information</p>
            </div>
            
            <div class="admin-grid">
                <div class="admin-card">
                    <h3><i class="fas fa-wifi"></i> Network Status</h3>
                    <div id="network-status">Loading...</div>
                </div>
                
                <div class="admin-card">
                    <h3><i class="fas fa-memory"></i> Bot Performance</h3>
                    <div id="bot-performance">Loading...</div>
                </div>
                
                <div class="admin-card">
                    <h3><i class="fas fa-comments"></i> Command Usage</h3>
                    <div id="command-usage">Loading...</div>
                </div>
                
                <div class="admin-card">
                    <h3><i class="fas fa-clock"></i> Uptime Info</h3>
                    <div id="uptime-info">Loading...</div>
                </div>
            </div>
        </div>
        
        <!-- Bot Control Section -->
        <div id="bot-control" class="admin-section">
            <div class="section-header">
                <h2><i class="fas fa-play"></i> Bot Control Panel</h2>
                <p>Start, stop, restart, and manage bot operations</p>
            </div>
            
            <div class="admin-grid">
                <div class="admin-card">
                    <h3><i class="fas fa-power-off"></i> Bot Operations</h3>
                    <div style="display: flex; gap: 1rem; flex-wrap: wrap;">
                        <button class="btn btn-success" onclick="startBot()">
                            <i class="fas fa-play"></i> Start Bot
                        </button>
                        <button class="btn btn-warning" onclick="restartBot()">
                            <i class="fas fa-redo"></i> Restart Bot
                        </button>
                        <button class="btn btn-danger" onclick="stopBot()">
                            <i class="fas fa-stop"></i> Stop Bot
                        </button>
                    </div>
                </div>
                
                <div class="admin-card">
                    <h3><i class="fas fa-network-wired"></i> Individual Network Controls</h3>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                        <div style="text-align: center;">
                            <h4 style="color: var(--primary-color); margin-bottom: 0.75rem;">
                                <i class="fas fa-hashtag"></i> Rizon Network
                            </h4>
                            <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                                <button class="btn btn-warning" onclick="restartRizonBot()" style="width: 100%;">
                                    <i class="fas fa-redo"></i> Restart Rizon
                                </button>
                                <small style="color: var(--text-secondary);">Channels: #8BitVape, #livingroom, #8bitcode</small>
                            </div>
                        </div>
                        <div style="text-align: center;">
                            <h4 style="color: var(--primary-color); margin-bottom: 0.75rem;">
                                <i class="fas fa-hashtag"></i> Libera Network
                            </h4>
                            <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                                <button class="btn btn-warning" onclick="restartLiberaBot()" style="width: 100%;">
                                    <i class="fas fa-redo"></i> Restart Libera
                                </button>
                                <small style="color: var(--text-secondary);">Channels: #bakedbeans, #pyborg</small>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="admin-card">
                    <h3><i class="fas fa-terminal"></i> Quick Commands</h3>
                    <div class="form-group">
                        <label>Send Command to Bot:</label>
                        <input type="text" id="bot-command" placeholder="Enter command">
                    </div>
                    <button class="btn btn-primary" onclick="sendBotCommand()">
                        <i class="fas fa-paper-plane"></i> Send Command
                    </button>
                </div>
            </div>
        </div>
        
        <!-- User Management Section -->
        <div id="user-management" class="admin-section">
            <div class="section-header">
                <h2><i class="fas fa-users"></i> User Management</h2>
                <p>Manage IRC users, permissions, and moderation</p>
            </div>
            
            <div class="admin-grid">
                <div class="admin-card">
                    <h3><i class="fas fa-chart-bar"></i> User Statistics</h3>
                    <div id="user-stats">Loading...</div>
                </div>
                
                <div class="admin-card">
                    <h3><i class="fas fa-crown"></i> Admin Management</h3>
                    <div class="form-group">
                        <label>Add Trusted User:</label>
                        <input type="text" id="new-admin" placeholder="username!hostmask">
                    </div>
                    <button class="btn btn-success" onclick="addTrustedUser()">
                        <i class="fas fa-plus"></i> Add User
                    </button>
                </div>
            </div>
        </div>
        
        <!-- Logs Section -->
        <div id="logs" class="admin-section">
            <div class="section-header">
                <h2><i class="fas fa-file-alt"></i> Logs & Monitoring</h2>
                <p>View bot logs, error reports, and system monitoring</p>
            </div>
            
            <div class="admin-grid">
                <div class="admin-card">
                    <h3><i class="fas fa-network-wired"></i> IRC Network Logs</h3>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
                        <div style="text-align: center;">
                            <h4 style="color: var(--primary-color); margin-bottom: 0.75rem;">Rizon Network</h4>
                            <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                                <button class="btn btn-primary" onclick="loadRizonLogs()" style="width: 100%;">
                                    <i class="fas fa-hashtag"></i> Rizon Bot Logs
                                </button>
                                <button class="btn btn-secondary" onclick="loadDetailedLogs('rizon')" style="width: 100%;">
                                    <i class="fas fa-list-alt"></i> Detailed Logs
                                </button>
                            </div>
                        </div>
                        <div style="text-align: center;">
                            <h4 style="color: var(--primary-color); margin-bottom: 0.75rem;">Libera Network</h4>
                            <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                                <button class="btn btn-primary" onclick="loadLiberaLogs()" style="width: 100%;">
                                    <i class="fas fa-hashtag"></i> Libera Bot Logs
                                </button>
                                <button class="btn btn-secondary" onclick="loadDetailedLogs('libera')" style="width: 100%;">
                                    <i class="fas fa-list-alt"></i> Detailed Logs
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="admin-card">
                    <h3><i class="fas fa-server"></i> System Logs</h3>
                    <div style="display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1rem;">
                        <button class="btn btn-info" onclick="loadLogs('error')">
                            <i class="fas fa-exclamation-triangle"></i> Error Logs
                        </button>
                        <button class="btn btn-info" onclick="loadLogs('access')">
                            <i class="fas fa-globe"></i> Access Logs
                        </button>
                    </div>
                    <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                        <button class="btn btn-success" onclick="syncLogs()">
                            <i class="fas fa-sync"></i> Sync Logs
                        </button>
                        <button class="btn btn-warning" onclick="clearLogs()">
                            <i class="fas fa-trash"></i> Clear Logs
                        </button>
                    </div>
                </div>
            </div>
            
            <div class="log-viewer" id="log-viewer">
                Select a log type to view logs...
            </div>
        </div>
        
        <!-- Database Section -->
        <div id="database" class="admin-section">
            <div class="section-header">
                <h2><i class="fas fa-database"></i> Database Management</h2>
                <p>Backup, restore, and manage database operations</p>
            </div>
            
            <div class="admin-grid">
                <div class="admin-card">
                    <h3><i class="fas fa-download"></i> Backup Operations</h3>
                    <button class="btn btn-success" onclick="backupDatabase()">
                        <i class="fas fa-download"></i> Create Backup
                    </button>
                    <button class="btn btn-primary" onclick="downloadBackup()">
                        <i class="fas fa-file-download"></i> Download Backup
                    </button>
                </div>
                
                <div class="admin-card">
                    <h3><i class="fas fa-broom"></i> Maintenance</h3>
                    <button class="btn btn-warning" onclick="cleanupDatabase()">
                        <i class="fas fa-broom"></i> Cleanup Old Data
                    </button>
                    <button class="btn btn-primary" onclick="optimizeDatabase()">
                        <i class="fas fa-tachometer-alt"></i> Optimize DB
                    </button>
                </div>
            </div>
        </div>
        
        <!-- Settings Section -->
        <div id="settings" class="admin-section">
            <div class="section-header">
                <h2><i class="fas fa-cog"></i> Bot Settings</h2>
                <p>Configure bot behavior and system settings</p>
            </div>
            
            <div class="admin-grid">
                <div class="admin-card">
                    <h3><i class="fas fa-sliders-h"></i> Bot Configuration</h3>
                    <div class="form-group">
                        <label>Command Prefix:</label>
                        <input type="text" id="command-prefix" value="!">
                    </div>
                    <div class="form-group">
                        <label>Bot Nickname:</label>
                        <input type="text" id="bot-nickname" value="CR0SIS">
                    </div>
                    <button class="btn btn-success" onclick="saveSettings()">
                        <i class="fas fa-save"></i> Save Settings
                    </button>
                </div>
                
                <div class="admin-card">
                    <h3><i class="fas fa-shield-alt"></i> Security Settings</h3>
                    <div class="form-group">
                        <label>Rate Limit (msgs/min):</label>
                        <input type="number" id="rate-limit" value="30">
                    </div>
                    <div class="form-group">
                        <label>Max Message Length:</label>
                        <input type="number" id="max-message-length" value="400">
                    </div>
                    <button class="btn btn-success" onclick="saveSecuritySettings()">
                        <i class="fas fa-save"></i> Save Security
                    </button>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Tab switching functionality
        function showSection(sectionId, saveToStorage = true) {
            // Hide all sections
            document.querySelectorAll('.admin-section').forEach(section => {
                section.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.nav-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected section
            document.getElementById(sectionId).classList.add('active');
            
            // Activate corresponding tab
            const targetTab = document.querySelector(`[onclick="showSection('${sectionId}')"]`);
            if (targetTab) {
                targetTab.classList.add('active');
            }
            
            // Save current tab to localStorage for persistence
            if (saveToStorage) {
                localStorage.setItem('adminPanelActiveTab', sectionId);
            }
            
            // Load section-specific data
            loadSectionData(sectionId);
        }
        
        function loadSectionData(sectionId) {
            switch(sectionId) {
                case 'overview':
                    loadOverview();
                    loadSystemHealth();
                    loadRecentActivity();
                    break;
                case 'breakout':
                    loadHighScores();
                    break;
                case 'bot-status':
                    loadBotStatus();
                    break;
                case 'user-management':
                    loadUserManagement();
                    break;
            }
        }
        
        // API call helper
        async function apiCall(endpoint, method = 'GET', data = null) {
            try {
                console.log('API Call:', endpoint, method, data);
                const options = {
                    method,
                    headers: {
                        'Content-Type': 'application/json',
                    }
                };
                
                if (data) {
                    options.body = JSON.stringify(data);
                    console.log('Request body:', options.body);
                }
                
                const url = `admin_api.php?action=${endpoint}`;
                console.log('Fetching URL:', url);
                
                const response = await fetch(url, options);
                console.log('Response status:', response.status, response.statusText);
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                const result = await response.json();
                console.log('API Response:', result);
                return result;
            } catch (error) {
                console.error('API call failed:', error);
                return { error: 'API call failed: ' + error.message };
            }
        }
        
        // Test function for debugging
        function testFunction() {
            showCustomAlert('JavaScript is working! Click events are responsive.');
            console.log('Test function called successfully');
        }
        
        // Load overview data
        async function loadOverview() {
            try {
                console.log('Loading overview data...');
                
                const botStatus = await apiCall('bot_status');
                console.log('Bot status received:', botStatus);
                
                const breakoutStats = await apiCall('breakout_stats');
                console.log('Breakout stats received:', breakoutStats);
                
                // Update bot status display
                const botStatusElement = document.getElementById('bot-status-overview');
                if (botStatusElement) {
                    if (botStatus && typeof botStatus.online !== 'undefined') {
                        botStatusElement.innerHTML = botStatus.online ? 
                            '<span class="status-indicator status-online"><i class="fas fa-check-circle"></i> Online</span>' :
                            '<span class="status-indicator status-offline"><i class="fas fa-times-circle"></i> Offline</span>';
                        
                        // Add network details if available
                        if (botStatus.networks) {
                            let networkInfo = '<br><small>';
                            for (const [network, info] of Object.entries(botStatus.networks)) {
                                const statusIcon = info.online ? '🟢' : '🔴';
                                networkInfo += `${statusIcon} ${network.charAt(0).toUpperCase() + network.slice(1)}: ${info.online ? 'Online' : 'Offline'}`;
                                if (info.uptime) networkInfo += ` (${info.uptime})`;
                                networkInfo += '<br>';
                            }
                            networkInfo += '</small>';
                            botStatusElement.innerHTML += networkInfo;
                        }
                    } else {
                        botStatusElement.innerHTML = '<span class="status-indicator status-error">⚠️ Status Unknown</span>';
                    }
                } else {
                    console.error('Bot status element not found');
                }
                
                // Update breakout stats display  
                const breakoutStatsElement = document.getElementById('breakout-stats-overview');
                if (breakoutStatsElement) {
                    if (breakoutStats && !breakoutStats.error) {
                        breakoutStatsElement.innerHTML = 
                            `<p>Total Scores: ${breakoutStats.total_scores || 0}</p>
                             <p>Top Score: ${breakoutStats.top_score || 0}</p>
                             <p>Unique Players: ${breakoutStats.unique_players || 0}</p>
                             <p>Today's Games: ${breakoutStats.today_games || 0}</p>`;
                    } else {
                        breakoutStatsElement.innerHTML = '<p>⚠️ Unable to load stats</p>';
                    }
                } else {
                    console.error('Breakout stats element not found');
                }
                
                console.log('Overview loaded successfully');
            } catch (error) {
                console.error('Error loading overview:', error);
                
                // Show error in UI
                const botStatusElement = document.getElementById('bot-status-overview');
                if (botStatusElement) {
                    botStatusElement.innerHTML = '<span class="status-indicator status-error">⚠️ Error loading status</span>';
                }
                
                const breakoutStatsElement = document.getElementById('breakout-stats-overview');
                if (breakoutStatsElement) {
                    breakoutStatsElement.innerHTML = '<p>⚠️ Error loading stats</p>';
                }
            }
        }
        
        // Load bot status details
        async function loadBotStatus() {
            try {
                console.log('Loading detailed bot status...');
                
                const botStatus = await apiCall('bot_status');
                const userStats = await apiCall('get_user_stats');
                
                // Update network status
                const networkStatusElement = document.getElementById('network-status');
                if (networkStatusElement && botStatus && botStatus.networks) {
                    let networkHTML = '';
                    for (const [network, info] of Object.entries(botStatus.networks)) {
                        const statusClass = info.online ? 'status-online' : 'status-offline';
                        const statusIcon = info.online ? 'fas fa-check-circle' : 'fas fa-times-circle';
                        networkHTML += `
                            <div style="margin-bottom: 1rem; padding: 0.75rem; border-left: 4px solid ${info.online ? '#10b981' : '#ef4444'}; background: ${info.online ? '#f0fdf4' : '#fef2f2'};">
                                <h4><span class="status-indicator ${statusClass}"><i class="${statusIcon}"></i> ${network.charAt(0).toUpperCase() + network.slice(1)}</span></h4>
                                <p><strong>Status:</strong> ${info.online ? 'Online' : 'Offline'}</p>
                                ${info.pid ? `<p><strong>PID:</strong> ${info.pid}</p>` : ''}
                                ${info.uptime ? `<p><strong>Uptime:</strong> ${info.uptime}</p>` : ''}
                                <p><strong>Detection:</strong> ${info.method || 'Unknown'}</p>
                            </div>
                        `;
                    }
                    networkStatusElement.innerHTML = networkHTML;
                }
                
                // Update bot performance (simplified for now)
                const performanceElement = document.getElementById('bot-performance');
                if (performanceElement) {
                    const onlineCount = botStatus.networks ? Object.values(botStatus.networks).filter(n => n.online).length : 0;
                    const totalNetworks = botStatus.networks ? Object.keys(botStatus.networks).length : 0;
                    performanceElement.innerHTML = `
                        <p><strong>Active Networks:</strong> ${onlineCount}/${totalNetworks}</p>
                        <p><strong>Overall Status:</strong> ${botStatus.online ? '🟢 Operational' : '🔴 Offline'}</p>
                        <p><strong>Last Check:</strong> ${new Date().toLocaleTimeString()}</p>
                    `;
                }
                
                // Update command usage
                const commandUsageElement = document.getElementById('command-usage');
                if (commandUsageElement && userStats) {
                    let usageHTML = '';
                    for (const [network, stats] of Object.entries(userStats)) {
                        if (stats.week_stats) {
                            usageHTML += `
                                <div style="margin-bottom: 1rem;">
                                    <h4>${network.charAt(0).toUpperCase() + network.slice(1)} Network</h4>
                                    <p><strong>Commands (7d):</strong> ${stats.week_stats.total_commands || 0}</p>
                                    <p><strong>Active Users (7d):</strong> ${stats.week_stats.unique_users || 0}</p>
                                </div>
                            `;
                        }
                    }
                    commandUsageElement.innerHTML = usageHTML || '<p>No recent command data available</p>';
                }
                
                // Update uptime info
                const uptimeElement = document.getElementById('uptime-info');
                if (uptimeElement && botStatus.networks) {
                    let uptimeHTML = '';
                    for (const [network, info] of Object.entries(botStatus.networks)) {
                        uptimeHTML += `
                            <div style="margin-bottom: 0.5rem;">
                                <strong>${network.charAt(0).toUpperCase() + network.slice(1)}:</strong> 
                                ${info.uptime || 'N/A'}
                            </div>
                        `;
                    }
                    uptimeElement.innerHTML = uptimeHTML;
                }
                
                console.log('Bot status loaded successfully');
            } catch (error) {
                console.error('Error loading bot status:', error);
                
                // Show errors in UI
                ['network-status', 'bot-performance', 'command-usage', 'uptime-info'].forEach(elementId => {
                    const element = document.getElementById(elementId);
                    if (element) {
                        element.innerHTML = '<p>⚠️ Error loading data</p>';
                    }
                });
            }
        }
        
        // Load system health
        async function loadSystemHealth() {
            try {
                console.log('Loading system health...');
                
                const systemHealthElement = document.getElementById('system-health');
                if (!systemHealthElement) return;
                
                // Get comprehensive system health metrics
                const healthData = await apiCall('system_health');
                
                if (!healthData.success) {
                    throw new Error(healthData.error || 'Failed to load health data');
                }
                
                const currentTime = new Date();
                
                systemHealthElement.innerHTML = `
                    <div style="display: grid; gap: 0.75rem;">
                        <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 1.1em;">
                            <span>${healthData.status_icon}</span>
                            <strong>Overall Health:</strong>
                            <span style="color: ${healthData.status_color}; font-weight: bold; text-transform: uppercase;">${healthData.status}</span>
                        </div>
                        
                        <div style="border-top: 1px solid #444; padding-top: 0.5rem;">
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; font-size: 0.9em;">
                                <div><strong>Rizon Bot:</strong> ${healthData.components.rizon_bot}</div>
                                <div><strong>Libera Bot:</strong> ${healthData.components.libera_bot}</div>
                                <div><strong>Database:</strong> ${healthData.components.database}</div>
                                <div><strong>System Load:</strong> ${healthData.metrics.load}</div>
                                <div><strong>Memory:</strong> ${healthData.metrics.memory}%</div>
                                <div><strong>Disk Usage:</strong> ${healthData.metrics.disk}%</div>
                            </div>
                        </div>
                        
                        <div style="border-top: 1px solid #444; padding-top: 0.5rem; font-size: 0.8em; color: #888;">
                            <div><strong>Last Check:</strong> ${currentTime.toLocaleTimeString()}</div>
                        </div>
                    </div>
                `;
                
                console.log('System health loaded successfully');
            } catch (error) {
                console.error('Error loading system health:', error);
                const systemHealthElement = document.getElementById('system-health');
                if (systemHealthElement) {
                    systemHealthElement.innerHTML = `
                        <div style="color: #ff6b6b;">
                            <p>⚠️ Unable to load system health</p>
                            <p style="font-size: 0.8em; margin-top: 0.5rem;">Error: ${error.message}</p>
                        </div>
                    `;
                }
            }
        }
        
        // Load recent activity
        async function loadRecentActivity() {
            try {
                console.log('Loading recent activity...');
                
                const recentActivityElement = document.getElementById('recent-activity');
                if (!recentActivityElement) return;
                
                const userStats = await apiCall('get_user_stats');
                const breakoutStats = await apiCall('breakout_stats');
                
                let activityHTML = '<div style="font-size: 0.9rem;">';
                
                // Recent commands activity
                if (userStats) {
                    let totalCommands = 0;
                    let totalUsers = 0;
                    
                    for (const [network, stats] of Object.entries(userStats)) {
                        if (stats.week_stats) {
                            totalCommands += stats.week_stats.total_commands || 0;
                            totalUsers += stats.week_stats.unique_users || 0;
                        }
                    }
                    
                    activityHTML += `
                        <div style="margin-bottom: 0.5rem;">
                            <strong>Commands (7d):</strong> ${totalCommands}
                        </div>
                        <div style="margin-bottom: 0.5rem;">
                            <strong>Active Users:</strong> ${totalUsers}
                        </div>
                    `;
                }
                
                // Recent game activity
                if (breakoutStats && !breakoutStats.error) {
                    activityHTML += `
                        <div style="margin-bottom: 0.5rem;">
                            <strong>Games Today:</strong> ${breakoutStats.today_games || 0}
                        </div>
                        <div style="margin-bottom: 0.5rem;">
                            <strong>Top Score:</strong> ${breakoutStats.top_score || 0}
                        </div>
                    `;
                }
                
                activityHTML += `
                    <div style="color: #6b7280; font-size: 0.8rem; margin-top: 0.5rem;">
                        Updated: ${new Date().toLocaleTimeString()}
                    </div>
                `;
                activityHTML += '</div>';
                
                recentActivityElement.innerHTML = activityHTML;
                
                console.log('Recent activity loaded');
            } catch (error) {
                console.error('Error loading recent activity:', error);
                const recentActivityElement = document.getElementById('recent-activity');
                if (recentActivityElement) {
                    recentActivityElement.innerHTML = '<p>⚠️ Unable to load recent activity</p>';
                }
            }
        }
        
        // Load user management
        async function loadUserManagement() {
            try {
                console.log('Loading user management...');
                
                const userStatsElement = document.getElementById('user-stats');
                if (!userStatsElement) return;
                
                const userStats = await apiCall('get_user_stats');
                
                if (userStats && Object.keys(userStats).length > 0) {
                    let statsHTML = '';
                    
                    for (const [network, stats] of Object.entries(userStats)) {
                        statsHTML += `
                            <div style="margin-bottom: 1.5rem; padding: 1rem; background: var(--bg-secondary); border-radius: 8px;">
                                <h4 style="color: var(--primary-color); margin-bottom: 0.75rem;">
                                    ${network.charAt(0).toUpperCase() + network.slice(1)} Network
                                </h4>
                        `;
                        
                        if (stats.week_stats) {
                            statsHTML += `
                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
                                    <div>
                                        <strong>Commands (7d):</strong><br>
                                        <span style="font-size: 1.5rem; color: var(--primary-color);">${stats.week_stats.total_commands || 0}</span>
                                    </div>
                                    <div>
                                        <strong>Active Users (7d):</strong><br>
                                        <span style="font-size: 1.5rem; color: var(--primary-color);">${stats.week_stats.unique_users || 0}</span>
                                    </div>
                                </div>
                            `;
                        }
                        
                        if (stats.top_users && stats.top_users.length > 0) {
                            statsHTML += `
                                <div>
                                    <strong>Most Active Users (7d):</strong>
                                    <ol style="margin: 0.5rem 0; padding-left: 1.5rem;">
                            `;
                            
                            stats.top_users.slice(0, 5).forEach(user => {
                                statsHTML += `
                                    <li style="margin: 0.25rem 0;">
                                        <strong>${user.user}</strong> - ${user.command_count} commands
                                    </li>
                                `;
                            });
                            
                            statsHTML += '</ol></div>';
                        }
                        
                        statsHTML += '</div>';
                    }
                    
                    userStatsElement.innerHTML = statsHTML;
                } else {
                    userStatsElement.innerHTML = '<p>No user statistics available</p>';
                }
                
                console.log('User management loaded');
            } catch (error) {
                console.error('Error loading user management:', error);
                const userStatsElement = document.getElementById('user-stats');
                if (userStatsElement) {
                    userStatsElement.innerHTML = '<p>⚠️ Error loading user statistics</p>';
                }
            }
        }
        
        // Load high scores
        async function loadHighScores() {
            const scores = await apiCall('get_high_scores');
            console.log('Loaded scores:', scores);
            
            if (!Array.isArray(scores)) {
                console.error('Expected array but got:', scores);
                document.getElementById('high-scores-table').innerHTML = '<p>Error loading scores</p>';
                return;
            }
            
            const tableHtml = `
                <h3><i class="fas fa-trophy"></i> Current High Scores</h3>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Rank</th>
                            <th>Player</th>
                            <th>Score</th>
                            <th>Level</th>
                            <th>Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${scores.map((score, index) => {
                            console.log(`Score ${index}:`, score);
                            return `
                            <tr>
                                <td>${index + 1}</td>
                                <td>${score.player_name}</td>
                                <td>${score.score.toLocaleString()}</td>
                                <td>${score.level_reached}</td>
                                <td>${new Date(score.date_played).toLocaleDateString()}</td>
                                <td>
                                    <button class="btn btn-danger btn-sm delete-score-btn" data-score-id="${score.id}" data-player-name="${score.player_name}">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </td>
                            </tr>
                        `;}).join('')}
                    </tbody>
                </table>
            `;
            document.getElementById('high-scores-table').innerHTML = tableHtml;
            
            // Add event listeners to delete buttons using event delegation
            const highScoresTable = document.getElementById('high-scores-table');
            if (highScoresTable) {
                // Remove any existing listeners
                highScoresTable.removeEventListener('click', handleDeleteClick);
                // Add new listener
                highScoresTable.addEventListener('click', handleDeleteClick);
            }
        }
        
        // Bot control functions
        async function startBot() {
            const result = await apiCall('start_bot', 'POST');
            showCustomAlert(result.message || 'Bot start command sent');
        }
        
        async function stopBot() {
            const result = await apiCall('stop_bot', 'POST');
            showCustomAlert(result.message || 'Bot stop command sent');
        }
        
        async function restartBot() {
            const result = await apiCall('restart_bot', 'POST');
            showCustomAlert(result.message || 'Bot restart command sent');
        }
        
        // Individual network restart functions
        async function restartRizonBot() {
            try {
                showCustomAlert('🔄 Restarting Rizon bot...');
                const result = await apiCall('restart_rizon', 'POST');
                
                if (result.success) {
                    showCustomAlert('✅ Rizon bot restart initiated successfully!');
                    // Refresh bot status after a short delay
                    setTimeout(() => {
                        if (document.getElementById('bot-status').style.display !== 'none') {
                            loadBotStatus();
                        }
                        if (document.getElementById('overview').style.display !== 'none') {
                            loadOverview();
                        }
                    }, 5000);
                } else {
                    showCustomAlert('❌ Error restarting Rizon bot: ' + (result.error || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error restarting Rizon bot:', error);
                showCustomAlert('❌ Failed to restart Rizon bot');
            }
        }
        
        async function restartLiberaBot() {
            try {
                showCustomAlert('🔄 Restarting Libera bot...');
                const result = await apiCall('restart_libera', 'POST');
                
                if (result.success) {
                    showCustomAlert('✅ Libera bot restart initiated successfully!');
                    // Refresh bot status after a short delay
                    setTimeout(() => {
                        if (document.getElementById('bot-status').style.display !== 'none') {
                            loadBotStatus();
                        }
                        if (document.getElementById('overview').style.display !== 'none') {
                            loadOverview();
                        }
                    }, 5000);
                } else {
                    showCustomAlert('❌ Error restarting Libera bot: ' + (result.error || 'Unknown error'));
                }
            } catch (error) {
                console.error('Error restarting Libera bot:', error);
                showCustomAlert('❌ Failed to restart Libera bot');
            }
        }
        
        // Breakout game management
        async function resetAllScores() {
            const confirmed = await showCustomConfirm('Are you sure you want to reset ALL scores? This cannot be undone!');
            if (confirmed) {
                const result = await apiCall('reset_scores', 'POST');
                showCustomAlert(result.message || 'Scores reset');
                loadHighScores();
            }
        }
        
        // Handle clicks on delete buttons
        function handleDeleteClick(event) {
            const target = event.target.closest('.delete-score-btn');
            if (target) {
                const scoreId = target.getAttribute('data-score-id');
                const playerName = target.getAttribute('data-player-name');
                console.log('Delete button clicked for score ID:', scoreId, 'Player:', playerName);
                deleteScore(scoreId, playerName);
            }
        }
        
        // Custom modal functions to replace browser confirm/alert
        function showCustomConfirm(message) {
            return new Promise((resolve) => {
                const modal = document.createElement('div');
                modal.style.cssText = `
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0,0,0,0.5);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    z-index: 10000;
                `;
                
                const dialog = document.createElement('div');
                dialog.style.cssText = `
                    background: var(--bg-primary);
                    padding: 2rem;
                    border-radius: var(--radius-lg);
                    box-shadow: var(--shadow-lg);
                    max-width: 400px;
                    text-align: center;
                    border: 1px solid var(--border-light);
                `;
                
                dialog.innerHTML = `
                    <div style="margin-bottom: 1.5rem; color: var(--text-primary); font-size: 1.1rem;">
                        ${message}
                    </div>
                    <div style="display: flex; gap: 1rem; justify-content: center;">
                        <button id="confirmYes" class="btn btn-danger">Yes, Delete</button>
                        <button id="confirmNo" class="btn btn-primary">Cancel</button>
                    </div>
                `;
                
                modal.appendChild(dialog);
                document.body.appendChild(modal);
                
                document.getElementById('confirmYes').onclick = () => {
                    document.body.removeChild(modal);
                    resolve(true);
                };
                
                document.getElementById('confirmNo').onclick = () => {
                    document.body.removeChild(modal);
                    resolve(false);
                };
                
                // Allow clicking outside to cancel
                modal.onclick = (e) => {
                    if (e.target === modal) {
                        document.body.removeChild(modal);
                        resolve(false);
                    }
                };
                
                // Focus the cancel button
                setTimeout(() => document.getElementById('confirmNo').focus(), 100);
            });
        }
        
        function showCustomAlert(message) {
            const modal = document.createElement('div');
            modal.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0,0,0,0.7);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 50000;
                backdrop-filter: blur(2px);
            `;
            
            const dialog = document.createElement('div');
            dialog.style.cssText = `
                background: var(--bg-primary);
                padding: 2rem;
                border-radius: var(--radius-lg);
                box-shadow: 0 20px 40px rgba(0,0,0,0.3);
                max-width: 400px;
                width: 90%;
                text-align: center;
                border: 1px solid var(--border-light);
                position: relative;
                z-index: 50001;
            `;
            
            dialog.innerHTML = `
                <div style="margin-bottom: 1.5rem; color: var(--text-primary); font-size: 1.1rem; line-height: 1.5;">
                    ${message}
                </div>
                <button id="alertOk" class="btn btn-primary" style="min-width: 80px; padding: 0.75rem 1.5rem; font-weight: 600; cursor: pointer; position: relative; z-index: 50002;">OK</button>
            `;
            
            modal.appendChild(dialog);
            document.body.appendChild(modal);
            
            const removeModal = () => {
                if (modal.parentNode) {
                    document.body.removeChild(modal);
                }
            };
            
            // Add multiple event listeners for better reliability
            const okButton = document.getElementById('alertOk');
            if (okButton) {
                okButton.addEventListener('click', removeModal);
                okButton.addEventListener('touchend', removeModal);
            }
            
            // Close on background click
            modal.addEventListener('click', (e) => {
                if (e.target === modal) removeModal();
            });
            
            // Close on Escape key
            const escapeHandler = (e) => {
                if (e.key === 'Escape') {
                    removeModal();
                    document.removeEventListener('keydown', escapeHandler);
                }
            };
            document.addEventListener('keydown', escapeHandler);
            
            // Focus the OK button with longer delay
            setTimeout(() => {
                const btn = document.getElementById('alertOk');
                if (btn) {
                    btn.focus();
                    btn.style.outline = '2px solid var(--accent-primary)';
                }
            }, 200);
        }
        
        async function deleteScore(scoreId, playerName = '') {
            console.log('Attempting to delete score with ID:', scoreId);
            console.log('Player name:', playerName);
            
            try {
                const confirmMessage = playerName ? `Delete score for "${playerName}"?` : 'Delete this score?';
                console.log('Showing custom confirmation modal');
                
                const userConfirmed = await showCustomConfirm(confirmMessage);
                console.log('User confirmed:', userConfirmed);
                
                if (userConfirmed) {
                    console.log('Making API call to delete score...');
                    const result = await apiCall('delete_score', 'POST', { id: scoreId });
                    console.log('Delete result:', result);
                    
                    if (result && result.error) {
                        console.error('Delete error:', result.error);
                        showCustomAlert('Error: ' + result.error);
                    } else if (result && result.success) {
                        console.log('Delete successful');
                        showCustomAlert(result.message || 'Score deleted successfully');
                        loadHighScores();
                    } else {
                        console.error('Unexpected result format:', result);
                        showCustomAlert('Unexpected response from server');
                    }
                } else {
                    console.log('User cancelled deletion');
                }
            } catch (error) {
                console.error('Error in deleteScore function:', error);
                showCustomAlert('An error occurred: ' + error.message);
            }
        }
        
        async function banPlayer() {
            const playerName = document.getElementById('ban-player-name').value;
            if (playerName) {
                const confirmed = await showCustomConfirm(`Ban player "${playerName}"?`);
                if (confirmed) {
                    const result = await apiCall('ban_player', 'POST', { player_name: playerName });
                    showCustomAlert(result.message || 'Player banned');
                    document.getElementById('ban-player-name').value = '';
                }
            }
        }
        
        // Helper function to scroll log viewer to bottom
        function scrollLogViewerToBottom() {
            const logViewer = document.getElementById('log-viewer');
            if (logViewer) {
                // Small delay to ensure content is rendered before scrolling
                setTimeout(() => {
                    logViewer.scrollTop = logViewer.scrollHeight;
                }, 100);
            }
        }
        
        // Load logs
        async function loadLogs(type) {
            const logs = await apiCall('get_logs', 'POST', { type });
            document.getElementById('log-viewer').textContent = logs.content || 'No logs available';
            scrollLogViewerToBottom();
        }
        
        // Load network-specific logs
        async function loadRizonLogs() {
            try {
                const logs = await apiCall('get_rizon_logs');
                const logViewer = document.getElementById('log-viewer');
                
                if (logs.content) {
                    logViewer.innerHTML = `
                        <div style="margin-bottom: 1rem; padding: 0.75rem; background: var(--bg-secondary); border-radius: 5px;">
                            <h4 style="color: var(--primary-color); margin: 0;">📡 Rizon Network Bot Logs (Last 100 lines)</h4>
                            <small style="color: var(--text-secondary);">Live IRC chat and command activity</small>
                        </div>
                        <pre style="white-space: pre-wrap; word-wrap: break-word;">${logs.content}</pre>
                    `;
                } else {
                    logViewer.textContent = 'No Rizon logs available';
                }
                scrollLogViewerToBottom();
            } catch (error) {
                console.error('Error loading Rizon logs:', error);
                document.getElementById('log-viewer').textContent = 'Error loading Rizon logs';
            }
        }
        
        async function loadLiberaLogs() {
            try {
                const logs = await apiCall('get_libera_logs');
                const logViewer = document.getElementById('log-viewer');
                
                if (logs.content) {
                    logViewer.innerHTML = `
                        <div style="margin-bottom: 1rem; padding: 0.75rem; background: var(--bg-secondary); border-radius: 5px;">
                            <h4 style="color: var(--primary-color); margin: 0;">📡 Libera Network Bot Logs (Last 100 lines)</h4>
                            <small style="color: var(--text-secondary);">Live IRC chat and command activity</small>
                        </div>
                        <pre style="white-space: pre-wrap; word-wrap: break-word;">${logs.content}</pre>
                    `;
                } else {
                    logViewer.textContent = 'No Libera logs available';
                }
                scrollLogViewerToBottom();
            } catch (error) {
                console.error('Error loading Libera logs:', error);
                document.getElementById('log-viewer').textContent = 'Error loading Libera logs';
            }
        }
        
        async function loadDetailedLogs(network) {
            try {
                const logs = await apiCall('get_bot_logs', 'POST', { network });
                const logViewer = document.getElementById('log-viewer');
                
                if (logs.logs) {
                    let html = `
                        <div style="margin-bottom: 1rem; padding: 0.75rem; background: var(--bg-secondary); border-radius: 5px;">
                            <h4 style="color: var(--primary-color); margin: 0;">🔍 ${network.charAt(0).toUpperCase() + network.slice(1)} Network - Detailed Logs</h4>
                            <small style="color: var(--text-secondary);">Updated: ${logs.timestamp}</small>
                        </div>
                    `;
                    
                    // Main bot log
                    if (logs.logs.main) {
                        html += `
                            <div style="margin-bottom: 1.5rem;">
                                <h5 style="color: var(--primary-color); background: var(--bg-tertiary); padding: 0.5rem; margin: 0 0 0.5rem 0; border-radius: 3px;">
                                    🤖 Main Bot Activity (Last 50 lines)
                                </h5>
                                <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 300px; overflow-y: auto; border: 1px solid var(--border-light); padding: 0.75rem; background: #000; color: #00ff00; border-radius: 3px;">${logs.logs.main}</pre>
                            </div>
                        `;
                    }
                    
                    // Error log
                    if (logs.logs.errors && logs.logs.errors !== 'Log file is empty') {
                        html += `
                            <div style="margin-bottom: 1.5rem;">
                                <h5 style="color: #ef4444; background: #fef2f2; padding: 0.5rem; margin: 0 0 0.5rem 0; border-radius: 3px;">
                                    ⚠️ Error Log (Last 50 lines)
                                </h5>
                                <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto; border: 1px solid #fca5a5; padding: 0.75rem; background: #fef2f2; color: #dc2626; border-radius: 3px;">${logs.logs.errors}</pre>
                            </div>
                        `;
                    }
                    
                    // Startup log
                    if (logs.logs.startup && logs.logs.startup !== 'Log file is empty') {
                        html += `
                            <div style="margin-bottom: 1.5rem;">
                                <h5 style="color: #059669; background: #f0fdf4; padding: 0.5rem; margin: 0 0 0.5rem 0; border-radius: 3px;">
                                    🚀 Startup Log (Last 50 lines)
                                </h5>
                                <pre style="white-space: pre-wrap; word-wrap: break-word; max-height: 200px; overflow-y: auto; border: 1px solid #a7f3d0; padding: 0.75rem; background: #f0fdf4; color: #047857; border-radius: 3px;">${logs.logs.startup}</pre>
                            </div>
                        `;
                    }
                    
                    logViewer.innerHTML = html;
                } else {
                    logViewer.textContent = `No detailed logs available for ${network}`;
                }
                scrollLogViewerToBottom();
            } catch (error) {
                console.error(`Error loading ${network} detailed logs:`, error);
                document.getElementById('log-viewer').textContent = `Error loading ${network} detailed logs`;
            }
        }
        
        // Sync logs function
        async function syncLogs() {
            try {
                console.log('Starting log sync...');
                showSyncStatus('🔄 Synchronizing logs...', 'info');
                
                const result = await apiCall('sync_logs', 'POST');
                console.log('Sync logs API result:', result);
                
                if (result && result.success) {
                    showSyncStatus('✅ Logs synchronized successfully!', 'success');
                    if (result.output) {
                        console.log('Sync output:', result.output);
                        showSyncOutput(result.output);
                    }
                } else if (result && result.error) {
                    showSyncStatus('❌ Error syncing logs: ' + result.error, 'error');
                } else {
                    showSyncStatus('❌ Unexpected response from sync logs API', 'error');
                }
            } catch (error) {
                console.error('Error syncing logs:', error);
                showSyncStatus('❌ Failed to sync logs: ' + error.message, 'error');
            }
        }
        
        function showSyncStatus(message, type = 'info') {
            // Remove any existing status messages
            const existing = document.querySelectorAll('.sync-status-message');
            existing.forEach(el => el.remove());
            
            // Create new status message
            const statusDiv = document.createElement('div');
            statusDiv.className = 'sync-status-message';
            statusDiv.style.cssText = `
                padding: 1rem;
                margin: 1rem 0;
                border-radius: var(--radius-md);
                font-weight: 500;
                display: flex;
                align-items: center;
                gap: 0.5rem;
                animation: slideIn 0.3s ease-out;
                ${type === 'success' ? 'background: #d4edda; color: #155724; border: 1px solid #c3e6cb;' : 
                  type === 'error' ? 'background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb;' : 
                  'background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb;'}
            `;
            statusDiv.textContent = message;
            
            // Find a good place to insert it (after the sync logs button)
            const syncButton = document.querySelector('button[onclick="syncLogs()"]');
            if (syncButton && syncButton.parentNode) {
                syncButton.parentNode.insertBefore(statusDiv, syncButton.nextSibling);
            } else {
                // Fallback: add to the current active section
                const activeSection = document.querySelector('.section.active');
                if (activeSection) {
                    activeSection.insertBefore(statusDiv, activeSection.firstChild);
                }
            }
            
            // Auto-remove success/info messages after 5 seconds
            if (type !== 'error') {
                setTimeout(() => {
                    if (statusDiv.parentNode) {
                        statusDiv.style.opacity = '0';
                        setTimeout(() => statusDiv.remove(), 300);
                    }
                }, 5000);
            }
        }
        
        function showSyncOutput(output) {
            // Create collapsible output section
            const outputDiv = document.createElement('div');
            outputDiv.className = 'sync-output';
            outputDiv.style.cssText = `
                margin: 0.5rem 0;
                padding: 1rem;
                background: var(--bg-secondary);
                border: 1px solid var(--border-light);
                border-radius: var(--radius-md);
                font-family: monospace;
                font-size: 0.9rem;
                color: var(--text-secondary);
                white-space: pre-wrap;
                max-height: 200px;
                overflow-y: auto;
                cursor: pointer;
            `;
            
            const header = document.createElement('div');
            header.style.cssText = `
                font-weight: bold;
                margin-bottom: 0.5rem;
                color: var(--text-primary);
            `;
            header.textContent = '📄 Sync Details (click to toggle)';
            
            const content = document.createElement('div');
            content.style.display = 'none';
            content.textContent = output;
            
            outputDiv.appendChild(header);
            outputDiv.appendChild(content);
            
            // Toggle functionality
            outputDiv.addEventListener('click', () => {
                const isVisible = content.style.display !== 'none';
                content.style.display = isVisible ? 'none' : 'block';
                header.textContent = isVisible ? '📄 Sync Details (click to toggle)' : '📄 Sync Details (click to hide)';
            });
            
            // Insert after status message
            const statusMsg = document.querySelector('.sync-status-message');
            if (statusMsg && statusMsg.parentNode) {
                statusMsg.parentNode.insertBefore(outputDiv, statusMsg.nextSibling);
                
                // Auto-remove after 30 seconds
                setTimeout(() => {
                    if (outputDiv.parentNode) {
                        outputDiv.style.opacity = '0';
                        setTimeout(() => outputDiv.remove(), 300);
                    }
                }, 30000);
            }
        }
        
        // Initialize the page
        document.addEventListener('DOMContentLoaded', function() {
            // Restore previously selected tab or default to overview
            const savedTab = localStorage.getItem('adminPanelActiveTab') || 'overview';
            
            // Show the saved/default section without saving to storage (to avoid loop)
            showSection(savedTab, false);
        });
        
        // Theme management
        function toggleTheme() {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            
            const themeIcon = document.getElementById('theme-icon');
            const themeText = document.getElementById('theme-text');
            
            if (newTheme === 'dark') {
                themeIcon.className = 'fas fa-moon';
                themeText.textContent = 'Dark';
            } else {
                themeIcon.className = 'fas fa-sun';
                themeText.textContent = 'Light';
            }
        }
        
        // Initialize theme
        function initializeTheme() {
            const savedTheme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-theme', savedTheme);
            
            const themeIcon = document.getElementById('theme-icon');
            const themeText = document.getElementById('theme-text');
            
            if (savedTheme === 'dark') {
                themeIcon.className = 'fas fa-moon';
                themeText.textContent = 'Dark';
            } else {
                themeIcon.className = 'fas fa-sun';
                themeText.textContent = 'Light';
            }
        }
        
        // LocalStorage score management
        async function resetLocalStorageScores() {
            if (confirm('This will reset all localStorage scores for users visiting the website. Continue?')) {
                // Send instruction to client-side localStorage management
                const result = await apiCall('reset_local_scores', 'POST');
                if (result.success) {
                    alert('LocalStorage reset instruction sent. Users will see reset scores on next visit.');
                } else {
                    alert('Failed to set localStorage reset flag');
                }
            }
        }
        
        async function viewLocalStorageScores() {
            alert('LocalStorage scores are stored on individual user devices. Database scores are shown in the high scores table above.');
        }
        
        // Auto-refresh overview every 30 seconds
        setInterval(() => {
            if (document.querySelector('.admin-section[style*="display: block"]')?.id === 'overview') {
                loadOverview();
                loadSystemHealth();
                loadRecentActivity();
            }
        }, 30000);
        
        // Initialize theme on page load
        initializeTheme();
    </script>
</body>
</html>