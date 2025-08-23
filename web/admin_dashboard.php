<?php
/**
 * Main Admin Dashboard
 * Clean, consolidated admin interface using new bootstrap system
 * Replaces: comprehensive_admin.php + integrated_admin.php + admin_styled.php
 */

// Use consolidated bootstrap - replaces 15+ lines of includes and security setup
require_once 'core_security_system.php';
require_once 'core_admin_bootstrap.php';
require_once 'advanced_admin_functions.php';

// Admin authentication handled by bootstrap
$admin_status = $admin_status ?? initAdminSecurity();

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
            
        case 'update_config':
            $config_data = $_POST['config_data'] ?? [];
            $response = AdvancedAdmin::updateConfiguration($config_data);
            break;
            
        default:
            $response['message'] = 'Invalid action';
    }
    
    echo json_encode($response);
    exit;
}

// Render page using bootstrap functions
renderAdminHeader('Admin Dashboard');
?>

<div class="status-indicator status-success">
    Admin Dashboard - Authenticated as <?= htmlspecialchars($_SESSION['username']) ?>
</div>

<div class="dashboard-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px;">
    <div class="dashboard-section">
        <h2>Bot Management</h2>
        <div class="bot-controls">
            <button onclick="manageBots('status', 'all')" class="btn btn-info">Check Status</button>
            <button onclick="manageBots('restart', 'rizon')" class="btn btn-warning">Restart Rizon</button>
            <button onclick="manageBots('restart', 'libera')" class="btn btn-warning">Restart Libera</button>
            <button onclick="manageBots('restart', 'all')" class="btn btn-danger">Restart All</button>
        </div>
        <div id="bot-status" class="status-display"></div>
    </div>
    
    <div class="dashboard-section">
        <h2>Quick Stats</h2>
        <div id="quick-stats" class="stats-display">
            <div class="stat-item">
                <span class="stat-label">Commands Today:</span>
                <span class="stat-value" id="commands-today">Loading...</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Active Users:</span>
                <span class="stat-value" id="active-users">Loading...</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">Games Played:</span>
                <span class="stat-value" id="games-played">Loading...</span>
            </div>
        </div>
    </div>
</div>

<div class="dashboard-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
    <div class="dashboard-section">
        <h2>Recent Commands</h2>
        <div id="recent-commands" class="command-list"></div>
    </div>
    
    <div class="dashboard-section">
        <h2>Security Events</h2>
        <div id="security-events" class="event-list"></div>
    </div>
</div>

<style>
.dashboard-section {
    background: #f9f9f9;
    padding: 20px;
    border-radius: 6px;
    border: 1px solid #ddd;
}

.dashboard-section h2 {
    margin-top: 0;
    color: #333;
    border-bottom: 1px solid #ddd;
    padding-bottom: 10px;
}

.bot-controls {
    margin-bottom: 15px;
}

.btn {
    padding: 8px 16px;
    margin-right: 10px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 14px;
}

.btn-info { background: #2196F3; color: white; }
.btn-warning { background: #FF9800; color: white; }
.btn-danger { background: #F44336; color: white; }
.btn:hover { opacity: 0.8; }

.stat-item {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid #eee;
}

.stat-label { font-weight: bold; }
.stat-value { color: #2196F3; font-weight: bold; }

.status-display, .command-list, .event-list {
    max-height: 300px;
    overflow-y: auto;
    background: white;
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: 4px;
}
</style>

<script>
// Auto-refresh dashboard data every 30 seconds
let refreshInterval;

function startAutoRefresh() {
    refreshInterval = setInterval(refreshDashboard, 30000);
    refreshDashboard(); // Initial load
}

function refreshDashboard() {
    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=get_live_data'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            updateQuickStats(data);
            updateRecentCommands(data.recent_commands);
            updateSecurityEvents(data.security_events);
        }
    })
    .catch(error => console.error('Dashboard refresh failed:', error));
}

function manageBots(action, network) {
    fetch('', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `action=bot_action&bot_action=${action}&network=${network}`
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('bot-status').innerHTML = 
            `<div class="status-${data.success ? 'success' : 'error'}">${data.message}</div>`;
    });
}

function updateQuickStats(data) {
    if (data.user_analytics) {
        document.getElementById('commands-today').textContent = data.user_analytics.commands_today || '0';
        document.getElementById('active-users').textContent = data.user_analytics.active_users || '0';
    }
    if (data.game_stats) {
        document.getElementById('games-played').textContent = data.game_stats.total_games || '0';
    }
}

function updateRecentCommands(commands) {
    const container = document.getElementById('recent-commands');
    if (commands && commands.length > 0) {
        container.innerHTML = commands.map(cmd => 
            `<div class="command-item">
                <strong>${cmd.command}</strong> by ${cmd.user} 
                <span style="color: #666; font-size: 12px;">${cmd.timestamp}</span>
            </div>`
        ).join('');
    } else {
        container.innerHTML = '<div>No recent commands</div>';
    }
}

function updateSecurityEvents(events) {
    const container = document.getElementById('security-events');
    if (events && events.length > 0) {
        container.innerHTML = events.map(event => 
            `<div class="event-item">
                <strong style="color: ${event.severity === 'HIGH' ? 'red' : 'orange'};">${event.type}</strong>
                <div style="font-size: 12px; color: #666;">${event.message}</div>
            </div>`
        ).join('');
    } else {
        container.innerHTML = '<div>No recent security events</div>';
    }
}

// Start auto-refresh when page loads
document.addEventListener('DOMContentLoaded', startAutoRefresh);
</script>

<?php renderAdminFooter(); ?>