<?php
/**
 * SECURITY MONITORING DASHBOARD
 * Real-time security status and threat monitoring for hardened Pi
 */

require_once 'security_config.php';
require_once 'security_hardened.php';
require_once 'secure_database.php';

// Require admin authentication
requireAdmin();

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['api'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['api']) {
        case 'security_status':
            echo json_encode(getSecurityStatus());
            break;
        case 'blocked_ips':
            echo json_encode(HardcoreSecurityManager::getSecurityDashboard());
            break;
        case 'database_security':
            echo json_encode(getDatabaseSecurityReport());
            break;
        case 'system_threats':
            echo json_encode(getSystemThreats());
            break;
        default:
            echo json_encode(['error' => 'Unknown API endpoint']);
    }
    exit;
}

function getSecurityStatus() {
    $status = [
        'overall_status' => 'secure',
        'threat_level' => 'low',
        'active_protections' => [
            'ip_blocking' => true,
            'rate_limiting' => true,
            'csrf_protection' => true,
            'input_sanitization' => true,
            'json_bomb_protection' => true,
            'path_traversal_protection' => true,
            'intrusion_detection' => true,
            'secure_sessions' => true
        ],
        'security_score' => 0,
        'issues' => []
    ];
    
    // Check database security
    $dbReport = getDatabaseSecurityReport();
    if ($dbReport['status'] === 'critical') {
        $status['overall_status'] = 'critical';
        $status['threat_level'] = 'high';
        $status['issues'] = array_merge($status['issues'], $dbReport['issues']);
    }
    
    // Check for recent attacks
    $dashboard = HardcoreSecurityManager::getSecurityDashboard();
    $recentAttacks = 0;
    foreach ($dashboard['recent_events'] as $event) {
        if ($event['type'] === 'ATTACK' && time() - strtotime($event['timestamp']) < 3600) {
            $recentAttacks++;
        }
    }
    
    if ($recentAttacks > 10) {
        $status['threat_level'] = 'high';
        $status['issues'][] = "$recentAttacks attacks detected in the last hour";
    } elseif ($recentAttacks > 5) {
        $status['threat_level'] = 'medium';
        $status['issues'][] = "$recentAttacks attacks detected in the last hour";
    }
    
    // Calculate security score
    $maxScore = 100;
    $penalties = count($status['issues']) * 10;
    if ($dbReport['status'] === 'critical') $penalties += 30;
    if ($recentAttacks > 10) $penalties += 20;
    
    $status['security_score'] = max(0, $maxScore - $penalties);
    
    return $status;
}

function getSystemThreats() {
    $threats = [
        'active_attacks' => 0,
        'blocked_ips' => 0,
        'suspicious_activity' => 0,
        'recent_blocks' => [],
        'attack_vectors' => [],
        'geographic_threats' => []
    ];
    
    $dashboard = HardcoreSecurityManager::getSecurityDashboard();
    
    // Count active threats
    foreach ($dashboard['recent_events'] as $event) {
        $eventTime = strtotime($event['timestamp']);
        $hourAgo = time() - 3600;
        
        if ($eventTime > $hourAgo) {
            switch ($event['type']) {
                case 'ATTACK':
                    $threats['active_attacks']++;
                    $threats['attack_vectors'][] = [
                        'type' => $event['message'],
                        'ip' => $event['ip'],
                        'time' => $event['timestamp']
                    ];
                    break;
                case 'BLOCK':
                    $threats['recent_blocks'][] = [
                        'ip' => $event['ip'],
                        'reason' => $event['message'],
                        'time' => $event['timestamp']
                    ];
                    break;
                case 'BOT':
                case 'RATE_LIMIT':
                    $threats['suspicious_activity']++;
                    break;
            }
        }
    }
    
    $threats['blocked_ips'] = count($dashboard['active_blocks']);
    
    return $threats;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Security Dashboard - Pi Fortress</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #fff;
            min-height: 100vh;
        }
        
        .header {
            background: rgba(0,0,0,0.3);
            padding: 1rem 2rem;
            border-bottom: 2px solid rgba(255,255,255,0.1);
        }
        
        .header h1 {
            font-size: 2rem;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
        }
        
        .dashboard {
            padding: 1rem;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(min(300px, 100%), 1fr));
            gap: 1.5rem;
            max-width: 1600px;
            margin: 0 auto;
        }
        
        .card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 12px;
            padding: 1.25rem;
            border: 1px solid rgba(255,255,255,0.2);
            box-shadow: 0 4px 16px rgba(0,0,0,0.3);
            min-width: 0; /* Allows flex children to shrink */
            overflow: hidden; /* Prevents content overflow */
        }
        
        .card h2 {
            font-size: 1.3rem;
            margin-bottom: 1rem;
            color: #fff;
            border-bottom: 2px solid rgba(255,255,255,0.2);
            padding-bottom: 0.5rem;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-secure { background: #00ff88; box-shadow: 0 0 10px #00ff88; }
        .status-warning { background: #ffaa00; box-shadow: 0 0 10px #ffaa00; }
        .status-critical { background: #ff3333; box-shadow: 0 0 10px #ff3333; }
        
        .metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin: 0.5rem 0;
            padding: 0.5rem;
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
        }
        
        .metric-value {
            font-weight: bold;
            font-size: 1.1rem;
        }
        
        .threat-level-low { color: #00ff88; }
        .threat-level-medium { color: #ffaa00; }
        .threat-level-high { color: #ff3333; }
        
        .event-log {
            max-height: 280px;
            overflow-y: auto;
            background: rgba(0,0,0,0.3);
            border-radius: 8px;
            padding: 0.875rem;
            scrollbar-width: thin;
            scrollbar-color: rgba(255,255,255,0.3) rgba(0,0,0,0.1);
        }
        
        .event-log::-webkit-scrollbar {
            width: 6px;
        }
        
        .event-log::-webkit-scrollbar-track {
            background: rgba(0,0,0,0.1);
            border-radius: 3px;
        }
        
        .event-log::-webkit-scrollbar-thumb {
            background: rgba(255,255,255,0.3);
            border-radius: 3px;
        }
        
        .event {
            margin: 0.5rem 0;
            padding: 0.75rem;
            border-left: 3px solid #00ff88;
            background: rgba(255,255,255,0.05);
            border-radius: 6px;
            font-size: 0.85rem;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        
        .event.attack { border-left-color: #ff3333; }
        .event.warning { border-left-color: #ffaa00; }
        .event.block { border-left-color: #ff6600; }
        
        .refresh-btn {
            background: linear-gradient(45deg, #00ff88, #00cc66);
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 25px;
            color: white;
            cursor: pointer;
            font-weight: bold;
            transition: transform 0.2s;
        }
        
        .refresh-btn:hover {
            transform: scale(1.05);
        }
        
        .ip-list {
            max-height: 240px;
            overflow-y: auto;
            scrollbar-width: thin;
            scrollbar-color: rgba(255,255,255,0.3) rgba(0,0,0,0.1);
        }
        
        .ip-list::-webkit-scrollbar {
            width: 6px;
        }
        
        .ip-list::-webkit-scrollbar-track {
            background: rgba(0,0,0,0.1);
            border-radius: 3px;
        }
        
        .ip-list::-webkit-scrollbar-thumb {
            background: rgba(255,255,255,0.3);
            border-radius: 3px;
        }
        
        .blocked-ip {
            background: rgba(255,51,51,0.15);
            border: 1px solid rgba(255,51,51,0.6);
            border-radius: 8px;
            padding: 0.75rem;
            margin: 0.5rem 0;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.85rem;
            word-break: break-all;
            transition: all 0.2s ease;
        }
        
        .blocked-ip:hover {
            background: rgba(255,51,51,0.25);
            border-color: rgba(255,51,51,0.8);
            transform: translateX(2px);
        }
        
        .protection-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(min(140px, 100%), 1fr));
            gap: 0.5rem;
        }
        
        .protection-item {
            display: flex;
            align-items: center;
            padding: 0.625rem;
            background: rgba(255,255,255,0.05);
            border-radius: 8px;
            font-size: 0.8rem;
            transition: all 0.2s ease;
            border: 1px solid transparent;
        }
        
        .protection-item:hover {
            background: rgba(255,255,255,0.1);
            border-color: rgba(255,255,255,0.2);
        }
        
        .protection-active { color: #00ff88; }
        .protection-inactive { color: #ff3333; }
        
        /* Mobile Responsiveness */
        @media (max-width: 768px) {
            .dashboard {
                padding: 0.5rem;
                grid-template-columns: 1fr;
                gap: 1rem;
            }
            
            .card[style*="grid-column"] {
                grid-column: 1 / -1 !important;
            }
            
            .card {
                padding: 1rem;
                border-radius: 10px;
            }
            
            .header {
                padding: 0.75rem 1rem;
            }
            
            .header h1 {
                font-size: 1.5rem;
            }
            
            .protection-grid {
                grid-template-columns: 1fr;
            }
            
            .protection-item {
                justify-content: center;
                text-align: center;
            }
            
            .event-log {
                max-height: 200px;
                font-size: 0.8rem;
            }
            
            .ip-list {
                max-height: 180px;
            }
            
            .blocked-ip {
                font-size: 0.75rem;
                padding: 0.5rem;
            }
        }
        
        @media (max-width: 480px) {
            .dashboard {
                padding: 0.25rem;
            }
            
            .card {
                padding: 0.75rem;
            }
            
            .header h1 {
                font-size: 1.25rem;
            }
            
            .metric {
                flex-direction: column;
                text-align: center;
                gap: 0.25rem;
            }
            
            .event {
                font-size: 0.75rem;
                padding: 0.5rem;
            }
        }
        
        /* Animations */
        .card {
            animation: fadeInUp 0.6s ease-out;
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .status-indicator {
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Pi Fortress Security Dashboard</h1>
        <p>Real-time security monitoring for internet-exposed Raspberry Pi</p>
    </div>
    
    <div class="dashboard">
        <!-- Top Row: Critical Status -->
        <div class="card" style="grid-column: 1 / -1;">
            <h2>🎯 Security Status</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                <div class="metric">
                    <span>Overall Status:</span>
                    <span class="metric-value" id="overall-status">Loading...</span>
                </div>
                <div class="metric">
                    <span>Threat Level:</span>
                    <span class="metric-value" id="threat-level">Loading...</span>
                </div>
                <div class="metric">
                    <span>Security Score:</span>
                    <span class="metric-value" id="security-score">Loading...</span>
                </div>
                <div style="display: flex; align-items: center; justify-content: center;">
                    <button class="refresh-btn" onclick="refreshDashboard()">🔄 Refresh</button>
                </div>
            </div>
        </div>
        
        <!-- Live Threats -->
        <div class="card">
            <h2>⚡ Live Threats</h2>
            <div id="threat-metrics">
                <div class="metric">
                    <span>Active Attacks (1h):</span>
                    <span class="metric-value" id="active-attacks">0</span>
                </div>
                <div class="metric">
                    <span>Blocked IPs:</span>
                    <span class="metric-value" id="blocked-ips">0</span>
                </div>
                <div class="metric">
                    <span>Suspicious Activity:</span>
                    <span class="metric-value" id="suspicious-activity">0</span>
                </div>
            </div>
        </div>
        
        <!-- Active Protections -->
        <div class="card">
            <h2>🛡️ Active Protections</h2>
            <div class="protection-grid" id="protections">
                Loading protections...
            </div>
        </div>
        
        <!-- Recent Security Events -->
        <div class="card">
            <h2>📋 Recent Events</h2>
            <div class="event-log" id="security-events">
                Loading events...
            </div>
        </div>
        
        <!-- Blocked IPs -->
        <div class="card">
            <h2>🚫 Blocked IPs</h2>
            <div class="ip-list" id="blocked-ip-list">
                Loading blocked IPs...
            </div>
        </div>
        
        <!-- Database Security -->
        <div class="card">
            <h2>🗄️ Database Security</h2>
            <div id="database-security">
                <p>Checking database security...</p>
            </div>
        </div>
    </div>
    
    <script>
        let isRefreshing = false;
        
        function refreshDashboard() {
            if (isRefreshing) return;
            
            isRefreshing = true;
            const refreshBtn = document.querySelector('.refresh-btn');
            const originalText = refreshBtn.innerHTML;
            refreshBtn.innerHTML = '⏳ Loading...';
            refreshBtn.disabled = true;
            
            // Show loading states
            showLoadingStates();
            
            Promise.all([
                fetch('?api=security_status').then(r => {
                    if (!r.ok) throw new Error(`HTTP ${r.status}`);
                    return r.json();
                }),
                fetch('?api=blocked_ips').then(r => {
                    if (!r.ok) throw new Error(`HTTP ${r.status}`);
                    return r.json();
                }),
                fetch('?api=database_security').then(r => {
                    if (!r.ok) throw new Error(`HTTP ${r.status}`);
                    return r.json();
                }),
                fetch('?api=system_threats').then(r => {
                    if (!r.ok) throw new Error(`HTTP ${r.status}`);
                    return r.json();
                })
            ]).then(([securityStatus, blockedData, dbSecurity, threats]) => {
                updateSecurityStatus(securityStatus);
                updateProtections(securityStatus.active_protections);
                updateThreats(threats);
                updateDatabaseSecurity(dbSecurity);
                updateSecurityEvents(blockedData.recent_events || []);
                updateBlockedIPs(blockedData.active_blocks || {});
            }).catch(error => {
                console.error('Dashboard refresh failed:', error);
                showErrorStates(error.message);
            }).finally(() => {
                isRefreshing = false;
                refreshBtn.innerHTML = originalText;
                refreshBtn.disabled = false;
            });
        }
        
        function showLoadingStates() {
            document.getElementById('overall-status').innerHTML = '⏳ Loading...';
            document.getElementById('threat-level').innerHTML = '⏳ Loading...';
            document.getElementById('security-score').innerHTML = '⏳ Loading...';
            document.getElementById('security-events').innerHTML = '<div style="text-align: center; padding: 2rem;">⏳ Loading events...</div>';
            document.getElementById('blocked-ip-list').innerHTML = '<div style="text-align: center; padding: 2rem;">⏳ Loading blocked IPs...</div>';
        }
        
        function showErrorStates(errorMsg) {
            const errorHTML = `<div style="color: #ff3333; text-align: center; padding: 1rem;">❌ Error: ${errorMsg}</div>`;
            document.getElementById('security-events').innerHTML = errorHTML;
            document.getElementById('blocked-ip-list').innerHTML = errorHTML;
        }
        
        function updateSecurityStatus(status) {
            const overallStatus = document.getElementById('overall-status');
            const threatLevel = document.getElementById('threat-level');
            const securityScore = document.getElementById('security-score');
            
            overallStatus.innerHTML = `<span class="status-indicator status-${status.overall_status}"></span>${status.overall_status.toUpperCase()}`;
            threatLevel.innerHTML = `<span class="threat-level-${status.threat_level}">${status.threat_level.toUpperCase()}</span>`;
            securityScore.textContent = `${status.security_score}/100`;
        }
        
        function updateProtections(protections) {
            const container = document.getElementById('protections');
            container.innerHTML = '';
            
            for (const [name, active] of Object.entries(protections)) {
                const item = document.createElement('div');
                item.className = 'protection-item';
                item.innerHTML = `
                    <span class="status-indicator ${active ? 'status-secure' : 'status-critical'}"></span>
                    <span class="${active ? 'protection-active' : 'protection-inactive'}">
                        ${name.replace(/_/g, ' ').toUpperCase()}
                    </span>
                `;
                container.appendChild(item);
            }
        }
        
        function updateThreats(threats) {
            document.getElementById('active-attacks').textContent = threats.active_attacks;
            document.getElementById('blocked-ips').textContent = threats.blocked_ips;
            document.getElementById('suspicious-activity').textContent = threats.suspicious_activity;
        }
        
        function updateDatabaseSecurity(dbSecurity) {
            const container = document.getElementById('database-security');
            const statusIcon = dbSecurity.status === 'secure' ? '✅' : 
                               dbSecurity.status === 'warning' ? '⚠️' : '❌';
            
            let html = `<p>${statusIcon} Status: ${dbSecurity.status.toUpperCase()}</p>`;
            
            if (dbSecurity.issues.length > 0) {
                html += '<ul>';
                dbSecurity.issues.forEach(issue => {
                    html += `<li style="color: #ff3333;">${issue}</li>`;
                });
                html += '</ul>';
            }
            
            container.innerHTML = html;
        }
        
        function updateSecurityEvents(events) {
            const container = document.getElementById('security-events');
            container.innerHTML = '';
            
            events.slice(-20).reverse().forEach(event => {
                const eventDiv = document.createElement('div');
                eventDiv.className = `event ${event.type.toLowerCase()}`;
                eventDiv.innerHTML = `
                    <strong>${event.type}</strong> - ${event.timestamp}<br>
                    IP: ${event.ip} | ${event.message}
                `;
                container.appendChild(eventDiv);
            });
        }
        
        function updateBlockedIPs(blockedIPs) {
            const container = document.getElementById('blocked-ip-list');
            container.innerHTML = '';
            
            if (Object.keys(blockedIPs).length === 0) {
                container.innerHTML = '<p>No IPs currently blocked</p>';
                return;
            }
            
            for (const [ip, info] of Object.entries(blockedIPs)) {
                const blockedDiv = document.createElement('div');
                blockedDiv.className = 'blocked-ip';
                const timeLeft = Math.max(0, info.until - Math.floor(Date.now() / 1000));
                blockedDiv.innerHTML = `
                    <strong>${ip}</strong><br>
                    Reason: ${info.reason}<br>
                    Expires in: ${Math.floor(timeLeft / 60)}m ${timeLeft % 60}s
                `;
                container.appendChild(blockedDiv);
            }
        }
        
        // Auto-refresh every 30 seconds
        setInterval(refreshDashboard, 30000);
        
        // Initial load
        refreshDashboard();
    </script>
</body>
</html>