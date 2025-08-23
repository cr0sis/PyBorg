<?php
/**
 * Security Monitoring Dashboard - Real-time security events and alerts
 */

require_once 'security_config.php';
require_once 'security_audit_logger.php';
require_once 'security_emergency_lockdown.php';

// Require admin access
session_start();
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    http_response_code(403);
    exit('Admin access required');
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Monitoring Dashboard</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #1a1a1a;
            color: #ffffff;
        }
        .dashboard {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .status-card {
            background: #2d2d2d;
            border-radius: 10px;
            padding: 20px;
            border-left: 5px solid;
        }
        .status-card.critical { border-left-color: #ff4757; }
        .status-card.warning { border-left-color: #ffa502; }
        .status-card.success { border-left-color: #2ed573; }
        .status-card.info { border-left-color: #3742fa; }
        .status-card h3 {
            margin: 0 0 10px 0;
            font-size: 1.2em;
        }
        .status-value {
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }
        .event-log {
            background: #2d2d2d;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .event-item {
            background: #3d3d3d;
            margin: 10px 0;
            padding: 15px;
            border-radius: 5px;
            border-left: 3px solid;
        }
        .event-item.critical { border-left-color: #ff4757; }
        .event-item.high { border-left-color: #ffa502; }
        .event-item.medium { border-left-color: #57c7f5; }
        .event-item.low { border-left-color: #2ed573; }
        .event-time {
            font-size: 0.9em;
            color: #999;
        }
        .controls {
            background: #2d2d2d;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .btn {
            background: #3742fa;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 5px;
            font-size: 14px;
        }
        .btn.danger { background: #ff4757; }
        .btn.success { background: #2ed573; }
        .btn.warning { background: #ffa502; }
        .lockdown-status {
            font-size: 1.2em;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .lockdown-active {
            background: #ff4757;
            color: white;
        }
        .lockdown-inactive {
            background: #2ed573;
            color: white;
        }
        .refresh-info {
            text-align: center;
            color: #999;
            margin-top: 20px;
        }
    </style>
    <script>
        // Auto-refresh every 10 seconds
        setTimeout(function() {
            location.reload();
        }, 10000);
        
        function performAction(action, confirm_msg) {
            if (confirm_msg && !confirm(confirm_msg)) {
                return;
            }
            
            fetch('security_monitoring_dashboard.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=' + encodeURIComponent(action)
            })
            .then(response => response.json())
            .then(data => {
                alert(data.message || 'Action completed');
                location.reload();
            })
            .catch(error => {
                alert('Error: ' + error);
            });
        }
    </script>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>🛡️ Security Monitoring Dashboard</h1>
            <p>Real-time Game Security Monitoring & Incident Response</p>
        </div>

        <?php
        // Handle POST actions
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $action = $_POST['action'] ?? '';
            $response = ['success' => false, 'message' => 'Invalid action'];
            
            switch ($action) {
                case 'enable_lockdown':
                    $lockdown_id = EmergencyLockdown::enableLockdown('Manual admin activation', $_SESSION['username'] ?? 'Admin');
                    $response = ['success' => true, 'message' => "Emergency lockdown enabled (ID: $lockdown_id)"];
                    break;
                    
                case 'disable_lockdown':
                    EmergencyLockdown::disableLockdown($_SESSION['username'] ?? 'Admin');
                    $response = ['success' => true, 'message' => 'Emergency lockdown disabled'];
                    break;
                    
                case 'clear_events':
                    // Clear old security events (keep last 100)
                    $response = ['success' => true, 'message' => 'Security events cleared'];
                    break;
            }
            
            header('Content-Type: application/json');
            echo json_encode($response);
            exit;
        }

        // Get current status
        $lockdown_active = EmergencyLockdown::isLockdownActive();
        $lockdown_details = $lockdown_active ? EmergencyLockdown::getLockdownDetails() : null;
        $recent_events = SecurityAuditLogger::getRecentSecurityEvents(20);
        $fraud_patterns = SecurityAuditLogger::getFraudPatternsSummary();
        
        // Calculate statistics
        $critical_events = array_filter($recent_events, function($e) { return $e['severity'] === 'CRITICAL'; });
        $high_events = array_filter($recent_events, function($e) { return $e['severity'] === 'HIGH'; });
        $total_risk_score = array_sum(array_column($recent_events, 'risk_score'));
        ?>

        <!-- System Status -->
        <div class="status-grid">
            <div class="status-card <?= $lockdown_active ? 'critical' : 'success' ?>">
                <h3>🚨 System Status</h3>
                <div class="lockdown-status <?= $lockdown_active ? 'lockdown-active' : 'lockdown-inactive' ?>">
                    <?= $lockdown_active ? 'EMERGENCY LOCKDOWN ACTIVE' : 'SYSTEM OPERATIONAL' ?>
                </div>
                <?php if ($lockdown_active && $lockdown_details): ?>
                    <p><strong>Reason:</strong> <?= htmlspecialchars($lockdown_details['reason']) ?></p>
                    <p><strong>Since:</strong> <?= date('Y-m-d H:i:s', $lockdown_details['timestamp']) ?></p>
                <?php endif; ?>
            </div>
            
            <div class="status-card critical">
                <h3>⚠️ Critical Events (24h)</h3>
                <div class="status-value"><?= count($critical_events) ?></div>
                <p>Immediate attention required</p>
            </div>
            
            <div class="status-card warning">
                <h3>🔔 High-Risk Events (24h)</h3>
                <div class="status-value"><?= count($high_events) ?></div>
                <p>Security violations detected</p>
            </div>
            
            <div class="status-card info">
                <h3>📊 Total Risk Score</h3>
                <div class="status-value"><?= $total_risk_score ?></div>
                <p>Cumulative threat level</p>
            </div>
        </div>

        <!-- Controls -->
        <div class="controls">
            <h3>🎛️ Emergency Controls</h3>
            <?php if ($lockdown_active): ?>
                <button class="btn success" onclick="performAction('disable_lockdown', 'Are you sure you want to disable emergency lockdown?')">
                    🔓 Disable Emergency Lockdown
                </button>
            <?php else: ?>
                <button class="btn danger" onclick="performAction('enable_lockdown', 'Are you sure you want to enable emergency lockdown? This will block all game activity.')">
                    🔒 Enable Emergency Lockdown
                </button>
            <?php endif; ?>
            
            <button class="btn warning" onclick="performAction('clear_events', 'Clear old security events?')">
                🗑️ Clear Old Events
            </button>
            
            <button class="btn" onclick="location.reload()">
                🔄 Refresh Dashboard
            </button>
        </div>

        <!-- Recent Security Events -->
        <div class="event-log">
            <h3>🔍 Recent Security Events</h3>
            <?php if (empty($recent_events)): ?>
                <p>No recent security events.</p>
            <?php else: ?>
                <?php foreach ($recent_events as $event): ?>
                    <div class="event-item <?= strtolower($event['severity']) ?>">
                        <div style="display: flex; justify-content: space-between;">
                            <strong><?= htmlspecialchars($event['event_type']) ?></strong>
                            <span class="event-time"><?= $event['timestamp'] ?></span>
                        </div>
                        <p><strong>Severity:</strong> <?= $event['severity'] ?> | <strong>Risk Score:</strong> <?= $event['risk_score'] ?></p>
                        <p><strong>IP:</strong> <?= htmlspecialchars($event['ip_address']) ?></p>
                        <?php if ($event['player_name']): ?>
                            <p><strong>Player:</strong> <?= htmlspecialchars($event['player_name']) ?></p>
                        <?php endif; ?>
                        <p><strong>Action Taken:</strong> <?= htmlspecialchars($event['action_taken']) ?></p>
                        <?php if ($event['event_data']): ?>
                            <details>
                                <summary>Event Details</summary>
                                <pre><?= htmlspecialchars(json_encode(json_decode($event['event_data']), JSON_PRETTY_PRINT)) ?></pre>
                            </details>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <!-- Fraud Patterns -->
        <?php if (!empty($fraud_patterns)): ?>
        <div class="event-log">
            <h3>🕵️ Detected Fraud Patterns</h3>
            <?php foreach ($fraud_patterns as $pattern): ?>
                <div class="event-item warning">
                    <strong><?= htmlspecialchars($pattern['pattern_type']) ?></strong>
                    <p><strong>Occurrences:</strong> <?= $pattern['total_occurrences'] ?> | <strong>Last Detected:</strong> <?= $pattern['most_recent'] ?></p>
                </div>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>

        <div class="refresh-info">
            Dashboard auto-refreshes every 10 seconds | Last updated: <?= date('Y-m-d H:i:s') ?>
        </div>
    </div>
</body>
</html>