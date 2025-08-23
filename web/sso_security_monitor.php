<?php
/**
 * SSO Security Monitoring Dashboard
 * Real-time monitoring of SSO security events and threats
 * 
 * Security: Admin-only access with comprehensive event analysis
 */

require_once 'security_config.php';
require_once 'sso/SSOManager.php';

// Initialize security and require admin
initSecureSession();
setSecurityHeaders();
requireAdmin();

// Get security statistics and events
$pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Recent security events (last 24 hours)
$stmt = $pdo->prepare("
    SELECT * FROM sso_security_events 
    WHERE timestamp > datetime('now', '-24 hours')
    ORDER BY timestamp DESC
    LIMIT 100
");
$stmt->execute();
$recent_events = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Security metrics
$security_stats = [];

// Event count by severity (last 24h)
$stmt = $pdo->prepare("
    SELECT severity, COUNT(*) as count 
    FROM sso_security_events 
    WHERE timestamp > datetime('now', '-24 hours')
    GROUP BY severity
");
$stmt->execute();
$severity_counts = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);

// Event count by type (last 24h)
$stmt = $pdo->prepare("
    SELECT event_type, COUNT(*) as count 
    FROM sso_security_events 
    WHERE timestamp > datetime('now', '-24 hours')
    GROUP BY event_type
    ORDER BY count DESC
    LIMIT 10
");
$stmt->execute();
$event_type_counts = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);

// Failed authentication attempts
$stmt = $pdo->prepare("
    SELECT COUNT(*) FROM sso_security_events 
    WHERE event_type IN ('AUTH_FAILURE', 'SAML_ACS_ERROR', 'OIDC_CALLBACK_ERROR', 'SSO_2FA_FAILED')
    AND timestamp > datetime('now', '-24 hours')
");
$stmt->execute();
$failed_auth_count = $stmt->fetchColumn();

// Successful authentications
$stmt = $pdo->prepare("
    SELECT COUNT(*) FROM sso_security_events 
    WHERE event_type IN ('AUTH_SUCCESS', 'SAML_LOGIN_SUCCESS', 'OIDC_LOGIN_SUCCESS', 'SSO_2FA_SUCCESS')
    AND timestamp > datetime('now', '-24 hours')
");
$stmt->execute();
$success_auth_count = $stmt->fetchColumn();

// Active SSO sessions
$stmt = $pdo->prepare("
    SELECT COUNT(*) FROM sso_auth_sessions 
    WHERE status = 'pending' AND expires_at > ?
");
$stmt->execute([time()]);
$active_sessions = $stmt->fetchColumn();

// Top IP addresses by event count (potential threats)
$stmt = $pdo->prepare("
    SELECT ip_address, COUNT(*) as event_count,
           SUM(CASE WHEN severity IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) as high_severity_count
    FROM sso_security_events 
    WHERE timestamp > datetime('now', '-24 hours')
    AND ip_address != 'unknown'
    GROUP BY ip_address
    ORDER BY high_severity_count DESC, event_count DESC
    LIMIT 20
");
$stmt->execute();
$suspicious_ips = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Provider usage statistics
$stmt = $pdo->prepare("
    SELECT p.display_name, p.type,
           COUNT(e.id) as event_count,
           MAX(e.timestamp) as last_used
    FROM sso_providers p
    LEFT JOIN sso_security_events e ON p.id = e.provider_id 
    WHERE p.is_active = 1
    GROUP BY p.id
    ORDER BY event_count DESC
");
$stmt->execute();
$provider_stats = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSO Security Monitor - cr0bot</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: #0f1419;
            color: #e6edf3;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
        }
        
        .navbar {
            background: linear-gradient(135deg, #1f2937 0%, #111827 100%) !important;
            border-bottom: 1px solid #374151;
        }
        
        .card {
            background: #1f2937;
            border: 1px solid #374151;
            border-radius: 12px;
        }
        
        .card-header {
            background: linear-gradient(135deg, #374151 0%, #1f2937 100%);
            border-bottom: 1px solid #4b5563;
            border-radius: 12px 12px 0 0 !important;
        }
        
        .metric-card {
            background: linear-gradient(135deg, #1e40af 0%, #1d4ed8 100%);
            color: white;
            text-align: center;
            padding: 1.5rem;
            border-radius: 12px;
            margin-bottom: 1rem;
        }
        
        .metric-value {
            font-size: 2.5rem;
            font-weight: bold;
            line-height: 1;
        }
        
        .metric-label {
            font-size: 0.9rem;
            opacity: 0.9;
            margin-top: 0.5rem;
        }
        
        .alert-card {
            background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%);
        }
        
        .warning-card {
            background: linear-gradient(135deg, #d97706 0%, #b45309 100%);
        }
        
        .success-card {
            background: linear-gradient(135deg, #059669 0%, #047857 100%);
        }
        
        .table-dark {
            background: #111827;
        }
        
        .table-dark td, .table-dark th {
            border-color: #374151;
        }
        
        .event-row {
            cursor: pointer;
            transition: background-color 0.2s;
        }
        
        .event-row:hover {
            background-color: #374151 !important;
        }
        
        .severity-critical { color: #dc2626; }
        .severity-high { color: #ea580c; }
        .severity-medium { color: #ca8a04; }
        .severity-low { color: #65a30d; }
        
        .refresh-indicator {
            position: fixed;
            top: 20px;
            right: 20px;
            background: #1f2937;
            border: 1px solid #374151;
            border-radius: 8px;
            padding: 0.5rem 1rem;
            font-size: 0.875rem;
            z-index: 1000;
        }
        
        .chart-container {
            height: 300px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #111827;
            border-radius: 8px;
            margin: 1rem 0;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .pulse { animation: pulse 2s infinite; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark">
        <div class="container-fluid">
            <span class="navbar-brand mb-0 h1">
                <i class="fas fa-shield-alt me-2"></i>
                SSO Security Monitor
            </span>
            <div class="d-flex">
                <button class="btn btn-outline-light btn-sm me-2" onclick="refreshData()" id="refresh-btn">
                    <i class="fas fa-sync-alt"></i> Refresh
                </button>
                <a href="/admin_sso.php" class="btn btn-outline-light btn-sm">
                    <i class="fas fa-cog"></i> SSO Admin
                </a>
            </div>
        </div>
    </nav>

    <div class="refresh-indicator" id="refresh-indicator" style="display: none;">
        <i class="fas fa-sync-alt fa-spin"></i> Refreshing...
    </div>

    <div class="container-fluid mt-4">
        <!-- Security Metrics Row -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="metric-card success-card">
                    <div class="metric-value"><?= $success_auth_count ?></div>
                    <div class="metric-label">Successful Logins (24h)</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card alert-card">
                    <div class="metric-value"><?= $failed_auth_count ?></div>
                    <div class="metric-label">Failed Attempts (24h)</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card warning-card">
                    <div class="metric-value"><?= $active_sessions ?></div>
                    <div class="metric-label">Active Sessions</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="metric-card <?= ($severity_counts['CRITICAL'] ?? 0) > 0 ? 'alert-card' : (($severity_counts['HIGH'] ?? 0) > 0 ? 'warning-card' : 'success-card') ?>">
                    <div class="metric-value"><?= array_sum($severity_counts) ?></div>
                    <div class="metric-label">Total Events (24h)</div>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- Recent Security Events -->
            <div class="col-lg-8 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-history me-2"></i>
                            Recent Security Events
                            <span class="badge bg-secondary ms-2"><?= count($recent_events) ?> events</span>
                        </h5>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-dark table-hover mb-0">
                                <thead>
                                    <tr>
                                        <th style="width: 120px;">Time</th>
                                        <th style="width: 100px;">Severity</th>
                                        <th style="width: 150px;">Event Type</th>
                                        <th>Message</th>
                                        <th style="width: 120px;">IP Address</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($recent_events)): ?>
                                        <tr>
                                            <td colspan="5" class="text-center py-4 text-muted">
                                                <i class="fas fa-info-circle me-2"></i>
                                                No security events in the last 24 hours
                                            </td>
                                        </tr>
                                    <?php else: ?>
                                        <?php foreach ($recent_events as $event): ?>
                                            <tr class="event-row" onclick="showEventDetails(<?= htmlspecialchars(json_encode($event)) ?>)">
                                                <td class="small">
                                                    <?= date('H:i:s', strtotime($event['timestamp'])) ?>
                                                    <br>
                                                    <span class="text-muted"><?= date('M j', strtotime($event['timestamp'])) ?></span>
                                                </td>
                                                <td>
                                                    <span class="badge bg-<?= 
                                                        $event['severity'] === 'CRITICAL' ? 'danger' : (
                                                        $event['severity'] === 'HIGH' ? 'warning' : (
                                                        $event['severity'] === 'MEDIUM' ? 'info' : 'secondary'
                                                    )) ?>"><?= $event['severity'] ?></span>
                                                </td>
                                                <td class="small">
                                                    <code><?= htmlspecialchars($event['event_type']) ?></code>
                                                </td>
                                                <td class="small">
                                                    <?= htmlspecialchars(substr($event['message'], 0, 80)) ?>
                                                    <?= strlen($event['message']) > 80 ? '...' : '' ?>
                                                </td>
                                                <td class="small">
                                                    <code><?= htmlspecialchars($event['ip_address']) ?></code>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Security Analytics -->
            <div class="col-lg-4 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-chart-pie me-2"></i>
                            Event Analysis
                        </h5>
                    </div>
                    <div class="card-body">
                        <h6>Event Types (24h)</h6>
                        <?php if (empty($event_type_counts)): ?>
                            <p class="text-muted small">No events to analyze</p>
                        <?php else: ?>
                            <?php foreach ($event_type_counts as $type => $count): ?>
                                <div class="d-flex justify-content-between align-items-center mb-2">
                                    <code class="small"><?= htmlspecialchars($type) ?></code>
                                    <span class="badge bg-secondary"><?= $count ?></span>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>

                        <hr class="my-3">

                        <h6>Severity Distribution</h6>
                        <?php if (empty($severity_counts)): ?>
                            <p class="text-muted small">No events to analyze</p>
                        <?php else: ?>
                            <?php foreach (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as $severity): ?>
                                <?php if (isset($severity_counts[$severity])): ?>
                                    <div class="d-flex justify-content-between align-items-center mb-2">
                                        <span class="severity-<?= strtolower($severity) ?>"><?= $severity ?></span>
                                        <span class="badge bg-<?= 
                                            $severity === 'CRITICAL' ? 'danger' : (
                                            $severity === 'HIGH' ? 'warning' : (
                                            $severity === 'MEDIUM' ? 'info' : 'secondary'
                                        )) ?>"><?= $severity_counts[$severity] ?></span>
                                    </div>
                                <?php endif; ?>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

        <!-- Additional Analytics Row -->
        <div class="row">
            <!-- Suspicious IP Addresses -->
            <div class="col-lg-6 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            Suspicious IP Addresses
                        </h5>
                    </div>
                    <div class="card-body">
                        <?php if (empty($suspicious_ips)): ?>
                            <p class="text-muted">No suspicious activity detected</p>
                        <?php else: ?>
                            <div class="table-responsive">
                                <table class="table table-sm table-dark">
                                    <thead>
                                        <tr>
                                            <th>IP Address</th>
                                            <th>Events</th>
                                            <th>High/Critical</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach (array_slice($suspicious_ips, 0, 10) as $ip_data): ?>
                                            <tr class="<?= $ip_data['high_severity_count'] > 0 ? 'table-danger' : '' ?>">
                                                <td><code><?= htmlspecialchars($ip_data['ip_address']) ?></code></td>
                                                <td><?= $ip_data['event_count'] ?></td>
                                                <td><?= $ip_data['high_severity_count'] ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Provider Usage Stats -->
            <div class="col-lg-6 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">
                            <i class="fas fa-plug me-2"></i>
                            Provider Usage
                        </h5>
                    </div>
                    <div class="card-body">
                        <?php if (empty($provider_stats)): ?>
                            <p class="text-muted">No SSO providers configured</p>
                        <?php else: ?>
                            <?php foreach ($provider_stats as $provider): ?>
                                <div class="d-flex justify-content-between align-items-center mb-3">
                                    <div>
                                        <strong><?= htmlspecialchars($provider['display_name']) ?></strong>
                                        <br>
                                        <small class="text-muted">
                                            <?= strtoupper($provider['type']) ?>
                                            <?= $provider['last_used'] ? '• Last used: ' . date('M j, H:i', strtotime($provider['last_used'])) : '• Never used' ?>
                                        </small>
                                    </div>
                                    <span class="badge bg-secondary"><?= $provider['event_count'] ?> events</span>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Event Details Modal -->
    <div class="modal fade" id="eventModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content bg-dark text-light">
                <div class="modal-header border-secondary">
                    <h5 class="modal-title">Security Event Details</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" id="eventDetails">
                    <!-- Event details will be loaded here -->
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    <script>
        function showEventDetails(event) {
            const modal = new bootstrap.Modal(document.getElementById('eventModal'));
            const detailsDiv = document.getElementById('eventDetails');
            
            let detailsJson = '';
            try {
                const details = JSON.parse(event.details_json || '{}');
                detailsJson = Object.keys(details).length > 0 ? JSON.stringify(details, null, 2) : 'No additional details';
            } catch (e) {
                detailsJson = 'Invalid details format';
            }
            
            detailsDiv.innerHTML = `
                <div class="row">
                    <div class="col-md-6">
                        <strong>Event Type:</strong><br>
                        <code>${escapeHtml(event.event_type)}</code>
                    </div>
                    <div class="col-md-6">
                        <strong>Severity:</strong><br>
                        <span class="badge bg-${getSeverityColor(event.severity)}">${event.severity}</span>
                    </div>
                </div>
                <hr>
                <div class="row">
                    <div class="col-md-6">
                        <strong>Timestamp:</strong><br>
                        ${new Date(event.timestamp).toLocaleString()}
                    </div>
                    <div class="col-md-6">
                        <strong>IP Address:</strong><br>
                        <code>${escapeHtml(event.ip_address)}</code>
                    </div>
                </div>
                <hr>
                <div class="row">
                    <div class="col-12">
                        <strong>Message:</strong><br>
                        <div class="bg-secondary p-2 rounded mt-1">${escapeHtml(event.message)}</div>
                    </div>
                </div>
                ${event.user_agent ? `
                <hr>
                <div class="row">
                    <div class="col-12">
                        <strong>User Agent:</strong><br>
                        <code class="small">${escapeHtml(event.user_agent)}</code>
                    </div>
                </div>
                ` : ''}
                <hr>
                <div class="row">
                    <div class="col-12">
                        <strong>Additional Details:</strong><br>
                        <pre class="bg-secondary p-2 rounded mt-1 small">${escapeHtml(detailsJson)}</pre>
                    </div>
                </div>
            `;
            
            modal.show();
        }
        
        function getSeverityColor(severity) {
            switch (severity) {
                case 'CRITICAL': return 'danger';
                case 'HIGH': return 'warning';
                case 'MEDIUM': return 'info';
                case 'LOW': return 'secondary';
                default: return 'secondary';
            }
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        async function refreshData() {
            const indicator = document.getElementById('refresh-indicator');
            const refreshBtn = document.getElementById('refresh-btn');
            
            indicator.style.display = 'block';
            refreshBtn.disabled = true;
            refreshBtn.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i> Refreshing...';
            
            try {
                // Simply reload the page for now - in production you'd use AJAX
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
                
            } catch (error) {
                console.error('Refresh failed:', error);
                indicator.style.display = 'none';
                refreshBtn.disabled = false;
                refreshBtn.innerHTML = '<i class="fas fa-sync-alt"></i> Refresh';
            }
        }
        
        // Auto-refresh every 30 seconds
        setInterval(() => {
            if (!document.getElementById('eventModal').classList.contains('show')) {
                refreshData();
            }
        }, 30000);
        
        // Add pulse effect to critical events
        document.addEventListener('DOMContentLoaded', function() {
            const criticalEvents = document.querySelectorAll('.table-danger');
            criticalEvents.forEach(row => {
                row.classList.add('pulse');
            });
        });
    </script>
</body>
</html>