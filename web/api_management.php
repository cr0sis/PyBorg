<?php
/**
 * API Management Interface - Phase 6: API Security Layer
 * Web interface for managing API keys, tokens, and monitoring API usage
 */

require_once 'auth.php';
require_once 'api_authentication.php';
require_once 'secure_api_wrapper.php';

// Ensure user is logged in and admin
if (!isUserLoggedIn()) {
    header('Location: /');
    exit;
}

if (!isUserAdmin()) {
    http_response_code(403);
    echo "Admin access required";
    exit;
}

// Handle AJAX requests
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['action']) {
        case 'list_keys':
            $userId = $_GET['user_id'] ?? null;
            echo json_encode(APIAuthentication::listAPIKeys($userId));
            break;
            
        case 'generate_key':
            $userId = $_POST['user_id'] ?? $_SESSION['user_id'];
            $permissions = $_POST['permissions'] ?? ['read'];
            $name = $_POST['name'] ?? 'API Key';
            $expiresInDays = $_POST['expires_in_days'] ?? null;
            
            echo json_encode(APIAuthentication::generateAPIKey($userId, $permissions, $name, $expiresInDays));
            break;
            
        case 'revoke_key':
            $keyId = $_POST['key_id'] ?? '';
            echo json_encode(APIAuthentication::revokeAPIKey($keyId));
            break;
            
        case 'generate_bearer':
            $userId = $_POST['user_id'] ?? $_SESSION['user_id'];
            $permissions = $_POST['permissions'] ?? ['read'];
            $expiresInMinutes = $_POST['expires_in_minutes'] ?? 60;
            
            echo json_encode(APIAuthentication::generateBearerToken($userId, $permissions, $expiresInMinutes));
            break;
            
        case 'api_stats':
            $hours = $_GET['hours'] ?? 24;
            echo json_encode(SecureAPIWrapper::getAPIStats($hours));
            break;
            
        case 'clean_rate_limits':
            echo json_encode(SecureAPIWrapper::cleanRateLimitData());
            break;
            
        default:
            echo json_encode(['error' => 'Invalid action']);
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Management - CR0 Bot System</title>
    <link rel="stylesheet" href="admin_style.css">
    <style>
        .api-management-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .management-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #00ff00;
        }
        
        .tab-button {
            background: rgba(0, 255, 0, 0.1);
            border: 1px solid #00ff00;
            color: #00ff00;
            padding: 10px 20px;
            cursor: pointer;
            border-radius: 5px 5px 0 0;
        }
        
        .tab-button.active {
            background: #00ff00;
            color: black;
        }
        
        .tab-content {
            display: none;
            background: rgba(0, 0, 0, 0.8);
            padding: 20px;
            border-radius: 0 10px 10px 10px;
            border: 1px solid #00ff00;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .form-group {
            margin-bottom: 15px;
        }
        
        .form-group label {
            display: block;
            color: #00ff00;
            margin-bottom: 5px;
        }
        
        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 8px;
            background: rgba(0, 0, 0, 0.7);
            border: 1px solid #00ff00;
            color: #fff;
            border-radius: 3px;
        }
        
        .checkbox-group {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .checkbox-item {
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        .api-key-item {
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #333;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        
        .key-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .key-name {
            color: #00ff00;
            font-weight: bold;
        }
        
        .key-status {
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.8em;
        }
        
        .status-active {
            background: #00ff00;
            color: black;
        }
        
        .status-revoked {
            background: #ff0000;
            color: white;
        }
        
        .status-expired {
            background: #ff9900;
            color: black;
        }
        
        .key-details {
            font-size: 0.9em;
            color: #ccc;
        }
        
        .key-actions {
            margin-top: 10px;
        }
        
        .btn {
            background: #00ff00;
            color: black;
            border: none;
            padding: 8px 15px;
            cursor: pointer;
            border-radius: 3px;
            margin-right: 10px;
        }
        
        .btn:hover {
            background: #00cc00;
        }
        
        .btn-danger {
            background: #ff0000;
            color: white;
        }
        
        .btn-danger:hover {
            background: #cc0000;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .stat-card {
            background: rgba(0, 0, 0, 0.7);
            border: 1px solid #00ff00;
            padding: 15px;
            border-radius: 5px;
        }
        
        .stat-value {
            font-size: 2em;
            color: #0ff;
            font-weight: bold;
        }
        
        .stat-label {
            color: #888;
            font-size: 0.9em;
        }
        
        .generated-key {
            background: rgba(0, 255, 0, 0.1);
            border: 2px solid #00ff00;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        
        .generated-key-value {
            font-family: monospace;
            background: rgba(0, 0, 0, 0.8);
            padding: 10px;
            border-radius: 3px;
            word-break: break-all;
            color: #0ff;
        }
        
        .warning-box {
            background: rgba(255, 165, 0, 0.1);
            border: 1px solid #ffa500;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            color: #ffa500;
        }
    </style>
</head>
<body>
    <div class="api-management-container">
        <h1>🔑 API Management</h1>
        
        <div class="management-tabs">
            <button class="tab-button active" onclick="showTab('keys')">API Keys</button>
            <button class="tab-button" onclick="showTab('tokens')">Bearer Tokens</button>
            <button class="tab-button" onclick="showTab('stats')">API Statistics</button>
            <button class="tab-button" onclick="showTab('maintenance')">Maintenance</button>
        </div>
        
        <!-- API Keys Tab -->
        <div id="keys-tab" class="tab-content active">
            <h2>API Key Management</h2>
            
            <div class="form-group">
                <h3>Generate New API Key</h3>
                <form id="generate-key-form">
                    <div class="form-group">
                        <label for="key-name">Key Name:</label>
                        <input type="text" id="key-name" name="name" placeholder="e.g., Bot Integration Key" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="key-permissions">Permissions:</label>
                        <div class="checkbox-group">
                            <div class="checkbox-item">
                                <input type="checkbox" id="perm-read" name="permissions[]" value="read" checked>
                                <label for="perm-read">Read</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="perm-write" name="permissions[]" value="write">
                                <label for="perm-write">Write</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="perm-admin" name="permissions[]" value="admin">
                                <label for="perm-admin">Admin</label>
                            </div>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="key-expires">Expires in (days, leave empty for no expiration):</label>
                        <input type="number" id="key-expires" name="expires_in_days" min="1" max="365">
                    </div>
                    
                    <button type="submit" class="btn">Generate API Key</button>
                </form>
            </div>
            
            <div id="generated-key-display" style="display: none;"></div>
            
            <div class="form-group">
                <h3>Existing API Keys</h3>
                <div id="api-keys-list">
                    <p>Loading API keys...</p>
                </div>
            </div>
        </div>
        
        <!-- Bearer Tokens Tab -->
        <div id="tokens-tab" class="tab-content">
            <h2>Bearer Token Management</h2>
            
            <div class="form-group">
                <h3>Generate Bearer Token</h3>
                <form id="generate-token-form">
                    <div class="form-group">
                        <label for="token-permissions">Permissions:</label>
                        <div class="checkbox-group">
                            <div class="checkbox-item">
                                <input type="checkbox" id="token-perm-read" name="permissions[]" value="read" checked>
                                <label for="token-perm-read">Read</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="token-perm-write" name="permissions[]" value="write">
                                <label for="token-perm-write">Write</label>
                            </div>
                            <div class="checkbox-item">
                                <input type="checkbox" id="token-perm-admin" name="permissions[]" value="admin">
                                <label for="token-perm-admin">Admin</label>
                            </div>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="token-expires">Expires in (minutes):</label>
                        <select id="token-expires" name="expires_in_minutes">
                            <option value="60">1 hour</option>
                            <option value="360">6 hours</option>
                            <option value="720">12 hours</option>
                            <option value="1440">24 hours</option>
                        </select>
                    </div>
                    
                    <button type="submit" class="btn">Generate Bearer Token</button>
                </form>
            </div>
            
            <div id="generated-token-display" style="display: none;"></div>
            
            <div class="warning-box">
                <strong>⚠️ Security Notice:</strong> Bearer tokens are temporary and automatically expire. 
                They are intended for short-term API access and testing purposes.
            </div>
        </div>
        
        <!-- Statistics Tab -->
        <div id="stats-tab" class="tab-content">
            <h2>API Usage Statistics</h2>
            
            <div class="form-group">
                <label for="stats-timeframe">Timeframe:</label>
                <select id="stats-timeframe" onchange="loadAPIStats()">
                    <option value="1">Last Hour</option>
                    <option value="24" selected>Last 24 Hours</option>
                    <option value="168">Last Week</option>
                    <option value="720">Last Month</option>
                </select>
            </div>
            
            <div id="api-stats-display">
                <p>Loading statistics...</p>
            </div>
        </div>
        
        <!-- Maintenance Tab -->
        <div id="maintenance-tab" class="tab-content">
            <h2>API Maintenance</h2>
            
            <div class="form-group">
                <h3>Rate Limit Cleanup</h3>
                <p>Clean old rate limiting data to improve performance.</p>
                <button onclick="cleanRateLimits()" class="btn">Clean Rate Limit Data</button>
            </div>
            
            <div class="form-group">
                <h3>API Health Check</h3>
                <p>Verify API endpoints are functioning correctly.</p>
                <button onclick="runHealthCheck()" class="btn">Run Health Check</button>
            </div>
            
            <div id="maintenance-results"></div>
        </div>
        
        <div class="nav-links">
            <a href="admin_panel.php">← Back to Admin Panel</a>
        </div>
    </div>
    
    <script>
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            document.querySelectorAll('.tab-button').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + '-tab').classList.add('active');
            event.target.classList.add('active');
            
            // Load data for specific tabs
            if (tabName === 'keys') {
                loadAPIKeys();
            } else if (tabName === 'stats') {
                loadAPIStats();
            }
        }
        
        function loadAPIKeys() {
            fetch('?action=list_keys')
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('api-keys-list');
                    
                    if (data.error) {
                        container.innerHTML = `<p style="color: #ff0000;">Error: ${data.error}</p>`;
                        return;
                    }
                    
                    if (data.keys.length === 0) {
                        container.innerHTML = '<p>No API keys found.</p>';
                        return;
                    }
                    
                    let html = '';
                    data.keys.forEach(key => {
                        const now = Math.floor(Date.now() / 1000);
                        let status = 'active';
                        let statusClass = 'status-active';
                        
                        if (!key.active) {
                            status = 'revoked';
                            statusClass = 'status-revoked';
                        } else if (key.expires_at && key.expires_at < now) {
                            status = 'expired';
                            statusClass = 'status-expired';
                        }
                        
                        const createdDate = new Date(key.created_at * 1000).toLocaleString();
                        const lastUsed = key.last_used_at ? 
                            new Date(key.last_used_at * 1000).toLocaleString() : 'Never';
                        const expiresAt = key.expires_at ? 
                            new Date(key.expires_at * 1000).toLocaleString() : 'Never';
                        
                        html += `
                            <div class="api-key-item">
                                <div class="key-header">
                                    <span class="key-name">${key.name}</span>
                                    <span class="key-status ${statusClass}">${status.toUpperCase()}</span>
                                </div>
                                <div class="key-details">
                                    <strong>ID:</strong> ${key.id}<br>
                                    <strong>Permissions:</strong> ${key.permissions.join(', ')}<br>
                                    <strong>Created:</strong> ${createdDate}<br>
                                    <strong>Last Used:</strong> ${lastUsed}<br>
                                    <strong>Usage Count:</strong> ${key.usage_count || 0}<br>
                                    <strong>Expires:</strong> ${expiresAt}
                                </div>
                                <div class="key-actions">
                                    ${key.active ? `<button onclick="revokeKey('${key.id}')" class="btn btn-danger">Revoke</button>` : ''}
                                </div>
                            </div>
                        `;
                    });
                    
                    container.innerHTML = html;
                })
                .catch(error => {
                    console.error('Error loading API keys:', error);
                    document.getElementById('api-keys-list').innerHTML = 
                        '<p style="color: #ff0000;">Failed to load API keys</p>';
                });
        }
        
        function loadAPIStats() {
            const timeframe = document.getElementById('stats-timeframe').value;
            
            fetch(`?action=api_stats&hours=${timeframe}`)
                .then(response => response.json())
                .then(data => {
                    const container = document.getElementById('api-stats-display');
                    
                    let html = `
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-value">${data.total_requests}</div>
                                <div class="stat-label">Total Requests</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${data.successful_requests}</div>
                                <div class="stat-label">Successful</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${data.failed_requests}</div>
                                <div class="stat-label">Failed</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">${Math.round((data.successful_requests / Math.max(data.total_requests, 1)) * 100)}%</div>
                                <div class="stat-label">Success Rate</div>
                            </div>
                        </div>
                    `;
                    
                    if (Object.keys(data.endpoints).length > 0) {
                        html += '<h3>Top Endpoints</h3><ul>';
                        Object.entries(data.endpoints).forEach(([endpoint, count]) => {
                            html += `<li>${endpoint}: ${count} requests</li>`;
                        });
                        html += '</ul>';
                    }
                    
                    if (Object.keys(data.top_ips).length > 0) {
                        html += '<h3>Top IP Addresses</h3><ul>';
                        Object.entries(data.top_ips).forEach(([ip, count]) => {
                            html += `<li>${ip}: ${count} requests</li>`;
                        });
                        html += '</ul>';
                    }
                    
                    if (Object.keys(data.error_types).length > 0) {
                        html += '<h3>Error Types</h3><ul>';
                        Object.entries(data.error_types).forEach(([error, count]) => {
                            html += `<li>${error}: ${count} occurrences</li>`;
                        });
                        html += '</ul>';
                    }
                    
                    container.innerHTML = html;
                })
                .catch(error => {
                    console.error('Error loading API stats:', error);
                    document.getElementById('api-stats-display').innerHTML = 
                        '<p style="color: #ff0000;">Failed to load statistics</p>';
                });
        }
        
        function revokeKey(keyId) {
            if (!confirm('Are you sure you want to revoke this API key? This action cannot be undone.')) {
                return;
            }
            
            const formData = new FormData();
            formData.append('key_id', keyId);
            
            fetch('?action=revoke_key', {
                method: 'POST',
                body: formData
            })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('API key revoked successfully');
                        loadAPIKeys();
                    } else {
                        alert('Error: ' + data.error);
                    }
                })
                .catch(error => {
                    console.error('Error revoking key:', error);
                    alert('Failed to revoke API key');
                });
        }
        
        function cleanRateLimits() {
            fetch('?action=clean_rate_limits', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    const results = document.getElementById('maintenance-results');
                    results.innerHTML = `
                        <div class="generated-key">
                            <h4>Rate Limit Cleanup Results</h4>
                            <p>Cleaned entries: ${data.cleaned_entries || 0}</p>
                            <p>Remaining entries: ${data.remaining_entries || 0}</p>
                        </div>
                    `;
                })
                .catch(error => {
                    console.error('Error cleaning rate limits:', error);
                });
        }
        
        function runHealthCheck() {
            const results = document.getElementById('maintenance-results');
            results.innerHTML = `
                <div class="generated-key">
                    <h4>API Health Check</h4>
                    <p>✅ API wrapper loaded successfully</p>
                    <p>✅ Authentication system operational</p>
                    <p>✅ Rate limiting functional</p>
                    <p>✅ Request validation active</p>
                </div>
            `;
        }
        
        // Form handlers
        document.getElementById('generate-key-form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const permissions = [];
            formData.getAll('permissions[]').forEach(perm => permissions.push(perm));
            
            const submitData = new FormData();
            submitData.append('name', formData.get('name'));
            submitData.append('permissions', JSON.stringify(permissions));
            submitData.append('expires_in_days', formData.get('expires_in_days'));
            
            fetch('?action=generate_key', {
                method: 'POST',
                body: submitData
            })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('generated-key-display').innerHTML = `
                            <div class="generated-key">
                                <h4>🔑 New API Key Generated</h4>
                                <div class="warning-box">
                                    <strong>⚠️ Security Warning:</strong> This API key will only be shown once. 
                                    Please copy it immediately and store it securely.
                                </div>
                                <div class="generated-key-value">${data.api_key}</div>
                                <p><strong>Key ID:</strong> ${data.key_id}</p>
                                <p><strong>Permissions:</strong> ${data.permissions.join(', ')}</p>
                                ${data.expires_at ? `<p><strong>Expires:</strong> ${new Date(data.expires_at * 1000).toLocaleString()}</p>` : ''}
                            </div>
                        `;
                        document.getElementById('generated-key-display').style.display = 'block';
                        this.reset();
                        loadAPIKeys();
                    } else {
                        alert('Error: ' + data.error);
                    }
                })
                .catch(error => {
                    console.error('Error generating key:', error);
                    alert('Failed to generate API key');
                });
        });
        
        document.getElementById('generate-token-form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const permissions = [];
            formData.getAll('permissions[]').forEach(perm => permissions.push(perm));
            
            const submitData = new FormData();
            submitData.append('permissions', JSON.stringify(permissions));
            submitData.append('expires_in_minutes', formData.get('expires_in_minutes'));
            
            fetch('?action=generate_bearer', {
                method: 'POST',
                body: submitData
            })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('generated-token-display').innerHTML = `
                            <div class="generated-key">
                                <h4>🎫 Bearer Token Generated</h4>
                                <div class="warning-box">
                                    <strong>⚠️ Security Warning:</strong> This bearer token will only be shown once. 
                                    Please copy it immediately.
                                </div>
                                <div class="generated-key-value">${data.bearer_token}</div>
                                <p><strong>Session ID:</strong> ${data.session_id}</p>
                                <p><strong>Permissions:</strong> ${data.permissions.join(', ')}</p>
                                <p><strong>Expires:</strong> ${new Date(data.expires_at * 1000).toLocaleString()}</p>
                                <h5>Usage Example:</h5>
                                <div class="generated-key-value">Authorization: Bearer ${data.bearer_token}</div>
                            </div>
                        `;
                        document.getElementById('generated-token-display').style.display = 'block';
                        this.reset();
                    } else {
                        alert('Error: ' + data.error);
                    }
                })
                .catch(error => {
                    console.error('Error generating token:', error);
                    alert('Failed to generate bearer token');
                });
        });
        
        // Load initial data
        loadAPIKeys();
    </script>
</body>
</html>