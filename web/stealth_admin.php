<?php
/**
 * Completely Invisible Admin Dashboard Button
 * Multiple hidden access methods with zero F12 footprint
 */

require_once 'admin_inject.php';

// Check if user should see admin controls
if (!shouldShowAdminControls()) {
    // Return nothing - completely invisible to non-admins
    http_response_code(404);
    echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
    exit;
}

// For authenticated admins, provide multiple invisible access methods
?><!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Status</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f8fafc;
            margin: 0;
            padding: 2rem;
            color: #334155;
        }
        
        .stealth-container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
            overflow: hidden;
        }
        
        .stealth-header {
            background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%);
            color: white;
            padding: 2rem;
            text-align: center;
        }
        
        .stealth-header h1 {
            margin: 0;
            font-size: 2rem;
            font-weight: 700;
        }
        
        .stealth-header p {
            margin: 0.5rem 0 0 0;
            opacity: 0.9;
        }
        
        .access-methods {
            padding: 2rem;
        }
        
        .access-method {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            transition: all 0.2s ease;
        }
        
        .access-method:hover {
            background: #f1f5f9;
            border-color: #cbd5e1;
            transform: translateY(-2px);
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
        }
        
        .access-method h3 {
            margin: 0 0 0.5rem 0;
            color: #1e40af;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .access-method p {
            margin: 0;
            color: #64748b;
            font-size: 0.875rem;
        }
        
        .access-method.clickable {
            cursor: pointer;
        }
        
        .quick-access {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 2rem;
        }
        
        .quick-btn {
            background: #1e40af;
            color: white;
            border: none;
            padding: 1rem;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }
        
        .quick-btn:hover {
            background: #1d4ed8;
            transform: translateY(-2px);
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
        }
        
        .admin-indicator {
            position: fixed;
            top: 1rem;
            right: 1rem;
            background: #10b981;
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
        }
    </style>
</head>
<body>
    <div class="admin-indicator">
        🛡️ Admin: <?php echo htmlspecialchars($_SESSION['username']); ?>
    </div>

    <div class="stealth-container">
        <div class="stealth-header">
            <h1>🔒 Stealth Admin Access</h1>
            <p>Multiple invisible entry methods for secure administration</p>
        </div>
        
        <div class="access-methods">
            <div class="access-method clickable" onclick="window.location.href='/sys-mgmt.php'">
                <h3><i class="fas fa-mouse-pointer"></i> Direct Click Access</h3>
                <p>Click anywhere on this panel to access the main admin dashboard</p>
            </div>
            
            <div class="access-method">
                <h3><i class="fas fa-keyboard"></i> Keyboard Shortcut</h3>
                <p>Press <strong>Ctrl + Shift + A</strong> from any page to instantly access admin panel</p>
            </div>
            
            <div class="access-method">
                <h3><i class="fas fa-mouse"></i> Right-Click Context Menu</h3>
                <p>Right-click on the main site header to reveal hidden admin context menu</p>
            </div>
            
            <div class="access-method">
                <h3><i class="fas fa-hand-pointer"></i> Logo Double-Click</h3>
                <p>Double-click the PyBorg logo on the main site for instant admin access</p>
            </div>
            
            <div class="access-method">
                <h3><i class="fas fa-link"></i> Direct URLs</h3>
                <p>Bookmark these invisible URLs: /sys-mgmt.php, /internal-ops.php, /core-panel.php</p>
            </div>
            
            <div class="quick-access">
                <a href="/sys-mgmt.php" class="quick-btn">
                    <i class="fas fa-tachometer-alt"></i>
                    Main Dashboard
                </a>
                <a href="/internal-ops.php" class="quick-btn">
                    <i class="fas fa-cogs"></i>
                    Operations
                </a>
                <a href="/core-panel.php" class="quick-btn">
                    <i class="fas fa-server"></i>
                    Core Panel
                </a>
                <a href="/index.php" class="quick-btn" style="background: #6b7280;">
                    <i class="fas fa-home"></i>
                    Main Site
                </a>
            </div>
        </div>
    </div>

    <script>
        // Keyboard shortcut: Ctrl+Shift+A
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && e.shiftKey && e.key === 'A') {
                e.preventDefault();
                window.location.href = '/sys-mgmt.php';
            }
        });
        
        // Double-click entire page for access
        document.addEventListener('dblclick', function(e) {
            if (!e.target.closest('a, button')) {
                window.location.href = '/sys-mgmt.php';
            }
        });
        
        // Show tooltip on hover for shortcuts
        document.querySelectorAll('.access-method').forEach(method => {
            method.addEventListener('mouseenter', function() {
                this.style.background = '#e2e8f0';
            });
            method.addEventListener('mouseleave', function() {
                this.style.background = '#f8fafc';
            });
        });
    </script>
</body>
</html>