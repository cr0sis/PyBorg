<?php
/**
 * Simple Admin Test - Minimal admin button test
 */

session_start();

// Simple admin check
$is_logged_in = isset($_SESSION['user_id']);
$is_admin = isset($_SESSION['is_admin']) && $_SESSION['is_admin'];

?><!DOCTYPE html>
<html>
<head>
    <title>Simple Admin Test</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        .admin-button {
            position: fixed;
            top: 20px;
            right: 20px;
            background: #dc2626;
            color: white;
            padding: 10px 15px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: bold;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
        }
        .admin-button:hover {
            background: #b91c1c;
            transform: translateY(-2px);
        }
        .status { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .ok { background: #d4edda; color: #155724; }
        .error { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <h1>🔧 Simple Admin Test</h1>
    
    <?php if ($is_logged_in && $is_admin): ?>
        <div class="status ok">
            ✅ <strong>You are logged in as an admin!</strong><br>
            Username: <?php echo htmlspecialchars($_SESSION['username'] ?? 'Unknown'); ?><br>
            The admin button should be visible in the top-right corner.
        </div>
        
        <!-- ADMIN BUTTON - Should be visible -->
        <a href="/sys-mgmt.php" class="admin-button">
            <i class="fas fa-shield-alt"></i> Admin Panel
        </a>
        
        <script>
            // Test keyboard shortcut
            document.addEventListener('keydown', function(e) {
                if (e.ctrlKey && e.shiftKey && e.key === 'A') {
                    e.preventDefault();
                    alert('Admin shortcut works! Redirecting to admin panel...');
                    window.location.href = '/sys-mgmt.php';
                }
            });
            
            // Test double-click
            document.body.addEventListener('dblclick', function() {
                alert('Double-click admin access works!');
            });
        </script>
        
    <?php elseif ($is_logged_in): ?>
        <div class="status error">
            ❌ <strong>You are logged in but not an admin</strong><br>
            Username: <?php echo htmlspecialchars($_SESSION['username'] ?? 'Unknown'); ?><br>
            Admin controls will not appear.
        </div>
        
    <?php else: ?>
        <div class="status error">
            ❌ <strong>You are not logged in</strong><br>
            <a href="/auth.php">Click here to log in</a>
        </div>
    <?php endif; ?>
    
    <h3>Debug Info:</h3>
    <pre>
Logged In: <?php echo $is_logged_in ? 'YES' : 'NO'; ?>
Is Admin: <?php echo $is_admin ? 'YES' : 'NO'; ?>
Session Data: <?php print_r($_SESSION); ?>
    </pre>
    
    <h3>Test Links:</h3>
    <ul>
        <li><a href="/auth.php">Login Page</a></li>
        <li><a href="/sys-mgmt.php">Admin Panel</a></li>
        <li><a href="/debug_admin.php">Full Debug</a></li>
        <li><a href="/index.php">Main Site</a></li>
    </ul>
</body>
</html>