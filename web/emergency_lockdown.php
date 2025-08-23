<?php
// EMERGENCY: Invalidate ALL admin sessions immediately
session_start();

// Clear all session data
$_SESSION = array();

// Destroy session cookie
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Destroy session
session_destroy();

// Clear any admin cookies
setcookie('admin_logged_in', '', time() - 3600, '/');
setcookie('user_id', '', time() - 3600, '/');

echo "EMERGENCY LOCKDOWN: All admin sessions invalidated. Please log in again.";

// Log the lockdown
$log_entry = json_encode([
    'timestamp' => date('Y-m-d H:i:s'),
    'action' => 'EMERGENCY_LOCKDOWN',
    'ip' => $_SERVER['REMOTE_ADDR'],
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
]) . "\n";

file_put_contents('/tmp/emergency_lockdown.log', $log_entry, FILE_APPEND | LOCK_EX);
?>

<html>
<body style="background: #000; color: #ff0000; font-family: monospace; text-align: center; padding: 50px;">
<h1>🚨 EMERGENCY SECURITY LOCKDOWN 🚨</h1>
<p>All admin sessions have been invalidated due to potential security breach.</p>
<p>Please <a href="/auth.php" style="color: #00ff00;">log in again</a> to continue.</p>
<p><strong>Session timeout reduced to 1 hour for security.</strong></p>
</body>
</html>