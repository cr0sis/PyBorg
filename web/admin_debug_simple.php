<?php
session_start();
require_once 'security_config.php';
require_once 'auth.php';
require_once 'advanced_admin_functions.php';

// Set server context
$_SERVER['REMOTE_ADDR'] = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$_SERVER['REQUEST_METHOD'] = $_SERVER['REQUEST_METHOD'] ?? 'GET';

echo "<h1>Admin Debug Test</h1>";

echo "<h2>Authentication Status</h2>";
echo "Logged in: " . (isLoggedIn() ? 'YES' : 'NO') . "<br>";
echo "Is admin: " . (isAdmin() ? 'YES' : 'NO') . "<br>";
echo "Session user: " . ($_SESSION['username'] ?? 'NONE') . "<br>";

if (isLoggedIn() && isAdmin()) {
    echo "<h2>Bot Statistics Test</h2>";
    try {
        $bot_stats = AdvancedAdmin::getBotStatistics();
        echo "<pre>";
        print_r($bot_stats);
        echo "</pre>";
        
        echo "<h2>Recent Commands Test</h2>";
        $recent_commands = AdvancedAdmin::getRecentCommands(5);
        echo "Command count: " . count($recent_commands) . "<br>";
        echo "<pre>";
        print_r($recent_commands);
        echo "</pre>";
        
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }
} else {
    echo "<p>Not authenticated as admin</p>";
}
?>