<?php
/**
 * Debug Admin Status
 */
require_once 'safe_admin_detect.php';

echo "<h2>Admin Debug Information</h2>";
echo "<p><strong>Session Status:</strong></p>";
echo "<ul>";
echo "<li>Session active: " . (session_status() === PHP_SESSION_ACTIVE ? "YES" : "NO") . "</li>";
echo "<li>User ID: " . ($_SESSION['user_id'] ?? 'NOT SET') . "</li>";
echo "<li>Username: " . ($_SESSION['username'] ?? 'NOT SET') . "</li>";
echo "<li>Is Admin: " . ($_SESSION['is_admin'] ?? 'NOT SET') . "</li>";
echo "<li>2FA Verified: " . ($_SESSION['2fa_verified'] ?? 'NOT SET') . "</li>";
echo "<li>2FA Verified Time: " . ($_SESSION['2fa_verified_time'] ?? 'NOT SET') . "</li>";
echo "</ul>";

echo "<p><strong>Admin Detection Results:</strong></p>";
echo "<ul>";
echo "<li>isSafeLoggedIn(): " . (isSafeLoggedIn() ? "TRUE" : "FALSE") . "</li>";
echo "<li>isSafeAdmin(): " . (isSafeAdmin() ? "TRUE" : "FALSE") . "</li>";
echo "</ul>";

if (isSafeAdmin()) {
    echo "<p><strong style='color: green;'>✅ Admin access should be working!</strong></p>";
    echo "<p>If invisible controls aren't working, the issue is with JavaScript injection.</p>";
} else {
    echo "<p><strong style='color: red;'>❌ Admin access not working</strong></p>";
    echo "<p>You need to complete 2FA verification or there's a session issue.</p>";
}

echo "<p><a href='/'>Back to main site</a> | <a href='/admin_styled.php'>Try Admin Panel Direct</a></p>";
?>