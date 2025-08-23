<?php
// Direct test to see what's in the session after SSO callback
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();

echo "<h2>Session Debug</h2>";
echo "<pre>";
echo "Session ID: " . session_id() . "\n\n";
echo "Session Contents:\n";
print_r($_SESSION);
echo "</pre>";

// Check if we're in the SSO flow
if (isset($_SESSION['pending_sso_2fa_user_id'])) {
    echo "<h3>SSO 2FA Pending</h3>";
    echo "<ul>";
    echo "<li>User ID: " . $_SESSION['pending_sso_2fa_user_id'] . "</li>";
    echo "<li>Username: " . $_SESSION['pending_sso_2fa_username'] . "</li>";
    echo "<li>Is Admin: " . ($_SESSION['pending_sso_2fa_is_admin'] ? 'Yes' : 'No') . "</li>";
    echo "<li>Provider: " . $_SESSION['pending_sso_2fa_provider'] . "</li>";
    echo "</ul>";
} else {
    echo "<h3>No SSO 2FA pending</h3>";
}

// Check regular login status
if (isset($_SESSION['user_id'])) {
    echo "<h3>Logged In User</h3>";
    echo "<ul>";
    echo "<li>User ID: " . $_SESSION['user_id'] . "</li>";
    echo "<li>Username: " . $_SESSION['username'] . "</li>";
    echo "<li>Is Admin: " . (isset($_SESSION['is_admin']) && $_SESSION['is_admin'] ? 'Yes' : 'No') . "</li>";
    echo "</ul>";
}
?>