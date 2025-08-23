<?php
// Absolute minimal test with no dependencies
echo "Test starting...<br>";

// Try to start session
@session_start();
echo "Session started<br>";

// Show session ID
echo "Session ID: " . session_id() . "<br>";

// Check if we have SSO data
if (isset($_SESSION['pending_sso_2fa_user_id'])) {
    echo "Found SSO data!<br>";
    echo "User ID: " . $_SESSION['pending_sso_2fa_user_id'] . "<br>";
} else {
    echo "No SSO data found<br>";
}

echo "Test complete.";
?>