<?php
/**
 * Enhanced Index with Invisible Admin Controls and Terminal Theme Support
 * Serves regular index.html to everyone, but adds invisible admin controls for authenticated admins
 * Also includes terminal theme integration
 */

// Include admin injection system
require_once 'admin_inject.php';

// Get the original index.html content
$index_content = file_get_contents('index.html');

// Handle logout messages from URL parameters
$msg = $_GET['msg'] ?? '';
$error = $_GET['error'] ?? '';
$message_script = '';

if (!empty($msg)) {
    $msg_escaped = htmlspecialchars($msg, ENT_QUOTES, 'UTF-8');
    $message_script = "
<script>
document.addEventListener('DOMContentLoaded', function() {
    alert('$msg_escaped');
});
</script>";
} elseif (!empty($error)) {
    $error_escaped = htmlspecialchars($error, ENT_QUOTES, 'UTF-8');
    $message_script = "
<script>
document.addEventListener('DOMContentLoaded', function() {
    alert('Error: $error_escaped');
});
</script>";
}

// Check if user is logged in (registered user) and inject appropriate analytics overlay control
require_once 'auth.php';
$is_logged_in = isLoggedIn();

// Analytics overlay control - hide for registered users, show for non-registered
$analytics_control = "
<script>
document.addEventListener('DOMContentLoaded', function() {
    const analyticsOverlay = document.getElementById('analytics-overlay');
    if (analyticsOverlay) {
        " . ($is_logged_in ? 
            "analyticsOverlay.style.display = 'none';" : 
            "analyticsOverlay.style.display = 'flex';") . "
    }
});
</script>";

// If admin is authenticated, inject invisible admin controls
require_once 'admin_inject.php';
if (shouldShowAdminControls()) {
    // Log admin access to enhanced index
    logSecurityEvent('ENHANCED_INDEX_ACCESS', "Enhanced index with admin controls accessed by {$_SESSION['username']}", 'LOW');
    
    // Inject invisible admin controls before closing </body> tag
    $admin_button = getInvisibleAdminButton();
    $keyboard_shortcut = getInvisibleKeyboardShortcut();
    $context_menu = getInvisibleContextMenu();
    $logo_access = getInvisibleLogoAccess();
    $admin_confirmation = '';
    
    $injection = $admin_button . $keyboard_shortcut . $context_menu . $logo_access . $admin_confirmation . $analytics_control . $message_script;
    
    // Insert before closing body tag
    $index_content = str_replace('</body>', $injection . '</body>', $index_content);
} else {
    // For registered users who are not admins, just inject analytics control and messages
    if ($is_logged_in) {
        $index_content = str_replace('</body>', $analytics_control . $message_script . '</body>', $index_content);
    } else {
        // For non-logged in users, only inject message script if present
        if (!empty($message_script)) {
            $index_content = str_replace('</body>', $message_script . '</body>', $index_content);
        }
    }
}

// Set security headers
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');

// Output the enhanced content
echo $index_content;
?>