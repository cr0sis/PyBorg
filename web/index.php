<?php
/**
 * Transparent Admin Detection and Redirect System
 * Serves enhanced_index.php to authenticated admins, index.html to everyone else
 * COMPLETELY INVISIBLE - zero traces of admin detection for regular users
 */

// Include admin detection functions
require_once 'admin_inject.php';

// Start session safely (no output)
safeInitSession();

// Check if current user is an authenticated admin
$is_authenticated_admin = shouldShowAdminControls();

if ($is_authenticated_admin) {
    // Redirect authenticated admins to enhanced version
    // No HTTP redirect - direct include for seamless experience
    include 'enhanced_index.php';
} else {
    // Serve regular index.html to everyone else
    // Read and output the original HTML file
    $html_content = file_get_contents('index_original.html');
    
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
    
    // Check if user is logged in to control analytics overlay
    require_once 'auth.php';
    $is_logged_in = isLoggedIn();
    
    // Analytics overlay control - show for non-registered users, hide for registered
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
    
    // Inject analytics control and message script before closing body tag
    $html_content = str_replace('</body>', $analytics_control . $message_script . '</body>', $html_content);
    
    // Set proper content type
    header('Content-Type: text/html; charset=UTF-8');
    
    // Output the original HTML content
    echo $html_content;
}
?>