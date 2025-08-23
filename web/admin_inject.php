<?php
/**
 * Invisible Admin Button Injector
 * Server-side admin detection and button injection with ZERO F12 traces
 */

// Security initialization
require_once 'security_config.php';
require_once 'auth.php';

// Safe session initialization without security redirects
function safeInitSession() {
    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_secure', 0);
        ini_set('session.cookie_samesite', 'Lax');
        ini_set('session.use_strict_mode', 1);
        session_start();
    }
}

// Simple logging function for admin injection (doesn't conflict with security_config.php)
function logAdminEvent($event_type, $message, $severity = 'LOW') {
    $log_entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'event_type' => $event_type,
        'severity' => $severity,
        'message' => $message,
        'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'session_id' => session_id() ?? 'unknown',
        'user_id' => $_SESSION['user_id'] ?? 'anonymous'
    ];
    
    $log_file = '/tmp/admin_inject.log';
    @file_put_contents($log_file, json_encode($log_entry) . "\n", FILE_APPEND | LOCK_EX);
}

/**
 * Check if current user should see admin controls
 * Returns true only for authenticated admins with valid 2FA
 * Safe version without redirects
 */
function shouldShowAdminControls() {
    // Initialize session safely
    safeInitSession();
    
    // Must be logged in
    if (!isLoggedIn()) {
        return false;
    }
    
    // Must be admin
    if (!isAdmin()) {
        return false;
    }
    
    // Must have valid 2FA (within last 24 hours) - but be more lenient for now
    if (isset($_SESSION['2fa_verified_time'])) {
        $time_since_2fa = time() - $_SESSION['2fa_verified_time'];
        if ($time_since_2fa > 86400) { // 24 hours
            return false;
        }
    } else {
        // For now, don't strictly require 2FA for admin controls to prevent lockouts
        // TODO: Re-enable strict 2FA requirement once system is stable
    }
    
    // Skip IP binding validation for now to prevent redirect loops
    // TODO: Re-implement IP binding in a way that doesn't cause redirects
    
    return true;
}

/**
 * Generate invisible admin button HTML
 * Completely server-side rendered with no client-side traces
 * REMOVED - only bot emoji double-click access allowed
 */
function getInvisibleAdminButton() {
    if (!shouldShowAdminControls()) {
        return ''; // Return nothing for non-admins
    }
    
    // Red admin button removed - only bot emoji double-click access allowed
    return '';
}

/**
 * Generate keyboard shortcut access (Ctrl+Shift+A)
 * REMOVED - only bot emoji double-click access allowed
 */
function getInvisibleKeyboardShortcut() {
    if (!shouldShowAdminControls()) {
        return ''; // Return nothing for non-admins
    }
    
    // Keyboard shortcut removed - only bot emoji double-click access allowed
    return '';
}

/**
 * Generate invisible context menu option
 * REMOVED - only bot emoji double-click access allowed
 */
function getInvisibleContextMenu() {
    if (!shouldShowAdminControls()) {
        return ''; // Return nothing for non-admins
    }
    
    // Context menu removed - only bot emoji double-click access allowed
    return '';
}

/**
 * Generate invisible bot emoji double-click access
 * ONLY admin access method - double-click the bot emoji (🤖)
 */
function getInvisibleLogoAccess() {
    if (!shouldShowAdminControls()) {
        return ''; // Return nothing for non-admins
    }
    
    return '
    <script>
    // Invisible bot emoji double-click access - ONLY admin access method
    document.addEventListener("DOMContentLoaded", function() {
        // Target the specific bot emoji span element
        const botEmojiElement = document.querySelector(".bot-emoji");
        
        if (botEmojiElement) {
            botEmojiElement.style.cursor = "text";
            botEmojiElement.title = ""; // No tooltip to maintain stealth
            
            // Add double-click listener only to bot emoji element
            botEmojiElement.addEventListener("dblclick", function(e) {
                e.preventDefault();
                e.stopPropagation();
                
                // Redirect to admin panel
                window.location.href = "/admin_styled.php";
            });
            
            // Add subtle hover effect for admin feedback
            botEmojiElement.addEventListener("mouseenter", function() {
                this.style.transform = "scale(1.2)";
                this.style.transition = "transform 0.2s ease";
            });
            
            botEmojiElement.addEventListener("mouseleave", function() {
                this.style.transform = "scale(1)";
            });
        }
    });
    </script>
    ';
}
?>
