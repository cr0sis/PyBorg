<?php
/**
 * Safe Admin Injection Functions
 * Provides admin controls without redirect-causing security checks
 */

require_once 'safe_admin_detect.php';

/**
 * Generate invisible admin button HTML
 * Completely server-side rendered with no client-side traces
 */
function getSafeInvisibleAdminButton() {
    if (!isSafeAdmin()) {
        return ''; // Return nothing for non-admins
    }
    
    // Bot emoji double-click access only
    return '';
}

/**
 * Generate invisible keyboard shortcuts for admin access
 */
function getSafeInvisibleKeyboardShortcut() {
    if (!isSafeAdmin()) {
        return '';
    }
    
    logSafeAdminEvent('KEYBOARD_SHORTCUT_LOADED', "Admin keyboard shortcut loaded for {$_SESSION['username']}");
    
    return '
<script>
document.addEventListener("keydown", function(e) {
    // Ctrl+Shift+A for Admin Panel
    if (e.ctrlKey && e.shiftKey && e.key === "A") {
        e.preventDefault();
        window.location.href = "/admin_styled.php";
    }
});
</script>';
}

/**
 * Generate invisible context menu access
 */
function getSafeInvisibleContextMenu() {
    if (!isSafeAdmin()) {
        return '';
    }
    
    return '
<script>
document.addEventListener("contextmenu", function(e) {
    if (e.ctrlKey && e.shiftKey) {
        e.preventDefault();
        const adminMenu = document.createElement("div");
        adminMenu.innerHTML = `
            <div style="position: fixed; top: ${e.clientY}px; left: ${e.clientX}px; 
                        background: #1f2937; border: 1px solid #374151; border-radius: 8px; 
                        padding: 8px; z-index: 10000; box-shadow: 0 10px 25px rgba(0,0,0,0.3);">
                <a href="/admin_styled.php" style="display: block; color: #f9fafb; 
                   text-decoration: none; padding: 8px 12px; border-radius: 4px; 
                   font-size: 14px; font-family: system-ui;">🔧 Admin Panel</a>
            </div>
        `;
        document.body.appendChild(adminMenu);
        
        setTimeout(() => {
            if (adminMenu.parentNode) {
                adminMenu.parentNode.removeChild(adminMenu);
            }
        }, 3000);
        
        adminMenu.addEventListener("click", () => {
            if (adminMenu.parentNode) {
                adminMenu.parentNode.removeChild(adminMenu);
            }
        });
    }
});
</script>';
}

/**
 * Generate invisible logo access
 */
function getSafeInvisibleLogoAccess() {
    if (!isSafeAdmin()) {
        return '';
    }
    
    return '
<script>
document.addEventListener("DOMContentLoaded", function() {
    // Find any logo or header element
    const logo = document.querySelector("h1, .logo, [class*=\"logo\"], [id*=\"logo\"]");
    if (logo) {
        let clickCount = 0;
        let clickTimer = null;
        
        logo.addEventListener("click", function(e) {
            clickCount++;
            if (clickCount === 1) {
                clickTimer = setTimeout(() => {
                    clickCount = 0;
                }, 500);
            } else if (clickCount === 3) {
                clearTimeout(clickTimer);
                clickCount = 0;
                e.preventDefault();
                window.location.href = "/admin_styled.php";
            }
        });
    }
});
</script>';
}

/**
 * Get admin confirmation (currently disabled)
 */
function getSafeAdminConfirmation() {
    return '';
}
?>