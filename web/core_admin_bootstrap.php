<?php
/**
 * Core Admin Bootstrap
 * Consolidated security initialization for all admin interfaces
 * Eliminates duplication across 15+ admin files
 */

// Prevent direct access
if (!defined('ADMIN_BOOTSTRAP_INCLUDED')) {
    define('ADMIN_BOOTSTRAP_INCLUDED', true);
} else {
    exit('Direct access not allowed');
}

// Core security initialization
require_once 'security_config.php';
require_once 'auth.php';
require_once 'security_hardened.php';
require_once 'input_sanitizer.php';
require_once 'config_paths.php';

/**
 * Initialize comprehensive admin security
 */
function initAdminSecurity(): array {
    // Standard security headers for all admin pages
    $security_headers = [
        'X-Frame-Options: DENY',
        'X-Content-Type-Options: nosniff',
        'X-XSS-Protection: 1; mode=block',
        'Referrer-Policy: no-referrer',
        'Cache-Control: no-cache, no-store, must-revalidate',
        'Pragma: no-cache',
        'Expires: 0'
    ];
    
    foreach ($security_headers as $header) {
        header($header);
    }
    
    // Initialize secure session
    initSecureSession();
    
    // Validate admin access
    $admin_status = validateAdminAccess();
    
    // Log admin access attempt
    logSecurityEvent('ADMIN_ACCESS_ATTEMPT', 
        "Admin page accessed: {$_SERVER['REQUEST_URI']}", 
        $_SERVER['REMOTE_ADDR']);
    
    return $admin_status;
}

/**
 * Comprehensive admin access validation
 */
function validateAdminAccess(): array {
    $status = [
        'is_logged_in' => false,
        'is_admin' => false,
        'is_2fa_verified' => false,
        'needs_2fa' => false,
        'error' => null
    ];
    
    // Check if logged in
    if (!isLoggedIn()) {
        $status['error'] = 'Authentication required';
        redirectToAuth();
        return $status;
    }
    $status['is_logged_in'] = true;
    
    // Check admin privileges
    if (!isAdmin()) {
        $status['error'] = 'Admin privileges required';
        logSecurityEvent('UNAUTHORIZED_ADMIN_ACCESS', 
            'Non-admin user attempted admin access', 'HIGH');
        http_response_code(403);
        exit('Access denied: Admin privileges required');
    }
    $status['is_admin'] = true;
    
    // Check 2FA verification (valid for 1 hour)
    if (!isset($_SESSION['2fa_verified_time']) || 
        (time() - $_SESSION['2fa_verified_time']) > 3600) {
        $status['needs_2fa'] = true;
        $status['error'] = '2FA verification required';
        redirectTo2FA();
        return $status;
    }
    $status['is_2fa_verified'] = true;
    
    return $status;
}

/**
 * Redirect to authentication page
 */
function redirectToAuth(): void {
    header('Location: /auth.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit();
}

/**
 * Redirect to 2FA verification
 */
function redirectTo2FA(): void {
    header('Location: /verify_2fa.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit();
}

/**
 * Render admin page header
 */
function renderAdminHeader(string $page_title = 'Admin Panel'): void {
    echo "<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>$page_title</title>
    <link rel='stylesheet' href='/css/terminal.css' id='terminal-css'>
    <style>
        /* Default admin styles */
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .admin-container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .admin-header { border-bottom: 2px solid #2196F3; padding-bottom: 15px; margin-bottom: 30px; }
        .admin-nav { margin-bottom: 30px; }
        .admin-nav a { margin-right: 15px; padding: 8px 16px; background: #2196F3; color: white; text-decoration: none; border-radius: 4px; }
        .admin-nav a:hover { background: #1976D2; }
        .status-indicator { padding: 8px 12px; border-radius: 4px; margin-bottom: 20px; }
        .status-success { background: #4CAF50; color: white; }
        .status-warning { background: #FF9800; color: white; }
        .status-error { background: #F44336; color: white; }
        
        /* Terminal theme toggle */
        .theme-toggle { position: fixed; top: 20px; right: 20px; z-index: 1000; display: flex; flex-direction: column; gap: 5px; }
        .theme-toggle button { 
            background: #2196F3; color: white; border: none; padding: 10px 15px; 
            border-radius: 4px; cursor: pointer; font-size: 12px;
        }
        .theme-toggle button:hover { background: #1976D2; }
    </style>
    <script>
        // Terminal theme functionality
        function toggleTerminalTheme() {
            document.body.classList.toggle('terminal-theme');
            const isTerminal = document.body.classList.contains('terminal-theme');
            localStorage.setItem('admin-terminal-theme', isTerminal ? 'enabled' : 'disabled');
            document.querySelector('.theme-toggle button').textContent = 
                isTerminal ? 'Normal' : 'Terminal';
        }
        
        // Load saved theme preference
        document.addEventListener('DOMContentLoaded', function() {
            const savedTheme = localStorage.getItem('admin-terminal-theme');
            if (savedTheme === 'enabled') {
                document.body.classList.add('terminal-theme');
                document.querySelector('.theme-toggle button').textContent = 'Normal';
            }
        });
    </script>
</head>
<body>
<div class='theme-toggle'>
    <button onclick='toggleTerminalTheme()'>Terminal</button>
</div>
<div class='admin-container'>
    <div class='admin-header'>
        <h1>$page_title</h1>
        <div class='admin-nav'>
            <a href='/comprehensive_admin.php'>Dashboard</a>
            <a href='/admin_api.php'>Bot Control</a>
            <a href='/security_dashboard.php'>Security</a>
            <a href='/auth.php?logout=1'>Logout</a>
        </div>
    </div>";
}

/**
 * Render admin page footer
 */
function renderAdminFooter(): void {
    echo "</div></body></html>";
}

// Auto-initialize if this file is included
if (!headers_sent()) {
    $admin_status = initAdminSecurity();
}