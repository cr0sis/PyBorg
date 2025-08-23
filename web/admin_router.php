<?php
/**
 * Admin Panel Router - Nginx Compatible
 * Handles routing for invisible admin panel without requiring nginx config changes
 */

// Get the requested path
$request_uri = $_SERVER['REQUEST_URI'];
$path = parse_url($request_uri, PHP_URL_PATH);

// Define admin routes
$admin_routes = [
    '/sys-mgmt',
    '/internal-ops', 
    '/core-panel'
];

// Check if this is an admin route
$is_admin_route = false;
foreach ($admin_routes as $route) {
    if (strpos($path, $route) === 0) {
        $is_admin_route = true;
        break;
    }
}

// If it's an admin route, include the secure admin entry
if ($is_admin_route) {
    // Set additional security headers
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    // Include the secure admin entry
    include_once 'secure_admin_entry.php';
    exit;
}

// Block direct access to admin entry file
if (basename($path) === 'secure_admin_entry.php') {
    http_response_code(404);
    echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
    exit;
}

// Block common admin discovery attempts
$blocked_paths = [
    '/admin', '/administrator', '/wp-admin', '/cpanel', 
    '/panel', '/dashboard', '/control', '/manager', '/administration'
];

foreach ($blocked_paths as $blocked) {
    if (strpos($path, $blocked) === 0) {
        http_response_code(404);
        echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
        exit;
    }
}

// If not an admin route, return 404 (this file should not be accessed directly)
http_response_code(404);
echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
exit;
?>