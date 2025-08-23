<?php
/**
 * Comprehensive Admin Panel Entry Point
 * Full-featured admin dashboard with monitoring and management tools
 */

// Set security headers immediately
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// Include the styled admin panel that matches main site design
require_once 'admin_styled.php';
?>