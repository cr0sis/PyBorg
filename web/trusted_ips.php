<?php
/**
 * Trusted IP Configuration
 * This file defines IP addresses that are considered trusted for security operations
 * 
 * SECURITY NOTICE:
 * - These IPs bypass certain rate limiting and security checks
 * - Only add IPs you completely trust and control
 * - Changes take effect immediately
 */

// Return array of trusted IP addresses
return [
    // Localhost variations
    '127.0.0.1',
    '::1',
    'localhost',
    
    // Local network ranges (modify as needed for your network)
    // '192.168.1.0/24',  // Uncomment and modify for your local network
    // '10.0.0.0/8',      // Uncomment for private network access
    // '172.16.0.0/12',   // Uncomment for private network access
    
    // Specific trusted IPs (add your admin IPs here)
    // 'your.admin.ip.here',
    
    // Cloud/hosting provider IPs (if applicable)
    // Add any cloud provider or hosting service IPs that need admin access
];

// Note: This file is loaded by security_hardened.php and other security modules
// The returned array is merged with default trusted IPs for comprehensive security coverage