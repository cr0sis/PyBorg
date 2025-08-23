<?php
/**
 * Real-Time Security Monitor
 * Detects and alerts on suspicious admin activity
 */

require_once 'config_paths.php';
require_once 'security_config.php';

class SecurityMonitor {
    private static $alert_thresholds = [
        'rapid_operations' => 20,
        'concurrent_sessions' => 2
    ];
    
    private static $alert_file = '/tmp/security_alerts.json';
    
    public static function monitorOperation($user_id, $operation, $ip_address) {
        $username = $_SESSION['username'] ?? 'unknown';
        
        // Check high-risk operations
        $high_risk_ops = ['delete_user', 'bulk_action', 'system_restart'];
        if (in_array($operation, $high_risk_ops)) {
            self::triggerAlert('HIGH_RISK_OPERATION', [
                'user_id' => $user_id,
                'username' => $username,
                'operation' => $operation,
                'ip' => $ip_address
            ]);
        }
    }
    
    public static function triggerAlert($type, $data) {
        $alert = [
            'id' => bin2hex(random_bytes(8)),
            'type' => $type,
            'severity' => 'MEDIUM',
            'timestamp' => time(),
            'data' => $data,
            'ip' => $_SERVER['REMOTE_ADDR']
        ];
        
        self::saveAlert($alert);
        
        logSecurityEvent('SECURITY_ALERT', 
            "Alert: $type for user " . ($data['username'] ?? 'unknown'), 
            'MEDIUM');
    }
    
    private static function saveAlert($alert) {
        $alerts = [];
        if (file_exists(self::$alert_file)) {
            $alerts = json_decode(file_get_contents(self::$alert_file), true) ?: [];
        }
        $alerts[] = $alert;
        file_put_contents(self::$alert_file, json_encode($alerts), LOCK_EX);
    }
}
?>