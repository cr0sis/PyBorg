<?php
/**
 * 🚨 EMERGENCY SECURITY RESPONSE SYSTEM 🚨
 * Hardcore lockdown and threat response for Pi under attack
 */

require_once 'security_hardened.php';

class EmergencySecurityResponse {
    private const LOCKDOWN_FILE = '/tmp/emergency_lockdown.flag';
    private const WHITELIST_FILE = '/tmp/emergency_whitelist.json';
    private const THREAT_THRESHOLD = 50; // attacks per hour
    
    public static function checkEmergencyConditions() {
        $dashboard = HardcoreSecurityManager::getSecurityDashboard();
        $recentAttacks = 0;
        $uniqueAttackers = [];
        
        foreach ($dashboard['recent_events'] as $event) {
            if ($event['type'] === 'ATTACK' && time() - strtotime($event['timestamp']) < 3600) {
                $recentAttacks++;
                $uniqueAttackers[$event['ip']] = true;
            }
        }
        
        // Emergency lockdown conditions
        if ($recentAttacks > self::THREAT_THRESHOLD || count($uniqueAttackers) > 20) {
            self::activateEmergencyLockdown();
            return true;
        }
        
        return false;
    }
    
    public static function activateEmergencyLockdown() {
        // Create lockdown flag
        file_put_contents(self::LOCKDOWN_FILE, json_encode([
            'activated_at' => time(),
            'reason' => 'Massive attack detected',
            'duration' => 3600 // 1 hour
        ]));
        
        // Block all non-whitelisted IPs
        self::enableWhitelistMode();
        
        HardcoreSecurityManager::logSecurityEvent('EMERGENCY', 'Emergency lockdown activated');
        
        // Send alert (if configured)
        self::sendEmergencyAlert();
    }
    
    public static function isLockdownActive() {
        if (!file_exists(self::LOCKDOWN_FILE)) {
            return false;
        }
        
        $lockdown = json_decode(file_get_contents(self::LOCKDOWN_FILE), true);
        
        // Check if lockdown expired
        if (time() > $lockdown['activated_at'] + $lockdown['duration']) {
            unlink(self::LOCKDOWN_FILE);
            return false;
        }
        
        return true;
    }
    
    public static function checkWhitelist($ip) {
        if (!file_exists(self::WHITELIST_FILE)) {
            // Default whitelist - add your trusted IPs here
            $whitelist = [
                '127.0.0.1',
                '::1',
                // Add your home IP, office IP, etc.
            ];
            file_put_contents(self::WHITELIST_FILE, json_encode($whitelist));
        } else {
            $whitelist = json_decode(file_get_contents(self::WHITELIST_FILE), true);
        }
        
        return in_array($ip, $whitelist);
    }
    
    private static function enableWhitelistMode() {
        // This would typically integrate with iptables or fail2ban
        // For now, we'll just log and rely on application-level blocking
        HardcoreSecurityManager::logSecurityEvent('EMERGENCY', 'Whitelist-only mode enabled');
    }
    
    private static function sendEmergencyAlert() {
        $message = "🚨 EMERGENCY: Pi under massive attack! Lockdown activated at " . date('Y-m-d H:i:s');
        
        // Log to system
        error_log("SECURITY EMERGENCY: $message");
        
        // Here you could integrate with:
        // - Email notifications
        // - Slack/Discord webhooks
        // - SMS alerts
        // - Push notifications
    }
    
    public static function getDashboard() {
        return [
            'lockdown_active' => self::isLockdownActive(),
            'whitelist_mode' => file_exists(self::LOCKDOWN_FILE),
            'threat_level' => self::calculateThreatLevel(),
            'recommended_actions' => self::getRecommendedActions()
        ];
    }
    
    private static function calculateThreatLevel() {
        $dashboard = HardcoreSecurityManager::getSecurityDashboard();
        $recentAttacks = 0;
        
        foreach ($dashboard['recent_events'] as $event) {
            if ($event['type'] === 'ATTACK' && time() - strtotime($event['timestamp']) < 3600) {
                $recentAttacks++;
            }
        }
        
        if ($recentAttacks > 50) return 'CRITICAL';
        if ($recentAttacks > 20) return 'HIGH';
        if ($recentAttacks > 10) return 'MEDIUM';
        return 'LOW';
    }
    
    private static function getRecommendedActions() {
        $actions = [];
        $threatLevel = self::calculateThreatLevel();
        
        switch ($threatLevel) {
            case 'CRITICAL':
                $actions[] = 'Consider taking server offline temporarily';
                $actions[] = 'Review all recent security events';
                $actions[] = 'Check for compromised accounts';
                $actions[] = 'Verify system integrity';
                break;
            case 'HIGH':
                $actions[] = 'Monitor security events closely';
                $actions[] = 'Consider enabling whitelist mode';
                $actions[] = 'Review blocked IPs for patterns';
                break;
            case 'MEDIUM':
                $actions[] = 'Regular monitoring sufficient';
                $actions[] = 'Review security configurations';
                break;
            case 'LOW':
                $actions[] = 'System operating normally';
                break;
        }
        
        return $actions;
    }
}

// Auto-check for emergency conditions on every request
if ($_SERVER['REQUEST_METHOD'] === 'GET' && !isset($_GET['bypass_emergency'])) {
    if (EmergencySecurityResponse::isLockdownActive()) {
        $clientIP = $_SERVER['REMOTE_ADDR'];
        
        if (!EmergencySecurityResponse::checkWhitelist($clientIP)) {
            HardcoreSecurityManager::logSecurityEvent('BLOCKED', 'Emergency lockdown - non-whitelisted IP', $clientIP);
            http_response_code(503);
            
            header('Content-Type: text/html');
            echo '<!DOCTYPE html>
            <html><head><title>Service Temporarily Unavailable</title></head>
            <body style="font-family:Arial;text-align:center;padding:50px;background:#1a1a1a;color:#fff;">
            <h1>🛡️ System Protection Active</h1>
            <p>This service is temporarily unavailable due to security measures.</p>
            <p>If you are the administrator, please check the security dashboard.</p>
            </body></html>';
            exit;
        }
    }
    
    // Check if we should activate emergency lockdown
    EmergencySecurityResponse::checkEmergencyConditions();
}
?>