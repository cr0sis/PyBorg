<?php
/**
 * Real-time Event Generator
 * Generates events from database changes and system updates
 */

require_once '/var/www/html/config_paths.php';

class EventGenerator {
    private static $eventQueueDir = '/data/cr0_system/realtime_events/';
    private static $lastProcessedFile = '/tmp/last_processed_events.json';
    
    /**
     * Generate event from database change
     */
    public static function generateEvent($type, $data, $priority = 'normal') {
        $eventId = microtime(true) * 10000; // Microsecond precision
        $eventFile = self::$eventQueueDir . $type . '/' . $eventId . '.json';
        
        $eventData = [
            'timestamp' => time(),
            'priority' => $priority,
            'data' => $data
        ];
        
        // Ensure directory exists  
        $dir = dirname($eventFile);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
        
        return file_put_contents($eventFile, json_encode($eventData));
    }
    
    /**
     * Monitor bot status changes
     */
    public static function monitorBotStatus() {
        $statusFiles = [
            'rizon' => '/data/cr0_system/bot_status/rizon_status.json',
            'libera' => '/data/cr0_system/bot_status/libera_status.json'
        ];
        
        $lastProcessed = self::getLastProcessed();
        
        foreach ($statusFiles as $network => $file) {
            if (!file_exists($file)) continue;
            
            $modTime = filemtime($file);
            $key = "bot_status_{$network}";
            
            if (!isset($lastProcessed[$key]) || $modTime > $lastProcessed[$key]) {
                $statusData = json_decode(file_get_contents($file), true);
                if ($statusData) {
                    self::generateEvent('bot_status', [
                        'network' => $network,
                        'status' => $statusData
                    ], 'high');
                    
                    $lastProcessed[$key] = $modTime;
                }
            }
        }
        
        self::saveLastProcessed($lastProcessed);
    }
    
    /**
     * Monitor database changes for commands
     */
    public static function monitorCommandChanges() {
        $databases = [
            'rizon' => '/data/cr0_system/databases/rizon_bot.db',
            'libera' => '/data/cr0_system/databases/libera_bot.db'
        ];
        
        $lastProcessed = self::getLastProcessed();
        
        foreach ($databases as $network => $dbPath) {
            if (!file_exists($dbPath)) continue;
            
            try {
                $pdo = new PDO("sqlite:$dbPath");
                $key = "commands_{$network}";
                
                // Get latest command timestamp
                $stmt = $pdo->prepare("SELECT * FROM command_usage ORDER BY timestamp DESC LIMIT 1");
                $stmt->execute();
                $latestCommand = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($latestCommand) {
                    $commandTime = strtotime($latestCommand['timestamp']);
                    
                    if (!isset($lastProcessed[$key]) || $commandTime > $lastProcessed[$key]) {
                        self::generateEvent('commands', [
                            'network' => $network,
                            'command' => $latestCommand
                        ], 'normal');
                        
                        $lastProcessed[$key] = $commandTime;
                    }
                }
            } catch (Exception $e) {
                error_log("Error monitoring commands for $network: " . $e->getMessage());
            }
        }
        
        self::saveLastProcessed($lastProcessed);
    }
    
    /**
     * Monitor security events
     */
    public static function monitorSecurityEvents() {
        $securityLog = '/tmp/admin_security.log';
        if (!file_exists($securityLog)) return;
        
        $lastProcessed = self::getLastProcessed();
        $key = 'security_events';
        $modTime = filemtime($securityLog);
        
        if (!isset($lastProcessed[$key]) || $modTime > $lastProcessed[$key]) {
            // Read last few lines of security log
            $lines = array_slice(file($securityLog), -5);
            
            foreach ($lines as $line) {
                $event = json_decode(trim($line), true);
                if ($event && $event['timestamp'] > ($lastProcessed[$key] ?? 0)) {
                    self::generateEvent('security', [
                        'event' => $event
                    ], $event['severity'] === 'HIGH' ? 'high' : 'normal');
                }
            }
            
            $lastProcessed[$key] = $modTime;
            self::saveLastProcessed($lastProcessed);
        }
    }
    
    /**
     * Get last processed timestamps
     */
    private static function getLastProcessed() {
        if (!file_exists(self::$lastProcessedFile)) {
            return [];
        }
        
        $data = file_get_contents(self::$lastProcessedFile);
        return json_decode($data, true) ?: [];
    }
    
    /**
     * Save last processed timestamps
     */
    private static function saveLastProcessed($data) {
        file_put_contents(self::$lastProcessedFile, json_encode($data));
    }
    
    /**
     * Run all monitoring tasks
     */
    public static function runMonitoring() {
        self::monitorBotStatus();
        self::monitorCommandChanges();
        self::monitorSecurityEvents();
    }
}

// If called directly, run monitoring
if (basename(__FILE__) == basename($_SERVER['SCRIPT_NAME'])) {
    EventGenerator::runMonitoring();
    echo "Event monitoring completed\n";
}
?>