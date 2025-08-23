<?php
/**
 * Real-time Events Core System
 * Manages event generation, queuing, and SQLite triggers for real-time data propagation
 */

require_once '../security_config.php';
require_once '../secure_admin_functions.php';
require_once '../config_paths.php';

class RealtimeEventsCore {
    private $eventDbPath;
    private $eventQueue;
    private $maxEventAge = 300; // 5 minutes
    
    public function __construct() {
        $this->eventDbPath = '/data/cr0_system/databases/realtime_events.db';
        $this->initializeEventSystem();
    }
    
    /**
     * Initialize the event system database and triggers
     */
    private function initializeEventSystem() {
        try {
            $db = new SQLite3($this->eventDbPath);
            $db->enableExceptions(true);
            
            // Create events table
            $db->exec('
                CREATE TABLE IF NOT EXISTS realtime_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    data TEXT NOT NULL,
                    source_table TEXT,
                    source_id INTEGER,
                    timestamp INTEGER NOT NULL,
                    consumed INTEGER DEFAULT 0,
                    session_id TEXT
                )
            ');
            
            // Create index for faster querying
            $db->exec('
                CREATE INDEX IF NOT EXISTS idx_events_type_timestamp 
                ON realtime_events(event_type, timestamp)
            ');
            
            $db->exec('
                CREATE INDEX IF NOT EXISTS idx_events_consumed 
                ON realtime_events(consumed, timestamp)
            ');
            
            // Create bot status tracking table
            $db->exec('
                CREATE TABLE IF NOT EXISTS bot_status_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    network TEXT NOT NULL,
                    status TEXT NOT NULL,
                    pid INTEGER,
                    uptime INTEGER DEFAULT 0,
                    timestamp INTEGER NOT NULL,
                    change_type TEXT NOT NULL
                )
            ');
            
            $db->close();
            
            // Setup triggers on other databases
            $this->setupDatabaseTriggers();
            
        } catch (Exception $e) {
            error_log("Failed to initialize event system: " . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Setup triggers on existing databases to generate events
     */
    private function setupDatabaseTriggers() {
        $databases = [
            'rizon_bot.db' => 'rizon',
            'libera_bot.db' => 'libera'
        ];
        
        foreach ($databases as $dbFile => $network) {
            $dbPath = "/data/cr0_system/databases/{$dbFile}";
            if (!file_exists($dbPath)) continue;
            
            try {
                $db = new SQLite3($dbPath);
                $db->enableExceptions(true);
                
                // Create event trigger table within this database
                $db->exec("
                    CREATE TABLE IF NOT EXISTS realtime_event_queue (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        event_data TEXT NOT NULL,
                        network TEXT NOT NULL,
                        timestamp INTEGER DEFAULT (strftime('%s', 'now')),
                        processed INTEGER DEFAULT 0
                    )
                ");
                
                // Add trigger for user_scores changes (games, achievements)
                $db->exec("
                    CREATE TRIGGER IF NOT EXISTS trigger_user_scores_realtime
                    AFTER UPDATE ON user_scores
                    BEGIN
                        INSERT INTO realtime_event_queue (event_type, event_data, network)
                        SELECT 
                            'user_score_updated',
                            json_object(
                                'network', '{$network}',
                                'user', NEW.user,
                                'game_type', NEW.game_type,
                                'score', NEW.score,
                                'best_score', NEW.best_score,
                                'games_played', NEW.games_played,
                                'old_score', OLD.score,
                                'old_best_score', OLD.best_score
                            ),
                            '{$network}'
                        WHERE OLD.score != NEW.score OR OLD.best_score != NEW.best_score;
                    END
                ");
                
                // Add trigger for new conversation entries
                $db->exec("
                    DROP TRIGGER IF EXISTS trigger_conversation_realtime
                ");
                
                $db->exec("
                    CREATE TRIGGER trigger_conversation_realtime
                    AFTER INSERT ON conversation_history
                    BEGIN
                        INSERT INTO realtime_event_queue (event_type, event_data, network)
                        VALUES (
                            'new_conversation',
                            json_object(
                                'network', '{$network}',
                                'user', NEW.user,
                                'message_preview', substr(NEW.message, 1, 100),
                                'timestamp', NEW.timestamp
                            ),
                            '{$network}'
                        );
                    END
                ");
                
                $db->close();
                
            } catch (Exception $e) {
                error_log("Failed to setup triggers for {$dbFile}: " . $e->getMessage());
            }
        }
    }
    
    /**
     * Generate a bot status change event
     */
    public function generateBotStatusEvent($network, $status, $pid = null, $uptime = 0, $changeType = 'status_change') {
        try {
            $db = new SQLite3($this->eventDbPath);
            $db->enableExceptions(true);
            
            // Insert status event
            $stmt = $db->prepare('
                INSERT INTO bot_status_events (network, status, pid, uptime, change_type, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ');
            $stmt->bindValue(1, $network, SQLITE3_TEXT);
            $stmt->bindValue(2, $status, SQLITE3_TEXT);
            $stmt->bindValue(3, $pid, SQLITE3_INTEGER);
            $stmt->bindValue(4, $uptime, SQLITE3_INTEGER);
            $stmt->bindValue(5, $changeType, SQLITE3_TEXT);
            $stmt->bindValue(6, time(), SQLITE3_INTEGER);
            $stmt->execute();
            
            // Generate real-time event
            $eventData = json_encode([
                'network' => $network,
                'status' => $status,
                'pid' => $pid,
                'uptime' => $uptime,
                'timestamp' => time(),
                'change_type' => $changeType
            ]);
            
            $stmt = $db->prepare('
                INSERT INTO realtime_events (event_type, data, source_table, timestamp)
                VALUES (?, ?, ?, ?)
            ');
            $stmt->bindValue(1, 'bot_status_change', SQLITE3_TEXT);
            $stmt->bindValue(2, $eventData, SQLITE3_TEXT);
            $stmt->bindValue(3, 'bot_status_events', SQLITE3_TEXT);
            $stmt->bindValue(4, time(), SQLITE3_INTEGER);
            $stmt->execute();
            
            $db->close();
            
        } catch (Exception $e) {
            error_log("Failed to generate bot status event: " . $e->getMessage());
        }
    }
    
    /**
     * Get pending events for SSE stream
     */
    public function getPendingEvents($sessionId = null, $lastEventId = 0) {
        try {
            $db = new SQLite3($this->eventDbPath);
            $db->enableExceptions(true);
            
            $query = '
                SELECT id, event_type, data, timestamp
                FROM realtime_events 
                WHERE id > ? AND consumed = 0
                ORDER BY id ASC 
                LIMIT 50
            ';
            
            $stmt = $db->prepare($query);
            $stmt->bindValue(1, $lastEventId, SQLITE3_INTEGER);
            $result = $stmt->execute();
            
            $events = [];
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $events[] = $row;
            }
            
            $db->close();
            return $events;
            
        } catch (Exception $e) {
            error_log("Failed to get pending events: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Mark events as consumed
     */
    public function markEventsConsumed($eventIds) {
        if (empty($eventIds)) return;
        
        try {
            $db = new SQLite3($this->eventDbPath);
            $db->enableExceptions(true);
            
            $placeholders = str_repeat('?,', count($eventIds) - 1) . '?';
            $query = "UPDATE realtime_events SET consumed = 1 WHERE id IN ({$placeholders})";
            
            $stmt = $db->prepare($query);
            foreach ($eventIds as $index => $eventId) {
                $stmt->bindValue($index + 1, $eventId, SQLITE3_INTEGER);
            }
            $stmt->execute();
            
            $db->close();
            
        } catch (Exception $e) {
            error_log("Failed to mark events as consumed: " . $e->getMessage());
        }
    }
    
    /**
     * Clean up old events to prevent database bloat
     */
    public function cleanupOldEvents() {
        try {
            $db = new SQLite3($this->eventDbPath);
            $db->enableExceptions(true);
            
            $cutoffTime = time() - $this->maxEventAge;
            
            $stmt = $db->prepare('
                DELETE FROM realtime_events 
                WHERE timestamp < ? AND consumed = 1
            ');
            $stmt->bindValue(1, $cutoffTime, SQLITE3_INTEGER);
            $stmt->execute();
            
            // Also clean up old bot status events
            $stmt = $db->prepare('
                DELETE FROM bot_status_events 
                WHERE timestamp < ?
            ');
            $stmt->bindValue(1, $cutoffTime, SQLITE3_INTEGER);
            $stmt->execute();
            
            $db->close();
            
        } catch (Exception $e) {
            error_log("Failed to cleanup old events: " . $e->getMessage());
        }
    }
    
    /**
     * Process trigger queues from individual bot databases
     */
    public function processTriggerQueues() {
        $databases = [
            'rizon_bot.db' => 'rizon',
            'libera_bot.db' => 'libera'
        ];
        
        foreach ($databases as $dbFile => $network) {
            $dbPath = "/data/cr0_system/databases/{$dbFile}";
            if (!file_exists($dbPath)) continue;
            
            try {
                $botDb = new SQLite3($dbPath);
                $botDb->enableExceptions(true);
                
                // Check if queue table exists
                $result = $botDb->query("SELECT name FROM sqlite_master WHERE type='table' AND name='realtime_event_queue'");
                if (!$result->fetchArray()) {
                    $botDb->close();
                    continue;
                }
                
                // Get unprocessed events
                $result = $botDb->query('SELECT * FROM realtime_event_queue WHERE processed = 0 ORDER BY id ASC LIMIT 100');
                $events = [];
                $eventIds = [];
                
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    $events[] = $row;
                    $eventIds[] = $row['id'];
                }
                
                if (!empty($events)) {
                    // Transfer events to central database
                    $eventsDb = new SQLite3($this->eventDbPath);
                    $eventsDb->enableExceptions(true);
                    
                    foreach ($events as $event) {
                        $stmt = $eventsDb->prepare('
                            INSERT INTO realtime_events (event_type, data, source_table, timestamp)
                            VALUES (?, ?, ?, ?)
                        ');
                        $stmt->bindValue(1, $event['event_type'], SQLITE3_TEXT);
                        $stmt->bindValue(2, $event['event_data'], SQLITE3_TEXT);
                        $stmt->bindValue(3, $network . '_bot_database', SQLITE3_TEXT);
                        $stmt->bindValue(4, $event['timestamp'], SQLITE3_INTEGER);
                        $stmt->execute();
                    }
                    
                    $eventsDb->close();
                    
                    // Mark events as processed
                    $placeholders = str_repeat('?,', count($eventIds) - 1) . '?';
                    $stmt = $botDb->prepare("UPDATE realtime_event_queue SET processed = 1 WHERE id IN ({$placeholders})");
                    foreach ($eventIds as $index => $eventId) {
                        $stmt->bindValue($index + 1, $eventId, SQLITE3_INTEGER);
                    }
                    $stmt->execute();
                }
                
                $botDb->close();
                
            } catch (Exception $e) {
                error_log("Failed to process trigger queue for {$dbFile}: " . $e->getMessage());
            }
        }
    }
    
    /**
     * Get event statistics
     */
    public function getEventStats() {
        try {
            $db = new SQLite3($this->eventDbPath);
            $db->enableExceptions(true);
            
            $stats = [];
            
            // Total events
            $result = $db->query('SELECT COUNT(*) as total FROM realtime_events');
            $stats['total_events'] = $result->fetchArray()['total'];
            
            // Pending events
            $result = $db->query('SELECT COUNT(*) as pending FROM realtime_events WHERE consumed = 0');
            $stats['pending_events'] = $result->fetchArray()['pending'];
            
            // Events by type
            $result = $db->query('
                SELECT event_type, COUNT(*) as count 
                FROM realtime_events 
                WHERE consumed = 0 
                GROUP BY event_type
            ');
            $stats['by_type'] = [];
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $stats['by_type'][$row['event_type']] = $row['count'];
            }
            
            $db->close();
            return $stats;
            
        } catch (Exception $e) {
            error_log("Failed to get event stats: " . $e->getMessage());
            return ['error' => $e->getMessage()];
        }
    }
}

// Initialize global instance
$GLOBALS['realtimeEventsCore'] = new RealtimeEventsCore();

/**
 * Convenience function for other scripts to generate events
 */
function generateRealtimeEvent($eventType, $data, $sourceTable = null, $sourceId = null) {
    global $realtimeEventsCore;
    
    try {
        $db = new SQLite3('/data/cr0_system/databases/realtime_events.db');
        $db->enableExceptions(true);
        
        $stmt = $db->prepare('
            INSERT INTO realtime_events (event_type, data, source_table, source_id, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ');
        $stmt->bindValue(1, $eventType, SQLITE3_TEXT);
        $stmt->bindValue(2, is_array($data) ? json_encode($data) : $data, SQLITE3_TEXT);
        $stmt->bindValue(3, $sourceTable, SQLITE3_TEXT);
        $stmt->bindValue(4, $sourceId, SQLITE3_INTEGER);
        $stmt->bindValue(5, time(), SQLITE3_INTEGER);
        $stmt->execute();
        
        $db->close();
        
    } catch (Exception $e) {
        error_log("Failed to generate realtime event: " . $e->getMessage());
    }
}
?>