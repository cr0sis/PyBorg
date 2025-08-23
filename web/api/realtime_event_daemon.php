#!/usr/bin/env php
<?php
/**
 * Real-time Event Processing Daemon
 * Processes trigger queues from bot databases and manages event lifecycle
 */

// Prevent web access
if (isset($_SERVER['REQUEST_METHOD'])) {
    header('HTTP/1.1 403 Forbidden');
    exit('Command line only');
}

require_once 'realtime_events_core.php';

class RealtimeEventDaemon {
    private $eventsCore;
    private $isRunning = false;
    private $pidFile = '/tmp/realtime_event_daemon.pid';
    private $logFile = '/data/cr0_system/logs/realtime_events.log';
    
    public function __construct() {
        $this->eventsCore = new RealtimeEventsCore();
        
        // Setup signal handlers for graceful shutdown
        if (function_exists('pcntl_signal')) {
            pcntl_signal(SIGTERM, [$this, 'shutdown']);
            pcntl_signal(SIGINT, [$this, 'shutdown']);
        }
    }
    
    /**
     * Start the daemon
     */
    public function start($daemonize = false) {
        if ($this->isRunning()) {
            $this->log('Daemon already running');
            return false;
        }
        
        if ($daemonize) {
            $this->daemonize();
        }
        
        $this->writePidFile();
        $this->isRunning = true;
        
        $this->log('Real-time event daemon started');
        
        $this->run();
    }
    
    /**
     * Main daemon loop
     */
    private function run() {
        $lastCleanup = 0;
        $lastStats = 0;
        
        while ($this->isRunning) {
            try {
                // Process trigger queues from bot databases
                $this->eventsCore->processTriggerQueues();
                
                // Cleanup old events every 5 minutes
                if ((time() - $lastCleanup) > 300) {
                    $this->eventsCore->cleanupOldEvents();
                    $lastCleanup = time();
                }
                
                // Log statistics every 10 minutes
                if ((time() - $lastStats) > 600) {
                    $stats = $this->eventsCore->getEventStats();
                    $this->log("Event stats: " . json_encode($stats));
                    $lastStats = time();
                }
                
                // Handle signals
                if (function_exists('pcntl_signal_dispatch')) {
                    pcntl_signal_dispatch();
                }
                
                // Sleep for 5 seconds between cycles
                sleep(5);
                
            } catch (Exception $e) {
                $this->log('Error in daemon loop: ' . $e->getMessage());
                sleep(10); // Longer sleep on error
            }
        }
        
        $this->cleanup();
    }
    
    /**
     * Stop the daemon
     */
    public function stop() {
        if (!$this->isRunning()) {
            $this->log('Daemon not running');
            return false;
        }
        
        $pid = $this->getPid();
        if ($pid && posix_kill($pid, SIGTERM)) {
            $this->log('Daemon stop signal sent');
            return true;
        }
        
        return false;
    }
    
    /**
     * Get daemon status
     */
    public function status() {
        if ($this->isRunning()) {
            $pid = $this->getPid();
            echo "Daemon running (PID: $pid)\n";
            
            // Show recent stats
            $stats = $this->eventsCore->getEventStats();
            echo "Event Statistics:\n";
            echo "  Total events: " . $stats['total_events'] . "\n";
            echo "  Pending events: " . $stats['pending_events'] . "\n";
            
            if (!empty($stats['by_type'])) {
                echo "  By type:\n";
                foreach ($stats['by_type'] as $type => $count) {
                    echo "    $type: $count\n";
                }
            }
        } else {
            echo "Daemon not running\n";
        }
    }
    
    /**
     * Daemonize the process
     */
    private function daemonize() {
        $pid = pcntl_fork();
        
        if ($pid == -1) {
            throw new Exception('Could not fork process');
        } elseif ($pid) {
            // Parent process
            exit(0);
        }
        
        // Child process
        if (posix_setsid() == -1) {
            throw new Exception('Could not detach from terminal');
        }
        
        // Change working directory
        chdir('/');
        
        // Close file descriptors
        fclose(STDIN);
        fclose(STDOUT);
        fclose(STDERR);
    }
    
    /**
     * Check if daemon is running
     */
    private function isRunning() {
        if (!file_exists($this->pidFile)) {
            return false;
        }
        
        $pid = trim(file_get_contents($this->pidFile));
        
        // Check if process exists
        return $pid && posix_kill($pid, 0);
    }
    
    /**
     * Get daemon PID
     */
    private function getPid() {
        if (!file_exists($this->pidFile)) {
            return false;
        }
        
        return trim(file_get_contents($this->pidFile));
    }
    
    /**
     * Write PID file
     */
    private function writePidFile() {
        file_put_contents($this->pidFile, getmypid());
    }
    
    /**
     * Graceful shutdown handler
     */
    public function shutdown() {
        $this->log('Received shutdown signal');
        $this->isRunning = false;
    }
    
    /**
     * Cleanup on exit
     */
    private function cleanup() {
        $this->log('Daemon shutting down');
        
        if (file_exists($this->pidFile)) {
            unlink($this->pidFile);
        }
    }
    
    /**
     * Log messages
     */
    private function log($message) {
        $timestamp = date('Y-m-d H:i:s');
        $logMessage = "[$timestamp] $message\n";
        
        // Create log directory if needed
        $logDir = dirname($this->logFile);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        
        file_put_contents($this->logFile, $logMessage, FILE_APPEND | LOCK_EX);
        
        // Also output to console if not daemonized
        if (!$this->isRunning || isset($_SERVER['TERM'])) {
            echo $logMessage;
        }
    }
}

// Command line interface
if ($argc < 2) {
    echo "Usage: {$argv[0]} {start|stop|restart|status} [--daemon]\n";
    exit(1);
}

$command = $argv[1];
$daemon = new RealtimeEventDaemon();

switch ($command) {
    case 'start':
        $daemonize = in_array('--daemon', $argv);
        $daemon->start($daemonize);
        break;
        
    case 'stop':
        $daemon->stop();
        break;
        
    case 'restart':
        $daemon->stop();
        sleep(2);
        $daemonize = in_array('--daemon', $argv);
        $daemon->start($daemonize);
        break;
        
    case 'status':
        $daemon->status();
        break;
        
    default:
        echo "Unknown command: $command\n";
        exit(1);
}
?>