<?php
/**
 * Real-time event handler for bot updates
 * Re-enabled with connection limits to prevent PHP-FPM worker exhaustion
 */

require_once '../config_paths.php';

header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('Connection: keep-alive');
header('X-Accel-Buffering: no'); // Nginx: disable buffering

// Enable output buffering for real-time streaming
if (ob_get_level()) ob_end_clean();
ob_implicit_flush(true);

// Function to send SSE event
function sendSSE($event, $data) {
    echo "event: $event\n";
    echo "data: " . json_encode($data) . "\n\n";
    flush();
}

// Monitor files for changes
$lastModTimes = [];
$monitorFiles = [
    'rizon_log' => ConfigPaths::getLogPath('bot', 'rizon'),
    'libera_log' => ConfigPaths::getLogPath('bot', 'libera'),
    'rizon_db' => ConfigPaths::getDatabase('rizon_bot'),
    'libera_db' => ConfigPaths::getDatabase('libera_bot')
];

// Initial connection message
sendSSE('connected', ['message' => 'Real-time updates connected']);

// Main monitoring loop with connection stability
$iterations = 0;
$maxIterations = 300; // 10 minutes at 2-second intervals

while (true) {
    // Send periodic heartbeat to keep connection alive
    $iterations++;
    if ($iterations % 30 === 0) { // Every 60 seconds
        sendSSE('heartbeat', ['timestamp' => time()]);
    }
    
    // Break after max iterations to prevent infinite loops
    if ($iterations > $maxIterations) {
        sendSSE('timeout', ['message' => 'Connection timeout, please refresh']);
        break;
    }
    
    foreach ($monitorFiles as $key => $file) {
        if (file_exists($file)) {
            $currentMtime = filemtime($file);
            
            if (!isset($lastModTimes[$key])) {
                $lastModTimes[$key] = $currentMtime;
                continue;
            }
            
            if ($currentMtime > $lastModTimes[$key]) {
                $lastModTimes[$key] = $currentMtime;
                
                // Determine event type
                if (strpos($key, 'log') !== false) {
                    $network = str_replace('_log', '', $key);
                    sendSSE('log_update', [
                        'network' => $network,
                        'timestamp' => $currentMtime,
                        'file' => $file
                    ]);
                } elseif (strpos($key, 'db') !== false) {
                    $network = str_replace('_db', '', $key);
                    sendSSE('database_update', [
                        'network' => $network,
                        'timestamp' => $currentMtime,
                        'file' => $file
                    ]);
                }
            }
        }
    }
    
    // Check for client disconnect
    if (connection_aborted()) {
        break;
    }
    
    // Sleep for 2 seconds before next check (reduce CPU usage)
    sleep(2);
}
?>