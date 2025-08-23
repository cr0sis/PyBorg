<?php
/**
 * Simple real-time log streaming - no security hardening
 */

require_once dirname(__DIR__) . '/config_paths.php';

// Set headers for Server-Sent Events
header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('Connection: keep-alive');
header('Access-Control-Allow-Origin: *');

// Disable output buffering
if (ob_get_level()) ob_end_clean();

// Get parameters
$network = $_GET['network'] ?? 'rizon';
$logType = $_GET['type'] ?? 'bot';
$lastPosition = (int)($_GET['position'] ?? 0);

// Validate network
if (!in_array($network, ['rizon', 'libera'])) {
    echo "event: error\n";
    echo "data: Invalid network\n\n";
    flush();
    exit;
}

// Get log file path
$logFile = ConfigPaths::getLogPath($logType, $network);

if (!$logFile || !file_exists($logFile)) {
    echo "event: error\n";
    echo "data: Log file not found\n\n";
    flush();
    exit;
}

// Send connection confirmation
echo "event: connected\n";
echo "data: " . json_encode(['network' => $network, 'type' => $logType]) . "\n\n";
flush();

// Get initial content if starting fresh
if ($lastPosition === 0) {
    $lines = [];
    if (file_exists($logFile)) {
        $allLines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $lines = array_slice($allLines, -50); // Last 50 lines
        $lastPosition = filesize($logFile);
    }
    
    if (!empty($lines)) {
        echo "event: initial\n";
        echo "data: " . json_encode(['lines' => $lines, 'position' => $lastPosition]) . "\n\n";
        flush();
    }
}

// Stream new content
$timeout = 60; // 1 minute timeout
$startTime = time();

while (time() - $startTime < $timeout) {
    if (connection_aborted()) {
        break;
    }
    
    clearstatcache(true, $logFile);
    $newSize = filesize($logFile);
    
    if ($newSize > $lastPosition) {
        $handle = fopen($logFile, 'r');
        if ($handle) {
            fseek($handle, $lastPosition);
            $lines = [];
            
            while (($line = fgets($handle)) !== false) {
                $lines[] = rtrim($line, "\r\n");
            }
            
            $lastPosition = ftell($handle);
            fclose($handle);
            
            if (!empty($lines)) {
                echo "event: update\n";
                echo "data: " . json_encode(['lines' => $lines, 'position' => $lastPosition]) . "\n\n";
                flush();
            }
        }
    }
    
    usleep(500000); // 0.5 second delay
}

echo "event: timeout\n";
echo "data: Stream ended\n\n";
flush();
?>