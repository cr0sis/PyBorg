<?php
/**
 * Real-time log streaming using Server-Sent Events (SSE)
 * Watches log files for changes and streams new content to browser
 */

require_once dirname(__DIR__) . '/config_paths.php';

// Set headers for Server-Sent Events
header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('Connection: keep-alive');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Cache-Control');

// Disable output buffering and enable auto-flush
if (ob_get_level()) ob_end_clean();
ini_set('output_buffering', 'off');
ini_set('zlib.output_compression', false);

// Get parameters
$network = $_GET['network'] ?? 'rizon';
$logType = $_GET['type'] ?? 'bot';
$lastPosition = (int)($_GET['position'] ?? 0);

// Validate network
if (!in_array($network, ['rizon', 'libera'])) {
    echo "event: error\n";
    echo "data: Invalid network specified\n\n";
    flush();
    exit;
}

// Validate log type
$validTypes = ['bot', 'errors', 'startup'];
if (!in_array($logType, $validTypes)) {
    echo "event: error\n";
    echo "data: Invalid log type specified\n\n";
    flush();
    exit;
}

// Get log file path
if ($logType === 'bot') {
    $logFile = ConfigPaths::getLogPath('bot', $network);
} else {
    // For other log types, construct path manually
    $logFile = "/data/cr0_system/logs/irc_networks/{$network}/{$network}_{$logType}.log";
}

if (!file_exists($logFile)) {
    echo "event: error\n";
    echo "data: Log file not found: {$logFile}\n\n";
    flush();
    exit;
}

// Function to send SSE message
function sendSSE($event, $data, $id = null) {
    if ($id !== null) {
        echo "id: {$id}\n";
    }
    echo "event: {$event}\n";
    echo "data: " . json_encode($data) . "\n\n";
    flush();
}

// Function to get file size
function getFileSize($file) {
    clearstatcache(true, $file);
    return file_exists($file) ? filesize($file) : 0;
}

// Function to read new lines from position
function readNewLines($file, $position) {
    if (!file_exists($file)) {
        return ['lines' => [], 'newPosition' => $position];
    }
    
    $handle = fopen($file, 'r');
    if (!$handle) {
        return ['lines' => [], 'newPosition' => $position];
    }
    
    fseek($handle, $position);
    $lines = [];
    
    while (($line = fgets($handle)) !== false) {
        $lines[] = rtrim($line, "\r\n");
    }
    
    $newPosition = ftell($handle);
    fclose($handle);
    
    return ['lines' => $lines, 'newPosition' => $newPosition];
}

// Send initial connection confirmation
sendSSE('connected', [
    'message' => 'Connected to log stream',
    'network' => $network,
    'type' => $logType,
    'file' => basename($logFile)
]);

// Get initial file size
$currentSize = getFileSize($logFile);
if ($lastPosition === 0) {
    // If starting fresh, get last 50 lines
    $lines = [];
    if (file_exists($logFile)) {
        $allLines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $lines = array_slice($allLines, -50); // Last 50 lines
        $lastPosition = $currentSize;
    }
    
    if (!empty($lines)) {
        sendSSE('initial', [
            'lines' => $lines,
            'position' => $lastPosition
        ]);
    }
}

// Main streaming loop
$timeout = 300; // 5 minutes timeout
$startTime = time();
$checkInterval = 500000; // 0.5 seconds in microseconds

while (time() - $startTime < $timeout) {
    // Check for client disconnect
    if (connection_aborted()) {
        break;
    }
    
    $newSize = getFileSize($logFile);
    
    // If file has grown, read new content
    if ($newSize > $currentSize) {
        $result = readNewLines($logFile, $lastPosition);
        
        if (!empty($result['lines'])) {
            sendSSE('update', [
                'lines' => $result['lines'],
                'position' => $result['newPosition'],
                'timestamp' => time()
            ]);
            
            $lastPosition = $result['newPosition'];
        }
        
        $currentSize = $newSize;
    }
    // If file has shrunk (rotated), restart from beginning
    elseif ($newSize < $currentSize) {
        $lastPosition = 0;
        $currentSize = $newSize;
        
        sendSSE('rotated', [
            'message' => 'Log file rotated, restarting stream',
            'position' => 0
        ]);
    }
    
    // Send keepalive every 30 seconds
    if (time() % 30 === 0) {
        sendSSE('keepalive', [
            'timestamp' => time(),
            'position' => $lastPosition
        ]);
    }
    
    // Small delay to prevent excessive CPU usage
    usleep($checkInterval);
}

// Connection timeout
sendSSE('timeout', ['message' => 'Stream timeout reached']);
?>