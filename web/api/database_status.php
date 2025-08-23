<?php
require_once '../security_middleware.php';
require_once '../config_paths.php';

// Initialize security
SecurityMiddleware::validateAdminAccess();

header('Content-Type: application/json');
// Secure CORS implementation
SecurityMiddleware::generateSecureCORS();

try {
    $rizon_db_path = ConfigPaths::getDatabase('rizon_bot');
    $libera_db_path = ConfigPaths::getDatabase('libera_bot');
    
    // Get database file info
    $rizon_exists = file_exists($rizon_db_path);
    $libera_exists = file_exists($libera_db_path);
    
    $rizon_size = $rizon_exists ? filesize($rizon_db_path) : 0;
    $libera_size = $libera_exists ? filesize($libera_db_path) : 0;
    
    $rizon_mtime = $rizon_exists ? filemtime($rizon_db_path) : 0;
    $libera_mtime = $libera_exists ? filemtime($libera_db_path) : 0;
    
    // Get the most recent sync time
    $latest_sync = max($rizon_mtime, $libera_mtime);
    $sync_age_seconds = time() - $latest_sync;
    
    // Determine sync status
    $status = 'healthy';
    $status_color = '#059669'; // green
    
    if ($sync_age_seconds > 300) { // 5 minutes
        $status = 'warning';
        $status_color = '#d97706'; // orange
    }
    
    if ($sync_age_seconds > 900) { // 15 minutes
        $status = 'critical';
        $status_color = '#dc2626'; // red
    }
    
    // Format sync age
    function formatSyncAge($seconds) {
        if ($seconds < 60) {
            return $seconds . ' seconds ago';
        } elseif ($seconds < 3600) {
            $minutes = floor($seconds / 60);
            return $minutes . ' minute' . ($minutes != 1 ? 's' : '') . ' ago';
        } else {
            $hours = floor($seconds / 3600);
            $remaining_minutes = floor(($seconds % 3600) / 60);
            $result = $hours . ' hour' . ($hours != 1 ? 's' : '');
            if ($remaining_minutes > 0) {
                $result .= ', ' . $remaining_minutes . ' minute' . ($remaining_minutes != 1 ? 's' : '');
            }
            return $result . ' ago';
        }
    }
    
    // Format file sizes
    function formatFileSize($bytes) {
        if ($bytes >= 1048576) {
            return round($bytes / 1048576, 1) . ' MB';
        } elseif ($bytes >= 1024) {
            return round($bytes / 1024, 1) . ' KB';
        } else {
            return $bytes . ' bytes';
        }
    }
    
    $response = [
        'success' => true,
        'rizon' => [
            'exists' => $rizon_exists,
            'size' => formatFileSize($rizon_size),
            'size_bytes' => $rizon_size,
            'last_modified' => $rizon_mtime,
            'last_modified_iso' => date('c', $rizon_mtime)
        ],
        'libera' => [
            'exists' => $libera_exists,
            'size' => formatFileSize($libera_size),
            'size_bytes' => $libera_size,
            'last_modified' => $libera_mtime,
            'last_modified_iso' => date('c', $libera_mtime)
        ],
        'sync_status' => [
            'last_sync_timestamp' => $latest_sync,
            'last_sync_iso' => date('c', $latest_sync),
            'sync_age_seconds' => $sync_age_seconds,
            'sync_age_formatted' => formatSyncAge($sync_age_seconds),
            'status' => $status,
            'status_color' => $status_color
        ]
    ];
    
    echo json_encode($response);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Failed to get database status: ' . $e->getMessage()
    ]);
}
?>