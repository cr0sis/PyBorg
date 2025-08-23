<?php
/**
 * Simple security events reader for the embedded admin panel
 */

require_once 'config_paths.php';

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

try {
    $eventsFile = ConfigPaths::getLogPath('security_events');
    
    if (file_exists($eventsFile)) {
        $events = json_decode(file_get_contents($eventsFile), true);
        
        if (is_array($events)) {
            // Return last 20 events
            $recentEvents = array_slice($events, -20);
            echo json_encode($recentEvents);
        } else {
            echo json_encode([]);
        }
    } else {
        echo json_encode([]);
    }
} catch (Exception $e) {
    echo json_encode([]);
}
?>