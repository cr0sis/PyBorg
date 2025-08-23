<?php
/**
 * SSE Connection Manager
 * Optimized Server-Sent Events handler with PHP-FPM protection and connection management
 */

require_once '../security_config.php';
require_once '../secure_admin_functions.php';
require_once '../security_middleware.php';
require_once 'realtime_events_core.php';

class SSEConnectionManager {
    private $sessionId;
    private $lastEventId;
    private $maxExecutionTime = 300; // 5 minutes max
    private $heartbeatInterval = 30; // 30 seconds
    private $eventCheckInterval = 1; // 1 second
    private $connectionStartTime;
    private $eventsCore;
    private $isAuthenticated = false;
    
    public function __construct() {
        $this->sessionId = uniqid('sse_', true);
        $this->connectionStartTime = time();
        $this->eventsCore = new RealtimeEventsCore();
        
        // Validate admin authentication
        $this->validateAuthentication();
    }
    
    /**
     * Validate that user has proper 2FA admin authentication for SSE access
     */
    private function validateAuthentication() {
        try {
            // Start session if needed
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            
            // Basic admin access validation (allow bypassing for SSE auth flow)
            try {
                SecurityMiddleware::validateAdminAccess();
            } catch (Exception $e) {
                // For SSE, try alternative auth methods
                if (!$this->validateSSEToken()) {
                    throw new SecurityException('Admin access required for real-time monitoring');
                }
            }
            
            // Check if this is an authenticated admin user
            if (!isset($_SESSION['user_id']) || !isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
                throw new SecurityException('Admin privileges required for SSE access');
            }
            
            // For SSE connections, allow longer session duration but verify token
            $maxSessionAge = 14400; // 4 hours instead of 8 hours for SSE
            if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) > $maxSessionAge) {
                // Allow session extension if 2FA was recently verified
                if (!$this->canExtendSession()) {
                    throw new SecurityException('Session expired, please re-authenticate');
                }
            }
            
            // For SSE, 2FA can be verified via token instead of session flag
            if (!$this->verify2FAForSSE()) {
                throw new SecurityException('2FA verification required for real-time access');
            }
            
            $this->isAuthenticated = true;
            
        } catch (Exception $e) {
            $this->sendError('Authentication failed: ' . $e->getMessage());
            exit;
        }
    }
    
    /**
     * Alternative SSE token validation (for long-lived connections)
     */
    private function validateSSEToken() {
        // Check for SSE auth token in headers or GET params
        $token = $_SERVER['HTTP_X_SSE_TOKEN'] ?? $_GET['sse_token'] ?? null;
        if (!$token) {
            return false;
        }
        
        // Validate token format and timing
        $tokenParts = explode(':', base64_decode($token));
        if (count($tokenParts) !== 3) {
            return false;
        }
        
        list($userId, $timestamp, $hash) = $tokenParts;
        
        // Check token age (max 5 minutes old)
        if ((time() - intval($timestamp)) > 300) {
            return false;
        }
        
        // Verify token hash (would need user's secret key)
        $expectedHash = hash_hmac('sha256', $userId . ':' . $timestamp, $_SESSION['auth_secret'] ?? 'fallback');
        
        return hash_equals($expectedHash, $hash);
    }
    
    /**
     * Check if session can be extended for SSE
     */
    private function canExtendSession() {
        // Allow extension if 2FA was verified recently (within last 30 minutes)
        if (isset($_SESSION['last_2fa_verification'])) {
            $timeSince2FA = time() - $_SESSION['last_2fa_verification'];
            return $timeSince2FA < 1800; // 30 minutes
        }
        
        return false;
    }
    
    /**
     * Verify 2FA for SSE connections (more flexible than strict session requirement)
     */
    private function verify2FAForSSE() {
        // Check if 2FA is explicitly disabled or bypassed for development
        if (isset($_GET['bypass_2fa']) && $_GET['bypass_2fa'] === 'dev' && 
            ($_SERVER['HTTP_HOST'] === 'localhost' || strpos($_SERVER['HTTP_HOST'], '127.0.0.1') !== false)) {
            error_log("SSE 2FA bypassed for development environment");
            return true;
        }
        
        // Check standard 2FA session flag
        if (isset($_SESSION['2fa_verified']) && $_SESSION['2fa_verified']) {
            return true;
        }
        
        // Alternative: Check if 2FA was verified recently (for session extension)
        if (isset($_SESSION['last_2fa_verification'])) {
            $timeSince2FA = time() - $_SESSION['last_2fa_verification'];
            if ($timeSince2FA < 7200) { // 2 hours for SSE connections
                return true;
            }
        }
        
        // Check for 2FA token in request (for programmatic access)
        $totpCode = $_SERVER['HTTP_X_TOTP_CODE'] ?? $_GET['totp_code'] ?? null;
        if ($totpCode && isset($_SESSION['user_id'])) {
            require_once '../two_factor_auth.php';
            $secret = TwoFactorAuth::getUserSecret($_SESSION['user_id']);
            if ($secret && TwoFactorAuth::verifyTOTP($secret, $totpCode)) {
                $_SESSION['2fa_verified'] = true;
                $_SESSION['last_2fa_verification'] = time();
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Start SSE stream with proper headers and connection management
     */
    public function startStream() {
        if (!$this->isAuthenticated) {
            $this->sendError('Not authenticated');
            return;
        }
        
        // Set SSE headers
        header('Content-Type: text/event-stream');
        header('Cache-Control: no-cache');
        header('Connection: keep-alive');
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Headers: Last-Event-ID');
        
        // Prevent PHP buffering
        if (ob_get_level()) ob_end_clean();
        
        // Set reasonable limits to prevent PHP-FPM exhaustion
        set_time_limit($this->maxExecutionTime);
        ini_set('memory_limit', '32M'); // Limit memory usage
        
        // Get last event ID from client
        $this->lastEventId = intval($_SERVER['HTTP_LAST_EVENT_ID'] ?? $_GET['lastEventId'] ?? 0);
        
        // Send initial connection event
        $this->sendEvent('connection', [
            'session_id' => $this->sessionId,
            'server_time' => time(),
            'message' => 'Real-time connection established'
        ]);
        
        // Main event loop
        $this->eventLoop();
    }
    
    /**
     * Main event processing loop with optimized resource usage
     */
    private function eventLoop() {
        $lastHeartbeat = time();
        $consecutiveEmptyChecks = 0;
        $maxEmptyChecks = 30; // Increase interval after 30 empty checks
        
        while (true) {
            // Check if we've exceeded max execution time
            if ((time() - $this->connectionStartTime) > $this->maxExecutionTime) {
                $this->sendEvent('timeout', ['message' => 'Connection timeout, reconnecting...']);
                break;
            }
            
            // Check if client disconnected
            if (connection_aborted()) {
                error_log("SSE client disconnected: {$this->sessionId}");
                break;
            }
            
            // Send heartbeat periodically
            if ((time() - $lastHeartbeat) > $this->heartbeatInterval) {
                $this->sendHeartbeat();
                $lastHeartbeat = time();
            }
            
            // Check for new events
            $events = $this->eventsCore->getPendingEvents($this->sessionId, $this->lastEventId);
            
            if (!empty($events)) {
                $this->processEvents($events);
                $consecutiveEmptyChecks = 0;
            } else {
                $consecutiveEmptyChecks++;
                
                // Gradually increase sleep time for idle connections
                if ($consecutiveEmptyChecks > $maxEmptyChecks) {
                    sleep(3); // Longer sleep for idle connections
                } else {
                    sleep($this->eventCheckInterval);
                }
            }
            
            // Flush output to client
            if (ob_get_level()) ob_flush();
            flush();
            
            // Clean up old events and process trigger queues periodically
            if ((time() - $this->connectionStartTime) % 60 == 0) {
                $this->eventsCore->cleanupOldEvents();
                $this->eventsCore->processTriggerQueues();
            }
        }
    }
    
    /**
     * Process and send events to client
     */
    private function processEvents($events) {
        $eventIds = [];
        
        foreach ($events as $event) {
            $this->sendEvent($event['event_type'], json_decode($event['data'], true), $event['id']);
            $this->lastEventId = $event['id'];
            $eventIds[] = $event['id'];
        }
        
        // Mark events as consumed
        if (!empty($eventIds)) {
            $this->eventsCore->markEventsConsumed($eventIds);
        }
    }
    
    /**
     * Send SSE event to client
     */
    private function sendEvent($type, $data, $id = null) {
        if ($id !== null) {
            echo "id: {$id}\n";
        }
        
        echo "event: {$type}\n";
        echo "data: " . json_encode($data) . "\n\n";
        
        // Immediate flush for real-time delivery
        if (ob_get_level()) ob_flush();
        flush();
    }
    
    /**
     * Send heartbeat to keep connection alive
     */
    private function sendHeartbeat() {
        $this->sendEvent('heartbeat', [
            'timestamp' => time(),
            'session_id' => $this->sessionId,
            'uptime' => time() - $this->connectionStartTime
        ]);
    }
    
    /**
     * Send error event and terminate
     */
    private function sendError($message) {
        $this->sendEvent('error', ['message' => $message]);
        if (ob_get_level()) ob_flush();
        flush();
    }
    
    /**
     * Get connection statistics
     */
    public function getConnectionStats() {
        return [
            'session_id' => $this->sessionId,
            'uptime' => time() - $this->connectionStartTime,
            'last_event_id' => $this->lastEventId,
            'is_authenticated' => $this->isAuthenticated,
            'memory_usage' => memory_get_usage(true),
            'memory_peak' => memory_get_peak_usage(true)
        ];
    }
}

// Connection timeout handler
register_shutdown_function(function() {
    if (connection_aborted()) {
        error_log("SSE connection terminated: " . ($_GET['session_id'] ?? 'unknown'));
    }
});

// Handle the SSE request
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    try {
        $manager = new SSEConnectionManager();
        $manager->startStream();
    } catch (Exception $e) {
        error_log("SSE Connection Manager Error: " . $e->getMessage());
        header('HTTP/1.1 500 Internal Server Error');
        echo "data: " . json_encode(['error' => 'Connection failed']) . "\n\n";
    }
} else {
    header('HTTP/1.1 405 Method Not Allowed');
    echo json_encode(['error' => 'Only GET method allowed']);
}
?>