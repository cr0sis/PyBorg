<?php
require_once 'security_config.php';
require_once 'config_paths.php';
require_once 'crypto_utils.php';

// Game-specific security monitoring - Admin only
session_start();
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    http_response_code(403);
    exit('Access denied');
}

header('Content-Type: application/json');

try {
    $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('game_sessions'));
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    $action = $_GET['action'] ?? 'dashboard';
    
    switch ($action) {
        case 'dashboard':
            // Recent suspicious activities
            $stmt = $pdo->prepare("SELECT * FROM game_sessions 
                                  WHERE status = 'completed' 
                                  AND behavior_flags IS NOT NULL 
                                  ORDER BY last_update DESC LIMIT 20");
            $stmt->execute();
            $suspicious_sessions = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // High-risk sessions in last 24 hours
            $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM game_sessions 
                                  WHERE last_update > ? 
                                  AND behavior_flags LIKE '%HIGH%'");
            $stmt->execute([time() - 86400]);
            $high_risk_count = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
            
            // Top scoring IPs
            $scores_pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('breakout_scores'));
            $stmt = $scores_pdo->prepare("SELECT ip_address, COUNT(*) as games, AVG(score) as avg_score, MAX(score) as max_score 
                                        FROM breakout_scores 
                                        WHERE date_played > datetime('now', '-24 hours')
                                        GROUP BY ip_address 
                                        ORDER BY avg_score DESC LIMIT 10");
            $stmt->execute();
            $top_ips = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            echo json_encode([
                'suspicious_sessions' => $suspicious_sessions,
                'high_risk_count' => $high_risk_count,
                'top_ips' => $top_ips,
                'timestamp' => date('Y-m-d H:i:s')
            ]);
            break;
            
        case 'block_ip':
            $ip = $_POST['ip'] ?? '';
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                echo json_encode(['error' => 'Invalid IP address']);
                exit;
            }
            
            // Add to blocked IPs list
            $blocked_file = '/tmp/blocked_ips.txt';
            file_put_contents($blocked_file, $ip . "\n", FILE_APPEND | LOCK_EX);
            
            echo json_encode(['success' => true, 'message' => "IP $ip blocked"]);
            break;
            
        case 'session_details':
            $session_id = $_GET['session_id'] ?? '';
            $stmt = $pdo->prepare("SELECT * FROM game_sessions WHERE session_id = ?");
            $stmt->execute([$session_id]);
            $session = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($session) {
                $session['behavior_flags'] = json_decode($session['behavior_flags'], true);
                echo json_encode($session);
            } else {
                echo json_encode(['error' => 'Session not found']);
            }
            break;
            
        default:
            echo json_encode(['error' => 'Invalid action']);
    }
    
} catch (Exception $e) {
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}
?>