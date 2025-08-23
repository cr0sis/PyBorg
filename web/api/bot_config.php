<?php
/**
 * Bot Configuration API
 * Manages bot settings like rate limits, channels, and prefixes
 */

require_once '../security_middleware.php';
require_once '../config_paths.php';

// Initialize security
SecurityMiddleware::validateAdminAccess();

header('Content-Type: application/json');
// Secure CORS implementation
SecurityMiddleware::generateSecureCORS();
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Database connections
$rizon_db = new SQLite3(ConfigPaths::getDatabase('rizon'));
$libera_db = new SQLite3(ConfigPaths::getDatabase('libera'));

function get_database($network) {
    global $rizon_db, $libera_db;
    switch (strtolower($network)) {
        case 'rizon':
            return $rizon_db;
        case 'libera':
            return $libera_db;
        default:
            return null;
    }
}

function convert_value($value_str, $type) {
    switch ($type) {
        case 'int':
            return intval($value_str);
        case 'float':
            return floatval($value_str);
        case 'bool':
            return $value_str === '1';
        case 'json':
            return json_decode($value_str, true);
        default:
            return $value_str;
    }
}

function store_value($value, $type) {
    switch ($type) {
        case 'json':
            return json_encode($value);
        case 'bool':
            return $value ? '1' : '0';
        default:
            return strval($value);
    }
}

// Route handling - use query parameters instead of path info
$method = $_SERVER['REQUEST_METHOD'];
$network = $_GET['network'] ?? null;
$setting = $_GET['setting'] ?? null;

try {
    switch ($method) {
        case 'GET':
            if (!$network) {
                // GET /api/bot_config.php - Get all network configs
                $config = [];
                
                foreach (['rizon', 'libera'] as $network) {
                    $db = get_database($network);
                    if (!$db) continue;
                    
                    $stmt = $db->prepare('
                        SELECT setting_name, setting_value, setting_type, description, updated_at
                        FROM bot_config 
                        WHERE network = ?
                        ORDER BY setting_name
                    ');
                    $stmt->bindValue(1, $network);
                    $result = $stmt->execute();
                    
                    $config[$network] = [];
                    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                        $config[$network][$row['setting_name']] = [
                            'value' => convert_value($row['setting_value'], $row['setting_type']),
                            'type' => $row['setting_type'],
                            'description' => $row['description'],
                            'updated_at' => $row['updated_at']
                        ];
                    }
                }
                
                echo json_encode([
                    'status' => 'success',
                    'config' => $config,
                    'last_updated' => date('c')
                ]);
                
            } elseif ($network && !$setting) {
                // GET /api/bot_config.php?network=rizon - Get specific network config
                $db = get_database($network);
                
                if (!$db) {
                    http_response_code(404);
                    echo json_encode(['status' => 'error', 'message' => 'Network not found']);
                    exit();
                }
                
                $stmt = $db->prepare('
                    SELECT setting_name, setting_value, setting_type, description, updated_at
                    FROM bot_config 
                    WHERE network = ?
                    ORDER BY setting_name
                ');
                $stmt->bindValue(1, $network);
                $result = $stmt->execute();
                
                $config = [];
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    $config[$row['setting_name']] = [
                        'value' => convert_value($row['setting_value'], $row['setting_type']),
                        'type' => $row['setting_type'],
                        'description' => $row['description'],
                        'updated_at' => $row['updated_at']
                    ];
                }
                
                echo json_encode([
                    'status' => 'success',
                    'network' => $network,
                    'config' => $config,
                    'last_updated' => date('c')
                ]);
                
            } elseif ($network && $setting) {
                // GET /api/bot_config.php?network=rizon&setting=rate_limit_messages - Get specific setting
                $db = get_database($network);
                
                if (!$db) {
                    http_response_code(404);
                    echo json_encode(['status' => 'error', 'message' => 'Network not found']);
                    exit();
                }
                
                $stmt = $db->prepare('
                    SELECT setting_value, setting_type, description, updated_at
                    FROM bot_config 
                    WHERE network = ? AND setting_name = ?
                ');
                $stmt->bindValue(1, $network);
                $stmt->bindValue(2, $setting);
                $result = $stmt->execute();
                
                $row = $result->fetchArray(SQLITE3_ASSOC);
                if (!$row) {
                    http_response_code(404);
                    echo json_encode(['status' => 'error', 'message' => 'Setting not found']);
                    exit();
                }
                
                echo json_encode([
                    'status' => 'success',
                    'network' => $network,
                    'setting' => $setting,
                    'value' => convert_value($row['setting_value'], $row['setting_type']),
                    'type' => $row['setting_type'],
                    'description' => $row['description'],
                    'updated_at' => $row['updated_at']
                ]);
            }
            break;
            
        case 'POST':
        case 'PUT':
            // POST/PUT /api/bot_config.php?network=rizon - Update network config
            if (!$network) {
                http_response_code(400);
                echo json_encode(['status' => 'error', 'message' => 'Network parameter required']);
                exit();
            }
            $db = get_database($network);
            
            if (!$db) {
                http_response_code(404);
                echo json_encode(['status' => 'error', 'message' => 'Network not found']);
                exit();
            }
            
            $input = json_decode(file_get_contents('php://input'), true);
            if (!$input) {
                http_response_code(400);
                echo json_encode(['status' => 'error', 'message' => 'Invalid JSON input']);
                exit();
            }
            
            $updated = [];
            foreach ($input as $setting_name => $setting_data) {
                if (!is_array($setting_data) || !isset($setting_data['value'])) {
                    continue;
                }
                
                $value = $setting_data['value'];
                $type = $setting_data['type'] ?? 'string';
                $description = $setting_data['description'] ?? null;
                
                // Store the setting
                $stmt = $db->prepare('
                    INSERT OR REPLACE INTO bot_config 
                    (network, setting_name, setting_value, setting_type, description, updated_at)
                    VALUES (?, ?, ?, ?, ?, datetime("now"))
                ');
                $stmt->bindValue(1, $network);
                $stmt->bindValue(2, $setting_name);
                $stmt->bindValue(3, store_value($value, $type));
                $stmt->bindValue(4, $type);
                $stmt->bindValue(5, $description);
                
                if ($stmt->execute()) {
                    $updated[] = $setting_name;
                }
            }
            
            echo json_encode([
                'status' => 'success',
                'message' => 'Configuration updated',
                'network' => $network,
                'updated_settings' => $updated,
                'updated_at' => date('c')
            ]);
            break;
            
        case 'DELETE':
            // DELETE /api/bot_config.php?network=rizon&setting=setting_name - Delete specific setting
            if (!$network || !$setting) {
                http_response_code(400);
                echo json_encode(['status' => 'error', 'message' => 'Network and setting parameters required']);
                exit();
            }
            $db = get_database($network);
            
            if (!$db) {
                http_response_code(404);
                echo json_encode(['status' => 'error', 'message' => 'Network not found']);
                exit();
            }
            
            $stmt = $db->prepare('DELETE FROM bot_config WHERE network = ? AND setting_name = ?');
            $stmt->bindValue(1, $network);
            $stmt->bindValue(2, $setting);
            
            if ($stmt->execute()) {
                echo json_encode([
                    'status' => 'success',
                    'message' => 'Setting deleted',
                    'network' => $network,
                    'setting' => $setting
                ]);
            } else {
                http_response_code(500);
                echo json_encode(['status' => 'error', 'message' => 'Failed to delete setting']);
            }
            break;
            
        default:
            http_response_code(405);
            echo json_encode(['status' => 'error', 'message' => 'Method not allowed']);
            break;
    }
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'message' => 'Internal server error: ' . $e->getMessage()
    ]);
}

// Close database connections
$rizon_db->close();
$libera_db->close();
?>