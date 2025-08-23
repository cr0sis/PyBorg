<?php
/**
 * Game Settings API
 * Provides game configuration to the Breakout game
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type');

require_once 'config_paths.php';

// Connect to settings database
$db_path = ConfigPaths::getDatabase('breakout_settings');

try {
    $pdo = new PDO("sqlite:$db_path");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Fetch all settings
    $stmt = $pdo->query("SELECT setting_key, setting_value, min_value, max_value, data_type FROM game_settings");
    $settings = [];
    
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $key = $row['setting_key'];
        $value = $row['setting_value'];
        $min = $row['min_value'];
        $max = $row['max_value'];
        $type = $row['data_type'];
        
        // Convert 1-10 scale to appropriate game values
        if ($type === 'slider') {
            // Convert slider values to percentages or multipliers
            $normalizedValue = ($value - 1) / 9; // 0 to 1 range
            
            switch ($key) {
                case 'ball_speed':
                    // Map 1-10 to speed multiplier with 5 = 1.0x (current default)
                    // Range: 0.5x to 2.0x, with 5 = 1.0x
                    $settings[$key] = 0.5 + ($normalizedValue * 1.5);
                    break;
                    
                case 'paddle_speed':
                    // Map 1-10 to paddle speed with 5 = 19.2 (current default)
                    // Range: 10 to 30, with 5 = 19.2
                    $settings[$key] = 10 + ($normalizedValue * 20);
                    break;
                    
                case 'mouse_sensitivity':
                    // Map 1-10 to sensitivity multiplier with 5 = 2.5x (current default)
                    // Range: 1.0x to 5.0x, with 5 = 2.5x
                    $settings[$key] = 1.0 + ($normalizedValue * 4.0);
                    break;
                    
                case 'gravity_effect':
                    // Map 1-10 to gravity strength (0 to 0.5)
                    $settings[$key] = $normalizedValue * 0.5;
                    break;
                    
                case 'bounce_elasticity':
                    // Map 1-10 to bounce multiplier (0.8 to 1.5)
                    $settings[$key] = 0.8 + ($normalizedValue * 0.7);
                    break;
                    
                case 'difficulty_curve':
                    // Map 1-10 to difficulty multiplier (0.5 to 2)
                    $settings[$key] = 0.5 + ($normalizedValue * 1.5);
                    break;
                    
                case 'powerup_frequency':
                    // Map 1-10 to drop chance (0.01 to 0.3)
                    $settings[$key] = 0.01 + ($normalizedValue * 0.29);
                    break;
                    
                case 'powerup_duration':
                    // Map 1-10 to seconds (5 to 20)
                    $settings[$key] = 5 + ($normalizedValue * 15);
                    break;
                    
                case 'speedball_duration':
                    // Map 1-10 to seconds (2 to 15)
                    $settings[$key] = 2 + ($normalizedValue * 13);
                    break;
                    
                case 'laser_power':
                    // Map 1-10 to damage (1 to 3)
                    $settings[$key] = 1 + ($normalizedValue * 2);
                    break;
                    
                case 'sticky_strength':
                    // Map 1-10 to hold time multiplier (0.5 to 2)
                    $settings[$key] = 0.5 + ($normalizedValue * 1.5);
                    break;
                    
                case 'paddle_size_min':
                    // Map 1-10 to size ratio (0.3 to 1)
                    $settings[$key] = 0.3 + ($normalizedValue * 0.7);
                    break;
                    
                case 'paddle_size_max':
                    // Map 1-10 to size ratio (1 to 3)
                    $settings[$key] = 1 + ($normalizedValue * 2);
                    break;
                    
                case 'turret_position':
                    // Map 1-10 to position percentage (0.15 to 0.45)
                    $settings[$key] = 0.15 + ($normalizedValue * 0.3);
                    break;
                    
                case 'score_multiplier':
                    // Map 1-10 to multiplier (0.5 to 3)
                    $settings[$key] = 0.5 + ($normalizedValue * 2.5);
                    break;
                    
                case 'combo_bonus':
                    // Map 1-10 to bonus multiplier (1 to 5)
                    $settings[$key] = 1 + ($normalizedValue * 4);
                    break;
                    
                case 'level_bonus':
                    // Map 1-10 to bonus points (100 to 10000)
                    $settings[$key] = 100 + ($normalizedValue * 9900);
                    break;
                    
                case 'particle_effects':
                    // Map 1-10 to particle count multiplier (0.1 to 2)
                    $settings[$key] = 0.1 + ($normalizedValue * 1.9);
                    break;
                    
                case 'screen_shake':
                    // Map 1-10 to shake intensity (0 to 20)
                    $settings[$key] = $normalizedValue * 20;
                    break;
                    
                case 'trail_length':
                    // Map 1-10 to trail segments (0 to 20)
                    $settings[$key] = round($normalizedValue * 20);
                    break;
                    
                case 'sound_volume':
                    // Map 1-10 to volume (0 to 1)
                    $settings[$key] = $normalizedValue;
                    break;
                    
                case 'extra_life_frequency':
                    // Map 1-10 to spawn chance (0.01 to 0.2)
                    $settings[$key] = 0.01 + ($normalizedValue * 0.19);
                    break;
                    
                case 'ball_penetration':
                    // Map 1-10 to penetration chance (0 to 0.2)
                    $settings[$key] = $normalizedValue * 0.2;
                    break;
                    
                default:
                    $settings[$key] = $value;
            }
        } elseif ($type === 'number') {
            $settings[$key] = intval($value);
        } elseif ($type === 'toggle') {
            $settings[$key] = $value === '1';
        } else {
            $settings[$key] = $value;
        }
    }
    
    // Add computed settings
    $settings['config_loaded'] = true;
    
    // Use the latest updated_at time from database as timestamp to avoid constant changes
    $timestampStmt = $pdo->query("SELECT MAX(updated_at) FROM game_settings");
    $latestUpdate = $timestampStmt->fetchColumn();
    $settings['timestamp'] = $latestUpdate ? strtotime($latestUpdate) : time();
    
    echo json_encode($settings);
    
} catch (PDOException $e) {
    // If database doesn't exist or error occurs, return default settings
    echo json_encode([
        'config_loaded' => false,
        'error' => 'Could not load custom settings',
        'ball_speed' => 1,
        'paddle_speed' => 19.2,
        'mouse_sensitivity' => 2.5,
        'powerup_frequency' => 0.15,
        'powerup_duration' => 10,
        'starting_lives' => 3,
        'multiball_count' => 3,
        'paddle_size_steps' => 4
    ]);
}