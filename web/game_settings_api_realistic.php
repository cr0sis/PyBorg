<?php
/**
 * Game Settings API - Realistic Values
 * Provides actual game configuration values directly from the realistic settings database
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type');

require_once 'config_paths.php';

// Connect to realistic settings database
$db_path = ConfigPaths::getDatabase('breakout_settings');

try {
    $pdo = new PDO("sqlite:$db_path");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Fetch all realistic settings
    $stmt = $pdo->query("SELECT setting_key, setting_value, data_type FROM game_settings_realistic");
    $settings = [];
    
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $key = $row['setting_key'];
        $value = $row['setting_value'];
        $type = $row['data_type'];
        
        // Convert values to appropriate types for the game
        if ($type === 'slider' || $type === 'number') {
            $settings[$key] = floatval($value);
        } elseif ($type === 'toggle') {
            $settings[$key] = $value === '1';
        } else {
            $settings[$key] = $value;
        }
    }
    
    // Add computed settings
    $settings['config_loaded'] = true;
    $settings['config_type'] = 'realistic';
    
    // Use the latest updated_at time from database as timestamp to avoid constant changes
    $timestampStmt = $pdo->query("SELECT MAX(updated_at) FROM game_settings_realistic");
    $latestUpdate = $timestampStmt->fetchColumn();
    $settings['timestamp'] = $latestUpdate ? strtotime($latestUpdate) : time();
    
    echo json_encode($settings);
    
} catch (PDOException $e) {
    // If database doesn't exist or error occurs, return default realistic settings
    echo json_encode([
        'config_loaded' => false,
        'config_type' => 'realistic',
        'error' => 'Could not load realistic settings',
        
        // Default realistic values matching the game's current implementation
        'ball_speed_multiplier' => 1.0,
        'paddle_speed' => 19.2,
        'mouse_sensitivity' => 2.5,
        'starting_lives' => 3,
        'score_multiplier' => 1.0,
        'powerup_drop_chance' => 0.15,
        'powerup_duration' => 10,
        'extra_life_chance' => 0.06,
        'multiball_count' => 3,
        'speedball_duration' => 8,
        'particle_count_multiplier' => 1.0,
        'screen_shake_intensity' => 10,
        'ball_trail_length' => 10,
        'sound_volume' => 0.7,
        'enable_boss_levels' => true,
        'enable_mystical_powers' => true,
        'enable_achievements' => true,
        'enable_screen_wrap' => false,
        
        'timestamp' => time()
    ]);
}