<?php
/**
 * User Color System - Shared functions for hall of fame color management
 * Handles color assignment and name protection across different endpoints
 */

require_once 'config_paths.php';

function generatePersistentColor() {
    $colors = [
        '#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FECA57',
        '#FF9FF3', '#54A0FF', '#5F27CD', '#00D2D3', '#FF9F43',
        '#10AC84', '#EE5A24', '#0984E3', '#A29BFE', '#FD79A8',
        '#E17055', '#74B9FF', '#E84393', '#00B894', '#FDCB6E',
        '#6C5CE7', '#A0E7E5', '#B2F5EA', '#FBB6CE', '#D63031'
    ];
    return $colors[array_rand($colors)];
}

function isRegisteredUser($player_name) {
    error_log("DEBUG: isRegisteredUser called for: $player_name");
    // Check against the users database
    $users_db_path = ConfigPaths::getDatabase('users');
    error_log("DEBUG: Users DB path: $users_db_path");
    try {
        error_log("DEBUG: Creating PDO connection to users database");
        $users_pdo = new PDO("sqlite:$users_db_path");
        $users_pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        error_log("DEBUG: Users PDO connection created successfully");
        
        error_log("DEBUG: About to execute users query");
        $stmt = $users_pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ? AND is_active = 1");
        $stmt->execute([$player_name]);
        $result = $stmt->fetchColumn() > 0;
        error_log("DEBUG: Users query completed, result: " . ($result ? 'true' : 'false'));
        return $result;
    } catch (PDOException $e) {
        error_log("Error checking registered user: " . $e->getMessage());
        return false;
    }
}

function getUserColor($player_name, $is_logged_in = false) {
    error_log("DEBUG: getUserColor called for player: $player_name");
    // Get database connection for color storage
    $scores_db_path = ConfigPaths::getDatabase('breakout_scores');
    try {
        error_log("DEBUG: Creating PDO connection for colors");
        $pdo = new PDO("sqlite:$scores_db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        error_log("DEBUG: PDO connection created successfully");
        
        // Ensure user_colors table exists
        error_log("DEBUG: About to create user_colors table");
        $pdo->exec("CREATE TABLE IF NOT EXISTS user_colors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            player_name TEXT UNIQUE NOT NULL,
            color_hex TEXT NOT NULL,
            is_registered_user INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_used DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        error_log("DEBUG: user_colors table creation completed");
        
        // Check if user is registered
        error_log("DEBUG: About to call isRegisteredUser");
        $is_registered = isRegisteredUser($player_name);
        error_log("DEBUG: isRegisteredUser completed, result: " . ($is_registered ? 'true' : 'false'));
        
        // Anonymous users (no name or generic names) get white
        if (!$player_name || $player_name === 'Anonymous' || $player_name === 'Guest') {
            return '#FFFFFF';
        }
        
        // Check if color already exists for this name (regardless of who's viewing)
        $stmt = $pdo->prepare("SELECT color_hex FROM user_colors WHERE player_name = ?");
        $stmt->execute([$player_name]);
        $existing_color = $stmt->fetchColumn();
        
        if ($existing_color) {
            // Update last_used timestamp
            $stmt = $pdo->prepare("UPDATE user_colors SET last_used = CURRENT_TIMESTAMP WHERE player_name = ?");
            $stmt->execute([$player_name]);
            return $existing_color;
        }
        
        // Generate new color for registered users (to ensure they get persistent colors)
        if ($is_registered) {
            $color = generatePersistentColor();
            $stmt = $pdo->prepare("INSERT OR REPLACE INTO user_colors (player_name, color_hex, is_registered_user) VALUES (?, ?, ?)");
            $stmt->execute([$player_name, $color, 1]);
            return $color;
        }
        
        // Default to white for unregistered named users
        return '#FFFFFF';
        
    } catch (PDOException $e) {
        error_log("Error managing user colors: " . $e->getMessage());
        // Return default colors based on user status
        if (!$is_logged_in && (!$player_name || $player_name === 'Anonymous' || $player_name === 'Guest')) {
            return '#FFFFFF';
        }
        return '#FFFFFF';
    }
}

function checkNameProtection($player_name, $is_logged_in = false) {
    // If user is logged in, they can use their own registered name
    if ($is_logged_in) {
        return true;
    }
    
    // Check if the name belongs to a registered user
    if (isRegisteredUser($player_name)) {
        return false; // Name is protected
    }
    
    return true; // Name is available
}
?>