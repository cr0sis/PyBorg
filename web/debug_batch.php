<?php
header('Content-Type: application/json');
require_once 'config_paths.php';
require_once 'input_sanitizer.php';

echo "Testing batch user check...\n";

$player_names = ['cr0sis', 'bigarse', 'Anonymous'];

$users_db_path = ConfigPaths::getDatabase('users');
try {
    $users_pdo = new PDO("sqlite:$users_db_path");
    $users_pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    echo "Users database connected...\n";
    
    $placeholders = str_repeat('?,', count($player_names) - 1) . '?';
    echo "Placeholders: $placeholders\n";
    
    $stmt = $users_pdo->prepare("SELECT username FROM users WHERE username IN ($placeholders) AND is_active = 1");
    $stmt->execute($player_names);
    $registered_users = array_flip($stmt->fetchAll(PDO::FETCH_COLUMN));
    
    echo "Registered users found: " . json_encode($registered_users) . "\n";
} catch (PDOException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}

echo "Done\n";
?>