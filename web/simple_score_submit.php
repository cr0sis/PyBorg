<?php
// Simple score submission endpoint for debugging
session_start();

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    error_log("SIMPLE: POST request received");
    
    // Get JSON input
    $input = json_decode(file_get_contents('php://input'), true);
    error_log("SIMPLE: Input decoded - " . json_encode($input));
    
    if (!$input) {
        echo json_encode(['error' => 'Invalid JSON input']);
        exit;
    }
    
    // Extract basic data
    $player_name = $input['player_name'] ?? 'Anonymous';
    $score = intval($input['score'] ?? 0);
    $level = intval($input['level_reached'] ?? 1);
    
    error_log("SIMPLE: Data extracted - player: $player_name, score: $score, level: $level");
    
    // Basic validation
    if (empty($player_name) || $score < 0 || $level < 1) {
        echo json_encode(['error' => 'Invalid input data']);
        exit;
    }
    
    try {
        // Database connection
        $db_path = '/data/cr0_system/databases/breakout_scores.db';
        $pdo = new PDO("sqlite:$db_path");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        error_log("SIMPLE: Database connected");
        
        // Simple insert
        $stmt = $pdo->prepare("INSERT INTO breakout_scores (player_name, score, level_reached, ip_address, date_played) VALUES (?, ?, ?, ?, datetime('now'))");
        $stmt->execute([$player_name, $score, $level, $_SERVER['REMOTE_ADDR']]);
        
        error_log("SIMPLE: Score inserted successfully");
        
        echo json_encode(['success' => true, 'message' => 'Score submitted successfully']);
        
    } catch (Exception $e) {
        error_log("SIMPLE: Database error - " . $e->getMessage());
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
} else {
    echo json_encode(['error' => 'Only POST method allowed']);
}
?>