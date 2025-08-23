<?php
header('Content-Type: application/json');
require_once 'config_paths.php';
require_once 'user_color_system.php';

$db_path = ConfigPaths::getDatabase('breakout_scores');
$pdo = new PDO("sqlite:$db_path");
$stmt = $pdo->prepare("SELECT player_name, score, level_reached FROM breakout_scores ORDER BY score DESC LIMIT 5");
$stmt->execute();
$scores = $stmt->fetchAll(PDO::FETCH_ASSOC);

foreach ($scores as &$score) {
    $score['color'] = getUserColor($score['player_name'], false);
}

echo json_encode($scores);
?>