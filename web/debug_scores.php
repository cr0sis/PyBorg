<?php
header('Content-Type: application/json');
require_once 'config_paths.php';

echo "Starting debug...\n";

$db_path = ConfigPaths::getDatabase('breakout_scores');
$pdo = new PDO("sqlite:$db_path");

echo "Database connected...\n";

$stmt = $pdo->prepare("SELECT player_name, score, level_reached FROM breakout_scores ORDER BY score DESC LIMIT 3");
$stmt->execute();
$scores = $stmt->fetchAll(PDO::FETCH_ASSOC);

echo "Scores fetched: " . count($scores) . "\n";

// Test if the user color system is the issue
require_once 'user_color_system.php';

echo "User color system loaded...\n";

foreach ($scores as &$score) {
    echo "Processing: " . $score['player_name'] . "\n";
    $score['color'] = getUserColor($score['player_name'], false);
    echo "Color assigned: " . $score['color'] . "\n";
}

echo "All colors processed...\n";

echo json_encode($scores);
?>