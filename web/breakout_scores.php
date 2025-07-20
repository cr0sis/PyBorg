<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Simple SQLite database for breakout scores
$db_path = '/tmp/breakout_scores.db';

try {
    $pdo = new PDO("sqlite:$db_path");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Create table if it doesn't exist
    $pdo->exec("CREATE TABLE IF NOT EXISTS breakout_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        player_name TEXT NOT NULL,
        score INTEGER NOT NULL,
        level_reached INTEGER NOT NULL,
        date_played DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Add new score
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!isset($input['player_name']) || !isset($input['score']) || !isset($input['level_reached'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Missing required fields']);
            exit;
        }
        
        $player_name = substr($input['player_name'], 0, 20); // Limit name length
        
        // Check if player is banned
        $banned_file = '/tmp/banned_players.txt';
        if (file_exists($banned_file)) {
            $banned_players = file($banned_file, FILE_IGNORE_NEW_LINES);
            if (in_array($player_name, $banned_players)) {
                http_response_code(403);
                echo json_encode(['error' => 'Player is banned from submitting scores']);
                exit;
            }
        }
        
        // Industry standard profanity filter
        if (containsProfanity($player_name)) {
            http_response_code(400);
            echo json_encode(['error' => 'Inappropriate player name']);
            exit;
        }
        
        $stmt = $pdo->prepare("INSERT INTO breakout_scores (player_name, score, level_reached) VALUES (?, ?, ?)");
        $stmt->execute([
            $player_name,
            intval($input['score']),
            intval($input['level_reached'])
        ]);
        
        echo json_encode(['success' => true, 'id' => $pdo->lastInsertId()]);
        
    } elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
        // Get high scores
        $limit = isset($_GET['limit']) ? min(intval($_GET['limit']), 50) : 10;
        
        $stmt = $pdo->prepare("SELECT player_name, score, level_reached, date_played 
                              FROM breakout_scores 
                              ORDER BY score DESC, level_reached DESC 
                              LIMIT ?");
        $stmt->execute([$limit]);
        $scores = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        echo json_encode($scores);
    }
    
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}

function containsProfanity($text) {
    // Comprehensive profanity list (industry standard)
    $profanity_list = [
        // Severe profanity
        'fuck', 'shit', 'bitch', 'damn', 'hell', 'ass', 'crap', 'piss', 'cock', 'dick', 'pussy', 'cunt', 'whore', 'slut', 
        'bastard', 'motherfucker', 'asshole', 'bullshit', 'goddamn', 'jesus', 'christ', 'wtf', 'stfu', 'gtfo',
        
        // Racial slurs and hate speech
        'nigger', 'nigga', 'faggot', 'retard', 'gay', 'homo', 'dyke', 'tranny', 'chink', 'spic', 'wetback', 'kike',
        'nazi', 'hitler', 'terrorist', 'jihad', 'isis', 'kkk',
        
        // Sexual content
        'porn', 'sex', 'anal', 'oral', 'cum', 'jizz', 'masturbate', 'orgasm', 'penis', 'vagina', 'boobs', 'tits',
        'nude', 'naked', 'xxx', 'milf', 'dildo', 'vibrator', 'bdsm', 'kinky', 'horny', 'erotic',
        
        // Violence and threats
        'kill', 'murder', 'rape', 'bomb', 'gun', 'knife', 'stab', 'shoot', 'die', 'death', 'suicide', 'kys',
        'violence', 'attack', 'assault', 'abuse', 'torture', 'harm', 'hurt', 'pain', 'blood', 'gore',
        
        // Drugs and substances
        'weed', 'marijuana', 'cocaine', 'heroin', 'meth', 'crack', 'drug', 'dealer', 'high', 'stoned',
        'drunk', 'alcohol', 'beer', 'wine', 'vodka', 'whiskey', 'smoke', 'joint', 'blunt', 'bong',
        
        // General inappropriate
        'admin', 'moderator', 'mod', 'owner', 'staff', 'official', 'bot', 'system', 'server', 'user',
        'spam', 'scam', 'hack', 'cheat', 'exploit', 'bug', 'glitch', 'noob', 'newb', 'scrub', 'trash',
        'toxic', 'cancer', 'aids', 'autism', 'autistic', 'mental', 'crazy', 'insane', 'stupid', 'idiot',
        
        // Leetspeak variations will be handled by normalization
    ];
    
    // Normalize the input text
    $normalized_text = normalizeProfanityText($text);
    
    // Check against profanity list
    foreach ($profanity_list as $word) {
        $normalized_word = normalizeProfanityText($word);
        
        // Direct match
        if (stripos($normalized_text, $normalized_word) !== false) {
            return true;
        }
        
        // Check for word boundaries to catch whole words
        if (preg_match('/\b' . preg_quote($normalized_word, '/') . '\b/i', $normalized_text)) {
            return true;
        }
        
        // Check for variations with numbers/symbols in between
        $pattern = '';
        for ($i = 0; $i < strlen($normalized_word); $i++) {
            $pattern .= preg_quote($normalized_word[$i], '/');
            if ($i < strlen($normalized_word) - 1) {
                $pattern .= '[0-9\s\-_\.\*\+]*?';
            }
        }
        if (preg_match('/' . $pattern . '/i', $normalized_text)) {
            return true;
        }
    }
    
    return false;
}

function normalizeProfanityText($text) {
    $text = strtolower(trim($text));
    
    // Remove spaces, hyphens, underscores, dots
    $text = str_replace([' ', '-', '_', '.', '*', '+', '!', '@', '#', '$', '%', '^', '&'], '', $text);
    
    // Replace common leetspeak substitutions
    $leetspeak = [
        '4' => 'a', '@' => 'a', 
        '3' => 'e', 
        '1' => 'i', '!' => 'i', '|' => 'i',
        '0' => 'o', 
        '5' => 's', '$' => 's', 'z' => 's',
        '7' => 't', '+' => 't',
        '8' => 'b',
        '6' => 'g',
        '2' => 'z',
        '9' => 'g',
    ];
    
    $text = str_replace(array_keys($leetspeak), array_values($leetspeak), $text);
    
    // Remove numbers that might be used as separators
    $text = preg_replace('/[0-9]+/', '', $text);
    
    return $text;
}
?>