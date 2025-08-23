<?php
/**
 * Breakout Game Configuration Admin Panel
 * Allows live configuration of game mechanics without code changes
 */

require_once 'security_config.php';
require_once 'auth.php';
require_once 'config_paths.php';

// Require admin authentication
requireAdmin();

// Initialize database for game settings
$db_path = ConfigPaths::getDatabase('breakout_settings');
try {
    $pdo = new PDO("sqlite:$db_path");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Create settings table if it doesn't exist
    $pdo->exec("CREATE TABLE IF NOT EXISTS game_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        setting_key TEXT UNIQUE NOT NULL,
        setting_value TEXT NOT NULL,
        category TEXT NOT NULL,
        display_name TEXT NOT NULL,
        description TEXT,
        min_value REAL,
        max_value REAL,
        data_type TEXT DEFAULT 'number',
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    
    // Initialize default settings if table is empty
    $stmt = $pdo->query("SELECT COUNT(*) FROM game_settings");
    if ($stmt->fetchColumn() == 0) {
        $defaultSettings = [
            // Physics & Movement (1-10 scale)
            ['ball_speed', '5', 'physics', 'Ball Speed', 'Base speed of the ball (1=very slow, 10=very fast)', 1, 10, 'slider'],
            ['paddle_speed', '5', 'physics', 'Paddle Speed', 'Movement speed of the paddle (1=sluggish, 10=lightning)', 1, 10, 'slider'],
            ['gravity_effect', '5', 'physics', 'Gravity Effect', 'How much gravity affects the ball (1=none, 10=heavy)', 1, 10, 'slider'],
            ['bounce_elasticity', '5', 'physics', 'Bounce Power', 'Ball bounce intensity (1=weak, 10=super bouncy)', 1, 10, 'slider'],
            ['mouse_sensitivity', '5', 'physics', 'Mouse Sensitivity', 'Pointer lock mouse sensitivity (1=slow, 10=fast)', 1, 10, 'slider'],
            
            // Difficulty & Progression
            ['difficulty_curve', '5', 'difficulty', 'Difficulty Curve', 'How quickly difficulty increases (1=gentle, 10=brutal)', 1, 10, 'slider'],
            ['starting_lives', '3', 'difficulty', 'Starting Lives', 'Number of lives at game start', 1, 10, 'number'],
            ['extra_life_frequency', '5', 'difficulty', 'Extra Life Frequency', 'How often extra lives appear (1=rare, 10=common)', 1, 10, 'slider'],
            ['ball_penetration', '5', 'difficulty', 'Ball Penetration', 'Chance ball passes through blocks (1=never, 10=often)', 1, 10, 'slider'],
            
            // Power-ups
            ['powerup_frequency', '5', 'powerups', 'Power-up Frequency', 'How often power-ups drop (1=rare, 10=common)', 1, 10, 'slider'],
            ['powerup_duration', '5', 'powerups', 'Power-up Duration', 'How long power-ups last (1=brief, 10=extended)', 1, 10, 'slider'],
            ['laser_power', '5', 'powerups', 'Laser Power', 'Damage dealt by laser (1=weak, 10=devastating)', 1, 10, 'slider'],
            ['multiball_count', '3', 'powerups', 'Multiball Count', 'Number of balls spawned by multiball', 2, 8, 'number'],
            ['sticky_strength', '5', 'powerups', 'Sticky Paddle Strength', 'How sticky the paddle is (1=barely, 10=super glue)', 1, 10, 'slider'],
            
            // Paddle Mechanics
            ['paddle_size_min', '3', 'paddle', 'Minimum Paddle Size', 'Smallest paddle size (1=tiny, 10=normal)', 1, 10, 'slider'],
            ['paddle_size_max', '7', 'paddle', 'Maximum Paddle Size', 'Largest paddle size (1=normal, 10=massive)', 1, 10, 'slider'],
            ['paddle_size_steps', '4', 'paddle', 'Paddle Size Steps', 'Number of size increments', 2, 8, 'number'],
            ['turret_position', '5', 'paddle', 'Turret Position', 'Position of laser turrets (1=center, 10=edges)', 1, 10, 'slider'],
            
            // Scoring
            ['score_multiplier', '5', 'scoring', 'Score Multiplier', 'Base score multiplication (1=low scores, 10=high scores)', 1, 10, 'slider'],
            ['combo_bonus', '5', 'scoring', 'Combo Bonus', 'Bonus for consecutive hits (1=minimal, 10=massive)', 1, 10, 'slider'],
            ['level_bonus', '5', 'scoring', 'Level Completion Bonus', 'Bonus for completing levels (1=small, 10=huge)', 1, 10, 'slider'],
            
            // Visual & Audio
            ['particle_effects', '5', 'visual', 'Particle Effects', 'Amount of visual effects (1=minimal, 10=maximum)', 1, 10, 'slider'],
            ['screen_shake', '5', 'visual', 'Screen Shake', 'Intensity of screen shake (1=none, 10=earthquake)', 1, 10, 'slider'],
            ['trail_length', '5', 'visual', 'Ball Trail Length', 'Length of ball trail effect (1=short, 10=long)', 1, 10, 'slider'],
            ['sound_volume', '7', 'visual', 'Sound Volume', 'Master volume level (1=quiet, 10=loud)', 1, 10, 'slider'],
            
            // Game Modes
            ['enable_boss_levels', '1', 'modes', 'Boss Levels', 'Enable boss encounters', 0, 1, 'toggle'],
            ['enable_mystical_powers', '1', 'modes', 'Mystical Powers', 'Enable magical abilities', 0, 1, 'toggle'],
            ['enable_world_progression', '1', 'modes', 'World Progression', 'Enable themed worlds', 0, 1, 'toggle'],
            ['enable_achievements', '1', 'modes', 'Achievements', 'Enable achievement system', 0, 1, 'toggle']
        ];
        
        $insertStmt = $pdo->prepare("INSERT INTO game_settings (setting_key, setting_value, category, display_name, description, min_value, max_value, data_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        foreach ($defaultSettings as $setting) {
            $insertStmt->execute($setting);
        }
    }
} catch (PDOException $e) {
    die("Database error: " . $e->getMessage());
}

// Handle AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    $input = json_decode(file_get_contents('php://input'), true);
    $action = $input['action'] ?? '';
    
    if ($action === 'update_setting') {
        $key = $input['key'] ?? '';
        $value = $input['value'] ?? '';
        
        try {
            $stmt = $pdo->prepare("UPDATE game_settings SET setting_value = ?, updated_at = CURRENT_TIMESTAMP WHERE setting_key = ?");
            $stmt->execute([$value, $key]);
            
            echo json_encode(['success' => true, 'message' => 'Setting updated']);
        } catch (PDOException $e) {
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }
    
    if ($action === 'reset_defaults') {
        try {
            // Reset all settings to default (5 for sliders, original values for others)
            $pdo->exec("UPDATE game_settings SET setting_value = CASE 
                WHEN data_type = 'slider' THEN '5'
                WHEN setting_key = 'starting_lives' THEN '3'
                WHEN setting_key = 'multiball_count' THEN '3'
                WHEN setting_key = 'paddle_size_steps' THEN '4'
                WHEN setting_key = 'sound_volume' THEN '7'
                WHEN data_type = 'toggle' THEN '1'
                ELSE setting_value END,
                updated_at = CURRENT_TIMESTAMP");
            
            echo json_encode(['success' => true, 'message' => 'All settings reset to defaults']);
        } catch (PDOException $e) {
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }
}

// Fetch all settings grouped by category
$stmt = $pdo->query("SELECT * FROM game_settings ORDER BY category, id");
$settings = [];
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $settings[$row['category']][] = $row;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Breakout Game Configuration - Admin Panel</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 30px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }
        
        h1 {
            color: #333;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .subtitle {
            color: #666;
            margin-bottom: 30px;
        }
        
        .category-section {
            margin-bottom: 30px;
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            border: 1px solid #dee2e6;
        }
        
        .category-title {
            font-size: 1.3em;
            color: #495057;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #dee2e6;
            text-transform: capitalize;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .setting-row {
            display: grid;
            grid-template-columns: 300px 1fr 150px;
            align-items: center;
            gap: 20px;
            margin-bottom: 20px;
            padding: 15px;
            background: white;
            border-radius: 8px;
            transition: all 0.3s ease;
        }
        
        .setting-row:hover {
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        
        .setting-name {
            font-weight: 600;
            color: #333;
        }
        
        .setting-description {
            font-size: 0.85em;
            color: #6c757d;
            margin-top: 5px;
        }
        
        .slider-container {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .slider {
            flex: 1;
            -webkit-appearance: none;
            height: 8px;
            border-radius: 5px;
            background: linear-gradient(to right, #dc3545 0%, #ffc107 50%, #28a745 100%);
            outline: none;
            opacity: 0.9;
            transition: opacity 0.2s;
        }
        
        .slider:hover {
            opacity: 1;
        }
        
        .slider::-webkit-slider-thumb {
            -webkit-appearance: none;
            appearance: none;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            background: #007bff;
            cursor: pointer;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }
        
        .slider::-moz-range-thumb {
            width: 20px;
            height: 20px;
            border-radius: 50%;
            background: #007bff;
            cursor: pointer;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }
        
        .value-display {
            min-width: 40px;
            text-align: center;
            font-weight: bold;
            font-size: 1.1em;
            color: #007bff;
        }
        
        .number-input {
            width: 80px;
            padding: 8px;
            border: 2px solid #dee2e6;
            border-radius: 5px;
            font-size: 1em;
        }
        
        .toggle-switch {
            position: relative;
            width: 60px;
            height: 30px;
        }
        
        .toggle-switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        
        .toggle-slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            transition: 0.4s;
            border-radius: 34px;
        }
        
        .toggle-slider:before {
            position: absolute;
            content: "";
            height: 22px;
            width: 22px;
            left: 4px;
            bottom: 4px;
            background-color: white;
            transition: 0.4s;
            border-radius: 50%;
        }
        
        input:checked + .toggle-slider {
            background-color: #28a745;
        }
        
        input:checked + .toggle-slider:before {
            transform: translateX(30px);
        }
        
        .action-buttons {
            display: flex;
            gap: 15px;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 2px solid #dee2e6;
        }
        
        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn-primary {
            background: #007bff;
            color: white;
        }
        
        .btn-primary:hover {
            background: #0056b3;
        }
        
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        
        .btn-danger:hover {
            background: #c82333;
        }
        
        .btn-success {
            background: #28a745;
            color: white;
        }
        
        .btn-success:hover {
            background: #218838;
        }
        
        .status-message {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            z-index: 1000;
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        
        .status-message.success {
            background: #28a745;
        }
        
        .status-message.error {
            background: #dc3545;
        }
        
        .status-message.show {
            opacity: 1;
        }
        
        .back-link {
            display: inline-block;
            margin-bottom: 20px;
            color: #007bff;
            text-decoration: none;
            font-weight: 600;
        }
        
        .back-link:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <a href="admin_styled.php" class="back-link">
            <i class="fas fa-arrow-left"></i> Back to Admin Panel
        </a>
        
        <h1>
            <i class="fas fa-gamepad"></i>
            Breakout Game Configuration
        </h1>
        <p class="subtitle">Fine-tune game mechanics without touching code. All values use a 1-10 scale for simplicity.</p>
        
        <?php foreach ($settings as $category => $categorySettings): ?>
        <div class="category-section">
            <div class="category-title">
                <?php
                $icons = [
                    'physics' => 'fa-atom',
                    'difficulty' => 'fa-chart-line',
                    'powerups' => 'fa-star',
                    'paddle' => 'fa-table-tennis',
                    'scoring' => 'fa-trophy',
                    'visual' => 'fa-palette',
                    'modes' => 'fa-toggle-on'
                ];
                $icon = $icons[$category] ?? 'fa-cog';
                ?>
                <i class="fas <?= $icon ?>"></i>
                <?= ucfirst($category) ?>
            </div>
            
            <?php foreach ($categorySettings as $setting): ?>
            <div class="setting-row">
                <div>
                    <div class="setting-name"><?= htmlspecialchars($setting['display_name']) ?></div>
                    <div class="setting-description"><?= htmlspecialchars($setting['description']) ?></div>
                </div>
                
                <?php if ($setting['data_type'] === 'slider'): ?>
                <div class="slider-container">
                    <input type="range" 
                           class="slider" 
                           id="<?= $setting['setting_key'] ?>"
                           min="<?= $setting['min_value'] ?>" 
                           max="<?= $setting['max_value'] ?>" 
                           value="<?= $setting['setting_value'] ?>"
                           step="0.5">
                    <span class="value-display" id="<?= $setting['setting_key'] ?>_value">
                        <?= $setting['setting_value'] ?>
                    </span>
                </div>
                <?php elseif ($setting['data_type'] === 'number'): ?>
                <div>
                    <input type="number" 
                           class="number-input" 
                           id="<?= $setting['setting_key'] ?>"
                           min="<?= $setting['min_value'] ?>" 
                           max="<?= $setting['max_value'] ?>" 
                           value="<?= $setting['setting_value'] ?>">
                </div>
                <?php elseif ($setting['data_type'] === 'toggle'): ?>
                <div>
                    <label class="toggle-switch">
                        <input type="checkbox" 
                               id="<?= $setting['setting_key'] ?>"
                               <?= $setting['setting_value'] == '1' ? 'checked' : '' ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
                <?php endif; ?>
                
                <div>
                    <button class="btn btn-primary btn-sm" onclick="saveSetting('<?= $setting['setting_key'] ?>')">
                        <i class="fas fa-save"></i> Save
                    </button>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
        <?php endforeach; ?>
        
        <div class="action-buttons">
            <button class="btn btn-success" onclick="saveAllSettings()">
                <i class="fas fa-save"></i> Save All Changes
            </button>
            <button class="btn btn-danger" onclick="resetDefaults()">
                <i class="fas fa-undo"></i> Reset to Defaults
            </button>
            <button class="btn btn-primary" onclick="testInGame()">
                <i class="fas fa-play"></i> Test in Game
            </button>
        </div>
    </div>
    
    <div id="statusMessage" class="status-message"></div>
    
    <script>
        // Track changed settings
        const changedSettings = new Set();
        
        // Update value displays for sliders
        document.querySelectorAll('.slider').forEach(slider => {
            slider.addEventListener('input', function() {
                document.getElementById(this.id + '_value').textContent = this.value;
                changedSettings.add(this.id);
            });
        });
        
        // Track changes for other inputs
        document.querySelectorAll('.number-input, input[type="checkbox"]').forEach(input => {
            input.addEventListener('change', function() {
                changedSettings.add(this.id);
            });
        });
        
        async function saveSetting(key) {
            const element = document.getElementById(key);
            let value;
            
            if (element.type === 'checkbox') {
                value = element.checked ? '1' : '0';
            } else {
                value = element.value;
            }
            
            try {
                const response = await fetch('admin_game_config.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        action: 'update_setting',
                        key: key,
                        value: value
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showStatus('Setting saved successfully', 'success');
                    changedSettings.delete(key);
                } else {
                    showStatus('Error: ' + result.error, 'error');
                }
            } catch (error) {
                showStatus('Failed to save setting', 'error');
            }
        }
        
        async function saveAllSettings() {
            let savedCount = 0;
            let errorCount = 0;
            
            for (const key of changedSettings) {
                const element = document.getElementById(key);
                let value;
                
                if (element.type === 'checkbox') {
                    value = element.checked ? '1' : '0';
                } else {
                    value = element.value;
                }
                
                try {
                    const response = await fetch('admin_game_config.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            action: 'update_setting',
                            key: key,
                            value: value
                        })
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        savedCount++;
                    } else {
                        errorCount++;
                    }
                } catch (error) {
                    errorCount++;
                }
            }
            
            if (errorCount === 0) {
                showStatus(`All ${savedCount} settings saved successfully`, 'success');
                changedSettings.clear();
            } else {
                showStatus(`Saved ${savedCount} settings, ${errorCount} errors`, 'error');
            }
        }
        
        async function resetDefaults() {
            if (!confirm('Are you sure you want to reset all settings to their default values?')) {
                return;
            }
            
            try {
                const response = await fetch('admin_game_config.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        action: 'reset_defaults'
                    })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showStatus('All settings reset to defaults', 'success');
                    setTimeout(() => location.reload(), 1500);
                } else {
                    showStatus('Error: ' + result.error, 'error');
                }
            } catch (error) {
                showStatus('Failed to reset settings', 'error');
            }
        }
        
        function testInGame() {
            // Open game in new tab with config parameter
            window.open('/breakout.html?config=live', '_blank');
        }
        
        function showStatus(message, type) {
            const statusEl = document.getElementById('statusMessage');
            statusEl.textContent = message;
            statusEl.className = `status-message ${type} show`;
            
            setTimeout(() => {
                statusEl.classList.remove('show');
            }, 3000);
        }
    </script>
</body>
</html>