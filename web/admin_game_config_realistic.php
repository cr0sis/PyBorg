<?php
/**
 * Breakout Game Configuration Admin Panel - Realistic Values
 * Shows actual game values instead of arbitrary 1-10 scales
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
    $pdo->exec("CREATE TABLE IF NOT EXISTS game_settings_realistic (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        setting_key TEXT UNIQUE NOT NULL,
        setting_value TEXT NOT NULL,
        category TEXT NOT NULL,
        display_name TEXT NOT NULL,
        description TEXT,
        min_value REAL,
        max_value REAL,
        step_value REAL DEFAULT 0.1,
        unit TEXT DEFAULT '',
        data_type TEXT DEFAULT 'number',
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    
    // Clear and reinitialize with realistic settings
    $pdo->exec("DELETE FROM game_settings_realistic");
    
    $realisticSettings = [
        // Physics & Movement - Real values
        ['ball_speed_multiplier', '1.0', 'physics', 'Ball Speed Multiplier', 'Multiplier for ball speed (1.0 = normal)', 0.5, 2.0, 0.1, 'x', 'slider'],
        ['paddle_speed', '19.2', 'physics', 'Paddle Speed', 'Paddle movement speed in pixels per frame', 10, 40, 0.5, 'px/frame', 'slider'],
        ['mouse_sensitivity', '2.5', 'physics', 'Mouse Sensitivity', 'Pointer lock sensitivity multiplier', 1.0, 6.0, 0.1, 'x', 'slider'],
        
        // Core Game Settings - Real values
        ['starting_lives', '3', 'core', 'Starting Lives', 'Number of lives at game start', 1, 10, 1, 'lives', 'number'],
        ['score_multiplier', '1.0', 'core', 'Score Multiplier', 'Multiplier for all score values', 0.5, 5.0, 0.1, 'x', 'slider'],
        
        // Power-up Settings - Real percentages
        ['powerup_drop_chance', '0.15', 'powerups', 'Power-up Drop Chance', 'Probability of power-up drop per block hit', 0.05, 0.5, 0.01, '%', 'slider'],
        ['powerup_duration', '10', 'powerups', 'Power-up Duration', 'How long power-ups last', 3, 20, 1, 'seconds', 'slider'],
        ['extra_life_chance', '0.06', 'powerups', 'Extra Life Chance', 'Probability of extra life power-up', 0.01, 0.2, 0.01, '%', 'slider'],
        ['multiball_count', '3', 'powerups', 'Multiball Count', 'Number of balls spawned by multiball', 2, 8, 1, 'balls', 'number'],
        ['speedball_duration', '8', 'powerups', 'Speed Ball Duration', 'How long speed ball effect lasts', 2, 15, 1, 'seconds', 'slider'],
        
        // Visual & Audio - Real values
        ['particle_count_multiplier', '1.0', 'visual', 'Particle Density', 'Multiplier for particle effects', 0.1, 3.0, 0.1, 'x', 'slider'],
        ['screen_shake_intensity', '10', 'visual', 'Screen Shake', 'Screen shake intensity in pixels', 0, 25, 1, 'px', 'slider'],
        ['ball_trail_length', '10', 'visual', 'Ball Trail Length', 'Number of trail segments', 0, 30, 1, 'segments', 'slider'],
        ['sound_volume', '0.7', 'visual', 'Sound Volume', 'Master volume level', 0.0, 1.0, 0.05, '', 'slider'],
        
        // Feature Toggles
        ['enable_boss_levels', '1', 'features', 'Boss Battles', 'Enable boss encounters', 0, 1, 1, '', 'toggle'],
        ['enable_mystical_powers', '1', 'features', 'Mystical Powers', 'Enable magical abilities system', 0, 1, 1, '', 'toggle'],
        ['enable_achievements', '1', 'features', 'Achievements', 'Enable achievement tracking', 0, 1, 1, '', 'toggle'],
        ['enable_screen_wrap', '0', 'features', 'Ball Wrap-Around', 'Ball wraps to other side of screen', 0, 1, 1, '', 'toggle']
    ];
    
    $insertStmt = $pdo->prepare("INSERT INTO game_settings_realistic (setting_key, setting_value, category, display_name, description, min_value, max_value, step_value, unit, data_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    foreach ($realisticSettings as $setting) {
        $insertStmt->execute($setting);
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
            $stmt = $pdo->prepare("UPDATE game_settings_realistic SET setting_value = ?, updated_at = CURRENT_TIMESTAMP WHERE setting_key = ?");
            $stmt->execute([$value, $key]);
            
            echo json_encode(['success' => true, 'message' => 'Setting updated']);
        } catch (PDOException $e) {
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }
    
    if ($action === 'reset_defaults') {
        try {
            // Reset to original values
            $defaultValues = [
                'ball_speed_multiplier' => '1.0',
                'paddle_speed' => '19.2',
                'mouse_sensitivity' => '2.5',
                'starting_lives' => '3',
                'score_multiplier' => '1.0',
                'powerup_drop_chance' => '0.15',
                'powerup_duration' => '10',
                'extra_life_chance' => '0.06',
                'multiball_count' => '3',
                'speedball_duration' => '8',
                'particle_count_multiplier' => '1.0',
                'screen_shake_intensity' => '10',
                'ball_trail_length' => '10',
                'sound_volume' => '0.7',
                'enable_boss_levels' => '1',
                'enable_mystical_powers' => '1',
                'enable_achievements' => '1',
                'enable_screen_wrap' => '0'
            ];
            
            foreach ($defaultValues as $key => $value) {
                $stmt = $pdo->prepare("UPDATE game_settings_realistic SET setting_value = ?, updated_at = CURRENT_TIMESTAMP WHERE setting_key = ?");
                $stmt->execute([$value, $key]);
            }
            
            echo json_encode(['success' => true, 'message' => 'All settings reset to defaults']);
        } catch (PDOException $e) {
            echo json_encode(['success' => false, 'error' => $e->getMessage()]);
        }
        exit;
    }
}

// Fetch all settings grouped by category
$stmt = $pdo->query("SELECT * FROM game_settings_realistic ORDER BY category, id");
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
    <title>Breakout Game Configuration - Realistic Values</title>
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
        
        .info-box {
            background: #e7f3ff;
            border: 1px solid #b8daff;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 25px;
            color: #004085;
        }
        
        .info-box h3 {
            margin-bottom: 10px;
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
            grid-template-columns: 300px 1fr;
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
        
        .value-display {
            min-width: 80px;
            text-align: center;
            font-weight: bold;
            font-size: 1.1em;
            color: #007bff;
            background: #f8f9fa;
            padding: 8px 12px;
            border-radius: 5px;
            border: 1px solid #dee2e6;
        }
        
        .number-input {
            width: 100px;
            padding: 8px;
            border: 2px solid #dee2e6;
            border-radius: 5px;
            font-size: 1em;
            text-align: center;
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
        
        .category-save-btn {
            margin-top: 15px;
            padding: 10px 20px;
            background: #28a745;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .category-save-btn:hover {
            background: #218838;
        }
        
        .category-save-btn:disabled {
            background: #6c757d;
            cursor: not-allowed;
        }
        
        .changed-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            background: #ffc107;
            border-radius: 50%;
            margin-left: 10px;
            animation: pulse 1s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
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
            Breakout Game Configuration (Realistic Values)
        </h1>
        <p class="subtitle">Adjust game mechanics using actual values instead of arbitrary scales.</p>
        
        <div class="info-box">
            <h3>💡 Real Values</h3>
            <p>This panel shows actual game values (like 19.2 pixels/frame for paddle speed) instead of confusing 1-10 scales. 
            What you see is exactly what the game uses.</p>
        </div>
        
        <?php 
        $categoryIcons = [
            'physics' => 'fa-atom',
            'core' => 'fa-gamepad',
            'powerups' => 'fa-star',
            'visual' => 'fa-palette',
            'features' => 'fa-toggle-on'
        ];
        
        foreach ($settings as $category => $categorySettings): ?>
        <div class="category-section" data-category="<?= $category ?>">
            <div class="category-title">
                <i class="fas <?= $categoryIcons[$category] ?? 'fa-cog' ?>"></i>
                <?= ucfirst($category) ?>
                <span class="changed-indicator" id="<?= $category ?>_indicator" style="display: none;"></span>
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
                           class="slider category-input" 
                           data-category="<?= $category ?>"
                           id="<?= $setting['setting_key'] ?>"
                           min="<?= $setting['min_value'] ?>" 
                           max="<?= $setting['max_value'] ?>" 
                           value="<?= $setting['setting_value'] ?>"
                           step="<?= $setting['step_value'] ?>">
                    <span class="value-display" id="<?= $setting['setting_key'] ?>_value">
                        <?= $setting['setting_value'] ?><?= $setting['unit'] ?>
                    </span>
                </div>
                <?php elseif ($setting['data_type'] === 'number'): ?>
                <div>
                    <input type="number" 
                           class="number-input category-input" 
                           data-category="<?= $category ?>"
                           id="<?= $setting['setting_key'] ?>"
                           min="<?= $setting['min_value'] ?>" 
                           max="<?= $setting['max_value'] ?>" 
                           value="<?= $setting['setting_value'] ?>"
                           step="<?= $setting['step_value'] ?>">
                </div>
                <?php elseif ($setting['data_type'] === 'toggle'): ?>
                <div>
                    <label class="toggle-switch">
                        <input type="checkbox" 
                               class="category-input"
                               data-category="<?= $category ?>"
                               id="<?= $setting['setting_key'] ?>"
                               <?= $setting['setting_value'] == '1' ? 'checked' : '' ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
                <?php endif; ?>
            </div>
            <?php endforeach; ?>
            
            <button class="category-save-btn" id="save_<?= $category ?>" onclick="saveCategorySettings('<?= $category ?>')" disabled>
                <i class="fas fa-save"></i> Save <?= ucfirst($category) ?> Settings
            </button>
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
        // Track changed settings by category
        const changedSettingsByCategory = {};
        
        // Initialize change tracking
        function initializeChangeTracking() {
            document.querySelectorAll('.category-input').forEach(input => {
                const category = input.dataset.category;
                if (!changedSettingsByCategory[category]) {
                    changedSettingsByCategory[category] = new Set();
                }
                
                // Store original value
                input.dataset.originalValue = input.type === 'checkbox' ? (input.checked ? '1' : '0') : input.value;
                
                // Add event listeners
                if (input.type === 'range') {
                    input.addEventListener('input', function() {
                        const unit = document.querySelector(`[data-setting="${this.id}"]`)?.dataset.unit || '';
                        const valueDisplay = document.getElementById(this.id + '_value');
                        if (valueDisplay) {
                            valueDisplay.textContent = this.value + (this.id.includes('chance') ? '%' : 
                                this.id.includes('multiplier') ? 'x' : 
                                this.id.includes('speed') ? 'px/frame' : 
                                this.id.includes('duration') ? 's' : 
                                this.id.includes('volume') ? '' : '');
                        }
                        markCategoryChanged(category, this.id);
                    });
                } else {
                    input.addEventListener('change', function() {
                        markCategoryChanged(category, this.id);
                    });
                }
            });
        }
        
        function markCategoryChanged(category, settingId) {
            changedSettingsByCategory[category].add(settingId);
            
            // Show indicator and enable save button
            const indicator = document.getElementById(category + '_indicator');
            const saveBtn = document.getElementById('save_' + category);
            
            if (indicator) indicator.style.display = 'inline-block';
            if (saveBtn) saveBtn.disabled = false;
        }
        
        function clearCategoryChanges(category) {
            changedSettingsByCategory[category].clear();
            
            // Hide indicator and disable save button
            const indicator = document.getElementById(category + '_indicator');
            const saveBtn = document.getElementById('save_' + category);
            
            if (indicator) indicator.style.display = 'none';
            if (saveBtn) saveBtn.disabled = true;
        }
        
        async function saveCategorySettings(category) {
            const changedSettings = changedSettingsByCategory[category];
            if (!changedSettings || changedSettings.size === 0) {
                showStatus('No changes to save in ' + category, 'error');
                return;
            }
            
            let savedCount = 0;
            let errorCount = 0;
            
            for (const settingId of changedSettings) {
                const element = document.getElementById(settingId);
                let value;
                
                if (element.type === 'checkbox') {
                    value = element.checked ? '1' : '0';
                } else {
                    value = element.value;
                }
                
                try {
                    const response = await fetch('admin_game_config_realistic.php', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            action: 'update_setting',
                            key: settingId,
                            value: value
                        })
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        savedCount++;
                        element.dataset.originalValue = value;
                    } else {
                        errorCount++;
                    }
                } catch (error) {
                    errorCount++;
                }
            }
            
            if (errorCount === 0) {
                showStatus(`${category.charAt(0).toUpperCase() + category.slice(1)} settings saved successfully`, 'success');
                clearCategoryChanges(category);
                notifyGameOfConfigChange();
            } else {
                showStatus(`Saved ${savedCount} settings, ${errorCount} errors in ${category}`, 'error');
            }
        }
        
        async function saveAllSettings() {
            let totalSaved = 0;
            
            for (const category in changedSettingsByCategory) {
                const changedSettings = changedSettingsByCategory[category];
                if (changedSettings.size > 0) {
                    await saveCategorySettings(category);
                    totalSaved += changedSettings.size;
                }
            }
            
            if (totalSaved > 0) {
                showStatus(`All ${totalSaved} settings saved successfully`, 'success');
            } else {
                showStatus('No changes to save', 'error');
            }
        }
        
        async function resetDefaults() {
            if (!confirm('Are you sure you want to reset all settings to their default values?')) {
                return;
            }
            
            try {
                const response = await fetch('admin_game_config_realistic.php', {
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
            window.gameWindow = window.open('/breakout.html?config=realistic', '_blank');
        }
        
        function notifyGameOfConfigChange() {
            try {
                if (window.gameWindow && !window.gameWindow.closed) {
                    window.gameWindow.postMessage({ type: 'reloadConfig' }, '*');
                }
            } catch (error) {
                console.log('Could not notify game windows:', error);
            }
        }
        
        function showStatus(message, type) {
            const statusEl = document.getElementById('statusMessage');
            statusEl.textContent = message;
            statusEl.className = `status-message ${type} show`;
            
            setTimeout(() => {
                statusEl.classList.remove('show');
            }, 3000);
        }
        
        // Initialize when page loads
        document.addEventListener('DOMContentLoaded', function() {
            initializeChangeTracking();
        });
    </script>
</body>
</html>