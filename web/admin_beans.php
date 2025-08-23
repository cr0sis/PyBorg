<?php
require_once 'security_config.php';
require_once 'auth.php';
require_once 'secure_session_manager.php';

// Start secure session
$session_manager = new SecureSessionManager();
$session = $session_manager->get_session();

// Check authentication - redirect if not logged in
if (!is_logged_in()) {
    header('Location: login.php');
    exit();
}

// CSRF protection
$csrf_token = generate_csrf_token();

// Handle delete action
$message = '';
$messageType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    // Verify CSRF token
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $message = 'Invalid CSRF token';
        $messageType = 'error';
    } else {
        if ($_POST['action'] === 'delete' && isset($_POST['bean_id'])) {
            $bean_id = intval($_POST['bean_id']);
            
            // Connect to the appropriate database based on network
            $network = $_POST['network'] ?? 'rizon';
            $db_file = ($network === 'libera') 
                ? '/data/cr0_system/databases/libera_bot.db' 
                : '/data/cr0_system/databases/rizon_bot.db';
            
            try {
                $db = new SQLite3($db_file);
                $db->busyTimeout(5000);
                
                // Get bean info before deletion for logging
                $stmt = $db->prepare('SELECT url, added_by FROM bean_images WHERE id = :id');
                $stmt->bindValue(':id', $bean_id, SQLITE3_INTEGER);
                $result = $stmt->execute();
                $bean_info = $result->fetchArray(SQLITE3_ASSOC);
                
                if ($bean_info) {
                    // Delete the bean
                    $stmt = $db->prepare('DELETE FROM bean_images WHERE id = :id');
                    $stmt->bindValue(':id', $bean_id, SQLITE3_INTEGER);
                    
                    if ($stmt->execute()) {
                        $message = "Bean deleted successfully (URL: " . htmlspecialchars($bean_info['url']) . ")";
                        $messageType = 'success';
                        
                        // Log the action
                        log_security_event('bean_deleted', [
                            'bean_id' => $bean_id,
                            'url' => $bean_info['url'],
                            'added_by' => $bean_info['added_by'],
                            'network' => $network,
                            'admin' => $session['username']
                        ]);
                    } else {
                        $message = 'Failed to delete bean';
                        $messageType = 'error';
                    }
                } else {
                    $message = 'Bean not found';
                    $messageType = 'error';
                }
                
                $db->close();
            } catch (Exception $e) {
                $message = 'Database error: ' . $e->getMessage();
                $messageType = 'error';
                error_log('Bean deletion error: ' . $e->getMessage());
            }
        }
    }
}

// Get beans from both networks
$beans = [];
$networks = ['rizon', 'libera'];

foreach ($networks as $network) {
    $db_file = ($network === 'libera') 
        ? '/data/cr0_system/databases/libera_bot.db' 
        : '/data/cr0_system/databases/rizon_bot.db';
    
    if (file_exists($db_file)) {
        try {
            $db = new SQLite3($db_file);
            $db->busyTimeout(5000);
            
            $query = 'SELECT id, url, added_by, added_time, channel, description, view_count, last_viewed 
                     FROM bean_images 
                     ORDER BY added_time DESC';
            
            $result = $db->query($query);
            
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $row['network'] = $network;
                $beans[] = $row;
            }
            
            $db->close();
        } catch (Exception $e) {
            error_log("Error loading beans from $network: " . $e->getMessage());
        }
    }
}

// Sort all beans by added_time DESC
usort($beans, function($a, $b) {
    return strtotime($b['added_time']) - strtotime($a['added_time']);
});

// Pagination
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$per_page = 50;
$total_beans = count($beans);
$total_pages = ceil($total_beans / $per_page);
$offset = ($page - 1) * $per_page;

// Get beans for current page
$page_beans = array_slice($beans, $offset, $per_page);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Beans Management - Admin Panel</title>
    <link rel="stylesheet" href="css/admin_style.css">
    <style>
        .beans-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .beans-table th,
        .beans-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #333;
        }
        
        .beans-table th {
            background: rgba(0, 255, 0, 0.1);
            color: #0f0;
            font-weight: bold;
        }
        
        .beans-table tr:hover {
            background: rgba(0, 255, 0, 0.05);
        }
        
        .bean-url {
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        .bean-preview {
            max-width: 100px;
            max-height: 100px;
            cursor: pointer;
            border: 1px solid #333;
        }
        
        .bean-preview.error {
            display: none;
        }
        
        .network-badge {
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
        }
        
        .network-rizon {
            background: rgba(255, 100, 0, 0.2);
            color: #ff6400;
        }
        
        .network-libera {
            background: rgba(0, 100, 255, 0.2);
            color: #0064ff;
        }
        
        .delete-btn {
            background: rgba(255, 0, 0, 0.2);
            color: #ff0000;
            border: 1px solid #ff0000;
            padding: 5px 10px;
            cursor: pointer;
            border-radius: 3px;
        }
        
        .delete-btn:hover {
            background: rgba(255, 0, 0, 0.3);
        }
        
        .stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .stat-box {
            background: rgba(0, 255, 0, 0.05);
            border: 1px solid #0f0;
            padding: 15px;
            border-radius: 5px;
        }
        
        .stat-value {
            font-size: 2em;
            color: #0f0;
            font-weight: bold;
        }
        
        .stat-label {
            color: #888;
            font-size: 0.9em;
            margin-top: 5px;
        }
        
        .pagination {
            margin: 20px 0;
            text-align: center;
        }
        
        .pagination a {
            padding: 5px 10px;
            margin: 0 5px;
            border: 1px solid #0f0;
            color: #0f0;
            text-decoration: none;
            display: inline-block;
        }
        
        .pagination a:hover,
        .pagination .current {
            background: rgba(0, 255, 0, 0.1);
        }
        
        .filter-bar {
            margin: 20px 0;
            padding: 15px;
            background: rgba(0, 255, 0, 0.05);
            border: 1px solid #333;
            border-radius: 5px;
        }
        
        .filter-bar input {
            background: #000;
            border: 1px solid #0f0;
            color: #0f0;
            padding: 5px 10px;
            margin-right: 10px;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.9);
        }
        
        .modal-content {
            margin: 5% auto;
            max-width: 90%;
            max-height: 90%;
            text-align: center;
        }
        
        .modal-content img {
            max-width: 100%;
            max-height: 80vh;
        }
        
        .close-modal {
            position: absolute;
            top: 20px;
            right: 40px;
            color: #f00;
            font-size: 40px;
            font-weight: bold;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="admin-container">
        <header>
            <h1>🫘 Beans Management</h1>
            <nav>
                <a href="admin.php">Dashboard</a>
                <a href="admin_inject.php">Bot Commands</a>
                <a href="admin_beans.php" class="active">Beans</a>
                <a href="logout.php">Logout</a>
            </nav>
        </header>

        <?php if ($message): ?>
            <div class="message <?php echo $messageType; ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <div class="content">
            <!-- Statistics -->
            <div class="stats-container">
                <div class="stat-box">
                    <div class="stat-value"><?php echo $total_beans; ?></div>
                    <div class="stat-label">Total Beans</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">
                        <?php 
                        $rizon_count = count(array_filter($beans, fn($b) => $b['network'] === 'rizon'));
                        echo $rizon_count;
                        ?>
                    </div>
                    <div class="stat-label">Rizon Beans</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">
                        <?php 
                        $libera_count = count(array_filter($beans, fn($b) => $b['network'] === 'libera'));
                        echo $libera_count;
                        ?>
                    </div>
                    <div class="stat-label">Libera Beans</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">
                        <?php 
                        $total_views = array_sum(array_column($beans, 'view_count'));
                        echo $total_views;
                        ?>
                    </div>
                    <div class="stat-label">Total Views</div>
                </div>
            </div>

            <!-- Filter Bar -->
            <div class="filter-bar">
                <input type="text" id="searchInput" placeholder="Search URLs, users, descriptions..." onkeyup="filterBeans()">
                <select id="networkFilter" onchange="filterBeans()">
                    <option value="">All Networks</option>
                    <option value="rizon">Rizon Only</option>
                    <option value="libera">Libera Only</option>
                </select>
            </div>

            <!-- Beans Table -->
            <table class="beans-table" id="beansTable">
                <thead>
                    <tr>
                        <th>Preview</th>
                        <th>Network</th>
                        <th>URL</th>
                        <th>Added By</th>
                        <th>Channel</th>
                        <th>Added Time</th>
                        <th>Views</th>
                        <th>Description</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($page_beans as $bean): ?>
                    <tr data-network="<?php echo $bean['network']; ?>" 
                        data-searchable="<?php echo strtolower($bean['url'] . ' ' . $bean['added_by'] . ' ' . ($bean['description'] ?? '')); ?>">
                        <td>
                            <img src="<?php echo htmlspecialchars($bean['url']); ?>" 
                                 class="bean-preview" 
                                 alt="Bean preview"
                                 onerror="this.classList.add('error'); this.parentElement.innerHTML='[No preview]';"
                                 onclick="showModal('<?php echo htmlspecialchars($bean['url']); ?>')">
                        </td>
                        <td>
                            <span class="network-badge network-<?php echo $bean['network']; ?>">
                                <?php echo strtoupper($bean['network']); ?>
                            </span>
                        </td>
                        <td class="bean-url" title="<?php echo htmlspecialchars($bean['url']); ?>">
                            <a href="<?php echo htmlspecialchars($bean['url']); ?>" target="_blank">
                                <?php echo htmlspecialchars($bean['url']); ?>
                            </a>
                        </td>
                        <td><?php echo htmlspecialchars($bean['added_by']); ?></td>
                        <td><?php echo htmlspecialchars($bean['channel'] ?? 'N/A'); ?></td>
                        <td><?php echo date('Y-m-d H:i', strtotime($bean['added_time'])); ?></td>
                        <td><?php echo $bean['view_count']; ?></td>
                        <td><?php echo htmlspecialchars($bean['description'] ?? ''); ?></td>
                        <td>
                            <form method="POST" style="display: inline;" 
                                  onsubmit="return confirm('Are you sure you want to delete this bean?');">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <input type="hidden" name="action" value="delete">
                                <input type="hidden" name="bean_id" value="<?php echo $bean['id']; ?>">
                                <input type="hidden" name="network" value="<?php echo $bean['network']; ?>">
                                <button type="submit" class="delete-btn">Delete</button>
                            </form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

            <!-- Pagination -->
            <?php if ($total_pages > 1): ?>
            <div class="pagination">
                <?php if ($page > 1): ?>
                    <a href="?page=1">First</a>
                    <a href="?page=<?php echo $page - 1; ?>">Previous</a>
                <?php endif; ?>
                
                <?php 
                $start_page = max(1, $page - 2);
                $end_page = min($total_pages, $page + 2);
                
                for ($i = $start_page; $i <= $end_page; $i++): ?>
                    <a href="?page=<?php echo $i; ?>" <?php echo $i == $page ? 'class="current"' : ''; ?>>
                        <?php echo $i; ?>
                    </a>
                <?php endfor; ?>
                
                <?php if ($page < $total_pages): ?>
                    <a href="?page=<?php echo $page + 1; ?>">Next</a>
                    <a href="?page=<?php echo $total_pages; ?>">Last</a>
                <?php endif; ?>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Image Modal -->
    <div id="imageModal" class="modal" onclick="closeModal()">
        <span class="close-modal">&times;</span>
        <div class="modal-content">
            <img id="modalImage" src="" alt="Bean image">
        </div>
    </div>

    <script>
        function filterBeans() {
            const searchInput = document.getElementById('searchInput').value.toLowerCase();
            const networkFilter = document.getElementById('networkFilter').value;
            const rows = document.querySelectorAll('#beansTable tbody tr');
            
            rows.forEach(row => {
                const searchable = row.getAttribute('data-searchable');
                const network = row.getAttribute('data-network');
                
                let showRow = true;
                
                if (searchInput && !searchable.includes(searchInput)) {
                    showRow = false;
                }
                
                if (networkFilter && network !== networkFilter) {
                    showRow = false;
                }
                
                row.style.display = showRow ? '' : 'none';
            });
        }
        
        function showModal(url) {
            const modal = document.getElementById('imageModal');
            const modalImg = document.getElementById('modalImage');
            modal.style.display = 'block';
            modalImg.src = url;
        }
        
        function closeModal() {
            document.getElementById('imageModal').style.display = 'none';
        }
        
        // Close modal on ESC key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeModal();
            }
        });
    </script>
</body>
</html>