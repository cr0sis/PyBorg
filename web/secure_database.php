<?php
/**
 * DATABASE SECURITY HARDENING
 * Ensures database files are properly secured for internet exposure
 */

require_once 'config_paths.php';

// Database security configuration
$SECURE_DB_CONFIG = [
    'user_db' => ConfigPaths::getDatabase('users'),
    'rizon_db' => ConfigPaths::getDatabase('rizon'), 
    'libera_db' => ConfigPaths::getDatabase('libera'),
    'required_perms' => 0640, // rw-r-----
    'owner' => 'pyborg',
    'group' => 'www-data'
];

function secureDatabaseFiles() {
    global $SECURE_DB_CONFIG;
    
    $issues = [];
    
    foreach ($SECURE_DB_CONFIG as $name => $path) {
        if ($name === 'required_perms' || $name === 'owner' || $name === 'group') continue;
        
        if (!file_exists($path)) {
            $issues[] = "Database file missing: $path";
            continue;
        }
        
        // Check file permissions
        $currentPerms = fileperms($path) & 0777;
        $requiredPerms = $SECURE_DB_CONFIG['required_perms'];
        
        if ($currentPerms !== $requiredPerms) {
            $issues[] = "Insecure permissions on $path: " . decoct($currentPerms) . " (should be " . decoct($requiredPerms) . ")";
        }
        
        // Check if file is readable by web server
        if (!is_readable($path)) {
            $issues[] = "Database file not readable: $path";
        }
        
        // Check if file is world-readable (security risk)
        if ($currentPerms & 0004) {
            $issues[] = "CRITICAL: Database file is world-readable: $path";
        }
        
        // Check if file is world-writable (major security risk)
        if ($currentPerms & 0002) {
            $issues[] = "CRITICAL: Database file is world-writable: $path";
        }
    }
    
    return $issues;
}

function getDatabaseSecurityReport() {
    $issues = secureDatabaseFiles();
    
    $report = [
        'status' => empty($issues) ? 'secure' : (count($issues) > 2 ? 'critical' : 'warning'),
        'issues' => $issues,
        'recommendations' => [],
        'timestamp' => date('Y-m-d H:i:s')
    ];
    
    if (!empty($issues)) {
        $report['recommendations'][] = 'Run: sudo chown cr0:www-data /var/www/html/data/*.db';
        $report['recommendations'][] = 'Run: sudo chmod 640 /var/www/html/data/*.db';
        $report['recommendations'][] = 'Verify web server user is in www-data group';
    }
    
    return $report;
}

// Secure database connection class
class SecureDatabaseConnection {
    private $pdo;
    private $dbPath;
    
    public function __construct($dbPath) {
        // Validate database path
        if (!HardcoreSecurityManager::validateFilePath($dbPath, ['/home/cr0/cr0bot/'])) {
            throw new Exception('Invalid database path');
        }
        
        if (!file_exists($dbPath)) {
            throw new Exception('Database file not found');
        }
        
        // Check file permissions
        $perms = fileperms($dbPath) & 0777;
        if ($perms & 0004) { // World readable
            HardcoreSecurityManager::logSecurityEvent('CRITICAL', 'World-readable database accessed: ' . $dbPath);
        }
        
        $this->dbPath = $dbPath;
        
        try {
            $this->pdo = new PDO("sqlite:$dbPath");
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Set secure defaults
            $this->pdo->exec('PRAGMA foreign_keys = ON');
            $this->pdo->exec('PRAGMA journal_mode = WAL');
            $this->pdo->exec('PRAGMA synchronous = FULL');
            $this->pdo->exec('PRAGMA temp_store = MEMORY');
            
        } catch (PDOException $e) {
            HardcoreSecurityManager::logSecurityEvent('ERROR', 'Database connection failed: ' . $e->getMessage());
            throw new Exception('Database connection failed');
        }
    }
    
    public function prepare($query) {
        // Log all database queries for audit
        HardcoreSecurityManager::logSecurityEvent('DB', 'Query: ' . substr($query, 0, 100));
        
        // Detect suspicious queries
        $suspiciousPatterns = [
            '/drop\s+table/i' => 'DROP TABLE attempt',
            '/drop\s+database/i' => 'DROP DATABASE attempt', 
            '/truncate\s+table/i' => 'TRUNCATE TABLE attempt',
            '/delete\s+from.*where\s+1=1/i' => 'Mass deletion attempt',
            '/union.*select/i' => 'SQL injection attempt',
            '/--/i' => 'SQL comment injection',
            '/\/\*/i' => 'SQL comment injection'
        ];
        
        foreach ($suspiciousPatterns as $pattern => $description) {
            if (preg_match($pattern, $query)) {
                HardcoreSecurityManager::logSecurityEvent('ATTACK', $description . ': ' . $query);
                
                // Check if IP is trusted before blocking
                $trustedIPs = ['127.0.0.1', '::1', 'localhost'];
                $trustedIPsFile = __DIR__ . '/trusted_ips.php';
                if (file_exists($trustedIPsFile)) {
                    $additionalIPs = include $trustedIPsFile;
                    if (is_array($additionalIPs)) {
                        $trustedIPs = array_merge($trustedIPs, $additionalIPs);
                    }
                }
                
                if (!in_array($_SERVER['REMOTE_ADDR'], $trustedIPs)) {
                    HardcoreSecurityManager::blockIP($_SERVER['REMOTE_ADDR'], $description);
                }
                throw new Exception('Suspicious query detected');
            }
        }
        
        return $this->pdo->prepare($query);
    }
    
    public function query($query) {
        return $this->prepare($query);
    }
    
    public function exec($query) {
        HardcoreSecurityManager::logSecurityEvent('DB', 'Exec: ' . substr($query, 0, 100));
        return $this->pdo->exec($query);
    }
    
    public function lastInsertId() {
        return $this->pdo->lastInsertId();
    }
    
    public function beginTransaction() {
        return $this->pdo->beginTransaction();
    }
    
    public function commit() {
        return $this->pdo->commit();
    }
    
    public function rollback() {
        return $this->pdo->rollback();
    }
}

// Database backup with integrity checking
class SecureDatabaseBackup {
    public static function createSecureBackup($sourceDb, $backupPath) {
        if (!HardcoreSecurityManager::validateFilePath($sourceDb, ['/home/cr0/cr0bot/'])) {
            throw new Exception('Invalid source database path');
        }
        
        if (!HardcoreSecurityManager::validateFilePath($backupPath, ['/tmp/', '/home/cr0/backups/'])) {
            throw new Exception('Invalid backup path');
        }
        
        // Create backup directory if needed
        $backupDir = dirname($backupPath);
        if (!is_dir($backupDir)) {
            mkdir($backupDir, 0750, true);
        }
        
        // Copy file securely
        if (!copy($sourceDb, $backupPath)) {
            throw new Exception('Backup creation failed');
        }
        
        // Set secure permissions
        chmod($backupPath, 0640);
        
        // Create checksum for integrity verification
        $checksum = hash_file('sha256', $backupPath);
        file_put_contents($backupPath . '.sha256', $checksum);
        
        HardcoreSecurityManager::logSecurityEvent('BACKUP', 'Database backup created: ' . basename($backupPath));
        
        return [
            'success' => true,
            'backup_path' => $backupPath,
            'checksum' => $checksum,
            'size' => filesize($backupPath)
        ];
    }
    
    public static function verifyBackup($backupPath) {
        if (!file_exists($backupPath) || !file_exists($backupPath . '.sha256')) {
            return false;
        }
        
        $expectedChecksum = trim(file_get_contents($backupPath . '.sha256'));
        $actualChecksum = hash_file('sha256', $backupPath);
        
        return hash_equals($expectedChecksum, $actualChecksum);
    }
}
?>