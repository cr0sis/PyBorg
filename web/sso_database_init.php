<?php
/**
 * SSO Database Schema Initialization
 * Creates database tables for Single Sign-On functionality
 * 
 * Security: Enterprise-grade SSO infrastructure with comprehensive logging
 * Standards: OWASP 2024, NIST 800-63B-4 compliance
 */

require_once 'config_paths.php';
require_once 'security_config.php';

class SSODatabaseInitializer {
    private static $db_path;
    
    public static function init() {
        self::$db_path = ConfigPaths::getDatabase('sso');
        self::createTables();
        self::createIndexes();
        self::initializeDefaults();
    }
    
    private static function createTables() {
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // SSO Providers table
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS sso_providers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    type TEXT NOT NULL CHECK(type IN ('saml', 'oidc', 'oauth2')),
                    display_name TEXT NOT NULL,
                    icon_url TEXT,
                    entity_id TEXT,
                    sso_url TEXT NOT NULL,
                    sls_url TEXT,
                    metadata_url TEXT,
                    client_id TEXT,
                    client_secret TEXT,
                    scope TEXT DEFAULT 'openid profile email',
                    discovery_url TEXT,
                    x509_cert TEXT,
                    private_key TEXT,
                    config_json TEXT DEFAULT '{}',
                    is_active INTEGER DEFAULT 1,
                    auto_provision INTEGER DEFAULT 1,
                    require_2fa INTEGER DEFAULT 0,
                    admin_only INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_used DATETIME,
                    usage_count INTEGER DEFAULT 0,
                    error_count INTEGER DEFAULT 0,
                    security_flags TEXT DEFAULT '{}'
                )
            ");
            
            // SSO User Mappings table
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS sso_user_mappings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    provider_id INTEGER NOT NULL,
                    external_id TEXT NOT NULL,
                    external_username TEXT,
                    external_email TEXT,
                    external_display_name TEXT,
                    attributes_json TEXT DEFAULT '{}',
                    first_login DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_login DATETIME,
                    login_count INTEGER DEFAULT 0,
                    is_active INTEGER DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (provider_id) REFERENCES sso_providers (id) ON DELETE CASCADE,
                    UNIQUE(provider_id, external_id)
                )
            ");
            
            // SSO Authentication Sessions table
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS sso_auth_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_token TEXT NOT NULL UNIQUE,
                    provider_id INTEGER NOT NULL,
                    external_id TEXT,
                    state TEXT NOT NULL,
                    nonce TEXT,
                    code_verifier TEXT,
                    redirect_uri TEXT,
                    initiated_ip TEXT NOT NULL,
                    user_agent_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    completed_at INTEGER,
                    user_id INTEGER,
                    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'completed', 'failed', 'expired')),
                    error_message TEXT,
                    security_flags TEXT DEFAULT '{}',
                    FOREIGN KEY (provider_id) REFERENCES sso_providers (id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
                )
            ");
            
            // SSO Security Events table
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS sso_security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    provider_id INTEGER,
                    user_id INTEGER,
                    session_token TEXT,
                    ip_address TEXT NOT NULL,
                    user_agent TEXT,
                    severity TEXT NOT NULL CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                    message TEXT NOT NULL,
                    details_json TEXT DEFAULT '{}',
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    resolved INTEGER DEFAULT 0,
                    FOREIGN KEY (provider_id) REFERENCES sso_providers (id) ON DELETE SET NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
                )
            ");
            
            // SSO Configuration table
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS sso_configuration (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_name TEXT NOT NULL UNIQUE,
                    value TEXT,
                    is_encrypted INTEGER DEFAULT 0,
                    description TEXT,
                    category TEXT DEFAULT 'general',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_by INTEGER,
                    FOREIGN KEY (updated_by) REFERENCES users (id) ON DELETE SET NULL
                )
            ");
            
            // Add SSO columns to existing users table if they don't exist
            $pdo->exec("
                ALTER TABLE users ADD COLUMN sso_provider_id INTEGER DEFAULT NULL
            ");
            
            $pdo->exec("
                ALTER TABLE users ADD COLUMN external_sso_id TEXT DEFAULT NULL
            ");
            
            $pdo->exec("
                ALTER TABLE users ADD COLUMN sso_auto_provisioned INTEGER DEFAULT 0
            ");
            
            $pdo->exec("
                ALTER TABLE users ADD COLUMN sso_last_login DATETIME DEFAULT NULL
            ");
            
        } catch (PDOException $e) {
            // Column might already exist, continue
            if (!strpos($e->getMessage(), 'duplicate column name')) {
                error_log("SSO Database init error: " . $e->getMessage());
                throw new Exception("Failed to initialize SSO database tables");
            }
        }
    }
    
    private static function createIndexes() {
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // SSO Providers indexes
            $pdo->exec("CREATE INDEX IF NOT EXISTS idx_sso_providers_type ON sso_providers(type)");
            $pdo->exec("CREATE INDEX IF NOT EXISTS idx_sso_providers_active ON sso_providers(is_active)");
            
            // SSO User Mappings indexes
            $pdo->exec("CREATE INDEX IF NOT EXISTS idx_sso_user_mappings_user_id ON sso_user_mappings(user_id)");
            $pdo->exec("CREATE INDEX IF NOT EXISTS idx_sso_user_mappings_provider_id ON sso_user_mappings(provider_id)");
            $pdo->exec("CREATE INDEX IF NOT EXISTS idx_sso_user_mappings_external_id ON sso_user_mappings(external_id)");
            
            // SSO Auth Sessions indexes
            $pdo->exec("CREATE INDEX IF NOT EXISTS idx_sso_auth_sessions_token ON sso_auth_sessions(session_token)");
            $pdo->exec("CREATE INDEX IF NOT EXISTS idx_sso_auth_sessions_status ON sso_auth_sessions(status)");
            $pdo->exec("CREATE INDEX IF NOT EXISTS idx_sso_auth_sessions_expires ON sso_auth_sessions(expires_at)");
            
            // SSO Security Events indexes
            $pdo->exec("CREATE INDEX IF NOT EXISTS idx_sso_security_events_type ON sso_security_events(event_type)");
            $pdo->exec("CREATE INDEX IF NOT EXISTS idx_sso_security_events_severity ON sso_security_events(severity)");
            $pdo->exec("CREATE INDEX IF NOT EXISTS idx_sso_security_events_timestamp ON sso_security_events(timestamp)");
            
            // Users table SSO indexes
            $pdo->exec("CREATE INDEX IF NOT EXISTS idx_users_sso_provider ON users(sso_provider_id)");
            
        } catch (PDOException $e) {
            error_log("SSO Index creation error: " . $e->getMessage());
            // Non-critical, continue
        }
    }
    
    private static function initializeDefaults() {
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Insert default configuration values
            $defaults = [
                ['sso_enabled', '1', 'Enable SSO functionality globally', 'security'],
                ['sso_auto_provision', '1', 'Auto-provision users from SSO', 'provisioning'],
                ['sso_require_2fa_admin', '1', 'Require 2FA for SSO admin users', 'security'],
                ['sso_session_timeout', '3600', 'SSO session timeout in seconds', 'session'],
                ['sso_encryption_key', bin2hex(random_bytes(32)), 'SSO encryption key', 'security'],
                ['sso_audit_retention_days', '365', 'Days to retain SSO audit logs', 'audit'],
                ['sso_max_concurrent_sessions', '5', 'Max concurrent SSO sessions per user', 'session'],
                ['sso_ip_binding_admin', '1', 'Bind admin SSO sessions to IP', 'security'],
                ['sso_emergency_disable', '0', 'Emergency disable all SSO', 'emergency']
            ];
            
            foreach ($defaults as $config) {
                $stmt = $pdo->prepare("
                    INSERT OR IGNORE INTO sso_configuration (key_name, value, description, category, is_encrypted)
                    VALUES (?, ?, ?, ?, ?)
                ");
                $stmt->execute([
                    $config[0], 
                    $config[1], 
                    $config[2], 
                    $config[3],
                    ($config[0] === 'sso_encryption_key') ? 1 : 0
                ]);
            }
            
        } catch (PDOException $e) {
            error_log("SSO Default config error: " . $e->getMessage());
            throw new Exception("Failed to initialize SSO default configuration");
        }
    }
    
    /**
     * Cleanup expired SSO sessions
     */
    public static function cleanup() {
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $now = time();
            
            // Mark expired sessions
            $stmt = $pdo->prepare("
                UPDATE sso_auth_sessions 
                SET status = 'expired' 
                WHERE expires_at < ? AND status = 'pending'
            ");
            $stmt->execute([$now]);
            
            // Log cleanup
            logSecurityEvent('SSO_CLEANUP', 'Cleaned up expired SSO auth sessions', 'LOW');
            
        } catch (PDOException $e) {
            error_log("SSO Cleanup error: " . $e->getMessage());
        }
    }
    
    /**
     * Validate database integrity
     */
    public static function validate() {
        try {
            $pdo = new PDO("sqlite:" . self::$db_path);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Check required tables exist
            $required_tables = [
                'sso_providers',
                'sso_user_mappings', 
                'sso_auth_sessions',
                'sso_security_events',
                'sso_configuration'
            ];
            
            foreach ($required_tables as $table) {
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?");
                $stmt->execute([$table]);
                if ($stmt->fetchColumn() == 0) {
                    throw new Exception("Required SSO table missing: $table");
                }
            }
            
            return true;
            
        } catch (PDOException $e) {
            error_log("SSO Database validation error: " . $e->getMessage());
            return false;
        }
    }
}

// Auto-initialize if run directly
if (basename($_SERVER['SCRIPT_NAME']) === 'sso_database_init.php') {
    try {
        SSODatabaseInitializer::init();
        echo "SSO database schema initialized successfully.\n";
        
        if (SSODatabaseInitializer::validate()) {
            echo "SSO database validation passed.\n";
        } else {
            echo "SSO database validation failed.\n";
        }
        
    } catch (Exception $e) {
        echo "SSO database initialization failed: " . $e->getMessage() . "\n";
        http_response_code(500);
    }
}
?>