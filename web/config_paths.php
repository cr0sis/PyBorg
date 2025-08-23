<?php
/**
 * Centralized Path Configuration
 * Central configuration for all data and log file paths
 */

class ConfigPaths {
    
    // Base directories
    const BASE_DATA_DIR = '/data/cr0_system';
    const BASE_LOG_DIR = '/data/cr0_system/logs';
    const BASE_DB_DIR = '/data/cr0_system/databases';
    const SHARED_STORAGE_DIR = '/data/cr0_system/shared_storage';
    
    // Database paths
    const DB_USERS = '/data/cr0_system/databases/users.db';
    const DB_RIZON_BOT = '/data/cr0_system/databases/rizon_bot.db';
    const DB_LIBERA_BOT = '/data/cr0_system/databases/libera_bot.db';
    const DB_BREAKOUT_SCORES = '/data/cr0_system/databases/breakout_scores.db';
    const DB_BREAKOUT_COMPLETIONISTS = '/data/cr0_system/databases/breakout_completionists.db';
    const DB_BREAKOUT_SETTINGS = '/data/cr0_system/databases/breakout_settings.db';
    const DB_GAME_SESSIONS = '/data/cr0_system/databases/game_sessions.db';
    const DB_SECURE_SESSIONS = '/data/cr0_system/databases/secure_sessions.db';
    const DB_SSO_FEDERATED_IDENTITIES = '/data/cr0_system/databases/sso_federated_identities.db';
    
    // Security log paths
    const LOG_SECURITY_EVENTS = '/data/cr0_system/logs/security/security_events.json';
    const LOG_FILE_ACCESS = '/data/cr0_system/logs/file_access/file_access.log';
    const LOG_API_ACCESS = '/data/cr0_system/logs/api/api_access.log';
    const LOG_INTEGRITY_ALERTS = '/data/cr0_system/logs/integrity/integrity_alerts.json';
    const LOG_SECURITY_DIR = '/data/cr0_system/logs/security';
    const LOG_SECURITY_CONFIG = '/data/cr0_system/logs/security/alert_config.json';
    const LOG_SECURITY_QUEUE = '/data/cr0_system/logs/security/alert_queue.json';
    
    // Website log paths
    const LOG_WEBSITE_ERRORS = '/data/cr0_system/logs/website/errors';
    const LOG_WEBSITE_SECURITY = '/data/cr0_system/logs/website/security';
    const LOG_BLOCKED_IPS = '/data/cr0_system/logs/website/security/blocked_ips.json';
    const LOG_THROTTLED_IPS = '/data/cr0_system/logs/website/security/throttled_ips.json';
    const LOG_CHALLENGE_IPS = '/data/cr0_system/logs/website/security/challenge_ips.json';
    const LOG_ALERT_NOTIFICATIONS = '/data/cr0_system/logs/website/security/alert_notifications.log';
    
    // IRC network log paths
    const LOG_RIZON_BOT = '/data/cr0_system/logs/irc_networks/rizon/rizon_bot.log';
    const LOG_RIZON_ERRORS = '/data/cr0_system/logs/irc_networks/rizon/rizon_errors.log';
    const LOG_RIZON_STARTUP = '/data/cr0_system/logs/irc_networks/rizon/rizon_startup.log';
    const LOG_LIBERA_BOT = '/data/cr0_system/logs/irc_networks/libera/libera_bot.log';
    const LOG_LIBERA_ERRORS = '/data/cr0_system/logs/irc_networks/libera/libera_errors.log';
    const LOG_LIBERA_STARTUP = '/data/cr0_system/logs/irc_networks/libera/libera_startup.log';
    
    // Secure storage paths
    const STORAGE_API_KEYS = '/data/cr0_system/shared_storage/api_keys.json';
    const STORAGE_API_SESSIONS = '/data/cr0_system/shared_storage/api_sessions.json';
    const STORAGE_API_RATE_LIMITS = '/data/cr0_system/shared_storage/api_rate_limits.json';
    const STORAGE_FILE_HASHES = '/data/cr0_system/shared_storage/file_hashes.json';
    const STORAGE_INTEGRITY_CONFIG = '/data/cr0_system/shared_storage/integrity_config.json';
    
    // Bot management script paths
    const SCRIPT_START_ALL = '/data/cr0_system/start_all_bots_web.sh';
    const SCRIPT_STOP_ALL = '/data/cr0_system/stop_all_bots_web.sh';
    const SCRIPT_RESTART_ALL = '/data/cr0_system/restart_all_bots_web.sh';
    const SCRIPT_START_RIZON = '/data/cr0_system/start_rizon_web.sh';
    const SCRIPT_STOP_RIZON = '/data/cr0_system/stop_rizon_web.sh';
    const SCRIPT_RESTART_RIZON = '/data/cr0_system/restart_rizon_web.sh';
    const SCRIPT_START_LIBERA = '/data/cr0_system/start_libera_web.sh';
    const SCRIPT_STOP_LIBERA = '/data/cr0_system/stop_libera_web.sh';
    const SCRIPT_RESTART_LIBERA = '/data/cr0_system/restart_libera_web.sh';
    
    // Upload directories (keep in web-accessible area for serving files)
    const UPLOAD_DIR = '/var/www/html/uploads';
    const QUARANTINE_DIR = '/var/www/html/quarantine';
    
    /**
     * Get database path by name
     */
    public static function getDatabase($name) {
        switch (strtolower($name)) {
            case 'users':
                return self::DB_USERS;
            case 'rizon_bot':
            case 'rizon':
                return self::DB_RIZON_BOT;
            case 'libera_bot':
            case 'libera':
                return self::DB_LIBERA_BOT;
            case 'breakout_scores':
            case 'breakout':
                return self::DB_BREAKOUT_SCORES;
            case 'breakout_completionists':
            case 'completionists':
                return self::DB_BREAKOUT_COMPLETIONISTS;
            case 'breakout_settings':
            case 'settings':
                return self::DB_BREAKOUT_SETTINGS;
            case 'game_sessions':
            case 'sessions':
                return self::DB_GAME_SESSIONS;
            case 'secure_sessions':
                return self::DB_SECURE_SESSIONS;
            case 'sso_federated_identities':
            case 'sso':
                return self::DB_SSO_FEDERATED_IDENTITIES;
            default:
                return null;
        }
    }
    
    /**
     * Get log path by type and network (if applicable)
     */
    public static function getLogPath($type, $network = null) {
        switch (strtolower($type)) {
            case 'security_events':
                return self::LOG_SECURITY_EVENTS;
            case 'file_access':
                return self::LOG_FILE_ACCESS;
            case 'api_access':
                return self::LOG_API_ACCESS;
            case 'integrity_alerts':
                return self::LOG_INTEGRITY_ALERTS;
            case 'security_dir':
                return self::LOG_SECURITY_DIR;
            case 'security_config':
                return self::LOG_SECURITY_CONFIG;
            case 'security_queue':
                return self::LOG_SECURITY_QUEUE;
            case 'bot':
                if ($network === 'rizon') return self::LOG_RIZON_BOT;
                if ($network === 'libera') return self::LOG_LIBERA_BOT;
                break;
            case 'errors':
                if ($network === 'rizon') return self::LOG_RIZON_ERRORS;
                if ($network === 'libera') return self::LOG_LIBERA_ERRORS;
                break;
            case 'startup':
                if ($network === 'rizon') return self::LOG_RIZON_STARTUP;
                if ($network === 'libera') return self::LOG_LIBERA_STARTUP;
                break;
        }
        return null;
    }
    
    /**
     * Get storage path by type
     */
    public static function getStoragePath($type) {
        switch (strtolower($type)) {
            case 'api_keys':
                return self::STORAGE_API_KEYS;
            case 'api_sessions':
                return self::STORAGE_API_SESSIONS;
            case 'api_rate_limits':
                return self::STORAGE_API_RATE_LIMITS;
            case 'file_hashes':
                return self::STORAGE_FILE_HASHES;
            case 'integrity_config':
                return self::STORAGE_INTEGRITY_CONFIG;
            default:
                return null;
        }
    }
    
    /**
     * Get bot management script path by action and network
     */
    public static function getBotScript($action, $network = 'all') {
        $key = strtolower($action . '_' . $network);
        
        switch ($key) {
            case 'start_all':
                return self::SCRIPT_START_ALL;
            case 'stop_all':
                return self::SCRIPT_STOP_ALL;
            case 'restart_all':
                return self::SCRIPT_RESTART_ALL;
            case 'start_rizon':
                return self::SCRIPT_START_RIZON;
            case 'stop_rizon':
                return self::SCRIPT_STOP_RIZON;
            case 'restart_rizon':
                return self::SCRIPT_RESTART_RIZON;
            case 'start_libera':
                return self::SCRIPT_START_LIBERA;
            case 'stop_libera':
                return self::SCRIPT_STOP_LIBERA;
            case 'restart_libera':
                return self::SCRIPT_RESTART_LIBERA;
            default:
                return null;
        }
    }
    
    /**
     * Ensure directory exists with proper permissions
     */
    public static function ensureDirectory($path) {
        $directory = is_file($path) ? dirname($path) : $path;
        
        if (!is_dir($directory)) {
            if (mkdir($directory, 0775, true)) {
                // Ensure proper ownership for shared access (skip if hanging)
                @chgrp($directory, 'www-data');
                @chmod($directory, 0775);
                return true;
            }
            return false;
        }
        return true;
    }
    
    /**
     * Initialize all required directories
     */
    public static function initializeDirectories() {
        $directories = [
            self::BASE_DATA_DIR,
            self::BASE_LOG_DIR,
            self::BASE_DB_DIR,
            self::SHARED_STORAGE_DIR,
            self::LOG_SECURITY_DIR,
            self::LOG_SECURITY_DIR . '/events',
            self::LOG_SECURITY_DIR . '/alerts',
            self::LOG_SECURITY_DIR . '/analysis',
            self::LOG_SECURITY_DIR . '/audit',
            dirname(self::LOG_FILE_ACCESS),
            dirname(self::LOG_API_ACCESS),
            dirname(self::LOG_INTEGRITY_ALERTS),
            self::LOG_WEBSITE_ERRORS,
            self::LOG_WEBSITE_SECURITY,
            dirname(self::LOG_RIZON_BOT),
            dirname(self::LOG_LIBERA_BOT)
        ];
        
        $created = 0;
        $errors = [];
        
        foreach ($directories as $dir) {
            if (self::ensureDirectory($dir)) {
                $created++;
            } else {
                $errors[] = $dir;
            }
        }
        
        return [
            'success' => empty($errors),
            'created' => $created,
            'errors' => $errors
        ];
    }
    
    /**
     * Check if all paths are accessible
     */
    public static function validatePaths() {
        $paths = [
            'users_db' => self::DB_USERS,
            'rizon_db' => self::DB_RIZON_BOT,
            'libera_db' => self::DB_LIBERA_BOT,
            'security_events' => self::LOG_SECURITY_EVENTS,
            'api_keys' => self::STORAGE_API_KEYS
        ];
        
        $results = [];
        
        foreach ($paths as $name => $path) {
            $results[$name] = [
                'path' => $path,
                'exists' => file_exists($path),
                'readable' => is_readable($path),
                'writable' => is_writable(dirname($path)),
                'directory_exists' => is_dir(dirname($path))
            ];
        }
        
        return $results;
    }
    
    /**
     * Legacy path mapping (for backwards compatibility during transition)
     */
    public static function getLegacyPath($newPath) {
        $mappings = [
            self::DB_USERS => '/var/www/html/data/users.db',
            self::DB_RIZON_BOT => '/var/www/html/data/rizon_bot.db',
            self::DB_LIBERA_BOT => '/var/www/html/data/libera_bot.db',
            self::LOG_SECURITY_EVENTS => '/tmp/security_events.json'
        ];
        
        return $mappings[$newPath] ?? null;
    }
    
    /**
     * Get all network databases
     */
    public static function getNetworkDatabases() {
        return [
            'rizon' => self::DB_RIZON_BOT,
            'libera' => self::DB_LIBERA_BOT
        ];
    }
    
    /**
     * Get all network log directories
     */
    public static function getNetworkLogDirs() {
        return [
            'rizon' => dirname(self::LOG_RIZON_BOT),
            'libera' => dirname(self::LOG_LIBERA_BOT)
        ];
    }
}

// Initialize directories on include (with timeout protection)
if (!defined('SKIP_CONFIG_INIT')) {
    ConfigPaths::initializeDirectories();
}
?>