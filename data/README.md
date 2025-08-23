# Centralized Data Synchronization System

This directory contains the centralized data synchronization system for the CR0 Bot infrastructure, providing automated sync between IRC bot networks and the website.

## Directory Structure

```
/data/cr0_system/
├── databases/              # Centralized database storage
│   ├── users.db           # User accounts and authentication  
│   ├── rizon_bot.db       # Rizon network bot data
│   ├── libera_bot.db      # Libera network bot data
│   └── breakout_scores.db # Game scores
├── logs/                  # Centralized logging
│   ├── security/          # Security events and alerts
│   ├── api/              # API access logs
│   ├── file_access/      # File operation logs
│   ├── integrity/        # File integrity monitoring
│   ├── website/          # Website error and security logs
│   └── irc_networks/     # IRC network logs
│       ├── rizon/        # Rizon network logs
│       └── libera/       # Libera network logs
├── shared_storage/        # Shared configuration and state
│   ├── api_keys.json     # API key management
│   ├── api_sessions.json # API session tracking
│   └── file_hashes.json  # File integrity baselines
└── cron_*.sh             # Synchronization scripts
```

## Cron Scripts

### Database Synchronization (`cron_sync_databases.sh`)
- **Frequency**: Every minute
- **Purpose**: Bidirectional sync of all database files between bot and website
- **Features**: 
  - Conflict detection and resolution
  - Automatic backups before sync
  - Weekly cleanup of old backups

### Log Synchronization (`cron_sync_logs.sh`)
- **Frequency**: Every minute  
- **Purpose**: Smart merging of IRC bot logs with centralized logs
- **Features**:
  - Intelligent log merging (appends new content only)
  - Automatic log rotation for large files
  - Daily cleanup of old rotated logs

### Security Monitoring (`cron_security_monitoring.sh`)
- **Frequency**: Every minute
- **Purpose**: File integrity monitoring and security maintenance
- **Features**:
  - File integrity checks every 5 minutes
  - API rate limit cleanup every hour
  - Security event archiving daily

## Installation

1. **Test the scripts first:**
   ```bash
   /data/cr0_system/test_cron_scripts.sh
   ```

2. **Install cron jobs:**
   ```bash
   /data/cr0_system/install_crontabs.sh
   ```

3. **Monitor activity:**
   ```bash
   tail -f /data/cr0_system/logs/cron_*.log
   ```

## Management Commands

### Manual Sync Operations
```bash
# Database operations
php /var/www/html/database_sync_script.php status
php /var/www/html/database_sync_script.php bidirectional
php /var/www/html/database_sync_script.php clean-backups

# Log operations  
php /var/www/html/log_sync_script.php status
php /var/www/html/log_sync_script.php bidirectional
php /var/www/html/log_sync_script.php rotate
```

### Crontab Management
```bash
# Install cron jobs
/data/cr0_system/install_crontabs.sh

# Remove cron jobs
/data/cr0_system/remove_crontabs.sh

# Test all scripts
/data/cr0_system/test_cron_scripts.sh
```

## Log Files

The system creates several log files to track synchronization activity:

- **`cron_database_sync.log`**: Database sync operations and results
- **`cron_log_sync.log`**: Log file sync operations and merging
- **`cron_security.log`**: Security monitoring and integrity checks

All log files automatically rotate when they exceed size limits.

## Security Features

- **Permissions**: All files use `cr0:www-data` ownership with appropriate permissions
- **Lock Files**: Prevents overlapping sync operations
- **Backup Creation**: Automatic backups before potentially destructive operations
- **Integrity Monitoring**: Regular checks of critical system files
- **Event Archiving**: Old security events are archived to prevent log bloat

## Troubleshooting

### Check Sync Status
```bash
# View current sync status
php /var/www/html/database_sync_script.php status
php /var/www/html/log_sync_script.php status

# Check recent log activity
tail -20 /data/cr0_system/logs/cron_database_sync.log
tail -20 /data/cr0_system/logs/cron_log_sync.log
```

### Common Issues

1. **Permission Errors**: Ensure files are owned by `cr0:www-data` with 775/664 permissions
2. **Lock File Issues**: Remove stuck lock files: `rm /tmp/*_sync.lock`
3. **Large Log Files**: Scripts automatically rotate logs, but manual rotation available
4. **Database Conflicts**: Review conflict details in sync logs and resolve manually if needed

### Manual Recovery
If automated sync fails, databases and logs can be manually synchronized:

```bash
# Force database sync from bot to central
php /var/www/html/database_sync_script.php sync-from-bot

# Force log sync from bot to central  
php /var/www/html/log_sync_script.php sync-all
```

## Integration

This system integrates with:
- **IRC Bot Networks**: Rizon and Libera Chat bots
- **Website Security System**: All 6 phases of security implementation
- **API Management**: Rate limiting and session tracking
- **File Integrity Monitoring**: Real-time file change detection

The centralized approach ensures data consistency across all components while maintaining security and providing automated maintenance.