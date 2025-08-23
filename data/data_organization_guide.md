# Data Organization Guide

## Standardized Directory Structure

This document defines the standardized structure for `/data/cr0_system/` to ensure consistency and maintainability.

### 1. Database Organization

**Location**: `/data/cr0_system/databases/`

**Naming Convention**:
- Bot databases: `{network}_bot.db` (rizon_bot.db, libera_bot.db)
- Game databases: `{game}_{type}.db` (breakout_scores.db, breakout_settings.db)
- System databases: `{system}.db` (users.db, security_audit.db)

**Backup Convention**:
- Automatic backups: `{database}.backup.{YYYY-MM-DD_HH-MM-SS}`
- Latest backup symlink: `{database}.backup.latest`
- Emergency backups: `{database}.emergency.{YYYY-MM-DD_HH-MM-SS}`

### 2. Logging Structure

**Location**: `/data/cr0_system/logs/`

```
logs/
├── irc_networks/           # IRC bot logs by network
│   ├── rizon/
│   │   ├── bot.log         # Main bot log
│   │   ├── errors.log      # Error log
│   │   └── startup.log     # Startup/shutdown log
│   └── libera/
│       ├── bot.log
│       ├── errors.log
│       └── startup.log
├── security/
│   ├── events/             # Daily security event logs
│   ├── alerts/             # Security alerts
│   ├── audit/              # Admin actions audit trail
│   └── analysis/           # Security analysis data
├── website/
│   ├── access.log          # Web access logs
│   ├── error.log           # PHP errors
│   └── security.log        # Web-specific security events
├── games/
│   ├── breakout.log        # Game-specific logs
│   └── uno.log
└── system/
    ├── cron.log            # Cron job logs
    ├── maintenance.log     # System maintenance
    └── performance.log     # Performance metrics
```

**Log Rotation**: Daily rotation with 30-day retention by default

### 3. Runtime Data

**Location**: `/data/cr0_system/runtime/`

```
runtime/
├── bot_status/             # Current bot status files
│   ├── rizon_status.json
│   └── libera_status.json
├── pid_files/              # Process ID files
│   ├── rizon_bot.pid
│   └── libera_bot.pid
├── locks/                  # Process locks
└── tmp/                    # Temporary files
    └── bot_commands/       # Command injection queue
```

### 4. Configuration

**Location**: `/data/cr0_system/config/`

```
config/
├── networks/               # Network-specific configurations
│   ├── rizon.json
│   └── libera.json
├── security/
│   ├── blocked_ips.json
│   ├── trusted_ips.json
│   └── security_rules.json
├── games/
│   ├── breakout_settings.json
│   └── game_config.json
└── system/
    ├── logging.json
    └── maintenance.json
```

### 5. Scripts Organization

**Location**: `/data/cr0_system/scripts/`

```
scripts/
├── bot_management/
│   ├── start_bot.sh        # Generic start script
│   ├── stop_bot.sh         # Generic stop script
│   ├── restart_bot.sh      # Generic restart script
│   └── manage_bot.sh       # Unified management script
├── maintenance/
│   ├── backup_databases.sh
│   ├── cleanup_logs.sh
│   └── health_check.sh
└── security/
    ├── security_scan.sh
    ├── update_blocks.sh
    └── audit_report.sh
```

## File Naming Standards

### Database Files
- Primary: `{purpose}.db`
- Backup: `{purpose}.backup.{timestamp}`
- Emergency: `{purpose}.emergency.{timestamp}`

### Log Files
- Daily logs: `{YYYY-MM-DD}.log`
- Service logs: `{service}.log`
- Rotated logs: `{service}.log.{YYYY-MM-DD}`

### Configuration Files
- JSON config: `{component}_config.json`
- Environment: `{component}.env`
- Settings: `{component}_settings.json`

### Status Files
- JSON status: `{service}_status.json`
- PID files: `{service}.pid`
- Lock files: `{service}.lock`

## Maintenance Procedures

### Daily
- Log rotation
- Database integrity check
- Status file cleanup
- Temporary file cleanup

### Weekly
- Database backup verification
- Log archive compression
- Security scan
- Performance analysis

### Monthly
- Full database backup
- Log archival
- Configuration backup
- System health report

## Migration Plan

To standardize existing data:

1. **Create new directory structure**
2. **Migrate files to new locations**
3. **Update scripts to use new paths**
4. **Update configuration references**
5. **Test all systems**
6. **Remove old structure**

## Benefits

- **Consistency**: Standardized naming and organization
- **Maintainability**: Easy to find and manage files
- **Automation**: Consistent structure enables better scripts
- **Monitoring**: Clear separation enables better monitoring
- **Scalability**: Easy to add new components