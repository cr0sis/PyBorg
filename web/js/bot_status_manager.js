/**
 * Centralized Bot Status Manager
 * Provides a unified interface for all bot status operations across the admin panel
 */

class BotStatusManager {
    constructor() {
        this.cache = new Map();
        this.cacheTimeout = 5000; // 5 seconds
        this.listeners = new Map();
        this.refreshInterval = null;
        this.lastUpdate = null;
        
        // Event types that components can listen to
        this.events = {
            STATUS_CHANGED: 'status_changed',
            BOT_ONLINE: 'bot_online',
            BOT_OFFLINE: 'bot_offline',
            ERROR: 'error'
        };
    }
    
    /**
     * Get comprehensive bot status
     * @param {boolean} forceRefresh - Force refresh from server
     * @returns {Promise<Object>} Bot status data
     */
    async getStatus(forceRefresh = false) {
        const cacheKey = 'comprehensive_status';
        
        // Check cache first unless force refresh
        if (!forceRefresh && this.isCacheValid(cacheKey)) {
            return this.cache.get(cacheKey).data;
        }
        
        try {
            const response = await fetch(`${window.location.protocol}//${window.location.host}/api/bot_status.php?action=full`, {
                credentials: 'same-origin'
            });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            
            if (data.error) {
                throw new Error(data.error);
            }
            
            // Cache the result
            this.cache.set(cacheKey, {
                data: data,
                timestamp: Date.now()
            });
            
            // Check for status changes and emit events
            this.checkStatusChanges(data);
            
            this.lastUpdate = Date.now();
            return data;
            
        } catch (error) {
            console.error('Bot Status Manager Error:', error);
            this.emit(this.events.ERROR, { error: error.message });
            throw error;
        }
    }
    
    /**
     * Get quick online/offline status for lightweight checks
     * @returns {Promise<Object>} Simple online status
     */
    async getQuickStatus() {
        const cacheKey = 'quick_status';
        
        if (this.isCacheValid(cacheKey)) {
            return this.cache.get(cacheKey).data;
        }
        
        try {
            const response = await fetch(`${window.location.protocol}//${window.location.host}/api/bot_status.php?action=quick`, {
                credentials: 'same-origin'
            });
            const data = await response.json();
            
            if (data.error) {
                throw new Error(data.error);
            }
            
            this.cache.set(cacheKey, {
                data: data,
                timestamp: Date.now()
            });
            
            return data;
            
        } catch (error) {
            console.error('Quick Status Error:', error);
            throw error;
        }
    }
    
    /**
     * Get status for a specific network
     * @param {string} network - rizon or libera
     * @returns {Promise<Object>} Network-specific status
     */
    async getNetworkStatus(network) {
        const fullStatus = await this.getStatus();
        return fullStatus.networks[network] || null;
    }
    
    /**
     * Get overall system status
     * @returns {Promise<Object>} Overall status summary
     */
    async getOverallStatus() {
        const fullStatus = await this.getStatus();
        return fullStatus.overall || null;
    }
    
    /**
     * Start automatic status updates
     * @param {number} interval - Refresh interval in milliseconds
     */
    startAutoRefresh(interval = 10000) {
        this.stopAutoRefresh();
        
        this.refreshInterval = setInterval(async () => {
            try {
                await this.getStatus(true); // Force refresh
            } catch (error) {
                console.error('Auto refresh error:', error);
            }
        }, interval);
        
        console.log(`Bot status auto-refresh started (${interval}ms interval)`);
    }
    
    /**
     * Stop automatic status updates
     */
    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
            console.log('Bot status auto-refresh stopped');
        }
    }
    
    /**
     * Subscribe to status events
     * @param {string} event - Event type
     * @param {function} callback - Event handler
     */
    on(event, callback) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, []);
        }
        this.listeners.get(event).push(callback);
    }
    
    /**
     * Unsubscribe from status events
     * @param {string} event - Event type
     * @param {function} callback - Event handler to remove
     */
    off(event, callback) {
        if (this.listeners.has(event)) {
            const callbacks = this.listeners.get(event);
            const index = callbacks.indexOf(callback);
            if (index > -1) {
                callbacks.splice(index, 1);
            }
        }
    }
    
    /**
     * Emit an event to all listeners
     * @private
     */
    emit(event, data) {
        if (this.listeners.has(event)) {
            this.listeners.get(event).forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    console.error(`Event listener error for ${event}:`, error);
                }
            });
        }
    }
    
    /**
     * Check for status changes and emit appropriate events
     * @private
     */
    checkStatusChanges(newStatus) {
        const oldStatus = this.cache.get('comprehensive_status_previous');
        
        if (oldStatus) {
            // Check for bot online/offline changes
            ['rizon', 'libera'].forEach(network => {
                const oldOnline = oldStatus.data?.networks?.[network]?.online || false;
                const newOnline = newStatus?.networks?.[network]?.online || false;
                
                if (oldOnline !== newOnline) {
                    const event = newOnline ? this.events.BOT_ONLINE : this.events.BOT_OFFLINE;
                    this.emit(event, { network, status: newStatus.networks[network] });
                }
            });
            
            // Emit general status change event
            this.emit(this.events.STATUS_CHANGED, newStatus);
        }
        
        // Store current status for next comparison
        this.cache.set('comprehensive_status_previous', {
            data: JSON.parse(JSON.stringify(newStatus)),
            timestamp: Date.now()
        });
    }
    
    /**
     * Check if cached data is still valid
     * @private
     */
    isCacheValid(key) {
        const cached = this.cache.get(key);
        return cached && (Date.now() - cached.timestamp) < this.cacheTimeout;
    }
    
    /**
     * Clear all cached data
     */
    clearCache() {
        this.cache.clear();
        console.log('Bot status cache cleared');
    }
    
    /**
     * Get cache statistics
     */
    getCacheStats() {
        return {
            entries: this.cache.size,
            lastUpdate: this.lastUpdate,
            cacheTimeout: this.cacheTimeout,
            autoRefreshActive: this.refreshInterval !== null
        };
    }
    
    /**
     * Helper method to format uptime
     * @param {number} seconds - Uptime in seconds
     * @returns {string} Formatted uptime string
     */
    static formatUptime(seconds) {
        if (!seconds || seconds < 0) return 'Unknown';
        
        if (seconds < 60) return `${seconds}s`;
        if (seconds < 3600) return `${Math.floor(seconds/60)}m ${seconds%60}s`;
        if (seconds < 86400) return `${Math.floor(seconds/3600)}h ${Math.floor((seconds%3600)/60)}m`;
        return `${Math.floor(seconds/86400)}d ${Math.floor((seconds%86400)/3600)}h ${Math.floor(((seconds%86400)%3600)/60)}m`;
    }
    
    /**
     * Helper method to get status color based on online state
     * @param {boolean} online - Whether bot is online
     * @returns {string} CSS color value
     */
    static getStatusColor(online) {
        return online ? '#059669' : '#dc2626';
    }
    
    /**
     * Helper method to get status icon based on online state
     * @param {boolean} online - Whether bot is online
     * @returns {string} Status icon
     */
    static getStatusIcon(online) {
        return online ? '🟢' : '🔴';
    }
}

// Create global instance
window.BotStatusManager = window.BotStatusManager || new BotStatusManager();

// Utility functions for backward compatibility with existing code
window.getBotStatus = async function(forceRefresh = false) {
    return await window.BotStatusManager.getStatus(forceRefresh);
};

window.getQuickBotStatus = async function() {
    return await window.BotStatusManager.getQuickStatus();
};

// Auto-initialize if we're in the admin panel
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        if (document.getElementById('admin-panel') || document.querySelector('.tab-content')) {
            window.BotStatusManager.startAutoRefresh(15000); // 15 second refresh
        }
    });
} else {
    if (document.getElementById('admin-panel') || document.querySelector('.tab-content')) {
        window.BotStatusManager.startAutoRefresh(15000);
    }
}