/**
 * Real-time Bot Status Manager
 * Replaces polling-based status updates with Server-Sent Events for real-time updates
 */

class RealtimeBotStatusManager {
    constructor() {
        this.eventSource = null;
        this.isConnected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 1000;
        this.listeners = new Map();
        this.lastEventId = 0;
        this.heartbeatTimeout = null;
        this.connectionStartTime = null;
        this.status = {
            networks: { rizon: {}, libera: {} },
            overall: {},
            lastUpdate: null
        };
        
        // Event types
        this.events = {
            STATUS_CHANGED: 'status_changed',
            BOT_ONLINE: 'bot_online',
            BOT_OFFLINE: 'bot_offline',
            BOT_STARTED: 'bot_started',
            BOT_STOPPED: 'bot_stopped',
            BOT_RESTARTED: 'bot_restarted',
            CONNECTION_ESTABLISHED: 'connection_established',
            CONNECTION_LOST: 'connection_lost',
            ERROR: 'error'
        };
        
        console.log('Real-time Bot Status Manager initialized');
    }
    
    /**
     * Start real-time connection
     */
    async connect() {
        if (this.isConnected) {
            console.log('Real-time connection already active');
            return;
        }
        
        try {
            // Get initial status
            await this.getInitialStatus();
            
            // Start SSE connection
            this.startSSEConnection();
            
        } catch (error) {
            console.error('Failed to establish real-time connection:', error);
            this.emit(this.events.ERROR, { error: error.message });
            
            // Fallback to initial status
            await this.getInitialStatus();
        }
    }
    
    /**
     * Get initial status via API
     */
    async getInitialStatus() {
        try {
            const response = await fetch('/api/realtime_bot_status.php?action=realtime');
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            if (data.error) {
                throw new Error(data.error);
            }
            
            this.updateStatus(data);
            console.log('Initial status loaded:', data);
            
        } catch (error) {
            console.error('Failed to get initial status:', error);
            throw error;
        }
    }
    
    /**
     * Start Server-Sent Events connection
     */
    startSSEConnection() {
        const sseUrl = `/api/sse_connection_manager.php?lastEventId=${this.lastEventId}`;
        
        console.log('Establishing SSE connection:', sseUrl);
        
        this.eventSource = new EventSource(sseUrl);
        this.connectionStartTime = Date.now();
        
        // Connection opened
        this.eventSource.onopen = (event) => {
            console.log('SSE connection established');
            this.isConnected = true;
            this.reconnectAttempts = 0;
            this.emit(this.events.CONNECTION_ESTABLISHED, { timestamp: Date.now() });
        };
        
        // Handle different event types
        this.eventSource.addEventListener('connection', (event) => {
            const data = JSON.parse(event.data);
            console.log('SSE connection confirmed:', data);
        });
        
        this.eventSource.addEventListener('bot_status_change', (event) => {
            const data = JSON.parse(event.data);
            this.handleBotStatusChange(data);
            this.lastEventId = parseInt(event.lastEventId) || this.lastEventId;
        });
        
        this.eventSource.addEventListener('heartbeat', (event) => {
            const data = JSON.parse(event.data);
            this.handleHeartbeat(data);
        });
        
        this.eventSource.addEventListener('error', (event) => {
            const data = JSON.parse(event.data);
            console.error('SSE error event:', data);
            this.emit(this.events.ERROR, data);
        });
        
        this.eventSource.addEventListener('timeout', (event) => {
            const data = JSON.parse(event.data);
            console.log('SSE timeout, will reconnect:', data);
            this.handleConnectionLoss();
        });
        
        // Connection error
        this.eventSource.onerror = (event) => {
            console.error('SSE connection error:', event);
            this.handleConnectionLoss();
        };
        
        // Generic message handler (fallback)
        this.eventSource.onmessage = (event) => {
            console.log('Generic SSE message:', event.data);
        };
    }
    
    /**
     * Handle bot status change events
     */
    handleBotStatusChange(data) {
        console.log('Bot status change:', data);
        
        const { network, status, change_type } = data;
        const wasOnline = this.status.networks[network]?.online || false;
        const isOnline = status === 'online';
        
        // Update internal status
        this.status.networks[network] = {
            online: isOnline,
            pid: data.pid,
            uptime: data.uptime,
            uptime_formatted: data.formatted_uptime,
            last_update: data.timestamp,
            change_type: change_type,
            status_color: isOnline ? '#059669' : '#dc2626',
            status_icon: isOnline ? '🟢' : '🔴',
            status_text: isOnline ? 'Online' : 'Offline'
        };
        
        // Update overall status
        this.updateOverallStatus();
        
        // Emit appropriate events
        this.emit(this.events.STATUS_CHANGED, {
            network,
            status: this.status.networks[network],
            change_type
        });
        
        if (change_type === 'bot_started' || (wasOnline !== isOnline && isOnline)) {
            this.emit(this.events.BOT_ONLINE, { network, status: this.status.networks[network] });
        } else if (change_type === 'bot_stopped' || (wasOnline !== isOnline && !isOnline)) {
            this.emit(this.events.BOT_OFFLINE, { network, status: this.status.networks[network] });
        }
        
        if (change_type === 'bot_restarted') {
            this.emit(this.events.BOT_RESTARTED, { network, status: this.status.networks[network] });
        }
        
        // Update DOM elements
        this.updateStatusDisplay();
    }
    
    /**
     * Handle heartbeat events
     */
    handleHeartbeat(data) {
        // Reset heartbeat timeout
        if (this.heartbeatTimeout) {
            clearTimeout(this.heartbeatTimeout);
        }
        
        // Set timeout for next expected heartbeat (45 seconds)
        this.heartbeatTimeout = setTimeout(() => {
            console.warn('Heartbeat timeout, connection may be lost');
            this.handleConnectionLoss();
        }, 45000);
    }
    
    /**
     * Handle connection loss and attempt reconnection
     */
    handleConnectionLoss() {
        console.log('Handling connection loss...');
        
        this.isConnected = false;
        this.emit(this.events.CONNECTION_LOST, { timestamp: Date.now() });
        
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
        }
        
        if (this.heartbeatTimeout) {
            clearTimeout(this.heartbeatTimeout);
            this.heartbeatTimeout = null;
        }
        
        // Attempt reconnection with exponential backoff
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
            
            console.log(`Attempting reconnection ${this.reconnectAttempts}/${this.maxReconnectAttempts} in ${delay}ms`);
            
            setTimeout(() => {
                this.startSSEConnection();
            }, delay);
        } else {
            console.error('Max reconnection attempts reached, falling back to polling');
            this.fallbackToPolling();
        }
    }
    
    /**
     * Fallback to polling when SSE fails
     */
    fallbackToPolling() {
        console.log('Falling back to polling mode');
        
        const pollInterval = setInterval(async () => {
            try {
                await this.getInitialStatus();
                this.updateStatusDisplay();
            } catch (error) {
                console.error('Polling error:', error);
            }
        }, 10000); // Poll every 10 seconds
        
        // Try to reconnect SSE every 60 seconds
        setTimeout(() => {
            clearInterval(pollInterval);
            this.reconnectAttempts = 0;
            this.connect();
        }, 60000);
    }
    
    /**
     * Update status from API response
     */
    updateStatus(data) {
        this.status = {
            networks: data.networks || {},
            overall: data.overall || {},
            lastUpdate: data.timestamp || Date.now()
        };
        
        this.emit(this.events.STATUS_CHANGED, this.status);
    }
    
    /**
     * Update overall status based on network status
     */
    updateOverallStatus() {
        const onlineCount = Object.values(this.status.networks).filter(n => n.online).length;
        
        this.status.overall = {
            bots_online: onlineCount,
            total_bots: 2,
            all_online: onlineCount === 2,
            any_online: onlineCount > 0,
            status_text: this.getOverallStatusText(onlineCount),
            status_color: this.getOverallStatusColor(onlineCount)
        };
    }
    
    /**
     * Update DOM elements with current status
     */
    updateStatusDisplay() {
        // Update network status displays
        ['rizon', 'libera'].forEach(network => {
            const status = this.status.networks[network];
            if (!status) return;
            
            // Update status indicators
            const indicators = document.querySelectorAll(`[data-network="${network}"]`);
            indicators.forEach(indicator => {
                const statusElement = indicator.querySelector('.status-indicator, .bot-status');
                if (statusElement) {
                    statusElement.textContent = status.status_icon + ' ' + status.status_text;
                    statusElement.style.color = status.status_color;
                }
                
                const uptimeElement = indicator.querySelector('.uptime, .bot-uptime');
                if (uptimeElement) {
                    uptimeElement.textContent = status.uptime_formatted || '0s';
                }
                
                const pidElement = indicator.querySelector('.pid, .bot-pid');
                if (pidElement) {
                    pidElement.textContent = status.pid || 'N/A';
                }
            });
        });
        
        // Update overall status
        const overallElements = document.querySelectorAll('.overall-status');
        overallElements.forEach(element => {
            element.textContent = this.status.overall.status_text;
            element.style.color = this.status.overall.status_color;
        });
        
        // Update last update time
        const lastUpdateElements = document.querySelectorAll('.last-update');
        lastUpdateElements.forEach(element => {
            element.textContent = new Date(this.status.lastUpdate * 1000).toLocaleString();
        });
    }
    
    /**
     * Get current status (for backward compatibility)
     */
    getStatus() {
        return Promise.resolve(this.status);
    }
    
    /**
     * Get quick status (for backward compatibility)
     */
    getQuickStatus() {
        return Promise.resolve({
            rizon: this.status.networks.rizon?.online || false,
            libera: this.status.networks.libera?.online || false,
            timestamp: this.status.lastUpdate
        });
    }
    
    /**
     * Subscribe to events
     */
    on(event, callback) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, []);
        }
        this.listeners.get(event).push(callback);
    }
    
    /**
     * Unsubscribe from events
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
     * Emit event to listeners
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
     * Disconnect from real-time updates
     */
    disconnect() {
        console.log('Disconnecting from real-time updates');
        
        this.isConnected = false;
        
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
        }
        
        if (this.heartbeatTimeout) {
            clearTimeout(this.heartbeatTimeout);
            this.heartbeatTimeout = null;
        }
    }
    
    /**
     * Get connection statistics
     */
    getConnectionStats() {
        return {
            isConnected: this.isConnected,
            reconnectAttempts: this.reconnectAttempts,
            connectionUptime: this.connectionStartTime ? Date.now() - this.connectionStartTime : 0,
            lastEventId: this.lastEventId,
            listenersCount: Array.from(this.listeners.values()).reduce((sum, arr) => sum + arr.length, 0)
        };
    }
    
    // Helper methods
    getOverallStatusText(onlineCount) {
        if (onlineCount === 2) return 'All Bots Online';
        if (onlineCount === 1) return 'Partial Service';
        return 'All Bots Offline';
    }
    
    getOverallStatusColor(onlineCount) {
        if (onlineCount === 2) return '#059669';
        if (onlineCount === 1) return '#f59e0b';
        return '#dc2626';
    }
    
    static formatUptime(seconds) {
        if (!seconds || seconds < 0) return 'Unknown';
        
        if (seconds < 60) return `${seconds}s`;
        if (seconds < 3600) return `${Math.floor(seconds/60)}m ${seconds%60}s`;
        if (seconds < 86400) return `${Math.floor(seconds/3600)}h ${Math.floor((seconds%3600)/60)}m`;
        return `${Math.floor(seconds/86400)}d ${Math.floor((seconds%86400)/3600)}h ${Math.floor(((seconds%86400)%3600)/60)}m`;
    }
    
    static getStatusColor(online) {
        return online ? '#059669' : '#dc2626';
    }
    
    static getStatusIcon(online) {
        return online ? '🟢' : '🔴';
    }
}

// Create global instance
window.RealtimeBotStatusManager = window.RealtimeBotStatusManager || new RealtimeBotStatusManager();

// Backward compatibility functions
window.getBotStatus = async function(forceRefresh = false) {
    return await window.RealtimeBotStatusManager.getStatus();
};

window.getQuickBotStatus = async function() {
    return await window.RealtimeBotStatusManager.getQuickStatus();
};

// Auto-initialize real-time connection when page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        if (document.getElementById('admin-panel') || document.querySelector('.tab-content')) {
            console.log('Auto-starting real-time bot status connection');
            window.RealtimeBotStatusManager.connect();
        }
    });
} else {
    if (document.getElementById('admin-panel') || document.querySelector('.tab-content')) {
        console.log('Auto-starting real-time bot status connection');
        window.RealtimeBotStatusManager.connect();
    }
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.RealtimeBotStatusManager) {
        window.RealtimeBotStatusManager.disconnect();
    }
});