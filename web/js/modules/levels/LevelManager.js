/**
 * LevelManager - Handles level loading, caching, and validation for Breakout game
 * 
 * Features:
 * - Async level loading with performance monitoring
 * - In-memory caching for optimal performance
 * - JSON format validation and error handling
 * - Fallback to procedural generation if loading fails
 * - Feature flag support for gradual migration
 */
class LevelManager {
    constructor(options = {}) {
        this.cache = new Map();
        this.loadingPromises = new Map();
        this.options = {
            useExternalLevels: options.useExternalLevels !== false, // Default true
            basePath: options.basePath || '/js/modules/levels/data/',
            maxCacheSize: options.maxCacheSize || 50,
            loadTimeoutMs: options.loadTimeoutMs || 5000,
            ...options
        };
        
        // Performance tracking
        this.stats = {
            totalLoads: 0,
            cacheHits: 0,
            loadTimes: [],
            errors: 0
        };
        
        // Validation schema for level JSON
        this.levelSchema = {
            version: 'string',
            levelNumber: 'number',
            name: 'string',
            description: 'string',
            blocks: 'array',
            metadata: 'object'
        };
        
        this.blockSchema = {
            col: 'number',
            row: 'number',
            hits: 'number',
            type: 'string',
            color: 'string'
        };
    }
    
    /**
     * Load level data - main entry point
     * @param {number} levelNumber - Level to load (1-100)
     * @returns {Promise<Object>} Level data object
     */
    async loadLevel(levelNumber) {
        const startTime = performance.now();
        
        try {
            // Check cache first
            if (this.cache.has(levelNumber)) {
                this.stats.cacheHits++;
                this.recordLoadTime(startTime);
                return this.cache.get(levelNumber);
            }
            
            // Check if already loading
            if (this.loadingPromises.has(levelNumber)) {
                return await this.loadingPromises.get(levelNumber);
            }
            
            // Start loading
            const loadPromise = this._loadLevelData(levelNumber);
            this.loadingPromises.set(levelNumber, loadPromise);
            
            try {
                const levelData = await loadPromise;
                this.loadingPromises.delete(levelNumber);
                
                // Cache the result
                this._cacheLevel(levelNumber, levelData);
                this.recordLoadTime(startTime);
                this.stats.totalLoads++;
                
                return levelData;
            } catch (error) {
                this.loadingPromises.delete(levelNumber);
                throw error;
            }
            
        } catch (error) {
            this.stats.errors++;
            console.warn(`Failed to load level ${levelNumber}:`, error);
            
            // Fallback to procedural generation
            return this._generateFallbackLevel(levelNumber);
        }
    }
    
    /**
     * Internal level loading with timeout and validation
     * @private
     */
    async _loadLevelData(levelNumber) {
        if (!this.options.useExternalLevels || levelNumber > 10) {
            // Use procedural generation for levels not yet externalized
            return this._generateFallbackLevel(levelNumber);
        }
        
        const filename = `level-${levelNumber.toString().padStart(3, '0')}.json`;
        const url = this.options.basePath + filename;
        
        // Implement timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.options.loadTimeoutMs);
        
        try {
            const response = await fetch(url, {
                signal: controller.signal,
                cache: 'no-cache' // Ensure we get latest version during development
            });
            
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const levelData = await response.json();
            
            // Validate the loaded data
            this._validateLevelData(levelData, levelNumber);
            
            return levelData;
            
        } catch (error) {
            clearTimeout(timeoutId);
            if (error.name === 'AbortError') {
                throw new Error(`Load timeout after ${this.options.loadTimeoutMs}ms`);
            }
            throw error;
        }
    }
    
    /**
     * Validate level data structure
     * @private
     */
    _validateLevelData(data, expectedLevel) {
        if (!data || typeof data !== 'object') {
            throw new Error('Invalid level data: not an object');
        }
        
        // Check required fields
        for (const [field, type] of Object.entries(this.levelSchema)) {
            if (!(field in data)) {
                throw new Error(`Missing required field: ${field}`);
            }
            
            if (type === 'array' && !Array.isArray(data[field])) {
                throw new Error(`Field ${field} must be an array`);
            } else if (type !== 'array' && typeof data[field] !== type) {
                throw new Error(`Field ${field} must be of type ${type}`);
            }
        }
        
        // Validate level number matches
        if (data.levelNumber !== expectedLevel) {
            throw new Error(`Level number mismatch: expected ${expectedLevel}, got ${data.levelNumber}`);
        }
        
        // Validate blocks array
        if (!Array.isArray(data.blocks)) {
            throw new Error('Blocks must be an array');
        }
        
        // Validate each block
        for (let i = 0; i < data.blocks.length; i++) {
            const block = data.blocks[i];
            for (const [field, type] of Object.entries(this.blockSchema)) {
                if (!(field in block)) {
                    throw new Error(`Block ${i} missing field: ${field}`);
                }
                if (typeof block[field] !== type) {
                    throw new Error(`Block ${i} field ${field} must be of type ${type}`);
                }
            }
            
            // Validate ranges
            if (block.col < 0 || block.col >= 20) {
                throw new Error(`Block ${i} col out of range: ${block.col}`);
            }
            if (block.row < 0 || block.row >= 8) {
                throw new Error(`Block ${i} row out of range: ${block.row}`);
            }
            if (block.hits < 1 || block.hits > 10) {
                throw new Error(`Block ${i} hits out of range: ${block.hits}`);
            }
        }
    }
    
    /**
     * Cache management with size limits
     * @private
     */
    _cacheLevel(levelNumber, levelData) {
        // Implement LRU cache behavior
        if (this.cache.size >= this.options.maxCacheSize) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }
        
        this.cache.set(levelNumber, levelData);
    }
    
    /**
     * Generate fallback level using original procedural logic
     * @private
     */
    _generateFallbackLevel(levelNumber) {
        // This will call the original game's level generation
        // We'll implement this during integration phase
        return {
            version: "1.0.0",
            levelNumber: levelNumber,
            name: `Procedural Level ${levelNumber}`,
            description: `Generated using original game logic`,
            blocks: [], // Will be populated by original generation logic
            metadata: {
                generated: true,
                timestamp: Date.now(),
                generationType: 'fallback'
            }
        };
    }
    
    /**
     * Convert block data from JSON format to game format
     * @param {Array} jsonBlocks - Blocks from JSON
     * @param {Object} gameConstants - Game constants (blockWidth, blockHeight, etc.)
     * @returns {Array} Blocks in game format
     */
    convertBlocksToGameFormat(jsonBlocks, gameConstants) {
        const { blockWidth, blockHeight, blockPadding } = gameConstants;
        
        return jsonBlocks.map(block => ({
            x: block.col * (blockWidth + blockPadding),
            y: block.row * (blockHeight + blockPadding),
            width: blockWidth,
            height: blockHeight,
            hits: block.hits,
            type: block.type,
            color: block.color,
            // Include original col/row for debugging
            col: block.col,
            row: block.row
        }));
    }
    
    /**
     * Performance and stats methods
     */
    recordLoadTime(startTime) {
        const loadTime = performance.now() - startTime;
        this.stats.loadTimes.push(loadTime);
        
        // Keep only last 100 measurements
        if (this.stats.loadTimes.length > 100) {
            this.stats.loadTimes.shift();
        }
    }
    
    getPerformanceStats() {
        const loadTimes = this.stats.loadTimes;
        return {
            totalLoads: this.stats.totalLoads,
            cacheHits: this.stats.cacheHits,
            errors: this.stats.errors,
            cacheHitRate: this.stats.totalLoads > 0 ? (this.stats.cacheHits / this.stats.totalLoads * 100).toFixed(1) + '%' : '0%',
            averageLoadTime: loadTimes.length > 0 ? (loadTimes.reduce((a, b) => a + b, 0) / loadTimes.length).toFixed(2) + 'ms' : '0ms',
            maxLoadTime: loadTimes.length > 0 ? Math.max(...loadTimes).toFixed(2) + 'ms' : '0ms',
            cacheSize: this.cache.size
        };
    }
    
    /**
     * Clear cache and reset stats
     */
    reset() {
        this.cache.clear();
        this.loadingPromises.clear();
        this.stats = {
            totalLoads: 0,
            cacheHits: 0,
            loadTimes: [],
            errors: 0
        };
    }
    
    /**
     * Preload multiple levels for better performance
     * @param {Array<number>} levelNumbers - Levels to preload
     */
    async preloadLevels(levelNumbers) {
        const promises = levelNumbers.map(level => this.loadLevel(level));
        const results = await Promise.allSettled(promises);
        
        const failed = results
            .map((result, index) => ({ result, level: levelNumbers[index] }))
            .filter(({ result }) => result.status === 'rejected')
            .map(({ level }) => level);
            
        if (failed.length > 0) {
            console.warn('Failed to preload levels:', failed);
        }
        
        return {
            successful: levelNumbers.length - failed.length,
            failed: failed.length,
            failedLevels: failed
        };
    }
}

// Export for use in the game
if (typeof module !== 'undefined' && module.exports) {
    module.exports = LevelManager;
} else {
    window.LevelManager = LevelManager;
}