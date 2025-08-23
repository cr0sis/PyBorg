/**
 * Level Data Generator - Extracts exact block positions from original game logic
 * This script recreates the original pattern generation to capture exact block data
 */

// Constants from the original game
const blockRows = 8;
const blockCols = 20;

// Color themes from original game
const colorThemes = {
    rainbow: ['#FF0000', '#FF7F00', '#FFFF00', '#00FF00', '#0000FF', '#4B0082', '#9400D3'],
    ocean: ['#001F3F', '#003A70', '#0074D9', '#39CCCC', '#7FDBFF', '#85DCB0', '#B3E5FC'],
    sunset: ['#FF6B35', '#F7931E', '#FCEE21', '#FF9F1C', '#FF4E50', '#FC913A', '#F9D423'],
    nature: ['#355E3B', '#4F7942', '#228B22', '#32CD32', '#7CFC00', '#ADFF2F', '#9ACD32'],
    space: ['#0B0C10', '#1F2833', '#45A29E', '#66FCF1', '#C5C6C7', '#1F2833', '#0B0C10'],
    neon: ['#FF00FF', '#00FFFF', '#FF00AA', '#00FF00', '#FFFF00', '#FF0099', '#00FFAA'],
    pastel: ['#FFB6C1', '#FFC0CB', '#FFE4E1', '#F0E68C', '#E6E6FA', '#D8BFD8', '#F5DEB3']
};

// Hit count calculation (simplified version of original)
function getBlockHitCount(currentLevel, requestedHits = 1) {
    if (currentLevel < 15) {
        return 1;
    } else if (currentLevel < 25) {
        return Math.min(requestedHits, 2);
    } else if (currentLevel < 75) {
        return Math.min(requestedHits, 4);
    } else if (currentLevel < 90) {
        return Math.min(requestedHits, 5);
    } else if (currentLevel < 95) {
        return Math.min(requestedHits, 6);
    } else if (currentLevel < 100) {
        return Math.min(requestedHits, 7);
    } else {
        return Math.min(requestedHits, 8);
    }
}

// Block creation function
function createBlock(col, row, hits = 1, type = 'normal', color = null) {
    const isMetalBrick = type === 'metal';
    const isLavaBrick = type === 'lava';
    
    let blockColor;
    if (color) {
        blockColor = color;
    } else if (isMetalBrick) {
        blockColor = '#666666';
    } else if (isLavaBrick) {
        blockColor = '#FF4500';
    } else {
        blockColor = '#FF0040'; // Default color
    }
    
    return {
        col: col,
        row: row,
        hits: hits,
        type: type,
        color: blockColor
    };
}

// Pattern generation functions (copied from original game)
function createGradientPattern(theme, currentLevel, direction = 'horizontal', hitModifier = 1) {
    const colors = colorThemes[theme] || colorThemes.rainbow;
    const blocks = [];
    
    for (let row = 0; row < blockRows; row++) {
        for (let col = 0; col < blockCols; col++) {
            let colorIndex;
            
            if (direction === 'horizontal') {
                colorIndex = Math.floor(col * colors.length / blockCols);
            } else if (direction === 'vertical') {
                colorIndex = Math.floor(row * colors.length / blockRows);
            } else if (direction === 'diagonal') {
                colorIndex = Math.floor((row + col) * colors.length / (blockRows + blockCols));
            } else if (direction === 'radial') {
                const centerRow = blockRows / 2;
                const centerCol = blockCols / 2;
                const distance = Math.sqrt(Math.pow(row - centerRow, 2) + Math.pow(col - centerCol, 2));
                const maxDistance = Math.sqrt(Math.pow(centerRow, 2) + Math.pow(centerCol, 2));
                colorIndex = Math.floor(distance * colors.length / maxDistance);
            }
            
            colorIndex = Math.min(colorIndex, colors.length - 1);
            const hits = getBlockHitCount(currentLevel, 1 + Math.floor(colorIndex / 2) * hitModifier);
            blocks.push(createBlock(col, row, hits, 'normal', colors[colorIndex]));
        }
    }
    
    return blocks;
}

function createWavePattern(theme, currentLevel, amplitude = 2, frequency = 0.5, hitModifier = 1) {
    const colors = colorThemes[theme] || colorThemes.rainbow;
    const blocks = [];
    
    for (let col = 0; col < blockCols; col++) {
        const wave = Math.sin(col * frequency) * amplitude;
        const centerRow = Math.floor(blockRows / 2);
        
        for (let row = 0; row < blockRows; row++) {
            const distance = Math.abs(row - (centerRow + wave));
            
            if (distance <= amplitude) {
                const colorIndex = Math.floor(distance + col / 3) % colors.length;
                const hits = getBlockHitCount(currentLevel, Math.min(4, 1 + Math.floor(distance)) * hitModifier);
                blocks.push(createBlock(col, row, hits, 'normal', colors[colorIndex]));
            }
        }
    }
    
    return blocks;
}

function createCheckerboard(theme, currentLevel, size = 2, hitModifier = 1) {
    const colors = colorThemes[theme] || colorThemes.rainbow;
    const blocks = [];
    
    for (let row = 0; row < blockRows; row++) {
        for (let col = 0; col < blockCols; col++) {
            const checkRow = Math.floor(row / size);
            const checkCol = Math.floor(col / size);
            
            if ((checkRow + checkCol) % 2 === 0) {
                const colorIndex = ((checkRow * 3) + checkCol) % colors.length;
                const hits = getBlockHitCount(currentLevel, 1 + (row % 2) * hitModifier);
                blocks.push(createBlock(col, row, hits, 'normal', colors[colorIndex]));
            }
        }
    }
    
    return blocks;
}

function createDiamond(theme, currentLevel, filled = true, hitModifier = 1) {
    const colors = colorThemes[theme] || colorThemes.rainbow;
    const blocks = [];
    const centerRow = Math.floor(blockRows / 2);
    const centerCol = Math.floor(blockCols / 2);
    
    for (let row = 0; row < blockRows; row++) {
        const colorIndex = row % colors.length;
        const currentColor = colors[colorIndex];
        const rowDist = Math.abs(row - centerRow);
        const width = blockCols - rowDist * 4;
        
        if (width > 0) {
            const start = Math.floor((blockCols - width) / 2);
            const end = start + width - 1;
            
            if (filled) {
                for (let col = start; col <= end; col++) {
                    const hits = getBlockHitCount(currentLevel, Math.min(4, 1 + Math.floor(rowDist / 2)) * hitModifier);
                    blocks.push(createBlock(col, row, hits, 'normal', currentColor));
                }
            } else {
                // Only edges
                if (start >= 0 && start < blockCols) {
                    blocks.push(createBlock(start, row, getBlockHitCount(currentLevel, 2 * hitModifier), 'normal', currentColor));
                }
                if (end >= 0 && end < blockCols && end !== start) {
                    blocks.push(createBlock(end, row, getBlockHitCount(currentLevel, 2 * hitModifier), 'normal', currentColor));
                }
            }
        }
    }
    
    return blocks;
}

function createPixelArt(artData, theme, currentLevel, hitModifier = 1) {
    const colors = colorThemes[theme] || colorThemes.rainbow;
    const blocks = [];
    
    for (let row = 0; row < Math.min(artData.length, blockRows); row++) {
        for (let col = 0; col < Math.min(artData[row].length, blockCols); col++) {
            if (artData[row][col] > 0) {
                const colorIndex = (artData[row][col] - 1) % colors.length;
                const hits = getBlockHitCount(currentLevel, artData[row][col] * hitModifier);
                blocks.push(createBlock(col, row, hits, 'normal', colors[colorIndex]));
            }
        }
    }
    
    return blocks;
}

// Level generation functions
function generateLevel1() {
    return createGradientPattern('rainbow', 1, 'horizontal', 1);
}

function generateLevel2() {
    return createWavePattern('ocean', 2, 1.5, 0.3, 1);
}

function generateLevel3() {
    return createCheckerboard('pastel', 3, 3, 1);
}

function generateLevel4() {
    return createDiamond('sunset', 4, false, 1);
}

function generateLevel5() {
    return createGradientPattern('nature', 5, 'vertical', 1);
}

function generateLevel6() {
    const colors6 = colorThemes.neon;
    const blocks = [];
    let colorIdx6 = 0;
    
    for (let row = 0; row < 3; row++) {
        for (let col = 2; col < blockCols - 2; col++) {
            blocks.push(createBlock(col, row, getBlockHitCount(6, 1), 'normal', colors6[colorIdx6 % colors6.length]));
            colorIdx6++;
        }
    }
    
    return blocks;
}

function generateLevel7() {
    const heart = [
        [0,1,1,0,0,0,1,1,0,0,0,1,1,0,0,0,1,1,0,0],
        [1,2,2,1,0,1,2,2,1,0,1,2,2,1,0,1,2,2,1,0],
        [1,2,2,2,1,2,2,2,1,0,1,2,2,2,1,2,2,2,1,0],
        [0,1,2,2,2,2,2,1,0,0,0,1,2,2,2,2,2,1,0,0],
        [0,0,1,2,2,2,1,0,0,0,0,0,1,2,2,2,1,0,0,0],
        [0,0,0,1,2,1,0,0,0,0,0,0,0,1,2,1,0,0,0,0],
        [0,0,0,0,1,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0],
        [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    ];
    return createPixelArt(heart, 'sunset', 7, 1);
}

function generateLevel8() {
    return createGradientPattern('space', 8, 'diagonal', 1);
}

function generateLevel9() {
    return createCheckerboard('rainbow', 9, 2, 1);
}

function generateLevel10() {
    return createGradientPattern('ocean', 10, 'radial', 1);
}

// Level generation mapping
const levelGenerators = {
    1: generateLevel1,
    2: generateLevel2,
    3: generateLevel3,
    4: generateLevel4,
    5: generateLevel5,
    6: generateLevel6,
    7: generateLevel7,
    8: generateLevel8,
    9: generateLevel9,
    10: generateLevel10
};

// Generate level data
function generateLevelData(levelNumber) {
    const generator = levelGenerators[levelNumber];
    if (!generator) {
        throw new Error(`No generator for level ${levelNumber}`);
    }
    
    const blocks = generator();
    
    return {
        version: "1.0.0",
        levelNumber: levelNumber,
        name: getLevelName(levelNumber),
        description: getLevelDescription(levelNumber),
        blocks: blocks,
        metadata: {
            blockCount: blocks.length,
            difficulty: getDifficulty(levelNumber),
            estimatedTime: getEstimatedTime(levelNumber),
            specialBlocks: getSpecialBlocks(blocks),
            colorThemes: getUsedThemes(levelNumber)
        }
    };
}

function getLevelName(level) {
    const names = {
        1: "Rainbow Rows",
        2: "Ocean Waves",
        3: "Pastel Checkerboard",
        4: "Sunset Diamond",
        5: "Nature Gradient",
        6: "Neon Spiral",
        7: "Heart Pattern",
        8: "Space Diagonal",
        9: "Rainbow Checkers",
        10: "Ocean Bullseye"
    };
    return names[level] || `Level ${level}`;
}

function getLevelDescription(level) {
    const descriptions = {
        1: "Simple horizontal rainbow stripes - perfect for beginners",
        2: "Gentle wave patterns with ocean colors",
        3: "Large checkerboard pattern with pastel colors",
        4: "Diamond outline in sunset colors",
        5: "Vertical nature gradient from green to yellow",
        6: "Simple neon colored rectangular pattern",
        7: "Heart pixel art pattern in sunset colors",
        8: "Diagonal gradient using space theme colors",
        9: "Small checkerboard pattern with rainbow colors",
        10: "Radial gradient creating a bullseye effect"
    };
    return descriptions[level] || `Level ${level} description`;
}

function getDifficulty(level) {
    if (level <= 3) return "easy";
    if (level <= 7) return "medium";
    return "hard";
}

function getEstimatedTime(level) {
    const times = {
        1: "30s", 2: "45s", 3: "60s", 4: "45s", 5: "60s",
        6: "40s", 7: "90s", 8: "75s", 9: "80s", 10: "120s"
    };
    return times[level] || "60s";
}

function getSpecialBlocks(blocks) {
    return blocks.filter(block => block.type !== 'normal').map(block => ({
        type: block.type,
        position: `${block.col},${block.row}`
    }));
}

function getUsedThemes(level) {
    const themes = {
        1: ["rainbow"], 2: ["ocean"], 3: ["pastel"], 4: ["sunset"], 5: ["nature"],
        6: ["neon"], 7: ["sunset"], 8: ["space"], 9: ["rainbow"], 10: ["ocean"]
    };
    return themes[level] || [];
}

// Export function for Node.js or browser
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { generateLevelData, levelGenerators };
} else {
    window.generateLevelData = generateLevelData;
}