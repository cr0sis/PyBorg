const fs = require('fs');

const blockRows = 8;
const blockCols = 20;

const colorThemes = {
    rainbow: ['#FF0000', '#FF7F00', '#FFFF00', '#00FF00', '#0000FF', '#4B0082', '#9400D3'],
    ocean: ['#001F3F', '#003A70', '#0074D9', '#39CCCC', '#7FDBFF', '#85DCB0', '#B3E5FC'],
    sunset: ['#FF6B35', '#F7931E', '#FCEE21', '#FF9F1C', '#FF4E50', '#FC913A', '#F9D423'],
    nature: ['#355E3B', '#4F7942', '#228B22', '#32CD32', '#7CFC00', '#ADFF2F', '#9ACD32'],
    space: ['#0B0C10', '#1F2833', '#45A29E', '#66FCF1', '#C5C6C7', '#1F2833', '#0B0C10'],
    neon: ['#FF00FF', '#00FFFF', '#FF00AA', '#00FF00', '#FFFF00', '#FF0099', '#00FFAA'],
    pastel: ['#FFB6C1', '#FFC0CB', '#FFE4E1', '#F0E68C', '#E6E6FA', '#D8BFD8', '#F5DEB3'],
    fire: ['#FF0000', '#FF4500', '#FF6600', '#FF8800', '#FFAA00', '#FFCC00', '#FFFF00'],
    ice: ['#E0FFFF', '#B0E0E6', '#87CEEB', '#4682B4', '#191970', '#000080', '#0000CD'],
    cosmic: ['#483D8B', '#6A5ACD', '#9370DB', '#BA55D3', '#DA70D6', '#EE82EE', '#DDA0DD'],
    tropical: ['#FF69B4', '#FF1493', '#DC143C', '#B22222', '#8B0000', '#800080', '#4B0082'],
    forest: ['#228B22', '#32CD32', '#9ACD32', '#ADFF2F', '#7CFC00', '#00FF00', '#00FF7F']
};

function getBlockHitCount(currentLevel, requestedHits = 1) {
    if (currentLevel < 15) return 1;
    if (currentLevel < 25) return Math.min(requestedHits, 2);
    if (currentLevel < 40) return Math.min(requestedHits, 3);
    if (currentLevel < 60) return Math.min(requestedHits, 4);
    return Math.min(requestedHits, 5);
}

function createBlock(col, row, hits = 1, type = 'normal', color = null) {
    return { col, row, hits, type, color: color || '#FF0040' };
}

function addSpecialBlocks(blocks, currentLevel, type = 'metal', percentage = 0.1) {
    if (currentLevel < 20) return blocks;
    
    const blockCount = Math.floor(blocks.length * percentage);
    const indices = [];
    
    while (indices.length < blockCount) {
        const randomIndex = Math.floor(Math.random() * blocks.length);
        if (!indices.includes(randomIndex)) {
            indices.push(randomIndex);
        }
    }
    
    indices.forEach(index => {
        blocks[index].type = type;
        if (type === 'metal') {
            blocks[index].color = '#666666';
            blocks[index].hits = Math.min(blocks[index].hits + 2, 5);
        } else if (type === 'lava') {
            blocks[index].color = '#FF4500';
            blocks[index].hits = Math.min(blocks[index].hits + 1, 5);
        }
    });
    
    return blocks;
}

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
    
    return addSpecialBlocks(blocks, currentLevel);
}

function createWavePattern(theme, currentLevel, waveType = 'sine') {
    const colors = colorThemes[theme] || colorThemes.rainbow;
    const blocks = [];
    
    for (let row = 0; row < blockRows; row++) {
        for (let col = 0; col < blockCols; col++) {
            let waveValue;
            
            if (waveType === 'sine') {
                waveValue = Math.sin(col * Math.PI / 5) + Math.sin(row * Math.PI / 3);
            } else if (waveType === 'cosine') {
                waveValue = Math.cos(col * Math.PI / 4) + Math.cos(row * Math.PI / 4);
            } else if (waveType === 'spiral') {
                const centerRow = blockRows / 2;
                const centerCol = blockCols / 2;
                const angle = Math.atan2(row - centerRow, col - centerCol);
                const distance = Math.sqrt(Math.pow(row - centerRow, 2) + Math.pow(col - centerCol, 2));
                waveValue = Math.sin(angle * 3 + distance);
            }
            
            const colorIndex = Math.floor((waveValue + 2) * colors.length / 4) % colors.length;
            const hits = getBlockHitCount(currentLevel, 1 + Math.floor(Math.abs(waveValue)));
            blocks.push(createBlock(col, row, hits, 'normal', colors[colorIndex]));
        }
    }
    
    return addSpecialBlocks(blocks, currentLevel);
}

function createMaze(theme, currentLevel) {
    const colors = colorThemes[theme] || colorThemes.rainbow;
    const blocks = [];
    
    // Create maze-like pattern with corridors
    for (let row = 0; row < blockRows; row++) {
        for (let col = 0; col < blockCols; col++) {
            // Create maze walls - skip certain patterns to create corridors
            if ((row % 2 === 0 && col % 3 !== 1) || (row % 2 === 1 && col % 4 === 0)) {
                const colorIndex = (row + col) % colors.length;
                const hits = getBlockHitCount(currentLevel, 1 + Math.floor(row / 2));
                blocks.push(createBlock(col, row, hits, 'normal', colors[colorIndex]));
            }
        }
    }
    
    return addSpecialBlocks(blocks, currentLevel, 'metal', 0.15);
}

function createSpiral(theme, currentLevel, clockwise = true) {
    const colors = colorThemes[theme] || colorThemes.rainbow;
    const blocks = [];
    
    const centerRow = Math.floor(blockRows / 2);
    const centerCol = Math.floor(blockCols / 2);
    
    for (let row = 0; row < blockRows; row++) {
        for (let col = 0; col < blockCols; col++) {
            const dx = col - centerCol;
            const dy = row - centerRow;
            let angle = Math.atan2(dy, dx);
            
            if (!clockwise) angle = -angle;
            angle = (angle + Math.PI) / (2 * Math.PI); // Normalize to 0-1
            
            const distance = Math.sqrt(dx * dx + dy * dy);
            const spiralValue = (angle + distance * 0.3) % 1;
            
            if (spiralValue < 0.7) { // Create gaps in the spiral
                const colorIndex = Math.floor(spiralValue * colors.length);
                const hits = getBlockHitCount(currentLevel, 1 + Math.floor(distance / 2));
                blocks.push(createBlock(col, row, hits, 'normal', colors[colorIndex]));
            }
        }
    }
    
    return addSpecialBlocks(blocks, currentLevel);
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
    
    return addSpecialBlocks(blocks, currentLevel);
}

// Pixel art patterns
const pixelPatterns = {
    star: [
        [0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,0,0],
        [0,0,0,0,0,0,0,0,1,2,2,1,0,0,0,0,0,0,0,0],
        [0,0,0,0,0,0,0,1,2,3,3,2,1,0,0,0,0,0,0,0],
        [0,0,0,0,0,0,1,2,3,4,4,3,2,1,0,0,0,0,0,0],
        [1,1,1,1,1,1,2,3,4,5,5,4,3,2,1,1,1,1,1,1],
        [0,0,0,0,0,0,1,2,3,4,4,3,2,1,0,0,0,0,0,0],
        [0,0,0,0,0,0,0,1,2,3,3,2,1,0,0,0,0,0,0,0],
        [0,0,0,0,0,0,0,0,1,2,2,1,0,0,0,0,0,0,0,0]
    ],
    
    castle: [
        [1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0],
        [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
        [2,0,0,2,0,0,2,0,0,2,0,0,2,0,0,2,0,0,2,0],
        [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
        [2,0,0,0,2,0,0,0,2,0,0,0,2,0,0,0,2,0,0,0],
        [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],
        [2,0,0,0,0,0,0,0,2,0,0,2,0,0,0,0,0,0,0,2],
        [3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3]
    ],
    
    flower: [
        [0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0],
        [0,0,0,1,1,2,2,2,2,2,2,2,2,2,2,1,1,0,0,0],
        [0,0,1,2,2,3,3,3,3,3,3,3,3,3,3,2,2,1,0,0],
        [0,1,2,3,3,3,3,3,4,4,4,4,3,3,3,3,3,2,1,0],
        [0,1,2,3,3,3,4,4,5,5,5,5,4,4,3,3,3,2,1,0],
        [0,0,1,2,2,3,3,3,3,3,3,3,3,3,3,2,2,1,0,0],
        [0,0,0,1,1,2,2,2,2,2,2,2,2,2,2,1,1,0,0,0],
        [0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0]
    ]
};

// Generate levels 11-100
const levels = [
    // Levels 11-20: Intermediate patterns with special blocks
    { number: 11, name: 'Fire Horizontal', description: 'Horizontal fire gradient with metal blocks', 
      generator: () => createGradientPattern('fire', 11, 'horizontal'), difficulty: 'medium', time: '90s', themes: ['fire'] },
    { number: 12, name: 'Ice Waves', description: 'Sine wave pattern in ice colors', 
      generator: () => createWavePattern('ice', 12, 'sine'), difficulty: 'medium', time: '95s', themes: ['ice'] },
    { number: 13, name: 'Cosmic Spiral', description: 'Clockwise spiral in cosmic colors', 
      generator: () => createSpiral('cosmic', 13, true), difficulty: 'medium', time: '100s', themes: ['cosmic'] },
    { number: 14, name: 'Tropical Maze', description: 'Maze pattern with tropical colors', 
      generator: () => createMaze('tropical', 14), difficulty: 'hard', time: '110s', themes: ['tropical'] },
    { number: 15, name: 'Forest Star', description: 'Star pattern in forest colors', 
      generator: () => createPixelArt(pixelPatterns.star, 'forest', 15), difficulty: 'hard', time: '120s', themes: ['forest'] },
    
    { number: 16, name: 'Neon Diagonal', description: 'Diagonal gradient with neon colors', 
      generator: () => createGradientPattern('neon', 16, 'diagonal'), difficulty: 'hard', time: '105s', themes: ['neon'] },
    { number: 17, name: 'Ocean Cosine', description: 'Cosine wave pattern in ocean colors', 
      generator: () => createWavePattern('ocean', 17, 'cosine'), difficulty: 'hard', time: '115s', themes: ['ocean'] },
    { number: 18, name: 'Rainbow Castle', description: 'Castle pattern with rainbow colors', 
      generator: () => createPixelArt(pixelPatterns.castle, 'rainbow', 18), difficulty: 'hard', time: '125s', themes: ['rainbow'] },
    { number: 19, name: 'Space Radial', description: 'Radial gradient from center in space theme', 
      generator: () => createGradientPattern('space', 19, 'radial'), difficulty: 'hard', time: '130s', themes: ['space'] },
    { number: 20, name: 'Sunset Flower', description: 'Flower pattern in sunset colors', 
      generator: () => createPixelArt(pixelPatterns.flower, 'sunset', 20), difficulty: 'hard', time: '135s', themes: ['sunset'] },

    // Levels 21-40: Advanced patterns with more special blocks
    ...Array.from({length: 20}, (_, i) => {
        const level = 21 + i;
        const themes = Object.keys(colorThemes);
        const theme = themes[level % themes.length];
        const patterns = ['horizontal', 'vertical', 'diagonal', 'radial'];
        const pattern = patterns[level % patterns.length];
        const waveTypes = ['sine', 'cosine', 'spiral'];
        const waveType = waveTypes[level % waveTypes.length];
        
        if (level % 4 === 0) {
            return {
                number: level,
                name: `${theme.charAt(0).toUpperCase() + theme.slice(1)} Spiral`,
                description: `Advanced spiral pattern in ${theme} colors`,
                generator: () => createSpiral(theme, level, level % 2 === 0),
                difficulty: 'hard',
                time: `${120 + (level - 20) * 2}s`,
                themes: [theme]
            };
        } else if (level % 4 === 1) {
            return {
                number: level,
                name: `${theme.charAt(0).toUpperCase() + theme.slice(1)} Maze`,
                description: `Complex maze pattern in ${theme} colors`,
                generator: () => createMaze(theme, level),
                difficulty: 'hard',
                time: `${125 + (level - 20) * 2}s`,
                themes: [theme]
            };
        } else if (level % 4 === 2) {
            return {
                number: level,
                name: `${theme.charAt(0).toUpperCase() + theme.slice(1)} Waves`,
                description: `${waveType} wave pattern in ${theme} colors`,
                generator: () => createWavePattern(theme, level, waveType),
                difficulty: 'hard',
                time: `${115 + (level - 20) * 2}s`,
                themes: [theme]
            };
        } else {
            return {
                number: level,
                name: `${theme.charAt(0).toUpperCase() + theme.slice(1)} Gradient`,
                description: `${pattern} gradient in ${theme} colors`,
                generator: () => createGradientPattern(theme, level, pattern),
                difficulty: 'hard',
                time: `${110 + (level - 20) * 2}s`,
                themes: [theme]
            };
        }
    }),

    // Levels 41-60: Expert patterns with increased difficulty
    ...Array.from({length: 20}, (_, i) => {
        const level = 41 + i;
        const themes = Object.keys(colorThemes);
        const theme = themes[level % themes.length];
        const patterns = ['horizontal', 'vertical', 'diagonal', 'radial'];
        const pattern = patterns[level % patterns.length];
        
        return {
            number: level,
            name: `Expert ${theme.charAt(0).toUpperCase() + theme.slice(1)}`,
            description: `Expert level ${pattern} pattern with multiple hit blocks`,
            generator: () => {
                let blocks = createGradientPattern(theme, level, pattern, 2);
                blocks = addSpecialBlocks(blocks, level, 'metal', 0.2);
                return addSpecialBlocks(blocks, level, 'lava', 0.1);
            },
            difficulty: 'expert',
            time: `${150 + (level - 40) * 3}s`,
            themes: [theme]
        };
    }),

    // Levels 61-80: Master patterns with maximum difficulty
    ...Array.from({length: 20}, (_, i) => {
        const level = 61 + i;
        const themes = Object.keys(colorThemes);
        const theme = themes[level % themes.length];
        const waveTypes = ['sine', 'cosine', 'spiral'];
        const waveType = waveTypes[level % waveTypes.length];
        
        return {
            number: level,
            name: `Master ${theme.charAt(0).toUpperCase() + theme.slice(1)}`,
            description: `Master level ${waveType} waves with heavy special blocks`,
            generator: () => {
                let blocks = createWavePattern(theme, level, waveType);
                blocks = addSpecialBlocks(blocks, level, 'metal', 0.25);
                return addSpecialBlocks(blocks, level, 'lava', 0.15);
            },
            difficulty: 'master',
            time: `${180 + (level - 60) * 4}s`,
            themes: [theme]
        };
    }),

    // Levels 81-100: Legendary patterns - ultimate challenge
    ...Array.from({length: 20}, (_, i) => {
        const level = 81 + i;
        const themes = Object.keys(colorThemes);
        const theme = themes[level % themes.length];
        
        if (level % 3 === 0) {
            return {
                number: level,
                name: `Legendary ${theme.charAt(0).toUpperCase() + theme.slice(1)} Fortress`,
                description: `Legendary fortress pattern with maximum difficulty`,
                generator: () => {
                    let blocks = createMaze(theme, level);
                    blocks = addSpecialBlocks(blocks, level, 'metal', 0.3);
                    return addSpecialBlocks(blocks, level, 'lava', 0.2);
                },
                difficulty: 'legendary',
                time: `${220 + (level - 80) * 5}s`,
                themes: [theme]
            };
        } else if (level % 3 === 1) {
            return {
                number: level,
                name: `Legendary ${theme.charAt(0).toUpperCase() + theme.slice(1)} Vortex`,
                description: `Legendary spiral vortex with ultimate challenge`,
                generator: () => {
                    let blocks = createSpiral(theme, level, level % 2 === 0);
                    blocks = addSpecialBlocks(blocks, level, 'metal', 0.35);
                    return addSpecialBlocks(blocks, level, 'lava', 0.25);
                },
                difficulty: 'legendary',
                time: `${225 + (level - 80) * 5}s`,
                themes: [theme]
            };
        } else {
            return {
                number: level,
                name: `Legendary ${theme.charAt(0).toUpperCase() + theme.slice(1)} Storm`,
                description: `Legendary wave storm - the ultimate test`,
                generator: () => {
                    let blocks = createWavePattern(theme, level, 'spiral');
                    blocks = addSpecialBlocks(blocks, level, 'metal', 0.4);
                    return addSpecialBlocks(blocks, level, 'lava', 0.3);
                },
                difficulty: 'legendary',
                time: `${230 + (level - 80) * 5}s`,
                themes: [theme]
            };
        }
    })
];

// Generate all levels
levels.forEach(level => {
    const levelData = {
        version: '1.0.0',
        levelNumber: level.number,
        name: level.name,
        description: level.description,
        blocks: level.generator(),
        metadata: {
            difficulty: level.difficulty,
            estimatedTime: level.time,
            specialBlocks: level.number >= 20 ? ['metal'] : [],
            colorThemes: level.themes
        }
    };
    
    // Add lava blocks to metadata for levels that have them
    if (level.number >= 40) {
        levelData.metadata.specialBlocks.push('lava');
    }
    
    levelData.metadata.blockCount = levelData.blocks.length;
    
    const filename = `data/level-${level.number.toString().padStart(3, '0')}.json`;
    fs.writeFileSync(filename, JSON.stringify(levelData, null, 2));
    console.log(`Generated ${filename} with ${levelData.blocks.length} blocks`);
});

console.log('All levels 11-100 generated successfully!');