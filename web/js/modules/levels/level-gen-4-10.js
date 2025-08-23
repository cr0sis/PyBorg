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
    pastel: ['#FFB6C1', '#FFC0CB', '#FFE4E1', '#F0E68C', '#E6E6FA', '#D8BFD8', '#F5DEB3']
};

function getBlockHitCount(currentLevel, requestedHits = 1) {
    if (currentLevel < 15) return 1;
    return Math.min(requestedHits, 2);
}

function createBlock(col, row, hits = 1, type = 'normal', color = null) {
    return { col, row, hits, type, color: color || '#FF0040' };
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
    
    return blocks;
}

function createDiamond(theme, currentLevel, filled = true, hitModifier = 1) {
    const colors = colorThemes[theme] || colorThemes.rainbow;
    const blocks = [];
    const centerRow = Math.floor(blockRows / 2);
    
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
                if (end >= 0 && end < blockCols && end != start) {
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

// Generate remaining levels
const levels = [
    {
        number: 4,
        name: 'Sunset Diamond',
        description: 'Diamond outline in sunset colors',
        generator: () => createDiamond('sunset', 4, false, 1),
        difficulty: 'medium',
        time: '45s',
        themes: ['sunset']
    },
    {
        number: 5,
        name: 'Nature Gradient',
        description: 'Vertical nature gradient from green to yellow',
        generator: () => createGradientPattern('nature', 5, 'vertical', 1),
        difficulty: 'medium',
        time: '60s',
        themes: ['nature']
    },
    {
        number: 6,
        name: 'Neon Spiral',
        description: 'Simple neon colored rectangular pattern',
        generator: () => {
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
        },
        difficulty: 'medium',
        time: '40s',
        themes: ['neon']
    },
    {
        number: 7,
        name: 'Heart Pattern',
        description: 'Heart pixel art pattern in sunset colors',
        generator: () => {
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
        },
        difficulty: 'medium',
        time: '90s',
        themes: ['sunset']
    },
    {
        number: 8,
        name: 'Space Diagonal',
        description: 'Diagonal gradient using space theme colors',
        generator: () => createGradientPattern('space', 8, 'diagonal', 1),
        difficulty: 'hard',
        time: '75s',
        themes: ['space']
    },
    {
        number: 9,
        name: 'Rainbow Checkers',
        description: 'Small checkerboard pattern with rainbow colors',
        generator: () => createCheckerboard('rainbow', 9, 2, 1),
        difficulty: 'hard',
        time: '80s',
        themes: ['rainbow']
    },
    {
        number: 10,
        name: 'Ocean Bullseye',
        description: 'Radial gradient creating a bullseye effect',
        generator: () => createGradientPattern('ocean', 10, 'radial', 1),
        difficulty: 'hard',
        time: '120s',
        themes: ['ocean']
    }
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
            specialBlocks: [],
            colorThemes: level.themes
        }
    };
    
    levelData.metadata.blockCount = levelData.blocks.length;
    
    const filename = `data/level-${level.number.toString().padStart(3, '0')}.json`;
    fs.writeFileSync(filename, JSON.stringify(levelData, null, 2));
    console.log(`Generated ${filename} with ${levelData.blocks.length} blocks`);
});

console.log('All levels 4-10 generated successfully!');