#!/bin/bash
# PyBorg Installation Script

set -e

echo "🤖 PyBorg Installation Script"
echo "============================="

# Check Python version
echo "🐍 Checking Python version..."
python3 --version || {
    echo "❌ Python 3 is required but not found"
    echo "Please install Python 3.8 or higher"
    exit 1
}

# Check pip
echo "📦 Checking pip..."
python3 -m pip --version || {
    echo "❌ pip is required but not found"
    echo "Please install pip for Python 3"
    exit 1
}

# Install dependencies
echo "📥 Installing Python dependencies..."
python3 -m pip install -r requirements.txt || {
    echo "❌ Failed to install dependencies"
    echo "You may need to run: sudo apt-get install python3-pip python3-dev"
    exit 1
}

# Create directories
echo "📁 Creating directories..."
mkdir -p logs data

# Set permissions
echo "🔒 Setting permissions..."
chmod +x scripts/*.py 2>/dev/null || true
chmod +x *.sh 2>/dev/null || true

# Run setup if no .env exists
if [ ! -f .env ]; then
    echo "⚙️ Running initial setup..."
    python3 scripts/setup.py
else
    echo "ℹ️ Configuration found (.env exists)"
    echo "Run 'python3 scripts/setup.py' to reconfigure"
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "Next steps:"
echo "1. Review your configuration: .env"
echo "2. Start your bot: ./start.sh"
echo "3. Join your configured channels and test commands"
echo ""
echo "For help, see: README.md"
echo "Happy botting! 🤖"