#!/bin/bash
# VulnChain Prerequisites Installation Script
# Detects OS and installs required dependencies

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "🔧 VulnChain Prerequisites Installer"
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
else
    echo -e "${RED}✗${NC} Unsupported OS: $OSTYPE"
    exit 1
fi

echo -e "${BLUE}→${NC} Detected OS: $OS"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# macOS Installation
install_macos() {
    echo "📦 Installing for macOS..."
    echo ""
    
    # Check for Homebrew
    if ! command_exists brew; then
        echo -e "${YELLOW}→${NC} Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        echo -e "${GREEN}✓${NC} Homebrew installed"
    else
        echo -e "${GREEN}✓${NC} Homebrew already installed"
    fi
    
    # Update Homebrew
    echo -e "${YELLOW}→${NC} Updating Homebrew..."
    brew update
    
    # Install Python
    if ! command_exists python3; then
        echo -e "${YELLOW}→${NC} Installing Python 3.11..."
        brew install python@3.11
        echo -e "${GREEN}✓${NC} Python installed"
    else
        echo -e "${GREEN}✓${NC} Python already installed ($(python3 --version))"
    fi
    
    # Install PostgreSQL
    if ! command_exists psql; then
        echo -e "${YELLOW}→${NC} Installing PostgreSQL..."
        brew install postgresql@16
        brew services start postgresql@16
        echo -e "${GREEN}✓${NC} PostgreSQL installed and started"
    else
        echo -e "${GREEN}✓${NC} PostgreSQL already installed"
        brew services start postgresql@16 2>/dev/null || true
    fi
    
    # Install Redis
    if ! command_exists redis-server; then
        echo -e "${YELLOW}→${NC} Installing Redis..."
        brew install redis
        brew services start redis
        echo -e "${GREEN}✓${NC} Redis installed and started"
    else
        echo -e "${GREEN}✓${NC} Redis already installed"
        brew services start redis 2>/dev/null || true
    fi
    
    # Install Node.js
    if ! command_exists node; then
        echo -e "${YELLOW}→${NC} Installing Node.js..."
        brew install node
        echo -e "${GREEN}✓${NC} Node.js installed"
    else
        echo -e "${GREEN}✓${NC} Node.js already installed ($(node --version))"
    fi
}

# Linux Installation
install_linux() {
    echo "📦 Installing for Linux..."
    echo ""
    
    # Detect Linux distribution
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
    else
        echo -e "${RED}✗${NC} Cannot detect Linux distribution"
        exit 1
    fi
    
    echo -e "${BLUE}→${NC} Distribution: $DISTRO"
    echo ""
    
    if [[ "$DISTRO" == "ubuntu" ]] || [[ "$DISTRO" == "debian" ]]; then
        # Update package list
        echo -e "${YELLOW}→${NC} Updating package list..."
        sudo apt update
        
        # Install Python
        if ! command_exists python3.11; then
            echo -e "${YELLOW}→${NC} Installing Python 3.11..."
            sudo apt install -y python3.11 python3.11-venv python3-pip
            echo -e "${GREEN}✓${NC} Python installed"
        else
            echo -e "${GREEN}✓${NC} Python already installed"
        fi
        
        # Install PostgreSQL
        if ! command_exists psql; then
            echo -e "${YELLOW}→${NC} Installing PostgreSQL..."
            sudo apt install -y postgresql postgresql-contrib
            sudo systemctl enable postgresql
            sudo systemctl start postgresql
            echo -e "${GREEN}✓${NC} PostgreSQL installed and started"
        else
            echo -e "${GREEN}✓${NC} PostgreSQL already installed"
            sudo systemctl start postgresql 2>/dev/null || true
        fi
        
        # Install Redis
        if ! command_exists redis-server; then
            echo -e "${YELLOW}→${NC} Installing Redis..."
            sudo apt install -y redis-server
            sudo systemctl enable redis-server
            sudo systemctl start redis-server
            echo -e "${GREEN}✓${NC} Redis installed and started"
        else
            echo -e "${GREEN}✓${NC} Redis already installed"
            sudo systemctl start redis-server 2>/dev/null || true
        fi
        
        # Install Node.js
        if ! command_exists node; then
            echo -e "${YELLOW}→${NC} Installing Node.js..."
            curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
            sudo apt install -y nodejs
            echo -e "${GREEN}✓${NC} Node.js installed"
        else
            echo -e "${GREEN}✓${NC} Node.js already installed ($(node --version))"
        fi
        
    elif [[ "$DISTRO" == "fedora" ]] || [[ "$DISTRO" == "rhel" ]] || [[ "$DISTRO" == "centos" ]]; then
        # Install Python
        if ! command_exists python3.11; then
            echo -e "${YELLOW}→${NC} Installing Python 3.11..."
            sudo dnf install -y python3.11
            echo -e "${GREEN}✓${NC} Python installed"
        else
            echo -e "${GREEN}✓${NC} Python already installed"
        fi
        
        # Install PostgreSQL
        if ! command_exists psql; then
            echo -e "${YELLOW}→${NC} Installing PostgreSQL..."
            sudo dnf install -y postgresql-server postgresql-contrib
            sudo postgresql-setup --initdb
            sudo systemctl enable postgresql
            sudo systemctl start postgresql
            echo -e "${GREEN}✓${NC} PostgreSQL installed and started"
        else
            echo -e "${GREEN}✓${NC} PostgreSQL already installed"
        fi
        
        # Install Redis
        if ! command_exists redis-server; then
            echo -e "${YELLOW}→${NC} Installing Redis..."
            sudo dnf install -y redis
            sudo systemctl enable redis
            sudo systemctl start redis
            echo -e "${GREEN}✓${NC} Redis installed and started"
        else
            echo -e "${GREEN}✓${NC} Redis already installed"
        fi
        
        # Install Node.js
        if ! command_exists node; then
            echo -e "${YELLOW}→${NC} Installing Node.js..."
            sudo dnf install -y nodejs
            echo -e "${GREEN}✓${NC} Node.js installed"
        else
            echo -e "${GREEN}✓${NC} Node.js already installed"
        fi
    else
        echo -e "${RED}✗${NC} Unsupported Linux distribution: $DISTRO"
        echo "Please install manually:"
        echo "  - Python 3.11+"
        echo "  - PostgreSQL 14+"
        echo "  - Redis 7+"
        echo "  - Node.js 18+"
        exit 1
    fi
}

# Windows Installation
install_windows() {
    echo "📦 Installing for Windows..."
    echo ""
    
    # Check for Chocolatey
    if ! command_exists choco; then
        echo -e "${YELLOW}→${NC} Installing Chocolatey..."
        echo "Please run this in PowerShell as Administrator:"
        echo ""
        echo "Set-ExecutionPolicy Bypass -Scope Process -Force"
        echo "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072"
        echo "iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
        echo ""
        echo "Then run this script again."
        exit 1
    fi
    
    echo -e "${GREEN}✓${NC} Chocolatey installed"
    
    # Install packages
    echo -e "${YELLOW}→${NC} Installing packages..."
    choco install -y python311 postgresql redis nodejs
    
    echo -e "${GREEN}✓${NC} All packages installed"
    echo ""
    echo "⚠️  Please start services manually:"
    echo "  - PostgreSQL: net start postgresql"
    echo "  - Redis: net start redis"
}

# Run installation based on OS
case $OS in
    macos)
        install_macos
        ;;
    linux)
        install_linux
        ;;
    windows)
        install_windows
        ;;
esac

echo ""
echo "🎉 Prerequisites installation complete!"
echo ""
echo "📋 Verification:"
echo ""

# Verify installations
if command_exists python3; then
    echo -e "${GREEN}✓${NC} Python: $(python3 --version)"
else
    echo -e "${RED}✗${NC} Python not found"
fi

if command_exists node; then
    echo -e "${GREEN}✓${NC} Node.js: $(node --version)"
else
    echo -e "${RED}✗${NC} Node.js not found"
fi

if command_exists npm; then
    echo -e "${GREEN}✓${NC} npm: $(npm --version)"
else
    echo -e "${RED}✗${NC} npm not found"
fi

if command_exists psql; then
    echo -e "${GREEN}✓${NC} PostgreSQL: $(psql --version | head -n1)"
else
    echo -e "${RED}✗${NC} PostgreSQL not found"
fi

if command_exists redis-server; then
    echo -e "${GREEN}✓${NC} Redis: $(redis-server --version | head -n1)"
else
    echo -e "${RED}✗${NC} Redis not found"
fi

echo ""
echo "🚀 Next steps:"
echo "   1. Setup database: createdb vulnchain"
echo "   2. Start VulnChain: ./start-native.sh"
echo ""
