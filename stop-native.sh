#!/bin/bash
# VulnChain Native Stop Script
# Stops all VulnChain services started by start-native.sh

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🛑 Stopping VulnChain services..."
echo ""

# Function to stop process
stop_process() {
    local name=$1
    local pid_file=$2
    
    if [ -f "$pid_file" ]; then
        PID=$(cat "$pid_file")
        if ps -p $PID > /dev/null 2>&1; then
            echo -e "${YELLOW}→${NC} Stopping $name (PID: $PID)..."
            kill $PID 2>/dev/null || kill -9 $PID 2>/dev/null
            rm "$pid_file"
            echo -e "${GREEN}✓${NC} $name stopped"
        else
            echo -e "${YELLOW}⚠${NC}  $name not running"
            rm "$pid_file"
        fi
    else
        echo -e "${YELLOW}⚠${NC}  $name PID file not found"
    fi
}

# Stop services
cd backend 2>/dev/null || {
    echo -e "${RED}✗${NC} backend directory not found"
    exit 1
}

stop_process "Frontend" "logs/frontend.pid"
stop_process "Flower" "logs/flower.pid"
stop_process "Celery worker" "logs/celery.pid"
stop_process "Backend" "logs/backend.pid"

# Also try to kill by process name (backup)
echo ""
echo "🔍 Checking for remaining processes..."

# Kill any remaining uvicorn processes
if pgrep -f "uvicorn app.main:app" > /dev/null; then
    echo -e "${YELLOW}→${NC} Killing remaining uvicorn processes..."
    pkill -f "uvicorn app.main:app"
fi

# Kill any remaining celery processes
if pgrep -f "celery.*celery_worker" > /dev/null; then
    echo -e "${YELLOW}→${NC} Killing remaining celery processes..."
    pkill -f "celery.*celery_worker"
fi

# Kill any remaining vite processes
if pgrep -f "vite" > /dev/null; then
    echo -e "${YELLOW}→${NC} Killing remaining vite processes..."
    pkill -f "vite"
fi

cd ..

echo ""
echo -e "${GREEN}✓${NC} All VulnChain services stopped"
echo ""
echo "💡 To start again, run: ./start-native.sh"
echo ""
