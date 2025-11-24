#!/bin/bash
# VulnChain Development Stop Script

set -e

echo "🛑 Stopping VulnChain Development Environment..."
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

cd backend

# Stop services
if [ -f "logs/backend.pid" ]; then
    BACKEND_PID=$(cat logs/backend.pid)
    if kill -0 $BACKEND_PID 2>/dev/null; then
        echo -e "${YELLOW}→${NC} Stopping backend (PID: $BACKEND_PID)..."
        kill $BACKEND_PID
        echo -e "${GREEN}✓${NC} Backend stopped"
    fi
    rm logs/backend.pid
fi

if [ -f "logs/celery.pid" ]; then
    CELERY_PID=$(cat logs/celery.pid)
    if kill -0 $CELERY_PID 2>/dev/null; then
        echo -e "${YELLOW}→${NC} Stopping Celery worker (PID: $CELERY_PID)..."
        kill $CELERY_PID
        echo -e "${GREEN}✓${NC} Celery worker stopped"
    fi
    rm logs/celery.pid
fi

if [ -f "logs/flower.pid" ]; then
    FLOWER_PID=$(cat logs/flower.pid)
    if kill -0 $FLOWER_PID 2>/dev/null; then
        echo -e "${YELLOW}→${NC} Stopping Flower (PID: $FLOWER_PID)..."
        kill $FLOWER_PID
        echo -e "${GREEN}✓${NC} Flower stopped"
    fi
    rm logs/flower.pid
fi

# Kill any remaining processes
pkill -f "uvicorn app.main:app" 2>/dev/null || true
pkill -f "celery.*celery_worker" 2>/dev/null || true

echo ""
echo -e "${GREEN}✓${NC} All services stopped"
echo ""
