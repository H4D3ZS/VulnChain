#!/bin/bash
# VulnChain Development Startup Script

set -e

echo "🚀 Starting VulnChain Development Environment..."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if services are running
check_service() {
    local service=$1
    local check_command=$2
    
    if eval "$check_command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} $service is running"
        return 0
    else
        echo -e "${RED}✗${NC} $service is not running"
        return 1
    fi
}

# Start service if not running
start_service() {
    local service=$1
    local start_command=$2
    
    echo -e "${YELLOW}→${NC} Starting $service..."
    eval "$start_command"
}

echo "📋 Checking prerequisites..."
echo ""

# Check Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION installed"
else
    echo -e "${RED}✗${NC} Python 3 not found. Please install Python 3.11+"
    exit 1
fi

# Check Redis
if ! check_service "Redis" "redis-cli ping"; then
    echo -e "${YELLOW}→${NC} Starting Redis..."
    if command -v brew &> /dev/null; then
        brew services start redis
    else
        redis-server --daemonize yes
    fi
    sleep 2
fi

# Check PostgreSQL
if ! check_service "PostgreSQL" "pg_isready"; then
    echo -e "${YELLOW}→${NC} Starting PostgreSQL..."
    if command -v brew &> /dev/null; then
        brew services start postgresql@16
    else
        sudo systemctl start postgresql
    fi
    sleep 2
fi

echo ""
echo "🔧 Setting up backend..."
echo ""

# Navigate to backend
cd backend

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}→${NC} Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo -e "${YELLOW}→${NC} Activating virtual environment..."
source venv/bin/activate

# Install dependencies if needed
if [ ! -f "venv/.installed" ]; then
    echo -e "${YELLOW}→${NC} Installing Python dependencies..."
    pip install -q -r requirements.txt
    touch venv/.installed
    echo -e "${GREEN}✓${NC} Dependencies installed"
else
    echo -e "${GREEN}✓${NC} Dependencies already installed"
fi

# Check if database exists
if ! psql -lqt | cut -d \| -f 1 | grep -qw vulnchain; then
    echo -e "${YELLOW}→${NC} Creating database..."
    createdb vulnchain 2>/dev/null || true
    echo -e "${GREEN}✓${NC} Database created"
fi

# Run migrations
echo -e "${YELLOW}→${NC} Running database migrations..."
alembic upgrade head > /dev/null 2>&1 || echo -e "${YELLOW}⚠${NC}  Migration warnings (non-critical)"

echo ""
echo "🎯 Starting services..."
echo ""

# Create log directory
mkdir -p logs

# Start backend
echo -e "${YELLOW}→${NC} Starting FastAPI backend on port 8000..."
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 > logs/backend.log 2>&1 &
BACKEND_PID=$!
echo $BACKEND_PID > logs/backend.pid

# Wait for backend to start
sleep 3

# Check if backend started successfully
if curl -s http://localhost:8000/health > /dev/null; then
    echo -e "${GREEN}✓${NC} Backend started (PID: $BACKEND_PID)"
else
    echo -e "${RED}✗${NC} Backend failed to start. Check logs/backend.log"
    exit 1
fi

# Start Celery worker
echo -e "${YELLOW}→${NC} Starting Celery worker..."
celery -A celery_worker worker --loglevel=info > logs/celery.log 2>&1 &
CELERY_PID=$!
echo $CELERY_PID > logs/celery.pid
echo -e "${GREEN}✓${NC} Celery worker started (PID: $CELERY_PID)"

# Start Flower (optional)
echo -e "${YELLOW}→${NC} Starting Flower monitoring on port 5555..."
celery -A celery_worker flower --port=5555 > logs/flower.log 2>&1 &
FLOWER_PID=$!
echo $FLOWER_PID > logs/flower.pid
echo -e "${GREEN}✓${NC} Flower started (PID: $FLOWER_PID)"

echo ""
echo "✨ VulnChain is ready!"
echo ""
echo "📍 Access points:"
echo "   • Backend API:    http://localhost:8000"
echo "   • API Docs:       http://localhost:8000/docs"
echo "   • Health Check:   http://localhost:8000/health"
echo "   • Flower:         http://localhost:5555"
echo ""
echo "📝 Logs:"
echo "   • Backend:        backend/logs/backend.log"
echo "   • Celery:         backend/logs/celery.log"
echo "   • Flower:         backend/logs/flower.log"
echo ""
echo "🛑 To stop all services, run: ./stop-dev.sh"
echo ""
echo "💡 Quick test:"
echo "   curl http://localhost:8000/health"
echo ""
