#!/bin/bash
# VulnChain Native Startup Script (No Docker)
# Starts both backend and frontend services

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "🚀 Starting VulnChain (Native Mode - No Docker)"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check service
check_service() {
    local service=$1
    local check_command=$2
    
    if eval "$check_command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} $service is running"
        return 0
    else
        echo -e "${YELLOW}⚠${NC} $service is not running"
        return 1
    fi
}

# Check prerequisites
echo "📋 Checking prerequisites..."
echo ""

# Check Python
if ! command_exists python3; then
    echo -e "${RED}✗${NC} Python 3 not found. Please install Python 3.11+"
    exit 1
fi
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION"

# Check Node.js
if ! command_exists node; then
    echo -e "${RED}✗${NC} Node.js not found. Please install Node.js 18+"
    exit 1
fi
NODE_VERSION=$(node --version)
echo -e "${GREEN}✓${NC} Node.js $NODE_VERSION"

# Check npm
if ! command_exists npm; then
    echo -e "${RED}✗${NC} npm not found. Please install npm"
    exit 1
fi
echo -e "${GREEN}✓${NC} npm $(npm --version)"

echo ""
echo "🔌 Checking/starting services..."
echo ""

# Start Redis if not running
if ! check_service "Redis" "redis-cli ping"; then
    echo -e "${YELLOW}→${NC} Starting Redis..."
    if command_exists brew; then
        brew services start redis
    elif command_exists systemctl; then
        sudo systemctl start redis-server
    else
        redis-server --daemonize yes
    fi
    sleep 2
    check_service "Redis" "redis-cli ping" || {
        echo -e "${RED}✗${NC} Failed to start Redis"
        exit 1
    }
fi

# Start PostgreSQL if not running
if ! check_service "PostgreSQL" "pg_isready"; then
    echo -e "${YELLOW}→${NC} Starting PostgreSQL..."
    if command_exists brew; then
        brew services start postgresql@16 || brew services start postgresql
    elif command_exists systemctl; then
        sudo systemctl start postgresql
    else
        echo -e "${RED}✗${NC} Cannot start PostgreSQL automatically"
        echo "Please start PostgreSQL manually and run this script again"
        exit 1
    fi
    sleep 2
    check_service "PostgreSQL" "pg_isready" || {
        echo -e "${RED}✗${NC} Failed to start PostgreSQL"
        exit 1
    }
fi

echo ""
echo "🔧 Setting up backend..."
echo ""

cd backend

# Create virtual environment if needed
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}→${NC} Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
if [ ! -f "venv/.deps_installed" ] || [ requirements.txt -nt venv/.deps_installed ]; then
    echo -e "${YELLOW}→${NC} Installing Python dependencies..."
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
    touch venv/.deps_installed
    echo -e "${GREEN}✓${NC} Python dependencies installed"
else
    echo -e "${GREEN}✓${NC} Python dependencies up to date"
fi

# Setup database
if ! psql -lqt 2>/dev/null | cut -d \| -f 1 | grep -qw vulnchain; then
    echo -e "${YELLOW}→${NC} Creating database..."
    createdb vulnchain 2>/dev/null || {
        echo -e "${YELLOW}⚠${NC}  Database may already exist"
    }
fi

# Run migrations
echo -e "${YELLOW}→${NC} Running database migrations..."
alembic upgrade head 2>&1 | grep -v "INFO" || true

# Create logs directory
mkdir -p logs

cd ..

echo ""
echo "🎨 Setting up frontend..."
echo ""

cd frontend

# Install dependencies
if [ ! -d "node_modules" ] || [ package.json -nt node_modules/.install_timestamp ]; then
    echo -e "${YELLOW}→${NC} Installing Node.js dependencies..."
    npm install --silent
    touch node_modules/.install_timestamp
    echo -e "${GREEN}✓${NC} Node.js dependencies installed"
else
    echo -e "${GREEN}✓${NC} Node.js dependencies up to date"
fi

# Create .env if not exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}→${NC} Creating frontend .env file..."
    cat > .env << 'EOF'
VITE_API_URL=http://localhost:8000
EOF
fi

cd ..

echo ""
echo "🎯 Starting services..."
echo ""

# Start backend services
cd backend

echo -e "${YELLOW}→${NC} Starting FastAPI backend (port 8000)..."
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 > logs/backend.log 2>&1 &
BACKEND_PID=$!
echo $BACKEND_PID > logs/backend.pid

# Wait for backend
sleep 3
if curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Backend started (PID: $BACKEND_PID)"
else
    echo -e "${RED}✗${NC} Backend failed to start. Check backend/logs/backend.log"
    cat logs/backend.log
    exit 1
fi

echo -e "${YELLOW}→${NC} Starting Celery worker..."
celery -A celery_worker worker --loglevel=info > logs/celery.log 2>&1 &
CELERY_PID=$!
echo $CELERY_PID > logs/celery.pid
echo -e "${GREEN}✓${NC} Celery worker started (PID: $CELERY_PID)"

echo -e "${YELLOW}→${NC} Starting Flower monitoring (port 5555)..."
celery -A celery_worker flower --port=5555 > logs/flower.log 2>&1 &
FLOWER_PID=$!
echo $FLOWER_PID > logs/flower.pid
echo -e "${GREEN}✓${NC} Flower started (PID: $FLOWER_PID)"

cd ..

# Start frontend
cd frontend

echo -e "${YELLOW}→${NC} Starting Vite frontend (port 3000)..."
npm run dev > ../backend/logs/frontend.log 2>&1 &
FRONTEND_PID=$!
echo $FRONTEND_PID > ../backend/logs/frontend.pid

# Wait for frontend
sleep 3
if curl -s http://localhost:3000 > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Frontend started (PID: $FRONTEND_PID)"
else
    echo -e "${YELLOW}⚠${NC}  Frontend may still be starting..."
fi

cd ..

echo ""
echo "✨ VulnChain is ready!"
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "📍 Access Points:"
echo -e "   ${GREEN}•${NC} Frontend:        ${BLUE}http://localhost:3000${NC}"
echo -e "   ${GREEN}•${NC} Backend API:     ${BLUE}http://localhost:8000${NC}"
echo -e "   ${GREEN}•${NC} API Docs:        ${BLUE}http://localhost:8000/docs${NC}"
echo -e "   ${GREEN}•${NC} Flower Monitor:  ${BLUE}http://localhost:5555${NC}"
echo ""
echo "📝 Logs:"
echo "   • Backend:        backend/logs/backend.log"
echo "   • Celery:         backend/logs/celery.log"
echo "   • Flower:         backend/logs/flower.log"
echo "   • Frontend:       backend/logs/frontend.log"
echo ""
echo "🛑 To stop all services:"
echo "   ./stop-native.sh"
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "💡 Quick test:"
echo "   curl http://localhost:8000/health"
echo ""
echo "🎉 Happy hacking!"
echo ""
