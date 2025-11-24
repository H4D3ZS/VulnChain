# VulnChain CTF Framework

An advanced CTF web exploitation framework designed for educational purposes, authorized CTF competitions, legal bug bounty programs, and controlled vulnerable-by-design platforms.

**📖 New to VulnChain?** Start with the [Getting Started Guide](GETTING_STARTED.md)

## Features

### 🎯 25+ Attack Modules
- **Injection:** SQL, NoSQL, XSS, Command, SSRF, SSTI, XXE
- **Authentication:** JWT manipulation, OAuth/SAML, Brute force
- **File Attacks:** Directory traversal, File upload bypass
- **API Testing:** REST/GraphQL, WebSocket/SSE
- **Session Attacks:** CSRF, CORS, Race conditions, Cache poisoning
- **Code Execution:** Deserialization, Prototype pollution
- **Discovery:** Reconnaissance, Quick scan
- **Advanced:** Headless browser, ML model exploitation

### 🚀 Core Features
- **Workspace Management** - Organize multi-challenge testing
- **Target Configuration** - Custom headers, proxy, WAF bypass
- **Real-time Fuzzing** - Intelligent filtering and monitoring
- **OOB Listener** - Blind vulnerability detection
- **Background Tasks** - Celery-powered async processing
- **Redis Caching** - 90%+ performance improvement
- **Evidence Management** - PoC storage and export
- **JWT Inspector** - Token analysis and manipulation
- **WebSocket Support** - Real-time updates
- **Team Collaboration** - Multi-user support

## Architecture

- **Backend**: Python 3.11+ with FastAPI
- **Frontend**: React 18+ with TypeScript
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Cache**: Redis
- **Task Queue**: Celery
- **Containerization**: Docker & Docker Compose

## Prerequisites

### For Native Setup (Recommended for Development)
- Python 3.11 or higher
- Node.js 18 or higher
- PostgreSQL 14 or higher
- Redis 7 or higher

### For Docker Setup
- Docker and Docker Compose

## Quick Start

### 🚀 Native Setup (No Docker - Low Memory)

**Best for development and systems with limited RAM (< 8GB)**

```bash
# 1. Install prerequisites (one-time)
./install-prerequisites.sh

# 2. Start everything (backend + frontend)
./start-native.sh

# Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Documentation: http://localhost:8000/docs
# Flower Monitor: http://localhost:5555

# Stop everything
./stop-native.sh
```

**Memory Usage:** ~400-650 MB (vs 2-3 GB with Docker)

See [NATIVE_SETUP.md](NATIVE_SETUP.md) for detailed instructions.

### 🐳 Docker Setup (Production)

**Best for production deployment and team consistency**

```bash
# Clone the repository
git clone https://github.com/H4D3ZS/VulnChain
cd vulnchain

# Start all services
docker-compose up -d

# Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Documentation: http://localhost:8000/docs
```

See [docs/deployment.md](docs/deployment.md) for production deployment.

### 🛠️ Manual Development Setup

#### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest

# Start development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Run tests
npm test

# Start development server
npm run dev
```

## Project Structure

```
vulnchain/
├── backend/                 # Python FastAPI backend
│   ├── app/
│   │   ├── core/           # Core engine components
│   │   ├── modules/        # Attack modules
│   │   ├── api/            # REST API endpoints
│   │   ├── models/         # Database models
│   │   └── main.py         # Application entry point
│   ├── tests/              # Backend tests
│   ├── requirements.txt    # Production dependencies
│   └── requirements-dev.txt # Development dependencies
├── frontend/               # React TypeScript frontend
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── pages/          # Page components
│   │   ├── hooks/          # Custom hooks
│   │   ├── services/       # API services
│   │   └── App.tsx         # Main application
│   └── tests/              # Frontend tests
├── docker-compose.yml      # Docker Compose configuration
├── docs/                   # Documentation
└── README.md              # This file
```

## Testing

### Backend Tests

```bash
cd backend

# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run property-based tests
pytest -m property
```

### Frontend Tests

```bash
cd frontend

# Run all tests
npm test

# Run with coverage
npm run test:coverage
```

## Documentation

**📚 [Complete Documentation Index](DOCUMENTATION_INDEX.md)** - Find all documentation in one place

### Setup Guides
- **[Getting Started](GETTING_STARTED.md)** - Beginner-friendly introduction
- **[Quick Reference](QUICK_REFERENCE.md)** - Common commands and troubleshooting
- **[Native Setup Guide](NATIVE_SETUP.md)** - Run without Docker (low memory)
- **[Native Setup Overview](NATIVE_SETUP_OVERVIEW.md)** - Visual overview with diagrams
- **[Setup Comparison](SETUP_COMPARISON.md)** - Compare setup methods
- **[Manual Setup Guide](MANUAL_SETUP_GUIDE.md)** - Detailed manual setup
- **[Deployment Guide](docs/deployment.md)** - Production deployment

### Architecture & Design
- **[Architecture Guide](ARCHITECTURE.md)** - System architecture and components
- [Requirements Document](.kiro/specs/vulnchain-ctf-framework/requirements.md)
- [Design Document](.kiro/specs/vulnchain-ctf-framework/design.md)
- [Implementation Tasks](.kiro/specs/vulnchain-ctf-framework/tasks.md)
- [API Documentation](http://localhost:8000/docs) (when running)

## Legal Disclaimer

**IMPORTANT**: This tool is designed exclusively for:
- Educational purposes in controlled environments
- Authorized CTF competitions
- Legal bug bounty programs with explicit permission
- Testing on vulnerable-by-design platforms (DVWA, WebGoat, etc.)

**Unauthorized use of this tool against systems without explicit permission is illegal and unethical.**

The developers assume no liability for misuse of this software.

## License

[To be determined]

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

## Support

For issues, questions, or feature requests, please open an issue on the project repository.
