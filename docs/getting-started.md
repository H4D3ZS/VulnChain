# Getting Started

This guide will help you set up and run VulnChain on your local machine.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.11 or higher**
- **Node.js 18 or higher**
- **Docker and Docker Compose** (for containerized deployment)
- **Git**

## Installation

### Option 1: Docker Compose (Recommended)

The easiest way to get started is using Docker Compose:

```bash
# Clone the repository
git clone <repository-url>
cd vulnchain

# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

Access the application:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs

### Option 2: Local Development

#### Backend Setup

```bash
cd backend

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Copy environment file
cp .env.example .env

# Edit .env with your configuration
# nano .env

# Run database migrations (once database is set up)
# alembic upgrade head

# Start the development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start the development server
npm run dev
```

## Verification

### Test Backend

```bash
# Health check
curl http://localhost:8000/health

# API documentation
open http://localhost:8000/docs
```

### Test Frontend

Open your browser and navigate to http://localhost:3000

## Next Steps

- Read the [Architecture](architecture.md) documentation
- Explore the [API Reference](api-reference.md)
- Check out the [Development Guide](development-guide.md)
- Review the [Requirements Document](../.kiro/specs/vulnchain-ctf-framework/requirements.md)

## Troubleshooting

### Port Already in Use

If you get port conflicts, you can change the ports in `docker-compose.yml` or your `.env` file.

### Database Connection Issues

Ensure PostgreSQL is running and the connection string in `.env` is correct.

### Frontend Build Errors

Try deleting `node_modules` and reinstalling:

```bash
cd frontend
rm -rf node_modules
npm install
```

## Support

For issues and questions, please refer to the project repository.
