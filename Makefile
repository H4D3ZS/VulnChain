.PHONY: help install install-backend install-frontend test test-backend test-frontend lint lint-backend lint-frontend format format-backend format-frontend clean docker-up docker-down docker-logs

help:
	@echo "VulnChain CTF Framework - Development Commands"
	@echo ""
	@echo "Installation:"
	@echo "  make install          - Install all dependencies"
	@echo "  make install-backend  - Install backend dependencies"
	@echo "  make install-frontend - Install frontend dependencies"
	@echo ""
	@echo "Testing:"
	@echo "  make test             - Run all tests"
	@echo "  make test-backend     - Run backend tests"
	@echo "  make test-frontend    - Run frontend tests"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint             - Lint all code"
	@echo "  make lint-backend     - Lint backend code"
	@echo "  make lint-frontend    - Lint frontend code"
	@echo "  make format           - Format all code"
	@echo "  make format-backend   - Format backend code"
	@echo "  make format-frontend  - Format frontend code"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-up        - Start all services"
	@echo "  make docker-down      - Stop all services"
	@echo "  make docker-logs      - View logs"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean            - Remove build artifacts"

install: install-backend install-frontend

install-backend:
	cd backend && python -m venv venv && \
	. venv/bin/activate && \
	pip install -r requirements.txt && \
	pip install -r requirements-dev.txt

install-frontend:
	cd frontend && npm install

test: test-backend test-frontend

test-backend:
	cd backend && . venv/bin/activate && pytest

test-frontend:
	cd frontend && npm test

lint: lint-backend lint-frontend

lint-backend:
	cd backend && . venv/bin/activate && \
	flake8 app/ tests/ && \
	mypy app/

lint-frontend:
	cd frontend && npm run lint

format: format-backend format-frontend

format-backend:
	cd backend && . venv/bin/activate && \
	black app/ tests/ && \
	isort app/ tests/

format-frontend:
	cd frontend && npm run format

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name "node_modules" -exec rm -rf {} +
	find . -type d -name "dist" -exec rm -rf {} +
	find . -type d -name "build" -exec rm -rf {} +

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f
