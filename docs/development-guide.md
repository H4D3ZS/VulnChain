# Development Guide

This guide covers development workflows, coding standards, and best practices for contributing to VulnChain.

## Development Environment Setup

See [Getting Started](getting-started.md) for initial setup instructions.

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
│   └── requirements.txt    # Dependencies
├── frontend/               # React TypeScript frontend
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── pages/          # Page components
│   │   ├── hooks/          # Custom hooks
│   │   └── services/       # API services
│   └── tests/              # Frontend tests
└── docs/                   # Documentation
```

## Coding Standards

### Python (Backend)

We use the following tools for code quality:

- **Black**: Code formatting
- **isort**: Import sorting
- **flake8**: Linting
- **mypy**: Type checking
- **pylint**: Additional linting

#### Format Code

```bash
cd backend

# Format with Black
black app/ tests/

# Sort imports
isort app/ tests/

# Check linting
flake8 app/ tests/

# Type checking
mypy app/
```

#### Code Style Guidelines

- Use type hints for all function parameters and return values
- Write docstrings for all public functions and classes
- Keep functions focused and under 50 lines when possible
- Use descriptive variable names
- Follow PEP 8 conventions

### TypeScript (Frontend)

We use the following tools:

- **ESLint**: Linting
- **Prettier**: Code formatting

#### Format Code

```bash
cd frontend

# Format with Prettier
npm run format

# Check formatting
npm run format:check

# Lint
npm run lint

# Fix linting issues
npm run lint:fix
```

#### Code Style Guidelines

- Use functional components with hooks
- Use TypeScript strict mode
- Define interfaces for all props and state
- Use meaningful component and variable names
- Keep components focused and reusable

## Testing

### Backend Testing

```bash
cd backend

# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_main.py

# Run property-based tests
pytest -m property

# Run with verbose output
pytest -v
```

### Frontend Testing

```bash
cd frontend

# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Run in watch mode
npm test -- --watch
```

## Git Workflow

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `refactor/description` - Code refactoring
- `docs/description` - Documentation updates
- `test/description` - Test additions/updates

### Commit Messages

Follow conventional commits format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Tests
- `chore`: Maintenance

Example:
```
feat(api): add target configuration endpoint

Implement POST /api/v1/targets endpoint for creating
new target configurations with validation.

Closes #123
```

## Adding New Features

### Backend Module

1. Create module file in `backend/app/modules/`
2. Implement module interface
3. Add tests in `backend/tests/`
4. Register module in core engine
5. Update API endpoints if needed

### Frontend Component

1. Create component in `frontend/src/components/`
2. Add TypeScript interfaces
3. Implement component logic
4. Add tests
5. Update parent components

## Database Migrations

```bash
cd backend

# Create migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

## Debugging

### Backend

Use Python debugger:

```python
import ipdb; ipdb.set_trace()
```

Or use IDE debugging with breakpoints.

### Frontend

Use browser DevTools and React DevTools extension.

## Performance Profiling

### Backend

```bash
# Profile with cProfile
python -m cProfile -o output.prof app/main.py

# Analyze with snakeviz
snakeviz output.prof
```

### Frontend

Use Chrome DevTools Performance tab.

## Documentation

- Update relevant documentation when adding features
- Add docstrings to all public APIs
- Include examples in documentation
- Keep README.md up to date

## Code Review Checklist

- [ ] Code follows style guidelines
- [ ] Tests are included and passing
- [ ] Documentation is updated
- [ ] No security vulnerabilities introduced
- [ ] Performance impact considered
- [ ] Error handling implemented
- [ ] Logging added where appropriate
