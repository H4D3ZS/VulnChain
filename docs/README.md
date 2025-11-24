# VulnChain Documentation

Welcome to the VulnChain CTF Framework documentation.

## Contents

- [Getting Started](getting-started.md)
- [Architecture](architecture.md)
- [API Reference](api-reference.md)
- [Development Guide](development-guide.md)
- [Testing Guide](testing-guide.md)
- [Deployment](deployment.md)

## Quick Links

- [Requirements Document](../.kiro/specs/vulnchain-ctf-framework/requirements.md)
- [Design Document](../.kiro/specs/vulnchain-ctf-framework/design.md)
- [Implementation Tasks](../.kiro/specs/vulnchain-ctf-framework/tasks.md)

## Overview

VulnChain is an advanced CTF web exploitation framework designed for:
- Educational purposes in controlled environments
- Authorized CTF competitions
- Legal bug bounty programs
- Testing on vulnerable-by-design platforms

## Key Features

- **Automated Reconnaissance**: Technology fingerprinting, directory fuzzing, subdomain enumeration
- **Injection Testing**: SQL, Command, SSRF, XXE, SSTI, NoSQL, and more
- **API Exploitation**: JWT manipulation, OAuth/SAML testing, GraphQL introspection
- **Advanced Techniques**: Deserialization, race conditions, cache poisoning
- **Real-time Monitoring**: Live fuzzing monitor with intelligent filtering
- **OOB Detection**: Out-of-band listener for blind vulnerabilities
- **ML-Powered**: Vulnerability prediction and adaptive attack strategies
- **Extensible**: Plugin system for custom modules
- **Collaborative**: Team features for multi-player CTFs

## Technology Stack

- **Backend**: Python 3.11+, FastAPI, SQLAlchemy, Celery
- **Frontend**: React 18+, TypeScript, TanStack Query
- **Database**: PostgreSQL
- **Cache**: Redis
- **Containerization**: Docker & Docker Compose

## Legal Notice

This tool is designed exclusively for authorized security testing. Unauthorized use against systems without explicit permission is illegal and unethical.
