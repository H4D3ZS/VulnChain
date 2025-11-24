# VulnChain Deployment Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Development Deployment](#development-deployment)
3. [Production Deployment](#production-deployment)
4. [Environment Configuration](#environment-configuration)
5. [SSL/TLS Setup](#ssltls-setup)
6. [Kubernetes Deployment](#kubernetes-deployment)
7. [Monitoring and Logging](#monitoring-and-logging)
8. [Backup and Recovery](#backup-and-recovery)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements
- **OS:** Linux (Ubuntu 20.04+ recommended) or macOS
- **CPU:** 4+ cores recommended
- **RAM:** 8GB minimum, 16GB+ recommended
- **Disk:** 50GB+ available space
- **Docker:** 20.10+
- **Docker Compose:** 2.0+

### Required Software
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version
```

## Development Deployment

### Quick Start

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/vulnchain.git
cd vulnchain
```

2. **Create environment file:**
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Start all services:**
```bash
docker-compose up -d
```

4. **Check service status:**
```bash
docker-compose ps
```

5. **View logs:**
```bash
docker-compose logs -f
```

6. **Access the application:**
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Flower (Celery): http://localhost:5555

### Development Commands

**Start services:**
```bash
docker-compose up -d
```

**Stop services:**
```bash
docker-compose down
```

**Rebuild services:**
```bash
docker-compose up -d --build
```

**View logs:**
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f celery-worker-scans
```

**Execute commands in containers:**
```bash
# Backend shell
docker-compose exec backend bash

# Run migrations
docker-compose exec backend alembic upgrade head

# Create admin user
docker-compose exec backend python -m app.scripts.create_admin
```

## Production Deployment

### Pre-deployment Checklist

- [ ] Configure production environment variables
- [ ] Set strong passwords for all services
- [ ] Configure SSL/TLS certificates
- [ ] Set up backup strategy
- [ ] Configure monitoring and alerting
- [ ] Review security settings
- [ ] Test disaster recovery procedures

### Production Setup

1. **Prepare environment:**
```bash
# Create production environment file
cp .env.example .env.production

# Edit with production values
nano .env.production
```

**Required production settings:**
```bash
# Security
DEBUG=false
SECRET_KEY=<generate-strong-random-key>
JWT_SECRET_KEY=<generate-strong-random-key>

# Database
POSTGRES_PASSWORD=<strong-password>

# Redis
REDIS_PASSWORD=<strong-password>

# Flower
FLOWER_USER=admin
FLOWER_PASSWORD=<strong-password>

# CORS
CORS_ORIGINS=https://yourdomain.com
```

2. **Generate secure keys:**
```bash
# Generate SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(50))"

# Generate JWT_SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(50))"
```

3. **Deploy with production compose:**
```bash
docker-compose -f docker-compose.prod.yml --env-file .env.production up -d
```

4. **Run database migrations:**
```bash
docker-compose -f docker-compose.prod.yml exec backend alembic upgrade head
```

5. **Create admin user:**
```bash
docker-compose -f docker-compose.prod.yml exec backend python -m app.scripts.create_admin
```

### Production Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Nginx (Reverse Proxy)                 │
│                  Port 80/443 (SSL/TLS)                   │
└────────────┬────────────────────────────┬────────────────┘
             │                            │
             ▼                            ▼
    ┌────────────────┐          ┌────────────────┐
    │    Frontend    │          │    Backend     │
    │   (React/TS)   │          │   (FastAPI)    │
    │   Port 3000    │          │   Port 8000    │
    └────────────────┘          └────────┬───────┘
                                         │
                    ┌────────────────────┼────────────────────┐
                    │                    │                    │
                    ▼                    ▼                    ▼
           ┌────────────────┐   ┌────────────────┐  ┌────────────────┐
           │   PostgreSQL   │   │     Redis      │  │  Celery Workers│
           │   (Database)   │   │  (Cache/Queue) │  │  (Background)  │
           └────────────────┘   └────────────────┘  └────────────────┘
```

## Environment Configuration

### Core Settings

**Application:**
```bash
APP_NAME=VulnChain
APP_VERSION=0.1.0
DEBUG=false
```

**Database:**
```bash
POSTGRES_USER=vulnchain
POSTGRES_PASSWORD=<secure-password>
POSTGRES_DB=vulnchain
POSTGRES_PORT=5432
```

**Redis:**
```bash
REDIS_PASSWORD=<secure-password>
REDIS_PORT=6379
```

**Backend:**
```bash
BACKEND_PORT=8000
SECRET_KEY=<50-char-random-string>
JWT_SECRET_KEY=<50-char-random-string>
JWT_EXPIRATION_MINUTES=60
```

**CORS:**
```bash
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

**Celery:**
```bash
FLOWER_PORT=5555
FLOWER_USER=admin
FLOWER_PASSWORD=<secure-password>
```

### Security Best Practices

1. **Never commit .env files to version control**
2. **Use strong, unique passwords for all services**
3. **Rotate secrets regularly**
4. **Limit CORS origins to your domain only**
5. **Enable SSL/TLS in production**
6. **Use environment-specific configurations**

## SSL/TLS Setup

### Using Let's Encrypt (Recommended)

1. **Install Certbot:**
```bash
sudo apt-get update
sudo apt-get install certbot python3-certbot-nginx
```

2. **Obtain certificate:**
```bash
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

3. **Configure auto-renewal:**
```bash
sudo certbot renew --dry-run
```

4. **Update nginx configuration:**
```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # ... rest of configuration
}
```

### Using Custom Certificates

1. **Place certificates:**
```bash
mkdir -p nginx/ssl
cp your-cert.crt nginx/ssl/
cp your-key.key nginx/ssl/
```

2. **Update docker-compose.prod.yml:**
```yaml
nginx:
  volumes:
    - ./nginx/ssl:/etc/nginx/ssl:ro
```

3. **Configure nginx:**
```nginx
ssl_certificate /etc/nginx/ssl/your-cert.crt;
ssl_certificate_key /etc/nginx/ssl/your-key.key;
```

## Kubernetes Deployment

### Prerequisites
- Kubernetes cluster (1.20+)
- kubectl configured
- Helm 3+ (optional)

### Kubernetes Manifests

See `k8s/` directory for complete manifests:
- `k8s/namespace.yaml` - Namespace configuration
- `k8s/configmap.yaml` - Configuration
- `k8s/secrets.yaml` - Secrets
- `k8s/postgres.yaml` - PostgreSQL StatefulSet
- `k8s/redis.yaml` - Redis Deployment
- `k8s/backend.yaml` - Backend Deployment
- `k8s/celery-workers.yaml` - Celery Workers
- `k8s/frontend.yaml` - Frontend Deployment
- `k8s/nginx.yaml` - Nginx Ingress
- `k8s/services.yaml` - Service definitions

### Deploy to Kubernetes

1. **Create namespace:**
```bash
kubectl apply -f k8s/namespace.yaml
```

2. **Create secrets:**
```bash
kubectl create secret generic vulnchain-secrets \
  --from-literal=postgres-password=<password> \
  --from-literal=redis-password=<password> \
  --from-literal=secret-key=<key> \
  --from-literal=jwt-secret-key=<key> \
  -n vulnchain
```

3. **Deploy services:**
```bash
kubectl apply -f k8s/
```

4. **Check deployment:**
```bash
kubectl get pods -n vulnchain
kubectl get services -n vulnchain
```

5. **Access application:**
```bash
kubectl port-forward -n vulnchain svc/nginx 8080:80
```

## Monitoring and Logging

### Flower (Celery Monitoring)

Access Flower dashboard:
```
http://localhost:5555
```

Features:
- Real-time task monitoring
- Worker status
- Task history
- Task statistics

### Application Logs

**View logs:**
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f celery-worker-scans

# Last 100 lines
docker-compose logs --tail=100 backend
```

**Log locations:**
- Backend: `/app/logs/`
- Celery: `/app/logs/`
- Nginx: `/var/log/nginx/`

### Prometheus + Grafana (Optional)

1. **Add monitoring stack:**
```yaml
# docker-compose.monitoring.yml
services:
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

2. **Start monitoring:**
```bash
docker-compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d
```

## Backup and Recovery

### Database Backup

**Manual backup:**
```bash
# Backup
docker-compose exec postgres pg_dump -U vulnchain vulnchain > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore
docker-compose exec -T postgres psql -U vulnchain vulnchain < backup.sql
```

**Automated backup script:**
```bash
#!/bin/bash
# backup.sh
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
docker-compose exec postgres pg_dump -U vulnchain vulnchain | gzip > $BACKUP_DIR/backup_$DATE.sql.gz

# Keep only last 7 days
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +7 -delete
```

**Schedule with cron:**
```bash
# Run daily at 2 AM
0 2 * * * /path/to/backup.sh
```

### Redis Backup

Redis automatically saves to `/data` volume:
```bash
# Manual save
docker-compose exec redis redis-cli SAVE

# Copy backup
docker cp vulnchain-redis:/data/dump.rdb ./redis-backup.rdb
```

### Volume Backup

```bash
# Backup all volumes
docker run --rm \
  -v vulnchain_postgres_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/postgres_data_backup.tar.gz /data
```

## Troubleshooting

### Common Issues

**1. Services won't start:**
```bash
# Check logs
docker-compose logs

# Check service status
docker-compose ps

# Restart services
docker-compose restart
```

**2. Database connection errors:**
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Check connection
docker-compose exec backend python -c "from app.db.session import engine; print(engine)"

# Reset database
docker-compose down -v
docker-compose up -d
```

**3. Celery workers not processing tasks:**
```bash
# Check worker status
docker-compose logs celery-worker-scans

# Restart workers
docker-compose restart celery-worker-scans celery-worker-fuzzing celery-worker-reports

# Check Flower
open http://localhost:5555
```

**4. Frontend can't connect to backend:**
```bash
# Check CORS settings
echo $CORS_ORIGINS

# Check backend is accessible
curl http://localhost:8000/health

# Check nginx proxy
docker-compose logs nginx
```

**5. Out of memory:**
```bash
# Check resource usage
docker stats

# Increase Docker memory limit
# Docker Desktop: Settings > Resources > Memory

# Reduce worker concurrency
# Edit docker-compose.yml: --concurrency=2
```

### Health Checks

**Check all services:**
```bash
# Backend
curl http://localhost:8000/health

# Redis
docker-compose exec redis redis-cli ping

# PostgreSQL
docker-compose exec postgres pg_isready -U vulnchain

# Celery
curl http://localhost:5555/api/workers
```

### Performance Tuning

**Backend:**
```bash
# Increase workers
uvicorn app.main:app --workers 8

# Enable HTTP/2
uvicorn app.main:app --http h11 --http h2
```

**Celery:**
```bash
# Adjust concurrency
celery -A celery_worker worker --concurrency=8

# Enable autoscaling
celery -A celery_worker worker --autoscale=10,3
```

**PostgreSQL:**
```sql
-- Increase connection pool
ALTER SYSTEM SET max_connections = 200;

-- Tune memory
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
```

**Redis:**
```bash
# Increase memory
redis-server --maxmemory 2gb

# Enable persistence
redis-server --appendonly yes
```

## Maintenance

### Updates

**Update application:**
```bash
# Pull latest code
git pull

# Rebuild and restart
docker-compose up -d --build
```

**Update dependencies:**
```bash
# Backend
docker-compose exec backend pip install -r requirements.txt --upgrade

# Frontend
docker-compose exec frontend npm update
```

### Database Migrations

**Create migration:**
```bash
docker-compose exec backend alembic revision --autogenerate -m "description"
```

**Apply migrations:**
```bash
docker-compose exec backend alembic upgrade head
```

**Rollback migration:**
```bash
docker-compose exec backend alembic downgrade -1
```

### Scaling

**Scale workers:**
```bash
# Scale fuzzing workers to 3 instances
docker-compose up -d --scale celery-worker-fuzzing=3
```

**Horizontal scaling with Kubernetes:**
```bash
kubectl scale deployment backend --replicas=3 -n vulnchain
kubectl scale deployment celery-worker-scans --replicas=5 -n vulnchain
```

## Security Hardening

### Network Security
- Use firewall to restrict access
- Enable SSL/TLS for all connections
- Use VPN for administrative access
- Implement rate limiting
- Enable DDoS protection

### Application Security
- Keep dependencies updated
- Regular security audits
- Enable authentication on all services
- Use strong passwords
- Implement IP whitelisting
- Enable audit logging

### Container Security
- Run containers as non-root user
- Use minimal base images
- Scan images for vulnerabilities
- Limit container resources
- Use read-only file systems where possible

## Support

For issues and questions:
- GitHub Issues: https://github.com/yourusername/vulnchain/issues
- Documentation: https://docs.vulnchain.io
- Community: https://discord.gg/vulnchain

## License

VulnChain is released under the MIT License. See LICENSE file for details.
