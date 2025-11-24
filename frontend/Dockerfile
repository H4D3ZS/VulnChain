# Multi-stage build for production optimization

# Build stage
FROM node:18-alpine as builder

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Copy application code
COPY . .

# Build application
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built application from builder
COPY --from=builder /app/dist /usr/share/nginx/html

# Create non-root user
RUN addgroup -g 1000 vulnchain && \
    adduser -D -u 1000 -G vulnchain vulnchain && \
    chown -R vulnchain:vulnchain /usr/share/nginx/html && \
    chown -R vulnchain:vulnchain /var/cache/nginx && \
    chown -R vulnchain:vulnchain /var/log/nginx && \
    chown -R vulnchain:vulnchain /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown -R vulnchain:vulnchain /var/run/nginx.pid

# Switch to non-root user
USER vulnchain

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
