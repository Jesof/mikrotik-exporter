# Build the Docker image
docker build -t ghcr.io/jesof/mikrotik-exporter:latest .

# Run locally for testing
docker run --rm -p 9090:9090 \
  -e ROUTERS_CONFIG='[{"name":"test","address":"192.168.88.1:8728","username":"admin","password":"admin"}]' \
  ghcr.io/jesof/mikrotik-exporter:latest

# Tag for version
docker tag ghcr.io/jesof/mikrotik-exporter:latest ghcr.io/jesof/mikrotik-exporter:v0.1.0

# Push to registry (requires authentication)
docker push ghcr.io/jesof/mikrotik-exporter:latest
docker push ghcr.io/jesof/mikrotik-exporter:v0.1.0
