Create a docker-compose.yml file:

version: '3.8'

services:
  bnra:
    build: .
    container_name: bnra_container
    ports:
      - "8080:8080"
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped
Run it with:

docker-compose up -d
