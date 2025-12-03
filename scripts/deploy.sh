#!/bin/bash
# deploy.sh - NIDS Deployment Script

set -e

echo "=========================================="
echo "NIDS Deployment Script"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Check if running as root for packet capture
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_warning "This script should be run with sudo for packet capture capabilities"
        echo "Continue without packet capture? (y/n)"
        read -r response
        if [[ ! $response =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Check system dependencies
check_dependencies() {
    echo ""
    echo "Checking system dependencies..."

    dependencies=("python3" "pip3" "docker" "docker-compose" "git")

    for dep in "${dependencies[@]}"; do
        if command -v $dep &> /dev/null; then
            print_success "$dep is installed"
        else
            print_error "$dep is not installed"
            exit 1
        fi
    done
}

# Create necessary directories
create_directories() {
    echo ""
    echo "Creating project directories..."

    directories=("models" "datasets" "logs" "alerts" "grafana/dashboards" "grafana/datasources")

    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            print_success "Created $dir/"
        fi
    done
}

# Setup Python virtual environment
setup_venv() {
    echo ""
    echo "Setting up Python virtual environment..."

    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_success "Virtual environment created"
    fi

    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    print_success "Dependencies installed"
}

# Generate initial models
train_initial_models() {
    echo ""
    echo "Training initial ML models..."

    if [ ! -f "models/nids_model.pkl" ]; then
        python train_models.py
        print_success "Models trained successfully"
    else
        print_warning "Models already exist, skipping training"
    fi
}

# Setup environment file
setup_env() {
    echo ""
    echo "Setting up environment file..."

    if [ ! -f ".env" ]; then
        cp .env.example .env
        print_warning "Created .env file - Please update with your configuration"
        print_warning "IMPORTANT: Change all passwords and secrets!"
    else
        print_success ".env file already exists"
    fi
}

# Build Docker images
build_docker() {
    echo ""
    echo "Building Docker images..."

    docker-compose build
    print_success "Docker images built successfully"
}

# Start services
start_services() {
    echo ""
    echo "Starting NIDS services..."

    docker-compose up -d
    print_success "Services started"

    echo ""
    echo "Waiting for services to be ready..."
    sleep 10

    # Check service health
    if curl -s http://localhost:8000/ > /dev/null; then
        print_success "API service is running"
    else
        print_error "API service failed to start"
    fi
}

# Display access information
display_info() {
    echo ""
    echo "=========================================="
    echo "NIDS Deployment Complete!"
    echo "=========================================="
    echo ""
    echo "Access points:"
    echo "  • API: http://localhost:8000"
    echo "  • API Docs: http://localhost:8000/docs"
    echo "  • Grafana: http://localhost:3000 (admin/admin_password_change_me)"
    echo "  • Prometheus: http://localhost:9090"
    echo ""
    echo "Useful commands:"
    echo "  • View logs: docker-compose logs -f"
    echo "  • Stop services: docker-compose down"
    echo "  • Restart: docker-compose restart"
    echo "  • View stats: curl http://localhost:8000/stats"
    echo ""
    print_warning "Remember to change default passwords in .env file!"
}

# Main deployment flow
main() {
    echo ""
    check_root
    check_dependencies
    create_directories
    setup_env
    setup_venv
    train_initial_models
    build_docker
    start_services
    display_info
}

# Run main function
main
