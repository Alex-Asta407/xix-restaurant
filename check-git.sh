#!/bin/bash
# Quick script to check if Git is available on your server
# Run this via SSH in your xixapp directory

echo "Checking Git availability..."
if command -v git &> /dev/null; then
    echo "✅ Git is installed!"
    git --version
    
    echo ""
    echo "Current directory:"
    pwd
    
    echo ""
    echo "To set up Git deployment, run:"
    echo "  cd /home/xixlzmqv/xixapp"
    echo "  git init"
    echo "  git remote add origin https://github.com/Alex-Asta407/xix-restaurant.git"
    echo "  git pull origin main"
    echo ""
    echo "Then for future updates, just run:"
    echo "  cd /home/xixlzmqv/xixapp"
    echo "  git pull origin main"
    echo "  (and restart app in cPanel)"
else
    echo "❌ Git is not available on your server"
    echo "You'll need to use manual file upload or contact Namecheap to enable Git"
fi

