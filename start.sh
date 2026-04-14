#!/bin/bash
INSTALL_DIR=$(cd "$(dirname "$0")" && pwd)

echo "🚀 Starting NDR Stack..."

# Start agent if not running
if ! pgrep -f ndr-agent.py > /dev/null; then
    sudo systemctl start ndr-agent
fi

# Start Docker stack
cd $INSTALL_DIR
docker compose up -d

# Start Angular UI
cd $INSTALL_DIR/ndr-ui
nohup npm start > /tmp/ndr-ui.log 2>&1 &
echo $! > /tmp/ndr-ui.pid

echo "✅ NDR Stack started"
echo "   UI:    http://localhost:4200"
echo "   API:   http://localhost:3000"
