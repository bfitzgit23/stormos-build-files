#!/bin/bash
# Stop Holocore, keep MongoDB running (use --with-mongo to stop both)
pkill -f "com.projectswg.holocore.ProjectSWG" && echo "Holocore stopped" || echo "Holocore not running"
if [ "$1" = "--with-mongo" ]; then
  pkill -x mongod && echo "MongoDB stopped" || echo "MongoDB not running"
fi
