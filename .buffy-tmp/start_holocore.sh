#!/bin/bash
# Start MongoDB (user-space) + Holocore CU server
APPS=$HOME/apps
HOLO=$HOME/Holocore
mkdir -p "$APPS/mongo_data" "$APPS/mongo_logs"
if ! pgrep -x mongod >/dev/null; then
  "$APPS/mongodb/bin/mongod" --dbpath "$APPS/mongo_data" --bind_ip 127.0.0.1 --port 27017 \
    --fork --logpath "$APPS/mongo_logs/mongod.log" --pidfilepath "$APPS/mongo_logs/mongod.pid" \
    --wiredTigerCacheSizeGB 1
  sleep 2
fi
if pgrep -f "com.projectswg.holocore.ProjectSWG" >/dev/null; then
  echo "Holocore already running (pid $(pgrep -f com.projectswg.holocore.ProjectSWG | head -1))"
  exit 0
fi
cd "$HOLO" || exit 1
setsid nohup "$HOLO/build/holocore/bin/holocore" --database "mongodb://127.0.0.1:27017" --dbName cu \
  > "$HOME/holocore.log" 2>&1 < /dev/null &
echo "Holocore starting (log: ~/holocore.log)"
