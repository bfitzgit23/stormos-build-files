#!/bin/bash
echo "== MongoDB =="
pgrep -x mongod >/dev/null && echo "running (pid $(pgrep -x mongod))" || echo "NOT running"
(echo > /dev/tcp/127.0.0.1/27017) 2>/dev/null && echo "port 27017: open" || echo "port 27017: closed"
echo "== Holocore =="
pgrep -f "com.projectswg.holocore.ProjectSWG" >/dev/null && echo "running (pid $(pgrep -f com.projectswg.holocore.ProjectSWG | head -1))" || echo "NOT running"
(echo > /dev/tcp/127.0.0.1/44463) 2>/dev/null && echo "port 44463 (game): open" || echo "port 44463 (game): closed"
echo "== last log lines =="
tail -5 "$HOME/holocore.log" 2>/dev/null
