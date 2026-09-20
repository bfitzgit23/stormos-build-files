const { app, BrowserWindow, ipcMain, screen } = require('electron');
const path = require('path');
const { exec, spawn } = require('child_process');
const os = require('os');
const fs = require('fs');

// ---------------------------------------------------------------------------
// System stats — runs bash commands and returns structured data to React
// ---------------------------------------------------------------------------

function run(cmd) {
  return new Promise((resolve) => {
    exec(cmd, { timeout: 5000 }, (err, stdout) => {
      resolve(err ? '' : stdout.trim());
    });
  });
}

function memoryInfo() {
  try {
    const raw = fs.readFileSync('/proc/meminfo', 'utf8');
    const get = (key) => {
      const m = raw.match(new RegExp(`^${key}:\\s+(\\d+)`, 'm'));
      return m ? parseInt(m[1], 10) * 1024 : 0;
    };
    const total = get('MemTotal');
    const available = get('MemAvailable') || get('MemFree');
    const used = total - available;
    return { used, total, percent: total ? Math.round((used / total) * 100) : 0 };
  } catch {
    return { used: 0, total: 0, percent: 0 };
  }
}

function storageInfo() {
  try {
    const st = fs.statvfsSync('/');
    const total = st.f_blocks * st.f_frsize;
    const free = st.f_bavail * st.f_frsize;
    const used = total - free;
    return { used, total, percent: total ? Math.round((used / total) * 100) : 0 };
  } catch {
    return { used: 0, total: 0, percent: 0 };
  }
}

function cpuSample() {
  try {
    const raw = fs.readFileSync('/proc/stat', 'utf8');
    const fields = raw.split('\n')[0].split(/\s+/).slice(1).map(Number);
    const idle = fields[3] + (fields[4] || 0);
    const total = fields.reduce((a, b) => a + b, 0);
    return { idle, total };
  } catch {
    return { idle: 0, total: 1 };
  }
}

let prevCpu = cpuSample();

function cpuPercent() {
  const cur = cpuSample();
  const dIdle = cur.idle - prevCpu.idle;
  const dTotal = cur.total - prevCpu.total;
  prevCpu = cur;
  return dTotal > 0 ? Math.round(100 * (1 - dIdle / dTotal)) : 0;
}

async function gpuInfo() {
  const out = await run("lspci 2>/dev/null | grep -Ei 'vga|3d|display' | sed -E 's/^[^:]+: //' | head -n 3");
  return out ? out.split('\n').filter(Boolean) : ['GPU information unavailable'];
}

async function getSystemStats() {
  const memory = memoryInfo();
  const storage = storageInfo();
  const cpu = cpuPercent();
  const gpus = await gpuInfo();
  const uptime = parseFloat((await run("cat /proc/uptime")).split(' ')[0] || '0');
  const kernel = await run('uname -r');
  const hostname = os.hostname();
  const localTime = await run('date +"%I:%M %p"');
  const localDate = await run('date +"%a, %b %-d"');
  const packages = await run('pacman -Q 2>/dev/null | wc -l');
  const osRelease = await run("sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '\"'");

  return {
    os: osRelease || 'StormOS',
    hostname,
    kernel: kernel || 'unknown',
    uptime: Math.round(uptime),
    packages: parseInt(packages) || 0,
    cpu: await run("sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -n 1") || 'CPU',
    cpuPercent: cpu,
    gpus,
    memory,
    storage,
    network: {
      hostname,
      connected: (await run("nmcli -t -f STATE general 2>/dev/null")) === 'connected'
    },
    bluetooth: fs.existsSync('/usr/bin/bluetoothctl'),
    localTime,
    localDate,
    timestamp: Math.floor(Date.now() / 1000)
  };
}

// ---------------------------------------------------------------------------
// IPC handlers — React calls these via preload.js
// ---------------------------------------------------------------------------

ipcMain.handle('get-system-stats', async () => {
  return getSystemStats();
});

ipcMain.handle('get-time', async () => {
  const now = new Date();
  return {
    time: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    date: now.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' }),
    timestamp: Math.floor(now.getTime() / 1000)
  };
});

ipcMain.handle('exec-command', async (_event, cmd) => {
  return run(cmd);
});

ipcMain.handle('launch-app', async (_event, appPath) => {
  return new Promise((resolve) => {
    spawn(appPath, [], {
      detached: true,
      stdio: 'ignore',
      env: { ...process.env, STORMOS_LAUNCH_ID: `${Date.now()}` }
    }).unref();
    resolve({ ok: true });
  });
});

// ---------------------------------------------------------------------------
// BrowserWindow — borderless, transparent, fullscreen, click-through on
// transparent regions so you can interact with windows behind the shell
// ---------------------------------------------------------------------------

let mainWindow = null;

function createWindow() {
  const { width, height } = screen.getPrimaryDisplay().workAreaSize;

  mainWindow = new BrowserWindow({
    x: 0,
    y: 0,
    width,
    height,
    fullscreen: true,
    frame: false,
    transparent: true,
    alwaysOnTop: false,
    skipTaskbar: true,
    resizable: false,
    movable: false,
    focusable: true,
    hasShadow: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
      offscreen: false,
      backgroundThrottling: false
    }
  });

  // In dev mode load Vite dev server; in production load the built index
  const isDev = process.argv.includes('--dev');
  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
  } else {
    mainWindow.loadFile(path.join(__dirname, 'dist', 'index.html'));
  }

  mainWindow.setIgnoreMouseEvents(false);

  // Log crashes for debugging
  mainWindow.webContents.on('crashed', (event, code) => {
    console.error(`[StormOS] Renderer crashed with code ${code}`);
  });
  mainWindow.webContents.on('unresponsive', () => {
    console.error('[StormOS] Renderer became unresponsive');
  });
  mainWindow.on('unresponsive', () => {
    console.error('[StormOS] Window became unresponsive');
  });
  mainWindow.on('render-process-gone', (event, details) => {
    console.error(`[StormOS] Render process gone: ${details.reason}`);
  });

  // Fallback: if window fails to show in 5 seconds, recreate with opaque background
  setTimeout(() => {
    if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.isVisible()) {
      console.warn('[StormOS] Window not visible after 5s — transparency may not be supported');
      console.warn('[StormOS] Falling back to opaque mode');
      mainWindow.destroy();
      // Recreate without transparency
      mainWindow = new BrowserWindow({
        x: 0, y: 0, width, height,
        fullscreen: true, frame: false,
        transparent: false,
        backgroundColor: '#050c15',
        alwaysOnTop: false, skipTaskbar: true,
        webPreferences: {
          nodeIntegration: false, contextIsolation: true,
          preload: path.join(__dirname, 'preload.js'),
          offscreen: false, backgroundThrottling: false
        }
      });
      if (isDev) mainWindow.loadURL('http://localhost:5173');
      else mainWindow.loadFile(path.join(__dirname, 'dist', 'index.html'));
    }
  }, 5000);
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

// Log startup
console.log('[StormOS] main.js loaded, creating window...');
