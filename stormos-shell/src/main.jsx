import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  AppWindow, Battery, Bluetooth, ChevronDown, CirclePower, Cpu, Folder,
  GalleryHorizontal, HardDrive, Image as ImageIcon, Laptop, Menu, Mic,
  Monitor, Music, Network, Package, Power, Search, Settings, Shield,
  SlidersHorizontal, Speaker, Terminal, UserRound, Wifi, X, Maximize2,
  Minus, Volume2, Gamepad2, FileText, Globe, Grid2X2, Sparkles, Zap,
  Activity, MemoryStick, Disc3, RefreshCw, LogOut
} from 'lucide-react';
import './styles.css';

const apps = [
  { id: 'gallery', name: 'StormOS Gallery', description: 'Image Viewer', icon: ImageIcon, color: 'blue' },
  { id: 'files', name: 'Thunar', description: 'File Manager', icon: Folder, color: 'blue' },
  { id: 'terminal', name: 'Foot', description: 'Terminal', icon: Terminal, color: 'slate' },
  { id: 'browser', name: 'Firefox', description: 'Web Browser', icon: Globe, color: 'orange' },
  { id: 'settings', name: 'StormOS Settings', description: 'System Settings', icon: Settings, color: 'steel' },
  { id: 'software', name: 'Software', description: 'Package Manager', icon: Package, color: 'red' },
  { id: 'office', name: 'LibreOffice', description: 'Office Suite', icon: FileText, color: 'silver' },
  { id: 'steam', name: 'Steam', description: 'Gaming Platform', icon: Gamepad2, color: 'blue' }
];


const BRIDGE_URL = 'http://127.0.0.1:47821';
const isElectron = typeof window !== 'undefined' && window.electronAPI;
const fallbackApps = apps.map(app => ({...app, internal: ['gallery','files','terminal','settings'].includes(app.id)}));
function DynamicAppIcon({app, size=22}) { return <AppIcon app={{...app, icon: app.icon && typeof app.icon === 'function' ? app.icon : AppWindow, color: app.color || 'blue'}} size={size}/>; }

async function launchNativeApp(app) {
  try {
    if (isElectron) {
      await window.electronAPI.launchApp(typeof app === 'string' ? app : (app.id || app.exec || ''));
      return true;
    }
    const response = await fetch(`${BRIDGE_URL}/api/launch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ app: typeof app === 'string' ? app : (app.id || app.exec || ''), launchId: `${Date.now()}-${Math.random().toString(36).slice(2)}` })
    });
    const result = await response.json();
    if (!response.ok || !result.ok) throw new Error(result.error || `Bridge returned HTTP ${response.status}`);
    return true;
  } catch (error) {
    console.warn(`StormOS could not launch ${app}:`, error);
    return false;
  }
}

const galleryImages = [
  'https://images.unsplash.com/photo-1464822759023-fed622ff2c3b?auto=format&fit=crop&w=900&q=85',
  'https://images.unsplash.com/photo-1519608487953-e999c86e7455?auto=format&fit=crop&w=900&q=85',
  'https://images.unsplash.com/photo-1500534623283-312aade485b7?auto=format&fit=crop&w=900&q=85',
  'https://images.unsplash.com/photo-1470770841072-f978cf4d019e?auto=format&fit=crop&w=900&q=85',
  'https://images.unsplash.com/photo-1511497584788-876760111969?auto=format&fit=crop&w=900&q=85',
  'https://images.unsplash.com/photo-1444703686981-a3abbc4d4fe3?auto=format&fit=crop&w=900&q=85'
];

function AppIcon({ app, size = 22 }) {
  const Icon = typeof app.icon === 'function' ? app.icon : AppWindow;
  return <span className={`app-icon ${app.color}`}><Icon size={size} strokeWidth={1.8} /></span>;
}

function TopBar({ onLauncher, onPower, onSettings, system }) {
  const timeText = system?.localTime || new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
  const dateText = system?.localDate || new Date().toLocaleDateString([], {weekday:'short', month:'short', day:'numeric'});
  const tz = system?.timezone || '';
  const button = (label, children, onClick) => <button className="status-button" title={label} aria-label={label} onClick={onClick}>{children}</button>;
  return <header className="topbar">
    <button className="brand-button" onClick={onLauncher} aria-label="Open applications"><span className="storm-ring small"/><span>StormOS</span></button>
    <nav className="workspaces" aria-label="Workspaces">{[1,2,3,4].map(n => <button key={n} onClick={()=>{}} className={n===1?'workspace active':'workspace'}>{n}</button>)}</nav>
    <button className="top-date" title={tz ? `Timezone: ${tz}${system?.ntpSynchronized ? ' • NTP synchronized' : ''}` : 'System clock'} onClick={onSettings}><span>{dateText}</span><strong>{timeText}</strong></button>
    <div className="status-icons">
      {button('Display settings', <Monitor size={16}/>, onSettings)}
      {button('Bluetooth', <Bluetooth size={17}/>, ()=>launchNativeApp('blueman-manager'))}
      {button('Network', <Wifi size={17}/>, ()=>launchNativeApp('nm-connection-editor'))}
      {button('Audio', <Volume2 size={17}/>, ()=>launchNativeApp('pavucontrol'))}
      {button('Power settings', <Battery size={18}/>, onSettings)}
      <span>{system?.batteryPercent != null ? `${system.batteryPercent}%` : ''}</span>
      <button className="power-button" onClick={onPower} title="Power"><Power size={17}/></button>
    </div>
  </header>;
}
function Launcher({ open, onClose, onOpenApp, installedApps, category, onCategory }) {
  const [query, setQuery] = useState('');
  const filtered = installedApps.filter(a => (category === 'Favorites' || category === 'All Applications' || a.category === category) && `${a.name} ${a.description || ''}`.toLowerCase().includes(query.toLowerCase()));
  if (!open) return null;
  return <aside className="launcher panel-glass">
    <div className="search-box"><Search size={17}/><input autoFocus value={query} onChange={e => setQuery(e.target.value)} placeholder="Search applications..." /></div>
    <div className="launcher-body">
      <div className="categories">
        {['Favorites', 'All Applications', 'Accessories', 'Graphics', 'Internet', 'Multimedia', 'Office', 'Settings', 'System'].map((x, i) => <button key={x} onClick={() => onCategory(x)} className={category === x ? 'category selected' : 'category'}><span>{i === 0 ? '☆' : '◈'}</span>{x}</button>)}
      </div>
      <div className="app-results">
        {filtered.map(app => <button className="app-row" key={app.id} onClick={() => onOpenApp(app)}><DynamicAppIcon app={app} size={25}/><span><strong>{app.name}</strong><small>{app.description}</small></span></button>)}
        {!filtered.length && <div className="empty">No applications found</div>}
      </div>
    </div>
  </aside>;
}

function WindowFrame({ title, icon: Icon, children, onClose, onMinimize, onMaximize, className = '' }) {
  const [position, setPosition] = useState({ x: null, y: null });
  const [size, setSize] = useState({ width: null, height: null });
  const [interaction, setInteraction] = useState(null);
  const interactionRef = React.useRef(null);

  const beginDrag = event => {
    if (event.button !== undefined && event.button !== 0) return;
    if (event.target.closest('button, input, select, textarea, a')) return;
    const frame = event.currentTarget.closest('.desktop-window');
    if (!frame) return;
    const rect = frame.getBoundingClientRect();
    interactionRef.current = {
      type: 'drag', startX: event.clientX, startY: event.clientY,
      x: rect.left, y: rect.top, width: rect.width, height: rect.height
    };
    setPosition({ x: rect.left, y: rect.top });
    setInteraction('drag');
    event.currentTarget.setPointerCapture?.(event.pointerId);
    event.preventDefault();
  };

  const beginResize = (event, direction) => {
    if (event.button !== undefined && event.button !== 0) return;
    const frame = event.currentTarget.closest('.desktop-window');
    if (!frame) return;
    const rect = frame.getBoundingClientRect();
    interactionRef.current = {
      type: 'resize', direction, startX: event.clientX, startY: event.clientY,
      x: rect.left, y: rect.top, width: rect.width, height: rect.height
    };
    setPosition({ x: rect.left, y: rect.top });
    setSize({ width: rect.width, height: rect.height });
    setInteraction('resize');
    event.currentTarget.setPointerCapture?.(event.pointerId);
    event.preventDefault();
    event.stopPropagation();
  };

  const moveInteraction = event => {
    const active = interactionRef.current;
    if (!active) return;
    const desktop = event.currentTarget.closest('.desktop') || document.querySelector('.desktop');
    const bounds = desktop?.getBoundingClientRect();
    const minWidth = 280;
    const minHeight = 180;
    const dx = event.clientX - active.startX;
    const dy = event.clientY - active.startY;

    if (active.type === 'drag') {
      const maxX = bounds ? Math.max(0, bounds.width - active.width) : window.innerWidth - active.width;
      const maxY = bounds ? Math.max(34, bounds.height - 78 - active.height) : window.innerHeight - active.height;
      setPosition({
        x: Math.max(0, Math.min(maxX, active.x + dx)),
        y: Math.max(34, Math.min(maxY, active.y + dy))
      });
      return;
    }

    let x = active.x;
    let y = active.y;
    let width = active.width;
    let height = active.height;
    const dir = active.direction;

    if (dir.includes('e')) width = Math.max(minWidth, active.width + dx);
    if (dir.includes('s')) height = Math.max(minHeight, active.height + dy);
    if (dir.includes('w')) {
      width = Math.max(minWidth, active.width - dx);
      x = active.x + active.width - width;
    }
    if (dir.includes('n')) {
      height = Math.max(minHeight, active.height - dy);
      y = active.y + active.height - height;
    }

    if (bounds) {
      width = Math.min(width, bounds.width - x);
      height = Math.min(height, bounds.height - 78 - Math.max(34, y));
      x = Math.max(0, Math.min(x, bounds.width - minWidth));
      y = Math.max(34, Math.min(y, bounds.height - 78 - minHeight));
    }

    setPosition({ x, y });
    setSize({ width: Math.max(minWidth, width), height: Math.max(minHeight, height) });
  };

  const endInteraction = event => {
    event?.stopPropagation?.();
    interactionRef.current = null;
    setInteraction(null);
  };

  const style = {
    ...(position.x === null ? {} : { left: `${position.x}px`, top: `${position.y}px`, right: 'auto', bottom: 'auto', transform: 'none' }),
    ...(size.width === null ? {} : { width: `${size.width}px`, height: `${size.height}px` })
  };
  const handles = ['n', 'e', 's', 'w', 'ne', 'se', 'sw', 'nw'];

  return <section className={`desktop-window ${className}${interaction ? ' is-interacting' : ''}`} style={style}>
    <div className="window-titlebar" onPointerDown={beginDrag} onPointerMove={moveInteraction} onPointerUp={endInteraction} onPointerCancel={endInteraction}>
      <div className="window-title"><span className="title-icon"><Icon size={15}/></span>{title}</div>
      <div className="window-actions"><button onClick={onMinimize}><Minus size={15}/></button><button onClick={onMaximize}><Maximize2 size={14}/></button><button onClick={onClose}><X size={15}/></button></div>
    </div>
    {children}
    {!className.includes('maximized-window') && handles.map(direction => <span key={direction} className={`resize-handle resize-${direction}`} onPointerDown={event => beginResize(event, direction)} onPointerMove={moveInteraction} onPointerUp={endInteraction} onPointerCancel={endInteraction} />)}
  </section>;
}
function FilesWindow({ close, minimize }) {
  const [maximized, setMaximized] = useState(false);
  const folders = ['Desktop', 'Documents', 'Downloads', 'Music', 'Pictures', 'Public', 'Templates', 'Videos'];
  return <WindowFrame title="Home - Thunar" icon={Folder} onClose={close} onMinimize={minimize} onMaximize={() => setMaximized(v => !v)} className={`files-window ${maximized ? "maximized-window" : ""}`}>
    <div className="menu-line">File&nbsp;&nbsp; Edit&nbsp;&nbsp; View&nbsp;&nbsp; Go&nbsp;&nbsp; Bookmarks&nbsp;&nbsp; Help</div>
    <div className="window-content file-content"><aside className="places"><strong>Places</strong>{['Home','Desktop','Documents','Downloads','Music','Pictures','Videos','Trash'].map((x,i)=><div className={i===0?'place active-place':'place'} key={x}><Folder size={14}/>{x}</div>)}<strong>Devices</strong><div className="place"><HardDrive size={14}/>File System</div><div className="place"><HardDrive size={14}/>Data</div></aside><main className="folder-area"><div className="pathbar">‹　›　⌂　 Home <RefreshCw size={14}/></div><div className="folder-grid">{folders.map(f=><div className="folder-item" key={f}><Folder size={31}/><span>{f}</span></div>)}</div><div className="statusbar">8 folders&nbsp;&nbsp;|&nbsp;&nbsp;Free space: 185.9 GiB</div></main></div>
  </WindowFrame>;
}

function TerminalWindow({ close, minimize }) {
  const [maximized, setMaximized] = useState(false);
  return <WindowFrame title="Foot" icon={Terminal} onClose={close} onMinimize={minimize} onMaximize={() => setMaximized(v => !v)} className={`terminal-window ${maximized ? "maximized-window" : ""}`}><div className="terminal-body"><pre>{`stormos@stormos
----------------
OS: StormOS (Arch Linux)
Kernel: 6.10.5-arch1-1
Uptime: 1h 24m
Packages: 1234 (pacman)
Shell: bash 5.2.26
DE: StormOS (labwc / Wayland)
WM: labwc
Theme: DarkCold
Icons: stormos
Terminal: foot
CPU: AMD Ryzen 7 7840HS
GPU: AMD Radeon 780M
     NVIDIA RTX 4060 Laptop
Memory: 2.8 GiB / 15.5 GiB

┌─────────────────────────────┐
│  StormOS native shell       │
│  React interface online     │
└─────────────────────────────┘

[stormos@stormos ~]$ `}</pre></div></WindowFrame>;
}

function GalleryWindow({ close, minimize }) {
  const [maximized, setMaximized] = useState(false);
  const [selected, setSelected] = useState(0);
  return <WindowFrame title="StormOS Gallery" icon={ImageIcon} onClose={close} onMinimize={minimize} onMaximize={() => setMaximized(v => !v)} className={`gallery-window ${maximized ? "maximized-window" : ""}`}><div className="menu-line">File&nbsp;&nbsp; Edit&nbsp;&nbsp; View&nbsp;&nbsp; Go&nbsp;&nbsp; Help</div><div className="window-content gallery-content"><aside className="gallery-sidebar"><strong>Library</strong>{['Images','Favorites','Recent','Trash'].map((x,i)=><div className={i===0?'place active-place':'place'} key={x}><ImageIcon size={14}/>{x}</div>)}<strong>Collections</strong>{['Wallpapers','Screenshots','Albums'].map(x=><div className="place" key={x}><Folder size={14}/>{x}</div>)}</aside><main className="gallery-main"><div className="gallery-grid">{galleryImages.map((src,i)=><button className={selected===i?'gallery-thumb selected-thumb':'gallery-thumb'} key={src} onClick={()=>setSelected(i)}><img src={src} alt={`StormOS wallpaper ${i+1}`}/></button>)}</div><div className="gallery-status">{selected+1} / {galleryImages.length}&nbsp;&nbsp; stormos-wallpaper.jpg&nbsp;&nbsp; 3840 × 2160</div></main></div></WindowFrame>;
}

function SettingsWindow({ close, minimize }) {
  const [maximized, setMaximized] = useState(false);
  const [section, setSection] = useState('Appearance');
  const [accent, setAccent] = useState('electric-blue');
  const [darkMode, setDarkMode] = useState(true);
  const [displayMode, setDisplayMode] = useState('extend');
  const [displayInfo, setDisplayInfo] = useState(null);
  const [displayMessage, setDisplayMessage] = useState('');
  const sections = ['Appearance','Desktop','Display','Panel & Dock','Applications','Network','Bluetooth','Power','Keyboard & Mouse','About'];
  const callBridge = async (path, body) => {
    try {
      const response = await fetch(`${BRIDGE_URL}${path}`, {method: body ? 'POST' : 'GET', headers: {'Content-Type':'application/json'}, body: body ? JSON.stringify(body) : undefined});
      const data = await response.json();
      if (!response.ok || data.ok === false) throw new Error(data.error || 'Operation failed');
      return data;
    } catch (error) { setDisplayMessage(error.message); return null; }
  };
  const loadDisplays = async () => {
    const data = await callBridge('/api/displays');
    if (data) { setDisplayInfo(data); setDisplayMessage(`${data.outputs?.length || 0} display(s) detected.`); }
  };
  const applyDisplayMode = async () => {
    const data = await callBridge('/api/displays/apply', {mode: displayMode});
    if (data) setDisplayMessage(data.message || 'Display layout applied.');
  };
  const renderSection = () => {
    if (section === 'Display') return <>
      <h2>Display</h2><p>Configure monitors, scaling, positioning, and mirroring.</p>
      <div className="setting-card"><div><strong>Connected displays</strong><small>Read the outputs detected by the Wayland compositor.</small></div><button className="settings-action" onClick={loadDisplays}>Detect Displays</button></div>
      {displayInfo?.outputs?.map(output => <div className="display-output" key={output.name}><strong>{output.name}</strong><span>{output.description || 'Display output'}</span><small>{output.modes?.join(', ') || 'Modes unavailable'}</small></div>)}
      <div className="setting-card"><div><strong>Display arrangement</strong><small>Choose how multiple displays should be arranged.</small></div><select value={displayMode} onChange={e=>setDisplayMode(e.target.value)}><option value="extend">Extend displays</option><option value="mirror">Mirror displays</option><option value="single">Use primary display only</option></select></div>
      <div className="setting-card"><div><strong>Resolution and refresh rate</strong><small>Use the compositor-supported mode for each output.</small></div><button className="settings-action" onClick={loadDisplays}>Refresh modes</button></div>
      <div className="setting-card"><div><strong>Scale and rotation</strong><small>These controls are exposed through the display backend when supported.</small></div><span className="setting-note">wlr-randr</span></div>
      <div className="setting-card"><div><strong>Apply layout</strong><small>Apply the selected layout. Use the compositor or display panel to revert if needed.</small></div><button className="settings-action primary" onClick={applyDisplayMode}>Apply</button></div>
      {displayMessage && <div className="settings-message">{displayMessage}</div>}
    </>;
    if (section === 'Power') return <><h2>Power</h2><p>Configure power and session behavior.</p><div className="setting-card"><div><strong>Lock screen</strong><small>Lock the current graphical session.</small></div><button className="settings-action" onClick={()=>launchNativeApp('lock')}>Lock</button></div><div className="setting-card"><div><strong>Log out</strong><small>End the current desktop session.</small></div><button className="settings-action" onClick={()=>launchNativeApp('logout')}>Log Out</button></div><div className="setting-card"><div><strong>Suspend</strong><small>Put the computer into sleep mode.</small></div><button className="settings-action" onClick={()=>launchNativeApp('suspend')}>Suspend</button></div><div className="setting-card"><div><strong>Restart or shut down</strong><small>Use systemd-logind for privileged power actions.</small></div><span className="setting-note">systemd</span></div></>;
    if (section === 'Desktop') return <><h2>Desktop</h2><p>Configure the StormOS desktop shell.</p><div className="setting-card"><div><strong>Dark mode</strong><small>Use the dark StormOS appearance.</small></div><input type="checkbox" checked={darkMode} onChange={e=>setDarkMode(e.target.checked)}/></div><div className="setting-card"><div><strong>Desktop effects</strong><small>Enable translucent panels and soft window shadows.</small></div><input type="checkbox" defaultChecked /></div><div className="setting-card"><div><strong>Workspace count</strong><small>Number of workspaces exposed by the session.</small></div><select defaultValue="4"><option>2</option><option>4</option><option>6</option><option>8</option></select></div></>;
    if (section === 'Panel & Dock') return <><h2>Panel & Dock</h2><p>Customize the launcher, dock, and panel behavior.</p><div className="setting-card"><div><strong>Dock position</strong><small>Choose the dock edge.</small></div><select defaultValue="bottom"><option value="bottom">Bottom</option><option value="left">Left</option><option value="right">Right</option></select></div><div className="setting-card"><div><strong>Auto-hide dock</strong><small>Hide the dock until the pointer reaches the edge.</small></div><input type="checkbox" /></div></>;
    if (section === 'Applications') return <><h2>Applications</h2><p>Choose default applications and startup behavior.</p><div className="setting-card"><div><strong>Default browser</strong><small>Application used for web links.</small></div><select defaultValue="firefox"><option value="firefox">Firefox</option><option value="chromium">Chromium</option><option value="waterfox">Waterfox</option></select></div><div className="setting-card"><div><strong>Startup applications</strong><small>Manage applications launched with the desktop.</small></div><button className="settings-action">Manage</button></div></>;
    if (section === 'Network' || section === 'Bluetooth' || section === 'Keyboard & Mouse') return <><h2>{section}</h2><p>These controls are provided by the installed system tools.</p><div className="setting-card"><div><strong>Open system configuration</strong><small>Launch the appropriate desktop utility.</small></div><button className="settings-action" onClick={()=>launchNativeApp(section === 'Bluetooth' ? 'blueman-manager' : section === 'Network' ? 'nm-connection-editor' : 'pavucontrol')}>Open</button></div></>;
    if (section === 'About') return <><h2>About StormOS</h2><p>StormOS React desktop shell.</p><div className="setting-card"><div><strong>Desktop shell</strong><small>React interface with GTK/WebKit host and a local Python bridge.</small></div><span className="setting-note">0.2.0</span></div><div className="setting-card"><div><strong>Session</strong><small>Wayland compositor integration.</small></div><span className="setting-note">labwc + systemd</span></div></>;
    return <><h2>Appearance</h2><p>Configure the StormOS visual experience.</p><div className="setting-card"><div><strong>Accent color</strong><small>Used for highlights, focus rings, and active controls.</small></div><select value={accent} onChange={e=>setAccent(e.target.value)}><option value="electric-blue">Electric Blue</option><option value="neon-purple">Neon Purple</option><option value="storm-green">Storm Green</option></select></div><div className="setting-card"><div><strong>GTK theme</strong><small>Use the bundled StormOS GTK theme.</small></div><select defaultValue="StormOS-GTK"><option>StormOS-GTK</option><option>Adwaita-dark</option><option>Adwaita</option></select></div><div className="setting-card"><div><strong>Icon theme</strong><small>Use the bundled StormOS icon set.</small></div><select defaultValue="StormOS-icons"><option>StormOS-icons</option><option>Adwaita</option><option>hicolor</option></select></div><div className="setting-card"><div><strong>Cursor theme</strong><small>Choose the pointer appearance.</small></div><select defaultValue="default"><option value="default">System Default</option><option>Adwaita</option><option>Bibata</option></select></div></>;
  };
  return <WindowFrame title="StormOS Settings" icon={Settings} onClose={close} onMinimize={minimize} onMaximize={() => setMaximized(v => !v)} className={`settings-window ${maximized ? 'maximized-window' : ''}`}><div className="settings-layout"><aside className="settings-nav"><div className="settings-heading"><Settings size={20}/> StormOS Settings</div>{sections.map(x=><button onClick={() => setSection(x)} className={section===x?'settings-nav-item active-setting':'settings-nav-item'} key={x}>{x}</button>)}</aside><main className="settings-main">{renderSection()}</main></div></WindowFrame>;
}
function SystemPanel({system, onOpenSettings}) {
  const memory = system?.memory;
  const storage = system?.storage;
  const uptime = system?.uptime ? `${Math.floor(system.uptime/86400)}d ${Math.floor(system.uptime/3600)%24}h ${Math.floor(system.uptime/60)%60}m` : '—';
  return <aside className="system-panel">
    <button className="system-logo" onClick={onOpenSettings}><span className="storm-ring"/> STORMOS</button>
    <SectionTitle>System Overview</SectionTitle>
    <InfoRow label="OS" value={system?.os || 'StormOS'}/><InfoRow label="Kernel" value={system?.kernel || '—'}/><InfoRow label="Uptime" value={uptime}/><InfoRow label="Packages" value={system?.packages ?? '—'}/>
    <SectionTitle>Hardware</SectionTitle>
    <Meter label="CPU" value={system?.cpu || '—'} percent={system?.cpuPercent != null ? `${system.cpuPercent}%` : '0%'}/>
    {(system?.gpus || []).map((gpu,i)=><Meter key={i} label={i ? 'GPU' : 'GPU'} value={gpu} percent="—"/>)}
    <Meter label="Memory" value={memory ? `${formatBytes(memory.used)} / ${formatBytes(memory.total)}` : '—'} percent={`${memory?.percent ?? 0}%`}/>
    <SectionTitle>Storage</SectionTitle><Meter label="/" value={storage ? `${formatBytes(storage.used)} / ${formatBytes(storage.total)}` : '—'} percent={`${storage?.percent ?? 0}%`}/>
    <SectionTitle>Network</SectionTitle><InfoRow label="Wi-Fi" value={system?.network?.connected ? 'Connected' : 'Disconnected'} accent/><InfoRow label="Host" value={system?.hostname || '—'}/><InfoRow label="Bluetooth" value={system?.bluetooth ? 'Available' : 'Unavailable'}/>
    <div className="built-script">Built for What’s Next.</div>
  </aside>;
}
function formatBytes(value){if(!Number.isFinite(value))return '—'; const units=['B','KiB','MiB','GiB','TiB']; let n=value,i=0; while(n>=1024&&i<units.length-1){n/=1024;i++;} return `${n.toFixed(i?1:0)} ${units[i]}`;}
function SectionTitle({children}) { return <h3 className="section-title">{children}<span/></h3>; }
function InfoRow({label,value,accent}) { return <div className="info-row"><span>{label}</span><strong className={accent?'accent-text':''}>{value}</strong></div>; }
function Meter({label,value,percent}) { return <div className="meter"><div className="meter-label"><span>{label}</span><span>{value}</span><em>{percent}</em></div><div className="meter-track"><span style={{width: percent === 'On Demand' ? '36%' : percent}}/></div></div>; }

function Dock({ onOpenApp, installedApps }) {
  const dockApps = ['terminal','files','browser','gallery','settings'];
  return <footer className="dock"><div className="dock-brand">STORMOS</div><div className="dock-icons">{dockApps.map(id=>{const app=installedApps.find(a=>a.id===id) || fallbackApps.find(a=>a.id===id); return <button key={id} className="dock-item" onClick={()=>onOpenApp(id)} title={app.name}><DynamicAppIcon app={app} size={25}/></button>})}</div><div className="dock-links"><span>Power</span><span>Performance</span><span>Freedom</span></div></footer>;
}

function App() {
  const [launcherOpen, setLauncherOpen] = useState(true);
  const [installedApps, setInstalledApps] = useState(fallbackApps);
  const [appCategory, setAppCategory] = useState('Favorites');
  const [powerOpen, setPowerOpen] = useState(false);
  const [windows, setWindows] = useState({ files: true, terminal: true, gallery: true, settings: false });
  const [minimized, setMinimized] = useState({});
  const [time, setTime] = useState(new Date());
  const [system, setSystem] = useState(null);
  useEffect(() => {
    let alive = true;
    const refreshApps = async () => {
      try {
        let appList = [];
        if (isElectron) {
          // Electron: use execCommand to discover .desktop files via Python bridge
          const raw = await window.electronAPI.execCommand('python3 /usr/local/share/stormos-desktop/native/stormos-bridge.py --apps-json 2>/dev/null || echo "[]"');
          try { appList = JSON.parse(raw); } catch { appList = []; }
        } else {
          const response = await fetch(`${BRIDGE_URL}/api/apps?ts=${Date.now()}`);
          if (!response.ok) throw new Error(`app discovery failed: ${response.status}`);
          const data = await response.json();
          if (Array.isArray(data.apps)) appList = data.apps;
        }
        if (alive && appList.length) {
          const discovered = appList.map(app => ({...app, description: app.description || app.category || 'Application', internal: false}));
          const internal = fallbackApps.filter(app => !discovered.some(x => x.id === app.id));
          setInstalledApps([...internal, ...discovered]);
        }
      } catch (_) {}
    };
    refreshApps();
    const appTimer = setInterval(refreshApps, 5000);
    return () => { alive = false; clearInterval(appTimer); };
  }, []);
  useEffect(()=>{
    let alive=true;
    const refreshSystem=async()=>{
      try {
        let d;
        if (isElectron) {
          d = await window.electronAPI.getSystemStats();
        } else {
          const r = await fetch(`${BRIDGE_URL}/api/system?ts=${Date.now()}`);
          d = await r.json();
        }
        if(alive){setSystem(d); if(d.timestamp) setTime(new Date(d.timestamp*1000));}
      } catch(_) { if(alive) setTime(new Date()); }
    };
    refreshSystem(); const t=setInterval(refreshSystem,1000); return()=>{alive=false;clearInterval(t)};
  },[]);
  const openApp = appOrId => {
    const requestedId = typeof appOrId === 'string' ? appOrId : appOrId?.id;
    const app = typeof appOrId === 'string'
      ? (installedApps.find(item => item.id === appOrId) || fallbackApps.find(item => item.id === appOrId))
      : appOrId;
    if (!app) return;
    const internalMap = { settings: 'settings', 'stormos-settings': 'settings', gallery: 'gallery' };
    const internal = internalMap[requestedId] || internalMap[app.id];
    if (internal) {
      setWindows(w => ({...w, [internal]: true}));
      setMinimized(m => ({...m, [internal]: false}));
    } else {
      launchNativeApp({ ...app, id: app.id });
    }
    setLauncherOpen(false);
  };
  const closeApp = id => setWindows(w=>({...w,[id]:false}));
  const minimizeApp = id => setMinimized(m=>({...m,[id]:true}));
  return <div className="desktop">
    <TopBar onLauncher={()=>setLauncherOpen(v=>!v)} onPower={()=>setPowerOpen(v=>!v)} onSettings={()=>openApp('settings')} system={system}/>
    <div className="wallpaper"><div className="lightning l1"/><div className="lightning l2"/><div className="mountains"/><div className="center-wordmark">STORM<span>O</span>S<small>POWER　•　PERFORMANCE　•　FREEDOM</small></div></div>
    <Launcher open={launcherOpen} onClose={()=>setLauncherOpen(false)} onOpenApp={openApp} installedApps={installedApps} category={appCategory} onCategory={setAppCategory}/>
    <Dock onOpenApp={openApp} installedApps={installedApps}/>
    {windows.files && !minimized.files && <FilesWindow close={()=>closeApp('files')} minimize={()=>minimizeApp('files')}/>}
    {windows.terminal && !minimized.terminal && <TerminalWindow close={()=>closeApp('terminal')} minimize={()=>minimizeApp('terminal')}/>}
    {windows.gallery && !minimized.gallery && <GalleryWindow close={()=>closeApp('gallery')} minimize={()=>minimizeApp('gallery')}/>}
    {windows.settings && !minimized.settings && <SettingsWindow close={()=>closeApp('settings')} minimize={()=>minimizeApp('settings')}/>}
    <SystemPanel system={system} onOpenSettings={()=>openApp('settings')}/>
    {powerOpen && <div className="power-menu panel-glass"><strong>Session</strong>
      <button onClick={async () => { const ok = await launchNativeApp('lock'); if (!ok) window.alert('StormOS could not lock the session. Check ~/.stormos-bridge.log'); }}><LockIcon/> Lock Screen</button>
      <button onClick={async () => { const ok = await launchNativeApp('logout'); if (!ok) window.alert('StormOS could not log out. Check ~/.stormos-bridge.log'); }}><LogOut size={16}/> Log Out</button>
      <button onClick={async () => { const ok = await launchNativeApp('restart'); if (!ok) window.alert('StormOS could not restart. Check ~/.stormos-bridge.log'); }}><RefreshCw size={16}/> Restart</button>
      <button onClick={async () => { const ok = await launchNativeApp('shutdown'); if (!ok) window.alert('StormOS could not shut down. Check ~/.stormos-bridge.log'); }}><CirclePower size={16}/> Shut Down</button>
      <button onClick={async () => { const ok = await launchNativeApp('suspend'); if (!ok) window.alert('StormOS could not suspend. Check ~/.stormos-bridge.log'); }}><Power size={16}/> Suspend</button>
      <button onClick={async () => { const ok = await launchNativeApp('hibernate'); if (!ok) window.alert('StormOS could not hibernate. Check ~/.stormos-bridge.log'); }}><Power size={16}/> Hibernate</button>
    </div>}
    <div className="clock-overlay">{system?.localTime || time.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</div>
  </div>;
}
function LockIcon(){return <Shield size={16}/>}

createRoot(document.getElementById('root')).render(<App/>);
