#!/usr/bin/env python3
import json, os, re, shlex, shutil, socket, subprocess, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
HOST = "127.0.0.1"
PORT = int(os.environ.get("STORMOS_BRIDGE_PORT", "47821"))
START = time.time()
def read_text(path, default=""):
    try: return Path(path).read_text(errors="replace").strip()
    except Exception: return default
def command(*args):
    try: return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception: return ""
def memory_info():
    values={}
    for line in read_text('/proc/meminfo').splitlines():
        p=line.split()
        if len(p)>=2: values[p[0].rstrip(':')]=int(p[1])*1024
    total=values.get('MemTotal',0); avail=values.get('MemAvailable',values.get('MemFree',0)); used=max(total-avail,0)
    return {'used':used,'total':total,'percent':round(used/total*100) if total else 0}
def storage_info():
    try:
        st=os.statvfs('/'); total=st.f_blocks*st.f_frsize; free=st.f_bavail*st.f_frsize; used=total-free
        return {'used':used,'total':total,'percent':round(used/total*100) if total else 0}
    except Exception: return {'used':0,'total':0,'percent':0}
def gpu_info():
    out=command('sh','-lc',"lspci 2>/dev/null | grep -Ei 'vga|3d|display' | sed -E 's/^[^:]+: //' | head -n 3")
    return [x for x in out.splitlines() if x] or ['GPU information unavailable']
def system_data():
    osrel=read_text('/etc/os-release')
    pretty=next((x.split('=',1)[1].strip('"') for x in osrel.splitlines() if x.startswith('PRETTY_NAME=')),'StormOS')
    host=socket.gethostname()
    tz=command('timedatectl','show','--property=Timezone','--value') or read_text('/etc/timezone','') or 'UTC'
    ntp=command('timedatectl','show','--property=NTPSynchronized','--value').lower() == 'yes'
    local_time=command('date','+%I:%M %p') or ''
    local_date=command('date','+%a, %b %-d') or ''
    cpu_percent=0
    try:
        def cpu_sample():
            fields=read_text('/proc/stat').splitlines()[0].split()
            nums=list(map(int,fields[1:]))
            return sum(nums), nums[3]
        t1,i1=cpu_sample(); time.sleep(0.05); t2,i2=cpu_sample()
        cpu_percent=round(max(0,100*(1-(i2-i1)/max(1,t2-t1))))
    except Exception: pass
    return {
        'os':pretty,'hostname':host,'kernel':command('uname','-r') or 'unknown',
        'uptime':int(float(read_text('/proc/uptime','0').split()[0] or 0)),
        'packages':int(command('sh','-lc','pacman -Q 2>/dev/null | wc -l') or 0),
        'cpu':command('sh','-lc',"sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -n 1") or 'CPU information unavailable',
        'cpuPercent':cpu_percent,'gpus':gpu_info(),'memory':memory_info(),'storage':storage_info(),
        'network':{'hostname':host,'connected':command('sh','-lc',"nmcli -t -f STATE general 2>/dev/null | grep -q connected; echo $?")=='0'},
        'bluetooth':shutil.which('bluetoothctl') is not None,
        'timezone':tz,'ntpSynchronized':ntp,'localTime':local_time,'localDate':local_date,
        'timestamp':int(time.time())
    }

def val(text,key):
    m=re.search(rf'^{re.escape(key)}=(.*)$',text,re.M); return m.group(1).strip() if m else ''
def discover_desktop_apps():
    dirs=[Path.home()/'.local/share/applications',Path('/usr/local/share/applications'),Path('/usr/share/applications')]; out=[]; seen=set()
    maps=[('Graphics','Graphics'),('AudioVideo','Multimedia'),('Audio','Multimedia'),('Video','Multimedia'),('Network','Internet'),('WebBrowser','Internet'),('Office','Office'),('Settings','Settings'),('System','System'),('Utility','Accessories'),('Accessories','Accessories'),('Development','Development'),('Game','Games')]
    for d in dirs:
        if not d.is_dir(): continue
        for f in sorted(d.glob('*.desktop')):
            try: text=f.read_text(errors='replace')
            except OSError: continue
            if '[Desktop Entry]' not in text or val(text,'NoDisplay').lower()=='true' or val(text,'Hidden').lower()=='true': continue
            name=val(text,'Name'); exe=re.sub(r'%[fFuUdDnNickvm]','',val(text,'Exec')).strip(); ident=f.stem
            if not name or not exe or ident in seen: continue
            if val(text,'Terminal').lower() == 'true' and not exe: continue
            seen.add(ident); cat='Other'; cats=val(text,'Categories').split(';')
            for token,label in maps:
                if token in cats: cat=label; break
            out.append({'id':ident,'name':name,'description':cat,'category':cat,'icon':val(text,'Icon') or 'app-window','exec':exe,'desktopFile':str(f)})
    return out
def display_data():
    raw=command('wlr-randr')
    outputs=[]; current=None
    for line in raw.splitlines():
        if line and not line.startswith((' ', '\t')) and ' ' in line:
            name=line.split()[0]
            current={'name':name,'description':' '.join(line.split()[1:]),'modes':[]}
            outputs.append(current)
        elif current and line.strip() and ('Hz' in line or 'x' in line):
            mode=line.strip().split()[0]
            if mode not in current['modes']: current['modes'].append(mode)
    return {'ok':True,'outputs':outputs,'raw':raw}
def apply_display_mode(mode):
    data=display_data(); names=[x['name'] for x in data['outputs']]
    if not names: raise RuntimeError('No displays detected or wlr-randr is unavailable')
    if mode=='mirror' and len(names)>1:
        args=['wlr-randr']
        for name in names: args += ['--output',name,'--pos','0,0']
    elif mode=='single':
        args=['wlr-randr','--output',names[0],'--pos','0,0']
        for name in names[1:]: args += ['--output',name,'--off']
    else:
        args=['wlr-randr']
        x=0
        for name in names:
            args += ['--output',name,'--pos',str(x)+',0']; x += 1920
    run_checked(args)
    return {'ok':True,'mode':mode,'message':f'{mode.capitalize()} display layout applied.'}

def current_session_id():
    sid = os.environ.get('XDG_SESSION_ID', '').strip()
    if sid:
        return sid
    uid = str(os.getuid())
    try:
        output = subprocess.check_output(
            ['loginctl', 'list-sessions', '--no-legend', '--no-pager'],
            text=True, stderr=subprocess.DEVNULL
        )
        candidates=[]
        for line in output.splitlines():
            fields=line.split()
            if len(fields) >= 2 and fields[1] == uid:
                candidates.append(fields[0])
        if candidates:
            return candidates[-1]
    except Exception:
        pass
    return ''

def run_checked(argv, timeout=12):
    result=subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          start_new_session=True, env=os.environ.copy())
    if result.returncode != 0:
        detail=(result.stderr or result.stdout or f'exit status {result.returncode}').strip()
        raise RuntimeError(f"{' '.join(argv)}: {detail}")
    return result

def run_session_action(action):
    sid=current_session_id()
    uid=str(os.getuid())
    if action == 'lock':
        attempts=[]
        if sid: attempts.append(['loginctl','lock-session',sid])
        attempts.append(['loginctl','lock-sessions'])
    elif action == 'logout':
        # This is the user-session-safe route and does not require root/polkit.
        attempts=[]
        if sid: attempts.append(['loginctl','terminate-session',sid])
        attempts.extend([
            ['systemctl','--user','exit'],
            ['loginctl','terminate-user',uid],
        ])
    elif action == 'suspend':
        attempts=[['loginctl','suspend'],['systemctl','suspend']]
    elif action == 'hibernate':
        attempts=[['loginctl','hibernate'],['systemctl','hibernate']]
    elif action == 'restart':
        attempts=[
            ['loginctl','reboot'],
            ['pkexec','/usr/bin/systemctl','reboot'],
            ['/usr/bin/systemctl','reboot'],
        ]
    elif action == 'shutdown':
        attempts=[
            ['loginctl','poweroff'],
            ['pkexec','/usr/bin/systemctl','poweroff'],
            ['/usr/bin/systemctl','poweroff'],
        ]
    else:
        raise ValueError('unknown session action')

    errors=[]
    for argv in attempts:
        if not shutil.which(argv[0]) and not os.path.isabs(argv[0]):
            continue
        try:
            run_checked(argv)
            return {'ok':True,'action':action,'command':argv}
        except Exception as exc:
            errors.append(str(exc))
    raise RuntimeError(' | '.join(errors) or 'no usable session-action command found')

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def send_json(self,obj,status=200):
        body=json.dumps(obj).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Access-Control-Allow-Origin','*'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_OPTIONS(self):
        self.send_response(204); self.send_header('Access-Control-Allow-Origin','*'); self.send_header('Access-Control-Allow-Methods','GET,POST,OPTIONS'); self.send_header('Access-Control-Allow-Headers','Content-Type'); self.end_headers()
    def do_GET(self):
        if self.path.startswith('/api/apps'): self.send_json({'apps':discover_desktop_apps()})
        elif self.path=='/api/system': self.send_json(system_data())
        elif self.path=='/api/health': self.send_json({'ok':True,'service':'stormos-bridge'})
        elif self.path=='/api/displays': self.send_json(display_data())
        else: self.send_json({'error':'not found'},404)
    def do_POST(self):
        if self.path == '/api/displays/apply':
            try:
                payload=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))) or b'{}')
                mode=payload.get('mode','extend')
                result=apply_display_mode(mode)
                self.send_json(result)
            except Exception as e: self.send_json({'ok':False,'error':str(e)},500)
            return
        if self.path!='/api/launch': self.send_json({'error':'not found'},404); return
        try:
            payload=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))) or b'{}'); app=payload.get('app',''); launch_id=str(payload.get('launchId',''))
            commands={
                'terminal':['foot'],
                'files':['thunar'],
                'browser':['firefox'],
                'gallery':['stormos-gallery'],
                'settings':['stormos-settings'],
                'thunar':['thunar'],
                'blueman-manager':['blueman-manager'],
                'nm-connection-editor':['nm-connection-editor'],
                'pavucontrol':['pavucontrol'],
                'software':['pamac-manager'],
                'office':['libreoffice'],
                'steam':['steam'],
                'lock':None,
                'logout':None,
                'restart':None,
                'shutdown':None,
                'suspend':None,
                'hibernate':None
            }
            if app in ('lock','logout','restart','shutdown','suspend','hibernate'):
                run_session_action(app)
                self.send_json({'ok':True,'app':app})
                return
            found = {x['id']: x for x in discover_desktop_apps()}.get(app)
            if found:
                cmd = shlex.split(found['exec'], posix=True)
                cmd = [x for x in cmd if x not in ('%f','%F','%u','%U','%d','%D','%n','%N','%i','%c','%k','%v','%m')]
                if not cmd:
                    self.send_json({'ok':False,'error':'desktop entry has no executable'},400); return
            else:
                cmd = commands.get(app)
            if not cmd:
                self.send_json({'ok':False,'error':'application unavailable'},404); return
            executable = cmd[0]
            if not shutil.which(executable):
                self.send_json({'ok':False,'error':f' executable not found: {executable}'},404); return
            # Always create a new process for each activation. No application-level
            # singleton/deduplication is performed here; the compositor manages
            # the resulting windows normally.
            child_env=os.environ.copy()
            child_env['STORMOS_LAUNCH_ID']=launch_id or str(time.time_ns())
            subprocess.Popen(cmd, start_new_session=True, env=child_env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             close_fds=True)
            self.send_json({'ok':True,'app':app,'command':cmd})
        except Exception as e: self.send_json({'ok':False,'error':str(e)},500)
if __name__=='__main__':
    ThreadingHTTPServer.allow_reuse_address = True
    ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
