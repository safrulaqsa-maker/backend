#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Safruz Deployer Pro - Backend Server (Final)
- Registrasi + Login untuk semua user
- Login Google
- Deploy asli ke Vercel
- Thread‑safe in‑memory cache + persistent JSON storage
"""
import json, time, hashlib, hmac, base64, os, datetime, random, string
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from functools import wraps
import threading

# ---------- Config ----------
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 5000))
SECRET_KEY = b'safruz-secret-key-2024'
TOKEN_EXPIRY = 24 * 3600
OWNER_EMAIL = os.environ.get('OWNER_EMAIL', 'safrulaqsa@gmail.com')
OWNER_PASSWORD = os.environ.get('OWNER_PASSWORD', 'safrul1')

# ---------- Data ----------
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(DATA_DIR, exist_ok=True)

_users = {}
_logs = []
_chats = {}
_pending = {}
_lock = threading.Lock()

def _load_json(fname):
    path = os.path.join(DATA_DIR, fname)
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}

def _save_json(fname, data):
    path = os.path.join(DATA_DIR, fname)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

# Load data awal
with _lock:
    _users = _load_json('users.json')
    _logs = _load_json('logs.json')
    _chats = _load_json('chats.json')
    _pending = _load_json('pending_verifications.json')

# ---------- Helpers ----------
def _hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()
def _make_token(user):
    ts = str(int(time.time()))
    msg = f"{user}:{ts}".encode()
    sig = hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()
    return base64.b64encode(f"{user}:{ts}:{sig}".encode()).decode()

def _check_token(token):
    try:
        user, ts, sig = base64.b64decode(token).decode().split(':')
        if int(ts) + TOKEN_EXPIRY < time.time(): return None
        expected = hmac.new(SECRET_KEY, f"{user}:{ts}".encode(), hashlib.sha256).hexdigest()
        return user if sig == expected else None
    except: return None

def _get_token(req):
    auth = req.headers.get('Authorization', '')
    return auth[7:] if auth.startswith('Bearer ') else None

def _ok(handler, data, code=200):
    try:
        handler.send_response(code)
        handler.send_header('Content-Type', 'application/json')
        handler.send_header('Access-Control-Allow-Origin', '*')
        handler.send_header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
        handler.send_header('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        handler.end_headers()
        handler.wfile.write(json.dumps(data).encode())
    except: pass

def _body(handler):
    try:
        n = int(handler.headers.get('Content-Length', 0))
        return json.loads(handler.rfile.read(n)) if n else {}
    except: return {}

def _bg_save():
    while True:
        time.sleep(30)
        with _lock:
            _save_json('users.json', dict(_users))
            _save_json('logs.json', list(_logs))
            _save_json('chats.json', dict(_chats))

def _bg_deploy_status(deploy_id, token):
    import requests
    for _ in range(30):
        time.sleep(2)
        try:
            resp = requests.get(f'https://api.vercel.com/v13/deployments/{deploy_id}',
                                headers={'Authorization': f'Bearer {token}'})
            if resp.ok:
                data = resp.json()
                if data.get('readyState') in ('READY', 'ERROR'):
                    with _lock:
                        for log in _logs:
                            if log.get('deploy_id') == deploy_id:
                                log['status'] = 'success' if data['readyState'] == 'READY' else 'failed'
                                log['url'] = f'https://{data.get("url","")}' if data.get('url') else log['url']
                                break
                    _save_json('logs.json', _logs)
                    return
        except: continue

# ---------- Handler ----------
class H(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        self.end_headers()

    def do_GET(self): self.go('GET')
    def do_POST(self): self.go('POST')
    def do_PUT(self): self.go('PUT')
    def do_DELETE(self): self.go('DELETE')

    def go(self, method):
        p = urlparse(self.path).path.rstrip('/')
        if p in ('', '/'): _ok(self, {'status':'online'})
        elif p == '/favicon.ico': self.send_response(204); self.end_headers()
        # Auth
        elif p == '/api/auth/register' and method == 'POST': self.register()
        elif p == '/api/auth/login' and method == 'POST': self.login()
        elif p == '/api/auth/google' and method == 'POST': self.google_login()
        elif p == '/api/auth/verify-email' and method == 'POST': self.verify_email()
        elif p == '/api/auth/forgot-password' and method == 'POST': self.forgot()
        elif p == '/api/auth/reset-password' and method == 'POST': self.reset()
        # User
        elif p == '/api/user/me' and method == 'GET': self.auth(self.profile)()
        elif p == '/api/user/change-password' and method == 'POST': self.auth(self.chpass)()
        # Deploy
        elif p == '/api/deploy' and method == 'POST': self.auth(self.deploy)()
        elif p == '/api/deploy/logs' and method == 'GET': self.auth(self.logs)()
        # Chat
        elif p.startswith('/api/chat/messages/') and method == 'GET': self.auth(self.chat_get)()
        elif p == '/api/chat/send' and method == 'POST': self.auth(self.chat_send)()
        # Owner
        elif p == '/api/owner/users' and method == 'GET': self.owner(self.owner_users)()
        elif p.startswith('/api/owner/user/') and method == 'PUT': self.owner(self.owner_update)()
        elif p.endswith('/ban') and method == 'POST': self.owner(self.owner_ban)()
        elif p.endswith('/unban') and method == 'POST': self.owner(self.owner_unban)()
        elif p == '/api/owner/create-user' and method == 'POST': self.owner(self.owner_create)()
        elif p == '/api/owner/broadcast' and method == 'POST': self.owner(self.owner_broadcast)()
        elif p == '/api/owner/delete-project' and method == 'DELETE': self.owner(self.owner_del)()
        elif p == '/api/owner/export-users' and method == 'GET': self.owner(self.export_users)()
        elif p == '/api/owner/import-users' and method == 'POST': self.owner(self.import_users)()
        else: _ok(self, {'error':'Not found'}, 404)

    def auth(self, fn):
        @wraps(fn)
        def wrapper():
            token = _get_token(self)
            user = _check_token(token)
            if not user: return _ok(self, {'error':'Unauthorized'}, 401)
            self.current_user = user
            return fn()
        return wrapper

    def owner(self, fn):
        @wraps(fn)
        def wrapper():
            token = _get_token(self)
            user = _check_token(token)
            if not user or user != OWNER_EMAIL: return _ok(self, {'error':'Owner only'}, 403)
            self.current_user = user
            return fn()
        return wrapper

    # ---------- Auth ----------
    def register(self):
        d = _body(self)
        email = d.get('email','').strip().lower()
        password = d.get('password','')
        name = d.get('name','')
        question = d.get('security_question','')
        answer = d.get('security_answer','')
        if not all([email, password, name, question, answer]):
            return _ok(self, {'error':'Semua field wajib diisi'}, 400)
        with _lock:
            if email in _users:
                return _ok(self, {'error':'Email sudah terdaftar'}, 400)
            code = ''.join(random.choices(string.digits, k=6))
            _pending[email] = {
                'password_hash': _hash_pw(password),
                'name': name,
                'security_question': question,
                'security_answer_hash': _hash_pw(answer),
                'code': code,
                'expires': time.time() + 600
            }
            _save_json('pending_verifications.json', dict(_pending))
        # Untuk demo, tampilkan kode di response
        return _ok(self, {'message':'Pendaftaran berhasil. Kode verifikasi: '+code, 'verification_code': code}, 201)

    def verify_email(self):
        d = _body(self)
        email = d.get('email','').strip().lower()
        code = d.get('code','')
        with _lock:
            p = _pending.get(email)
            if not p: return _ok(self, {'error':'Email tidak ditemukan'}, 400)
            if p['code'] != code: return _ok(self, {'error':'Kode salah'}, 400)
            if time.time() > p['expires']:
                del _pending[email]; _save_json('pending_verifications.json', dict(_pending))
                return _ok(self, {'error':'Kode kadaluarsa'}, 400)
            _users[email] = {
                'password_hash': p['password_hash'],
                'name': p['name'],
                'security_question': p['security_question'],
                'security_answer_hash': p['security_answer_hash'],
                'role': 'user',
                'trial_start': time.time(),
                'total_deploy': 0,
                'daily_deploy': 0,
                'daily_date': '',
                'banned': False,
                'ban_reason': '',
                'custom_limit': None,
                'messages': []
            }
            del _pending[email]
            _save_json('users.json', dict(_users))
            _save_json('pending_verifications.json', dict(_pending))
        return _ok(self, {'message':'Email terverifikasi, silakan login'})

    def login(self):
        d = _body(self)
        email = d.get('email','').strip().lower()
        password = d.get('password','')
        if email == OWNER_EMAIL and password == OWNER_PASSWORD:
            return _ok(self, {'access_token':_make_token(email), 'role':'owner', 'name':'Owner'})
        with _lock:
            user = _users.get(email)
        if not user:
            return _ok(self, {'error':'Email tidak ditemukan'}, 404)
        if user['password_hash'] != _hash_pw(password):
            return _ok(self, {'error':'Password salah'}, 401)
        if user.get('banned'):
            return _ok(self, {'error':'Akun dibanned'}, 403)
        token = _make_token(email)
        return _ok(self, {'access_token':token, 'role':user['role'], 'name':user.get('name','')})

    def google_login(self):
        d = _body(self)
        credential = d.get('credential','')
        if not credential: return _ok(self, {'error':'Token tidak ada'}, 400)
        try:
            import requests
            resp = requests.get(f'https://oauth2.googleapis.com/tokeninfo?id_token={credential}')
            if not resp.ok: return _ok(self, {'error':'Token Google tidak valid'}, 401)
            info = resp.json()
            email = info.get('email','').strip().lower()
            name = info.get('name','')
            if not email: return _ok(self, {'error':'Email tidak ditemukan'}, 401)
        except Exception as e: return _ok(self, {'error':str(e)}, 500)

        with _lock:
            if email not in _users:
                _users[email] = {
                    'password_hash':'', 'name':name, 'security_question':'', 'security_answer_hash':'',
                    'role':'user', 'trial_start':time.time(), 'total_deploy':0, 'daily_deploy':0,
                    'daily_date':'', 'banned':False, 'ban_reason':'', 'custom_limit':None, 'messages':[]
                }
                _save_json('users.json', dict(_users))
            elif not _users[email].get('name'):
                _users[email]['name'] = name
                _save_json('users.json', dict(_users))
            if _users[email]['banned']: return _ok(self, {'error':'Akun dibanned'}, 403)
            token = _make_token(email)
            return _ok(self, {'access_token':token, 'role':_users[email]['role'], 'name':_users[email].get('name',''), 'email':email})

    def forgot(self):
        d = _body(self)
        email = d.get('email','').strip().lower()
        with _lock:
            user = _users.get(email)
        if not user: return _ok(self, {'error':'Email tidak ditemukan'}, 404)
        return _ok(self, {'security_question':user['security_question']})

    def reset(self):
        d = _body(self)
        email = d.get('email','').strip().lower()
        answer = d.get('security_answer','')
        new_pw = d.get('new_password','')
        with _lock:
            user = _users.get(email)
        if not user: return _ok(self, {'error':'Email tidak ditemukan'}, 404)
        if user['security_answer_hash'] != _hash_pw(answer):
            return _ok(self, {'error':'Jawaban salah'}, 401)
        user['password_hash'] = _hash_pw(new_pw)
        _save_json('users.json', dict(_users))
        return _ok(self, {'message':'Password direset, silakan login'})

    def profile(self):
        with _lock:
            u = _users.get(self.current_user)
        if not u: return _ok(self, {'error':'User not found'}, 404)
        trial = (u['role']=='user' and time.time()-u['trial_start'] < 12*86400)
        limit = float('inf') if self.current_user == OWNER_EMAIL else (u['custom_limit'] or (300 if u['role']=='premium' else 10))
        if trial: limit = 300
        return _ok(self, {
            'username':self.current_user, 'role':'premium' if trial else u['role'],
            'total_deploy':u['total_deploy'], 'daily_deploy':u['daily_deploy'],
            'custom_limit':u['custom_limit'], 'limit':limit
        })

    def chpass(self):
        d = _body(self)
        old, new = d.get('old_password'), d.get('new_password')
        with _lock:
            u = _users.get(self.current_user)
            if not u or u['password_hash'] != _hash_pw(old):
                return _ok(self, {'error':'Password lama salah'}, 400)
            u['password_hash'] = _hash_pw(new)
            _save_json('users.json', dict(_users))
        return _ok(self, {'message':'Password diubah'})

    # ---------- Deploy ----------
    def deploy(self):
        d = _body(self)
        project_name = d.get('project_name','safrul-deploy')
        html_code = d.get('html_code','')
        files = d.get('files',[])
        with _lock:
            u = _users.get(self.current_user)
            if not u or u.get('banned'): return _ok(self, {'error':'Akun dibanned'}, 403)
            today = datetime.date.today().isoformat()
            if u['daily_date'] != today:
                u['daily_deploy'] = 0; u['daily_date'] = today
            limit = float('inf') if self.current_user == OWNER_EMAIL else (u['custom_limit'] or (300 if u['role']=='premium' else 10))
            if u['role']=='user' and time.time()-u['trial_start'] < 12*86400: limit = 300
            if u['daily_deploy'] >= limit: return _ok(self, {'error':'Limit harian habis'}, 429)

        vercel_token = os.environ.get('VERCEL_TOKEN')
        if not vercel_token:
            return _ok(self, {'error':'Token Vercel belum dikonfigurasi'}, 500)

        try:
            import requests
            resp = requests.post('https://api.vercel.com/v9/projects',
                                 headers={'Authorization':f'Bearer {vercel_token}'},
                                 json={'name':project_name, 'framework':'static'})
            if not resp.ok:
                err = resp.json().get('error',{}).get('message','Gagal buat project')
                return _ok(self, {'error':err}, 400)
            proj = resp.json()
            project_id = proj['id']

            deploy_files = files if files else [
                {'file':'index.html','data':base64.b64encode(html_code.encode()).decode(),'encoding':'base64'}
            ]
            deploy_resp = requests.post('https://api.vercel.com/v13/deployments',
                                        headers={'Authorization':f'Bearer {vercel_token}'},
                                        json={'name':project_name,'project':project_id,'target':'production','files':deploy_files})
            if not deploy_resp.ok:
                err = deploy_resp.json().get('error',{}).get('message','Gagal deploy')
                return _ok(self, {'error':err}, 400)

            deploy_data = deploy_resp.json()
            deploy_id = deploy_data['id']
            url = deploy_data.get('url','')

            with _lock:
                _logs.append({
                    'user':self.current_user,
                    'time':datetime.datetime.now().isoformat(),
                    'project_name':project_name,
                    'project_id':project_id,
                    'deploy_id':deploy_id,
                    'url':f'https://{url}' if url else '',
                    'status':'pending',
                    'mode':'vercel'
                })
                u['daily_deploy'] += 1
                u['total_deploy'] += 1

            t = threading.Thread(target=_bg_deploy_status, args=(deploy_id, vercel_token))
            t.daemon = True; t.start()

            return _ok(self, {
                'url':f'https://{url}' if url else 'https://vercel.com',
                'project_id':project_id,
                'deploy_id':deploy_id,
                'status':'building',
                'mode':'vercel',
                'message':'Deployment sedang dibangun'
            })

        except Exception as e:
            with _lock:
                _logs.append({
                    'user':self.current_user,
                    'time':datetime.datetime.now().isoformat(),
                    'project_name':project_name,
                    'project_id':'',
                    'url':'',
                    'status':'failed',
                    'error':str(e)
                })
            return _ok(self, {'error':str(e)}, 500)

    def logs(self):
        with _lock:
            user_logs = [l for l in _logs if l['user']==self.current_user][-50:]
        return _ok(self, user_logs)

    # ---------- Chat ----------
    def chat_get(self):
        chat_id = self.path.split('/')[-1]
        with _lock:
            msgs = _chats.get(chat_id, [])
        return _ok(self, msgs)

    def chat_send(self):
        d = _body(self)
        to, txt = d.get('to'), d.get('text')
        if not to or not txt: return _ok(self, {'error':'Pesan kosong'}, 400)
        cid = '_'.join(sorted([self.current_user, to]))
        now = datetime.datetime.now()
        msg = {'sender':self.current_user,'text':txt,'time':now.strftime('%H:%M'),'date':now.strftime('%Y-%m-%d')}
        with _lock:
            _chats.setdefault(cid, []).append(msg)
        return _ok(self, {'message':'Terkirim'}, 201)

    # ---------- Owner ----------
    def owner_users(self):
        with _lock:
            users = dict(_users)
        today = datetime.date.today().isoformat()
        return _ok(self, [{
            'username':n,'role':u['role'],
            'limit':u['custom_limit'] or (300 if u['role']=='premium' else 10),
            'daily_deploy':u['daily_deploy'] if u['daily_date']==today else 0,
            'banned':u['banned']
        } for n,u in users.items() if n!=OWNER_EMAIL])

    def owner_update(self):
        name = self.path.split('/')[-1]
        d = _body(self)
        with _lock:
            if name not in _users: return _ok(self, {'error':'User not found'}, 404)
            if 'role' in d: _users[name]['role'] = d['role']
            if 'limit' in d: _users[name]['custom_limit'] = d['limit']
        return _ok(self, {'message':'Updated'})

    def owner_ban(self):
        name = self.path.split('/')[-2]
        reason = _body(self).get('reason','')
        with _lock:
            if name in _users:
                _users[name]['banned'] = True
                _users[name]['ban_reason'] = reason
        return _ok(self, {'message':'Banned'})

    def owner_unban(self):
        name = self.path.split('/')[-2]
        with _lock:
            if name in _users:
                _users[name]['banned'] = False
                _users[name]['ban_reason'] = ''
        return _ok(self, {'message':'Unbanned'})

    def owner_create(self):
        d = _body(self)
        email,pw,name = d.get('email'), d.get('password'), d.get('name')
        if not email or not pw: return _ok(self, {'error':'Data tidak lengkap'}, 400)
        with _lock:
            if email in _users: return _ok(self, {'error':'Email sudah ada'}, 400)
            _users[email] = {
                'password_hash':_hash_pw(pw), 'name':name, 'security_question':'', 'security_answer_hash':'',
                'role':'user', 'trial_start':time.time(), 'total_deploy':0, 'daily_deploy':0, 'daily_date':'',
                'banned':False, 'ban_reason':'', 'custom_limit':None, 'messages':[]
            }
            _save_json('users.json', dict(_users))
        return _ok(self, {'message':'User dibuat'}, 201)

    def owner_broadcast(self):
        msg = _body(self).get('message','')
        if not msg: return _ok(self, {'error':'Pesan kosong'}, 400)
        with _lock:
            for n,u in _users.items():
                if n != OWNER_EMAIL:
                    u.setdefault('messages',[]).append(msg)
        return _ok(self, {'message':'Broadcast terkirim'})

    def owner_del(self):
        pid = _body(self).get('project_id','')
        token = os.environ.get('VERCEL_TOKEN')
        if token:
            try:
                import requests
                requests.delete(f'https://api.vercel.com/v9/projects/{pid}',
                                headers={'Authorization':f'Bearer {token}'})
            except: pass
        return _ok(self, {'message':f'Project {pid} dihapus'})

    def export_users(self):
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Disposition','attachment; filename=users.json')
        self.send_header('Access-Control-Allow-Origin','*')
        self.end_headers()
        with _lock:
            self.wfile.write(json.dumps(dict(_users), indent=2).encode())

    def import_users(self):
        try:
            imported = json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))))
            with _lock:
                for n,d in imported.items():
                    if n not in _users: _users[n] = d
                    else:
                        for k in ['password_hash','security_question','security_answer_hash','role','trial_start','total_deploy','custom_limit']:
                            if k in d: _users[n][k] = d[k]
                _save_json('users.json', dict(_users))
            return _ok(self, {'message':'Import berhasil'})
        except: return _ok(self, {'error':'Format tidak valid'}, 400)

# ---------- Threaded Server ----------
class ThreadedHTTPServer(threading.Thread, HTTPServer):
    def __init__(self, *args, **kwargs):
        HTTPServer.__init__(self, *args, **kwargs)
        threading.Thread.__init__(self)

    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
            self.shutdown_request(request)
        except:
            self.handle_error(request, client_address)
            self.shutdown_request(request)

    def process_request(self, request, client_address):
        t = threading.Thread(target=self.process_request_thread, args=(request, client_address))
        t.daemon = True
        t.start()

if __name__ == '__main__':
    threading.Thread(target=_bg_save, daemon=True).start()
    server = ThreadedHTTPServer((HOST, PORT), H)
    print(f'🚀 Backend berjalan di port {PORT}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()