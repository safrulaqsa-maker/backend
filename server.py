#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Safruz Deployer Pro - Backend Server
Siap deploy ke Railway / Render.
"""
import json, time, hashlib, hmac, base64, os, datetime, random, string
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# ----- CONFIG -----
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 5000))
SECRET_KEY = b'rahasia-jwt-key'
TOKEN_EXPIRY = 24 * 3600  # 1 hari

# ----- DATA -----
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

def load_json(fname):
    path = os.path.join(DATA_DIR, fname)
    return json.load(open(path, 'r')) if os.path.exists(path) else {}

def save_json(fname, data):
    path = os.path.join(DATA_DIR, fname)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def load_vercel_config():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vercel_config.json')
    return json.load(open(path, 'r')) if os.path.exists(path) else {}

# ----- AUTH -----
def hash_password(pw):
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()

def create_token(username):
    ts = str(int(time.time()))
    msg = f"{username}:{ts}".encode('utf-8')
    sig = hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()
    return base64.b64encode(f"{username}:{ts}:{sig}".encode('utf-8')).decode('utf-8')

def verify_token(token):
    try:
        decoded = base64.b64decode(token).decode('utf-8')
        username, ts, sig = decoded.split(':')
        if int(ts) + TOKEN_EXPIRY < time.time():
            return None
        msg = f"{username}:{ts}".encode('utf-8')
        expected = hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()
        return username if sig == expected else None
    except:
        return None

def get_token(request):
    auth = request.headers.get('Authorization', '')
    return auth[7:] if auth.startswith('Bearer ') else None

# ----- RESPONSES -----
def json_resp(handler, data, status=200):
    try:
        handler.send_response(status)
        handler.send_header('Content-Type', 'application/json')
        handler.send_header('Access-Control-Allow-Origin', '*')
        handler.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        handler.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        handler.end_headers()
        handler.wfile.write(json.dumps(data).encode('utf-8'))
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass

def read_body(handler):
    try:
        length = int(handler.headers.get('Content-Length', 0))
        return json.loads(handler.rfile.read(length).decode('utf-8')) if length > 0 else {}
    except:
        return {}

# ----- HANDLER -----
class SafruzHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_GET(self): self.route('GET')
    def do_POST(self): self.route('POST')
    def do_PUT(self): self.route('PUT')
    def do_DELETE(self): self.route('DELETE')

    def route(self, method):
        path = urlparse(self.path).path.rstrip('/')
        if path in ('', '/'):
            self.send_response(200); self.send_header('Content-Type', 'text/plain'); self.end_headers()
            self.wfile.write(b'Safruz Backend Online')
            return
        if path == '/favicon.ico':
            self.send_response(204); self.end_headers(); return

        # Auth
        if path == '/api/auth/register' and method == 'POST': self.register()
        elif path == '/api/auth/login' and method == 'POST': self.login()
        # User
        elif path == '/api/user/me' and method == 'GET': self.auth(self.profile)()
        elif path == '/api/user/change-password' and method == 'POST': self.auth(self.change_pass)()
        # Deploy
        elif path == '/api/deploy' and method == 'POST': self.auth(self.deploy)()
        elif path == '/api/deploy/logs' and method == 'GET': self.auth(self.logs)()
        # Chat
        elif path.startswith('/api/chat/messages/') and method == 'GET': self.auth(self.chat_get)()
        elif path == '/api/chat/send' and method == 'POST': self.auth(self.chat_send)()
        # Owner
        elif path == '/api/owner/users' and method == 'GET': self.owner(self.owner_users)()
        elif path.startswith('/api/owner/user/') and method == 'PUT': self.owner(self.owner_update)()
        elif path.endswith('/ban') and method == 'POST': self.owner(self.owner_ban)()
        elif path.endswith('/unban') and method == 'POST': self.owner(self.owner_unban)()
        elif path == '/api/owner/create-user' and method == 'POST': self.owner(self.owner_create)()
        elif path == '/api/owner/broadcast' and method == 'POST': self.owner(self.owner_broadcast)()
        elif path == '/api/owner/delete-project' and method == 'DELETE': self.owner(self.owner_delete)()
        elif path == '/api/owner/export-users' and method == 'GET': self.owner(self.export_users)()
        elif path == '/api/owner/import-users' and method == 'POST': self.owner(self.import_users)()
        else: json_resp(self, {'error': 'Not found'}, 404)

    def auth(self, func):
        def wrap():
            token = get_token(self)
            username = verify_token(token)
            if not username: return json_resp(self, {'error': 'Unauthorized'}, 401)
            self.current_user = username
            return func()
        return wrap

    def owner(self, func):
        def wrap():
            token = get_token(self)
            username = verify_token(token)
            if not username or username != 'safrul': return json_resp(self, {'error': 'Owner only'}, 403)
            self.current_user = username
            return func()
        return wrap

    # ---- AUTH ----
    def register(self):
        data = read_body(self)
        u = data.get('username', '').strip().lower()
        p = data.get('password', '')
        q = data.get('security_question', '')
        a = data.get('security_answer', '')
        if not all([u, p, q, a]): return json_resp(self, {'error': 'Data tidak lengkap'}, 400)
        users = load_json('users.json')
        if u in users: return json_resp(self, {'error': 'Username sudah ada'}, 400)
        users[u] = {
            'password_hash': hash_password(p),
            'security_question': q,
            'security_answer_hash': hash_password(a),
            'role': 'user', 'trial_start': time.time(),
            'total_deploy': 0, 'daily_deploy': 0, 'daily_date': '',
            'banned': False, 'ban_reason': '', 'custom_limit': None, 'messages': []
        }
        save_json('users.json', users)
        json_resp(self, {'message': 'Registrasi berhasil'}, 201)

    def login(self):
        data = read_body(self)
        u = data.get('username', '').strip().lower()
        p = data.get('password', '')
        ans = data.get('security_answer', None)
        if u == 'safrul' and p == 'safrul1':
            return json_resp(self, {'access_token': create_token(u), 'role': 'owner'})
        users = load_json('users.json')
        user = users.get(u)
        if not user or user['password_hash'] != hash_password(p):
            return json_resp(self, {'error': 'Username/password salah'}, 401)
        if user['banned']:
            return json_resp(self, {'error': f'Akun dibanned: {user["ban_reason"] or "Tidak ada alasan"}'}, 403)
        if user.get('security_question') and not ans:
            return json_resp(self, {'requires_security': True, 'security_question': user['security_question']})
        if ans and user.get('security_answer_hash') != hash_password(ans):
            return json_resp(self, {'error': 'Jawaban keamanan salah'}, 401)
        return json_resp(self, {'access_token': create_token(u), 'role': user['role']})

    # ---- USER ----
    def profile(self):
        user = load_json('users.json').get(self.current_user)
        if not user: return json_resp(self, {'error': 'User tidak ditemukan'}, 404)
        trial = (user['role'] == 'user' and time.time() - user['trial_start'] < 12*24*3600)
        return json_resp(self, {
            'username': self.current_user,
            'role': 'premium' if trial else user['role'],
            'total_deploy': user['total_deploy'],
            'daily_deploy': user['daily_deploy'],
            'banned': user['banned'],
            'ban_reason': user['ban_reason'],
            'trial_start': user['trial_start'],
            'custom_limit': user['custom_limit']
        })

    def change_pass(self):
        data = read_body(self)
        old, new = data.get('old_password'), data.get('new_password')
        if not old or not new: return json_resp(self, {'error': 'Field tidak lengkap'}, 400)
        users = load_json('users.json')
        user = users.get(self.current_user)
        if not user or user['password_hash'] != hash_password(old):
            return json_resp(self, {'error': 'Password lama salah'}, 400)
        user['password_hash'] = hash_password(new)
        save_json('users.json', users)
        json_resp(self, {'message': 'Password diubah'})

    # ---- DEPLOY ----
    def deploy(self):
        data = read_body(self)
        project_name = data.get('project_name', 'safrul-deploy')
        html_code = data.get('html_code', '')
        framework = data.get('framework', '')
        files = data.get('files', [])

        users = load_json('users.json')
        user = users.get(self.current_user)
        if user['banned']: return json_resp(self, {'error': 'Akun dibanned'}, 403)

        today = datetime.date.today().isoformat()
        if user['daily_date'] != today:
            user['daily_deploy'] = 0
            user['daily_date'] = today

        limit = float('inf') if self.current_user == 'safrul' else (user['custom_limit'] or (300 if user['role'] == 'premium' else 10))
        if user['role'] == 'user' and time.time() - user['trial_start'] < 12*24*3600:
            limit = 300
        if user['daily_deploy'] >= limit:
            return json_resp(self, {'error': 'Limit harian habis'}, 429)

        config = load_vercel_config()
        token = config.get('vercel_token')
        if not token: return json_resp(self, {'error': 'Token Vercel tidak diatur'}, 500)

        try:
            import requests
            # Buat project
            body = {'name': project_name}
            if framework: body['framework'] = framework
            r = requests.post('https://api.vercel.com/v9/projects',
                              headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}, json=body)
            if not r.ok: raise Exception(r.json().get('error', {}).get('message', 'Gagal buat project'))
            proj_id = r.json()['id']

            # Deployment
            dep_body = {
                'name': project_name, 'project': proj_id, 'target': 'production',
                'files': files if files else [{'file': 'index.html', 'data': base64.b64encode(html_code.encode()).decode(), 'encoding': 'base64'}]
            }
            dr = requests.post('https://api.vercel.com/v13/deployments',
                               headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}, json=dep_body)
            if not dr.ok: raise Exception(dr.json().get('error', {}).get('message', 'Gagal deploy'))
            d = dr.json()
            did, url, status = d['id'], d.get('url', ''), d.get('readyState', '')
            # Polling
            for _ in range(30):
                if status in ('READY', 'ERROR'): break
                time.sleep(2)
                sr = requests.get(f'https://api.vercel.com/v13/deployments/{did}', headers={'Authorization': f'Bearer {token}'})
                if sr.ok:
                    sd = sr.json()
                    status = sd['readyState']; url = sd.get('url', url)
                    if sd.get('alias'): url = sd['alias'][0]
            final_url = f'https://{url}'
            # Log
            logs = load_json('logs.json')
            logs.append({'user': self.current_user, 'time': datetime.datetime.now().isoformat(), 'project_name': project_name,
                         'project_id': proj_id, 'url': final_url, 'status': 'success' if status == 'READY' else 'failed'})
            save_json('logs.json', logs)
            user['daily_deploy'] += 1
            user['total_deploy'] += 1
            save_json('users.json', users)
            json_resp(self, {'url': final_url, 'project_id': proj_id, 'status': status})
        except Exception as e:
            logs = load_json('logs.json')
            logs.append({'user': self.current_user, 'time': datetime.datetime.now().isoformat(), 'project_name': project_name,
                         'project_id': '', 'url': '', 'status': 'failed', 'error': str(e)})
            save_json('logs.json', logs)
            json_resp(self, {'error': str(e)}, 500)

    def logs(self):
        all_logs = load_json('logs.json')
        return json_resp(self, [l for l in all_logs if l['user'] == self.current_user][-50:])

    # ---- CHAT ----
    def chat_get(self):
        chat_id = self.path.split('/')[-1]
        return json_resp(self, load_json('chats.json').get(chat_id, []))

    def chat_send(self):
        data = read_body(self)
        to, text = data.get('to'), data.get('text')
        if not to or not text: return json_resp(self, {'error': 'Pesan kosong'}, 400)
        chat_id = '_'.join(sorted([self.current_user, to]))
        chats = load_json('chats.json')
        chats.setdefault(chat_id, []).append({
            'sender': self.current_user, 'text': text,
            'time': datetime.datetime.now().strftime('%H:%M'),
            'date': datetime.datetime.now().strftime('%Y-%m-%d'),
            'location': data.get('location')
        })
        save_json('chats.json', chats)
        json_resp(self, {'message': 'Terkirim'}, 201)

    # ---- OWNER ----
    def owner_users(self):
        users = load_json('users.json')
        today = datetime.date.today().isoformat()
        return json_resp(self, [{
            'username': n, 'role': u['role'],
            'limit': u['custom_limit'] or (300 if u['role'] == 'premium' else 10),
            'daily_deploy': u['daily_deploy'] if u['daily_date'] == today else 0,
            'banned': u['banned'], 'ban_reason': u['ban_reason']
        } for n, u in users.items() if n != 'safrul'])

    def owner_update(self):
        username = self.path.split('/')[-1]
        data = read_body(self)
        users = load_json('users.json')
        if username not in users: return json_resp(self, {'error': 'User tidak ditemukan'}, 404)
        for k in ('role', 'limit'):
            if k in data: users[username]['custom_limit' if k == 'limit' else 'role'] = data[k]
        save_json('users.json', users)
        json_resp(self, {'message': 'Updated'})

    def owner_ban(self):
        username = self.path.split('/')[-2]
        reason = read_body(self).get('reason', '')
        users = load_json('users.json')
        if username in users:
            users[username]['banned'] = True
            users[username]['ban_reason'] = reason
            save_json('users.json', users)
        json_resp(self, {'message': 'Banned'})

    def owner_unban(self):
        username = self.path.split('/')[-2]
        users = load_json('users.json')
        if username in users:
            users[username]['banned'] = False
            users[username]['ban_reason'] = ''
            save_json('users.json', users)
        json_resp(self, {'message': 'Unbanned'})

    def owner_create(self):
        data = read_body(self)
        u = data.get('username', '').strip().lower()
        p = data.get('password', '')
        q = data.get('security_question', '')
        a = data.get('security_answer', '')
        if not u or not p: return json_resp(self, {'error': 'Data tidak lengkap'}, 400)
        users = load_json('users.json')
        if u in users: return json_resp(self, {'error': 'Username sudah ada'}, 400)
        users[u] = {
            'password_hash': hash_password(p), 'security_question': q,
            'security_answer_hash': hash_password(a) if a else '',
            'role': 'user', 'trial_start': time.time(), 'total_deploy': 0,
            'daily_deploy': 0, 'daily_date': '', 'banned': False,
            'ban_reason': '', 'custom_limit': None, 'messages': []
        }
        save_json('users.json', users)
        json_resp(self, {'message': 'User dibuat'}, 201)

    def owner_broadcast(self):
        msg = read_body(self).get('message', '')
        if not msg: return json_resp(self, {'error': 'Pesan kosong'}, 400)
        users = load_json('users.json')
        for n in users:
            if n != 'safrul': users[n].setdefault('messages', []).append(msg)
        save_json('users.json', users)
        json_resp(self, {'message': 'Broadcast terkirim'})

    def owner_delete(self):
        pid = read_body(self).get('project_id', '')
        token = load_vercel_config().get('vercel_token')
        if token:
            try:
                import requests
                requests.delete(f'https://api.vercel.com/v9/projects/{pid}',
                                headers={'Authorization': f'Bearer {token}'})
            except: pass
        json_resp(self, {'message': f'Project {pid} dihapus'})

    def export_users(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Disposition', 'attachment; filename=users_export.json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(load_json('users.json'), indent=2).encode('utf-8'))

    def import_users(self):
        try:
            imported = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
            users = load_json('users.json')
            for n, d in imported.items():
                if n not in users: users[n] = d
                else:
                    for k in ['password_hash', 'security_question', 'security_answer_hash', 'role', 'trial_start', 'total_deploy', 'custom_limit']:
                        if k in d: users[n][k] = d[k]
            save_json('users.json', users)
            json_resp(self, {'message': 'Import berhasil'})
        except Exception as e:
            json_resp(self, {'error': str(e)}, 400)

# ----- MAIN -----
if __name__ == '__main__':
    server = HTTPServer((HOST, PORT), SafruzHandler)
    print(f'Backend running on port {PORT}')
    try: server.serve_forever()
    except KeyboardInterrupt: server.server_close()