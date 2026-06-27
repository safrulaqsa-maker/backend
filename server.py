#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Safruz Deployer Pro - Backend Server (Python 3)
Fitur: Register ala Google (kode verifikasi), autentikasi 2 langkah, forgot password.
"""
import json, time, hashlib, hmac, base64, os, datetime, random, string, secrets
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# ========== CONFIG ==========
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 5000))
SECRET_KEY = b'safruz-secret-key-2024'
TOKEN_EXPIRY = 24 * 3600  # 1 hari
VERIFICATION_CODE_EXPIRY = 10 * 60  # 10 menit

# ========== DATA ==========
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

def load_json(filename):
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return {}

def save_json(filename, data):
    path = os.path.join(DATA_DIR, filename)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def load_vercel_config():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vercel_config.json')
    if os.path.exists(path):
        with open(path, 'r') as f:
            return json.load(f)
    return {}

# ========== HELPERS ==========
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(username):
    ts = str(int(time.time()))
    msg = f"{username}:{ts}".encode()
    sig = hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()
    return base64.b64encode(f"{username}:{ts}:{sig}".encode()).decode()

def verify_token(token):
    try:
        decoded = base64.b64decode(token).decode()
        username, ts, sig = decoded.split(':')
        if int(ts) + TOKEN_EXPIRY < time.time():
            return None
        expected = hmac.new(SECRET_KEY, f"{username}:{ts}".encode(), hashlib.sha256).hexdigest()
        if sig == expected:
            return username
    except:
        pass
    return None

def get_token_from_request(handler):
    auth = handler.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:]
    return None

def generate_verification_code():
    return ''.join(secrets.choice(string.digits) for _ in range(6))

def json_response(handler, data, status=200):
    try:
        handler.send_response(status)
        handler.send_header('Content-Type', 'application/json')
        handler.send_header('Access-Control-Allow-Origin', '*')
        handler.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        handler.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        handler.end_headers()
        handler.wfile.write(json.dumps(data).encode())
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass

def read_body(handler):
    length = int(handler.headers.get('Content-Length', 0))
    if length > 0:
        return json.loads(handler.rfile.read(length).decode())
    return {}

# ========== HANDLER ==========
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
            json_response(self, {'status': 'online', 'app': 'Safruz Deployer Pro'})
            return
        if path == '/favicon.ico':
            self.send_response(204); self.end_headers(); return

        # Auth routes
        if path == '/api/auth/register' and method == 'POST': self.handle_register()
        elif path == '/api/auth/verify-email' and method == 'POST': self.handle_verify_email()
        elif path == '/api/auth/login' and method == 'POST': self.handle_login()
        elif path == '/api/auth/forgot-password' and method == 'POST': self.handle_forgot_password()
        elif path == '/api/auth/reset-password' and method == 'POST': self.handle_reset_password()
        # User
        elif path == '/api/user/me' and method == 'GET': self.authenticated(self.handle_profile)()
        elif path == '/api/user/change-password' and method == 'POST': self.authenticated(self.handle_change_password)()
        # Deploy
        elif path == '/api/deploy' and method == 'POST': self.authenticated(self.handle_deploy)()
        elif path == '/api/deploy/logs' and method == 'GET': self.authenticated(self.handle_logs)()
        # Chat
        elif path.startswith('/api/chat/messages/') and method == 'GET': self.authenticated(self.handle_chat_get)()
        elif path == '/api/chat/send' and method == 'POST': self.authenticated(self.handle_chat_send)()
        # Owner
        elif path == '/api/owner/users' and method == 'GET': self.owner_only(self.handle_owner_users)()
        elif path.startswith('/api/owner/user/') and method == 'PUT': self.owner_only(self.handle_owner_update)()
        elif path.endswith('/ban') and method == 'POST': self.owner_only(self.handle_owner_ban)()
        elif path.endswith('/unban') and method == 'POST': self.owner_only(self.handle_owner_unban)()
        elif path == '/api/owner/create-user' and method == 'POST': self.owner_only(self.handle_owner_create)()
        elif path == '/api/owner/broadcast' and method == 'POST': self.owner_only(self.handle_owner_broadcast)()
        elif path == '/api/owner/delete-project' and method == 'DELETE': self.owner_only(self.handle_owner_delete)()
        elif path == '/api/owner/export-users' and method == 'GET': self.owner_only(self.handle_export_users)()
        elif path == '/api/owner/import-users' and method == 'POST': self.owner_only(self.handle_import_users)()
        else: json_response(self, {'error': 'Not found'}, 404)

    # ========== DECORATORS ==========
    def authenticated(self, func):
        def wrapper():
            token = get_token_from_request(self)
            username = verify_token(token)
            if not username:
                return json_response(self, {'error': 'Unauthorized'}, 401)
            self.current_user = username
            return func()
        return wrapper

    def owner_only(self, func):
        def wrapper():
            token = get_token_from_request(self)
            username = verify_token(token)
            if not username or username != 'safrul':
                return json_response(self, {'error': 'Owner only'}, 403)
            self.current_user = username
            return func()
        return wrapper

    # ========== AUTH HANDLERS ==========
    def handle_register(self):
        """Register dengan email, password, security question. Mengirim kode verifikasi."""
        data = read_body(self)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        name = data.get('name', '')
        security_question = data.get('security_question', '')
        security_answer = data.get('security_answer', '')

        if not all([email, password, name, security_question, security_answer]):
            return json_response(self, {'error': 'Semua field wajib diisi (email, password, nama, pertanyaan, jawaban)'}, 400)

        users = load_json('users.json')
        if email in users:
            return json_response(self, {'error': 'Email sudah terdaftar'}, 400)

        # Generate kode verifikasi (simulasi email)
        code = generate_verification_code()
        expires = time.time() + VERIFICATION_CODE_EXPIRY

        # Simpan data sementara di pending_verifications
        pending = load_json('pending_verifications.json')
        pending[email] = {
            'password_hash': hash_password(password),
            'name': name,
            'security_question': security_question,
            'security_answer_hash': hash_password(security_answer),
            'verification_code': code,
            'expires': expires
        }
        save_json('pending_verifications.json', pending)

        # Simulasi pengiriman email (dalam produksi gunakan SMTP)
        print(f"[SIMULASI EMAIL] Kode verifikasi untuk {email}: {code}")

        json_response(self, {
            'message': 'Kode verifikasi telah dikirim ke email Anda (simulasi). Silakan cek log server atau gunakan kode: ' + code,
            'verification_code': code  # Hanya untuk demo, hapus di produksi
        }, 201)

    def handle_verify_email(self):
        """Verifikasi email dengan kode yang dikirim."""
        data = read_body(self)
        email = data.get('email', '').strip().lower()
        code = data.get('code', '')

        pending = load_json('pending_verifications.json')
        if email not in pending:
            return json_response(self, {'error': 'Email tidak ditemukan atau belum mendaftar'}, 400)

        p = pending[email]
        if p['verification_code'] != code:
            return json_response(self, {'error': 'Kode verifikasi salah'}, 400)

        if time.time() > p['expires']:
            del pending[email]
            save_json('pending_verifications.json', pending)
            return json_response(self, {'error': 'Kode verifikasi kadaluarsa'}, 400)

        # Pindahkan ke users
        users = load_json('users.json')
        users[email] = {
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
        save_json('users.json', users)

        # Hapus pending
        del pending[email]
        save_json('pending_verifications.json', pending)

        json_response(self, {'message': 'Email berhasil diverifikasi. Akun Anda sudah aktif.'})

    def handle_login(self):
        """Login dengan email dan password."""
        data = read_body(self)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not email or not password:
            return json_response(self, {'error': 'Email dan password wajib diisi'}, 400)

        # Owner special
        if email == 'safrul' and password == 'safrul1':
            return json_response(self, {'access_token': create_token('safrul'), 'role': 'owner', 'name': 'Safrul'})

        users = load_json('users.json')
        user = users.get(email)
        if not user:
            # Cek pending
            pending = load_json('pending_verifications.json')
            if email in pending:
                return json_response(self, {'error': 'Email belum diverifikasi. Masukkan kode verifikasi terlebih dahulu.'}, 403)
            return json_response(self, {'error': 'Email tidak ditemukan'}, 404)

        if user['password_hash'] != hash_password(password):
            return json_response(self, {'error': 'Password salah'}, 401)

        if user['banned']:
            return json_response(self, {'error': f'Akun dibanned: {user["ban_reason"] or "Tidak ada alasan"}'}, 403)

        token = create_token(email)
        json_response(self, {
            'access_token': token,
            'role': user['role'],
            'name': user['name']
        })

    def handle_forgot_password(self):
        """Lupa password: kirim kode reset lewat security question."""
        data = read_body(self)
        email = data.get('email', '').strip().lower()
        users = load_json('users.json')
        user = users.get(email)
        if not user:
            return json_response(self, {'error': 'Email tidak ditemukan'}, 404)

        # Kembalikan security question untuk dijawab
        json_response(self, {
            'message': 'Jawab pertanyaan keamanan untuk reset password',
            'security_question': user['security_question']
        })

    def handle_reset_password(self):
        """Reset password setelah menjawab security question."""
        data = read_body(self)
        email = data.get('email', '').strip().lower()
        answer = data.get('security_answer', '')
        new_password = data.get('new_password', '')

        if not all([email, answer, new_password]):
            return json_response(self, {'error': 'Data tidak lengkap'}, 400)

        users = load_json('users.json')
        user = users.get(email)
        if not user:
            return json_response(self, {'error': 'Email tidak ditemukan'}, 404)

        if user['security_answer_hash'] != hash_password(answer):
            return json_response(self, {'error': 'Jawaban keamanan salah'}, 401)

        user['password_hash'] = hash_password(new_password)
        save_json('users.json', users)
        json_response(self, {'message': 'Password berhasil direset. Silakan login dengan password baru.'})

    # ========== PROFILE ==========
    def handle_profile(self):
        users = load_json('users.json')
        user = users.get(self.current_user)
        if not user:
            return json_response(self, {'error': 'User tidak ditemukan'}, 404)

        is_trial = (user['role'] == 'user' and time.time() - user['trial_start'] < 12 * 86400)
        role = 'premium' if is_trial else user['role']

        json_response(self, {
            'username': self.current_user,
            'role': role,
            'name': user.get('name', ''),
            'total_deploy': user['total_deploy'],
            'daily_deploy': user['daily_deploy'],
            'banned': user['banned'],
            'ban_reason': user['ban_reason'],
            'trial_start': user['trial_start'],
            'custom_limit': user['custom_limit']
        })

    def handle_change_password(self):
        data = read_body(self)
        old = data.get('old_password')
        new = data.get('new_password')
        users = load_json('users.json')
        user = users.get(self.current_user)
        if not user or user['password_hash'] != hash_password(old):
            return json_response(self, {'error': 'Password lama salah'}, 400)
        user['password_hash'] = hash_password(new)
        save_json('users.json', users)
        json_response(self, {'message': 'Password berhasil diubah'})

    # ========== DEPLOY (simulasi) ==========
    def handle_deploy(self):
        data = read_body(self)
        project_name = data.get('project_name', 'safrul-deploy')
        html_code = data.get('html_code', '')
        files = data.get('files', [])

        users = load_json('users.json')
        user = users.get(self.current_user)
        if not user:
            return json_response(self, {'error': 'User tidak ditemukan'}, 404)
        if user['banned']:
            return json_response(self, {'error': 'Akun dibanned'}, 403)

        today = datetime.date.today().isoformat()
        if user['daily_date'] != today:
            user['daily_deploy'] = 0
            user['daily_date'] = today

        if self.current_user == 'safrul':
            limit = float('inf')
        else:
            limit = user['custom_limit'] if user['custom_limit'] is not None else (300 if user['role'] == 'premium' else 10)
            if user['role'] == 'user' and time.time() - user['trial_start'] < 12 * 86400:
                limit = 300

        if user['daily_deploy'] >= limit:
            return json_response(self, {'error': 'Limit harian habis'}, 429)

        config = load_vercel_config()
        token = config.get('vercel_token', '')
        if not token:
            # Simulasi tanpa token
            project_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            url = f"{project_name}-{project_id}.vercel.app"
            logs = load_json('logs.json')
            logs.append({
                'user': self.current_user,
                'time': datetime.datetime.now().isoformat(),
                'project_name': project_name,
                'project_id': project_id,
                'url': f'https://{url}',
                'status': 'success',
                'error': ''
            })
            save_json('logs.json', logs)
            user['daily_deploy'] += 1
            user['total_deploy'] += 1
            save_json('users.json', users)
            return json_response(self, {'url': f'https://{url}', 'project_id': project_id, 'status': 'READY'})

        # Deploy sungguhan dengan Vercel token (jika ada)
        try:
            import requests
            body = {'name': project_name}
            resp = requests.post('https://api.vercel.com/v9/projects',
                                 headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
                                 json=body)
            if not resp.ok:
                raise Exception(resp.json().get('error', {}).get('message', 'Gagal membuat project'))

            project_data = resp.json()
            project_id = project_data['id']

            deploy_body = {
                'name': project_name,
                'project': project_id,
                'target': 'production',
                'files': files if files else [{'file': 'index.html', 'data': base64.b64encode(html_code.encode()).decode(), 'encoding': 'base64'}]
            }
            deploy_resp = requests.post('https://api.vercel.com/v13/deployments',
                                        headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
                                        json=deploy_body)
            if not deploy_resp.ok:
                raise Exception(deploy_resp.json().get('error', {}).get('message', 'Gagal deploy'))

            deploy_data = deploy_resp.json()
            deploy_id = deploy_data['id']
            url = deploy_data.get('url', '')
            status = deploy_data.get('readyState', '')

            for _ in range(30):
                if status in ('READY', 'ERROR'):
                    break
                time.sleep(2)
                sr = requests.get(f'https://api.vercel.com/v13/deployments/{deploy_id}',
                                  headers={'Authorization': f'Bearer {token}'})
                if sr.ok:
                    sd = sr.json()
                    status = sd['readyState']
                    url = sd.get('url', url)
                    if sd.get('alias'):
                        url = sd['alias'][0]

            final_url = f'https://{url}'
            logs = load_json('logs.json')
            logs.append({
                'user': self.current_user,
                'time': datetime.datetime.now().isoformat(),
                'project_name': project_name,
                'project_id': project_id,
                'url': final_url,
                'status': 'success' if status == 'READY' else 'failed',
                'error': ''
            })
            save_json('logs.json', logs)

            user['daily_deploy'] += 1
            user['total_deploy'] += 1
            save_json('users.json', users)

            json_response(self, {'url': final_url, 'project_id': project_id, 'status': status})
        except Exception as e:
            logs = load_json('logs.json')
            logs.append({
                'user': self.current_user,
                'time': datetime.datetime.now().isoformat(),
                'project_name': project_name,
                'project_id': '',
                'url': '',
                'status': 'failed',
                'error': str(e)
            })
            save_json('logs.json', logs)
            json_response(self, {'error': str(e)}, 500)

    def handle_logs(self):
        logs = load_json('logs.json')
        user_logs = [l for l in logs if l['user'] == self.current_user][-50:]
        json_response(self, user_logs)

    # ========== CHAT ==========
    def handle_chat_get(self):
        chat_id = self.path.split('/')[-1]
        chats = load_json('chats.json')
        json_response(self, chats.get(chat_id, []))

    def handle_chat_send(self):
        data = read_body(self)
        to_user = data.get('to', '')
        text = data.get('text', '')
        location = data.get('location', None)
        if not to_user or not text:
            return json_response(self, {'error': 'Pesan kosong'}, 400)

        participants = sorted([self.current_user, to_user])
        chat_id = '_'.join(participants)
        chats = load_json('chats.json')
        if chat_id not in chats:
            chats[chat_id] = []
        now = datetime.datetime.now()
        chats[chat_id].append({
            'sender': self.current_user,
            'text': text,
            'time': now.strftime('%H:%M'),
            'date': now.strftime('%Y-%m-%d'),
            'location': location
        })
        save_json('chats.json', chats)
        json_response(self, {'message': 'Pesan terkirim'}, 201)

    # ========== OWNER ==========
    def handle_owner_users(self):
        users = load_json('users.json')
        today = datetime.date.today().isoformat()
        result = []
        for email, u in users.items():
            if email == 'safrul': continue
            daily = u['daily_deploy'] if u['daily_date'] == today else 0
            limit = u['custom_limit'] if u['custom_limit'] is not None else (300 if u['role'] == 'premium' else 10)
            result.append({
                'username': email,
                'name': u.get('name', ''),
                'role': u['role'],
                'limit': limit,
                'daily_deploy': daily,
                'banned': u['banned'],
                'ban_reason': u['ban_reason']
            })
        json_response(self, result)

    def handle_owner_update(self):
        parts = self.path.split('/')
        email = parts[-1] if parts[-1] else parts[-2]
        data = read_body(self)
        users = load_json('users.json')
        if email not in users:
            return json_response(self, {'error': 'User tidak ditemukan'}, 404)
        if 'role' in data:
            users[email]['role'] = data['role']
        if 'limit' in data:
            users[email]['custom_limit'] = data['limit']
        save_json('users.json', users)
        json_response(self, {'message': 'Diperbarui'})

    def handle_owner_ban(self):
        parts = self.path.split('/')
        email = parts[-2]
        data = read_body(self)
        reason = data.get('reason', '')
        users = load_json('users.json')
        if email in users:
            users[email]['banned'] = True
            users[email]['ban_reason'] = reason
            save_json('users.json', users)
        json_response(self, {'message': 'User dibanned'})

    def handle_owner_unban(self):
        parts = self.path.split('/')
        email = parts[-2]
        users = load_json('users.json')
        if email in users:
            users[email]['banned'] = False
            users[email]['ban_reason'] = ''
            save_json('users.json', users)
        json_response(self, {'message': 'User diunban'})

    def handle_owner_create(self):
        data = read_body(self)
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        name = data.get('name', '')
        if not email or not password:
            return json_response(self, {'error': 'Data tidak lengkap'}, 400)
        users = load_json('users.json')
        if email in users:
            return json_response(self, {'error': 'Email sudah ada'}, 400)
        users[email] = {
            'password_hash': hash_password(password),
            'name': name,
            'security_question': '',
            'security_answer_hash': '',
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
        save_json('users.json', users)
        json_response(self, {'message': 'User dibuat'}, 201)

    def handle_owner_broadcast(self):
        data = read_body(self)
        msg = data.get('message', '')
        if not msg:
            return json_response(self, {'error': 'Pesan kosong'}, 400)
        users = load_json('users.json')
        for email in users:
            if email != 'safrul':
                users[email].setdefault('messages', []).append(msg)
        save_json('users.json', users)
        json_response(self, {'message': 'Broadcast terkirim'})

    def handle_owner_delete(self):
        data = read_body(self)
        project_id = data.get('project_id', '')
        config = load_vercel_config()
        token = config.get('vercel_token', '')
        if token:
            try:
                import requests
                requests.delete(f'https://api.vercel.com/v9/projects/{project_id}',
                                headers={'Authorization': f'Bearer {token}'})
            except: pass
        json_response(self, {'message': f'Project {project_id} dihapus'})

    def handle_export_users(self):
        users = load_json('users.json')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Disposition', 'attachment; filename=users_export.json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(users, indent=2).encode())

    def handle_import_users(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        try:
            imported = json.loads(body)
        except:
            return json_response(self, {'error': 'Format tidak valid'}, 400)
        users = load_json('users.json')
        for email, data in imported.items():
            if email not in users:
                users[email] = data
            else:
                for key in ['password_hash', 'security_question', 'security_answer_hash', 'role', 'trial_start', 'total_deploy', 'custom_limit']:
                    if key in data:
                        users[email][key] = data[key]
        save_json('users.json', users)
        json_response(self, {'message': 'Import berhasil'})

# ========== MAIN ==========
if __name__ == '__main__':
    server = HTTPServer((HOST, PORT), SafruzHandler)
    print(f'Server berjalan di port {PORT}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
