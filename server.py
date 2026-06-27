#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Safruz Deployer Pro - Backend Server
User lintas HP terbaca, kode ringkas.
"""
import json, time, hashlib, hmac, base64, os, datetime, random, string
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Config
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 5000))
SECRET_KEY = b'safruz-secret-key-2024'
TOKEN_EXPIRY = 24 * 3600

# Path data
DIR = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(DIR, 'data')
if not os.path.exists(DATA): os.makedirs(DATA)

def load(fname):
    p = os.path.join(DATA, fname)
    return json.load(open(p)) if os.path.exists(p) else {}

def save(fname, data):
    with open(os.path.join(DATA, fname), 'w') as f:
        json.dump(data, f, indent=2)

def load_config():
    p = os.path.join(DIR, 'vercel_config.json')
    return json.load(open(p)) if os.path.exists(p) else {}

# Helpers
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def make_token(user):
    ts = str(int(time.time()))
    msg = f"{user}:{ts}".encode()
    sig = hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()
    return base64.b64encode(f"{user}:{ts}:{sig}".encode()).decode()

def check_token(token):
    try:
        user, ts, sig = base64.b64decode(token).decode().split(':')
        if int(ts) + TOKEN_EXPIRY < time.time(): return None
        expected = hmac.new(SECRET_KEY, f"{user}:{ts}".encode(), hashlib.sha256).hexdigest()
        return user if sig == expected else None
    except: return None

def get_token(req):
    auth = req.headers.get('Authorization', '')
    return auth[7:] if auth.startswith('Bearer ') else None

def ok(handler, data, code=200):
    try:
        handler.send_response(code)
        handler.send_header('Content-Type', 'application/json')
        handler.send_header('Access-Control-Allow-Origin', '*')
        handler.send_header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
        handler.send_header('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        handler.end_headers()
        handler.wfile.write(json.dumps(data).encode())
    except: pass

def body(handler):
    try:
        n = int(handler.headers.get('Content-Length', 0))
        return json.loads(handler.rfile.read(n)) if n else {}
    except: return {}

# Handler
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
        if p in ('', '/'): ok(self, {'status':'online','app':'Safruz Deployer Pro'})
        elif p == '/favicon.ico': self.send_response(204); self.end_headers()
        elif p == '/api/auth/register' and method == 'POST': self.register()
        elif p == '/api/auth/login' and method == 'POST': self.login()
        elif p == '/api/user/me' and method == 'GET': self.auth(self.profile)()
        elif p == '/api/user/change-password' and method == 'POST': self.auth(self.chpass)()
        elif p == '/api/deploy' and method == 'POST': self.auth(self.deploy)()
        elif p == '/api/deploy/logs' and method == 'GET': self.auth(self.logs)()
        elif p.startswith('/api/chat/messages/') and method == 'GET': self.auth(self.chat_get)()
        elif p == '/api/chat/send' and method == 'POST': self.auth(self.chat_send)()
        elif p == '/api/owner/users' and method == 'GET': self.owner(self.owner_users)()
        elif p.startswith('/api/owner/user/') and method == 'PUT': self.owner(self.owner_update)()
        elif p.endswith('/ban') and method == 'POST': self.owner(self.owner_ban)()
        elif p.endswith('/unban') and method == 'POST': self.owner(self.owner_unban)()
        elif p == '/api/owner/create-user' and method == 'POST': self.owner(self.owner_create)()
        elif p == '/api/owner/broadcast' and method == 'POST': self.owner(self.owner_broadcast)()
        elif p == '/api/owner/delete-project' and method == 'DELETE': self.owner(self.owner_del)()
        elif p == '/api/owner/export-users' and method == 'GET': self.owner(self.export_users)()
        elif p == '/api/owner/import-users' and method == 'POST': self.owner(self.import_users)()
        else: ok(self, {'error':'Not found'}, 404)

    # Decorators
    def auth(self, fn):
        def w():
            t = get_token(self)
            u = check_token(t)
            if not u: return ok(self, {'error':'Unauthorized'}, 401)
            self.user = u
            return fn()
        return w

    def owner(self, fn):
        def w():
            t = get_token(self)
            u = check_token(t)
            if not u or u != 'safrul': return ok(self, {'error':'Owner only'}, 403)
            self.user = u
            return fn()
        return w

    # AUTH
    def register(self):
        d = body(self)
        u = d.get('username','').strip().lower()
        p = d.get('password','')
        q = d.get('security_question','')
        a = d.get('security_answer','')
        if not all([u,p,q,a]): return ok(self, {'error':'Data tidak lengkap'}, 400)
        users = load('users.json')
        if u in users: return ok(self, {'error':'Username sudah ada'}, 400)
        users[u] = {
            'password_hash': hash_pw(p),
            'security_question': q,
            'security_answer_hash': hash_pw(a),
            'role': 'user', 'trial_start': time.time(),
            'total_deploy': 0, 'daily_deploy': 0, 'daily_date': '',
            'banned': False, 'ban_reason': '', 'custom_limit': None, 'messages': []
        }
        save('users.json', users)
        ok(self, {'message':'Registrasi berhasil'}, 201)

    def login(self):
        d = body(self)
        u = d.get('username','').strip().lower()
        p = d.get('password','')
        ans = d.get('security_answer')
        if u == 'safrul' and p == 'safrul1':
            return ok(self, {'access_token':make_token(u),'role':'owner'})
        users = load('users.json')
        user = users.get(u)
        if not user or user['password_hash'] != hash_pw(p):
            return ok(self, {'error':'Username/password salah'}, 401)
        if user['banned']:
            return ok(self, {'error':f'Akun dibanned: {user["ban_reason"] or "Tidak ada alasan"}'}, 403)
        if user.get('security_question') and not ans:
            return ok(self, {'requires_security':True,'security_question':user['security_question']})
        if ans and user['security_answer_hash'] != hash_pw(ans):
            return ok(self, {'error':'Jawaban keamanan salah'}, 401)
        return ok(self, {'access_token':make_token(u),'role':user['role']})

    # USER
    def profile(self):
        u = load('users.json').get(self.user)
        if not u: return ok(self, {'error':'User not found'}, 404)
        trial = (u['role']=='user' and time.time()-u['trial_start'] < 12*86400)
        return ok(self, {
            'username':self.user, 'role':'premium' if trial else u['role'],
            'total_deploy':u['total_deploy'], 'daily_deploy':u['daily_deploy'],
            'banned':u['banned'], 'ban_reason':u['ban_reason'],
            'trial_start':u['trial_start'], 'custom_limit':u['custom_limit']
        })

    def chpass(self):
        d = body(self)
        old, new = d.get('old_password'), d.get('new_password')
        users = load('users.json')
        u = users.get(self.user)
        if not u or u['password_hash'] != hash_pw(old):
            return ok(self, {'error':'Password lama salah'}, 400)
        u['password_hash'] = hash_pw(new)
        save('users.json', users)
        ok(self, {'message':'Password diubah'})

    # DEPLOY (simulasi)
    def deploy(self):
        d = body(self)
        name = d.get('project_name','safrul-deploy')
        html = d.get('html_code','')
        files = d.get('files',[])
        users = load('users.json')
        u = users.get(self.user)
        if u['banned']: return ok(self, {'error':'Akun dibanned'}, 403)
        today = datetime.date.today().isoformat()
        if u['daily_date'] != today:
            u['daily_deploy'] = 0; u['daily_date'] = today
        limit = float('inf') if self.user == 'safrul' else (u['custom_limit'] or (300 if u['role']=='premium' else 10))
        if u['role']=='user' and time.time()-u['trial_start'] < 12*86400: limit = 300
        if u['daily_deploy'] >= limit: return ok(self, {'error':'Limit harian habis'}, 429)
        pid = ''.join(random.choices(string.ascii_lowercase+string.digits, k=10))
        url = f"{name}-{pid}.vercel.app"
        logs = load('logs.json')
        logs.append({'user':self.user,'time':datetime.datetime.now().isoformat(),'project_name':name,'project_id':pid,'url':f'https://{url}','status':'success'})
        save('logs.json', logs)
        u['daily_deploy'] += 1; u['total_deploy'] += 1
        save('users.json', users)
        ok(self, {'url':f'https://{url}','project_id':pid,'status':'READY'})

    def logs(self):
        all_logs = load('logs.json')
        return ok(self, [l for l in all_logs if l['user']==self.user][-50:])

    # CHAT
    def chat_get(self):
        cid = self.path.split('/')[-1]
        return ok(self, load('chats.json').get(cid, []))

    def chat_send(self):
        d = body(self)
        to, txt = d.get('to'), d.get('text')
        if not to or not txt: return ok(self, {'error':'Pesan kosong'}, 400)
        cid = '_'.join(sorted([self.user, to]))
        chats = load('chats.json')
        chats.setdefault(cid, []).append({
            'sender':self.user,'text':txt,
            'time':datetime.datetime.now().strftime('%H:%M'),
            'date':datetime.datetime.now().strftime('%Y-%m-%d'),
            'location':d.get('location')
        })
        save('chats.json', chats)
        ok(self, {'message':'Terkirim'}, 201)

    # OWNER
    def owner_users(self):
        users = load('users.json')
        today = datetime.date.today().isoformat()
        return ok(self, [{
            'username':n,'role':u['role'],
            'limit':u['custom_limit'] or (300 if u['role']=='premium' else 10),
            'daily_deploy':u['daily_deploy'] if u['daily_date']==today else 0,
            'banned':u['banned'],'ban_reason':u['ban_reason']
        } for n,u in users.items() if n!='safrul'])

    def owner_update(self):
        name = self.path.split('/')[-1]
        d = body(self)
        users = load('users.json')
        if name not in users: return ok(self, {'error':'User not found'}, 404)
        if 'role' in d: users[name]['role'] = d['role']
        if 'limit' in d: users[name]['custom_limit'] = d['limit']
        save('users.json', users)
        ok(self, {'message':'Updated'})

    def owner_ban(self):
        name = self.path.split('/')[-2]
        reason = body(self).get('reason','')
        users = load('users.json')
        if name in users:
            users[name]['banned'] = True
            users[name]['ban_reason'] = reason
            save('users.json', users)
        ok(self, {'message':'Banned'})

    def owner_unban(self):
        name = self.path.split('/')[-2]
        users = load('users.json')
        if name in users:
            users[name]['banned'] = False
            users[name]['ban_reason'] = ''
            save('users.json', users)
        ok(self, {'message':'Unbanned'})

    def owner_create(self):
        d = body(self)
        u,p,q,a = d.get('username','').strip().lower(), d.get('password',''), d.get('security_question',''), d.get('security_answer','')
        if not u or not p: return ok(self, {'error':'Data tidak lengkap'}, 400)
        users = load('users.json')
        if u in users: return ok(self, {'error':'Username sudah ada'}, 400)
        users[u] = {
            'password_hash':hash_pw(p),'security_question':q,'security_answer_hash':hash_pw(a) if a else '',
            'role':'user','trial_start':time.time(),'total_deploy':0,'daily_deploy':0,'daily_date':'',
            'banned':False,'ban_reason':'','custom_limit':None,'messages':[]
        }
        save('users.json', users)
        ok(self, {'message':'User dibuat'}, 201)

    def owner_broadcast(self):
        msg = body(self).get('message','')
        if not msg: return ok(self, {'error':'Pesan kosong'}, 400)
        users = load('users.json')
        for n in users:
            if n != 'safrul': users[n].setdefault('messages',[]).append(msg)
        save('users.json', users)
        ok(self, {'message':'Broadcast terkirim'})

    def owner_del(self):
        pid = body(self).get('project_id','')
        ok(self, {'message':f'Project {pid} dihapus (simulasi)'})

    def export_users(self):
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Disposition','attachment; filename=users.json')
        self.send_header('Access-Control-Allow-Origin','*')
        self.end_headers()
        self.wfile.write(json.dumps(load('users.json'), indent=2).encode())

    def import_users(self):
        try:
            imported = json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))))
            users = load('users.json')
            for n,d in imported.items():
                if n not in users: users[n] = d
                else:
                    for k in ['password_hash','security_question','security_answer_hash','role','trial_start','total_deploy','custom_limit']:
                        if k in d: users[n][k] = d[k]
            save('users.json', users)
            ok(self, {'message':'Import berhasil'})
        except: ok(self, {'error':'Format tidak valid'}, 400)

if __name__ == '__main__':
    server = HTTPServer((HOST, PORT), H)
    print(f'Backend running on port {PORT}')
    try: server.serve_forever()
    except KeyboardInterrupt: server.server_close()
