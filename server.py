#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Safruz Deployer Pro - Backend Server
Login Google + JWT lokal. Token Vercel via environment variable.
"""
import json, time, hashlib, hmac, base64, os, datetime, random, string
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Konfigurasi
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 5000))
SECRET_KEY = b'safruz-secret-key-2024'
TOKEN_EXPIRY = 24 * 3600

OWNER_EMAIL = 'safrulaqsa@gmail.com'
OWNER_PASSWORD = os.environ.get('OWNER_PASSWORD', 'safrul1')

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

def load_json(fname):
    path = os.path.join(DATA_DIR, fname)
    return json.load(open(path)) if os.path.exists(path) else {}

def save_json(fname, data):
    with open(os.path.join(DATA_DIR, fname), 'w') as f:
        json.dump(data, f, indent=2)

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
        if int(ts) + TOKEN_EXPIRY < time.time():
            return None
        expected = hmac.new(SECRET_KEY, f"{user}:{ts}".encode(), hashlib.sha256).hexdigest()
        return user if sig == expected else None
    except:
        return None

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
    except:
        pass

def body(handler):
    try:
        n = int(handler.headers.get('Content-Length', 0))
        return json.loads(handler.rfile.read(n)) if n else {}
    except:
        return {}

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
        if p in ('', '/'): ok(self, {'status':'online'})
        elif p == '/favicon.ico': self.send_response(204); self.end_headers()
        elif p == '/api/auth/google' and method == 'POST': self.google_login()
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
            if not u or u != OWNER_EMAIL: return ok(self, {'error':'Owner only'}, 403)
            self.user = u
            return fn()
        return w

    # ---------- Google Login ----------
    def google_login(self):
        data = body(self)
        credential = data.get('credential', '')
        if not credential:
            return ok(self, {'error':'Token tidak ada'}, 400)

        # Verifikasi token ke Google
        try:
            import requests
            resp = requests.get(f'https://oauth2.googleapis.com/tokeninfo?id_token={credential}')
            if not resp.ok:
                return ok(self, {'error':'Token Google tidak valid'}, 401)
            info = resp.json()
            email = info.get('email', '').strip().lower()
            name = info.get('name', '')
            if not email:
                return ok(self, {'error':'Email tidak ditemukan di token'}, 401)
        except Exception as e:
            return ok(self, {'error':str(e)}, 500)

        users = load_json('users.json')
        # Jika user belum ada, daftarkan otomatis
        if email not in users:
            users[email] = {
                'password_hash': '',
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
        else:
            # Update nama jika perlu
            if not users[email].get('name'):
                users[email]['name'] = name
                save_json('users.json', users)

        if users[email]['banned']:
            return ok(self, {'error':'Akun dibanned'}, 403)

        token = make_token(email)
        return ok(self, {
            'access_token': token,
            'role': users[email]['role'],
            'name': users[email].get('name', ''),
            'email': email
        })

    # ---------- Password Login (Owner) ----------
    def login(self):
        d = body(self)
        email = d.get('email','').strip().lower()
        pw = d.get('password','')
        if email == OWNER_EMAIL and pw == OWNER_PASSWORD:
            token = make_token(email)
            return ok(self, {'access_token':token,'role':'owner','name':'Owner'})
        return ok(self, {'error':'Hanya owner yang bisa login dengan password'}, 401)

    # ---------- Profile ----------
    def profile(self):
        u = load_json('users.json').get(self.user)
        if not u: return ok(self, {'error':'User not found'}, 404)
        trial = (u['role']=='user' and time.time()-u['trial_start'] < 12*86400)
        return ok(self, {
            'username':self.user,
            'role':'premium' if trial else u['role'],
            'name':u.get('name',''),
            'total_deploy':u['total_deploy'],
            'daily_deploy':u['daily_deploy'],
            'banned':u['banned'],
            'ban_reason':u['ban_reason']
        })

    def chpass(self):
        d = body(self)
        old, new = d.get('old_password'), d.get('new_password')
        u = load_json('users.json').get(self.user)
        if not u or u['password_hash'] != hash_pw(old):
            return ok(self, {'error':'Password lama salah'}, 400)
        u['password_hash'] = hash_pw(new)
        save_json('users.json', load_json('users.json'))
        ok(self, {'message':'Password diubah'})

    # ---------- Deploy ----------
    def deploy(self):
        d = body(self)
        project_name = d.get('project_name','safrul-deploy')
        html_code = d.get('html_code','')
        files = d.get('files',[])
        users = load_json('users.json')
        u = users.get(self.user)
        if not u or u['banned']: return ok(self, {'error':'Akun dibanned'}, 403)
        today = datetime.date.today().isoformat()
        if u['daily_date'] != today:
            u['daily_deploy'] = 0
            u['daily_date'] = today
        limit = float('inf') if self.user == OWNER_EMAIL else (u['custom_limit'] or (300 if u['role']=='premium' else 10))
        if u['role']=='user' and time.time()-u['trial_start'] < 12*86400:
            limit = 300
        if u['daily_deploy'] >= limit:
            return ok(self, {'error':'Limit harian habis'}, 429)

        token = os.environ.get('VERCEL_TOKEN')
        # Simulasi jika token tidak ada
        if not token:
            pid = ''.join(random.choices(string.ascii_lowercase+string.digits, k=10))
            url = f"{project_name}-{pid}.vercel.app"
            logs = load_json('logs.json')
            logs.append({'user':self.user,'time':datetime.datetime.now().isoformat(),'project_name':project_name,'project_id':pid,'url':f'https://{url}','status':'success'})
            save_json('logs.json', logs)
            u['daily_deploy'] += 1
            u['total_deploy'] += 1
            save_json('users.json', users)
            return ok(self, {'url':f'https://{url}','project_id':pid,'status':'READY'})

        try:
            import requests
            resp = requests.post('https://api.vercel.com/v9/projects',
                                 headers={'Authorization':f'Bearer {token}'},
                                 json={'name':project_name})
            if not resp.ok:
                raise Exception(resp.json().get('error',{}).get('message'))
            proj = resp.json()
            deploy_body = {
                'name':project_name, 'project':proj['id'], 'target':'production',
                'files': files if files else [{'file':'index.html','data':base64.b64encode(html_code.encode()).decode(),'encoding':'base64'}]
            }
            dr = requests.post('https://api.vercel.com/v13/deployments',
                               headers={'Authorization':f'Bearer {token}'},
                               json=deploy_body)
            if not dr.ok:
                raise Exception(dr.json().get('error',{}).get('message'))
            dd = dr.json()
            did, url, status = dd['id'], dd.get('url',''), dd.get('readyState','')
            for _ in range(30):
                if status in ('READY','ERROR'): break
                time.sleep(2)
                sr = requests.get(f'https://api.vercel.com/v13/deployments/{did}',
                                  headers={'Authorization':f'Bearer {token}'})
                if sr.ok:
                    sd = sr.json()
                    status = sd['readyState']
                    url = sd.get('url',url)
                    if sd.get('alias'): url = sd['alias'][0]
            final_url = f'https://{url}'
            logs = load_json('logs.json')
            logs.append({'user':self.user,'time':datetime.datetime.now().isoformat(),'project_name':project_name,'project_id':proj['id'],'url':final_url,'status':'success' if status=='READY' else 'failed'})
            save_json('logs.json', logs)
            u['daily_deploy'] += 1
            u['total_deploy'] += 1
            save_json('users.json', users)
            ok(self, {'url':final_url,'project_id':proj['id'],'status':status})
        except Exception as e:
            logs = load_json('logs.json')
            logs.append({'user':self.user,'time':datetime.datetime.now().isoformat(),'project_name':project_name,'project_id':'','url':'','status':'failed','error':str(e)})
            save_json('logs.json', logs)
            ok(self, {'error':str(e)}, 500)

    def logs(self):
        return ok(self, [l for l in load_json('logs.json') if l['user']==self.user][-50:])

    # Chat (tidak berubah)
    def chat_get(self):
        chat_id = self.path.split('/')[-1]
        return ok(self, load_json('chats.json').get(chat_id, []))

    def chat_send(self):
        d = body(self)
        to, txt = d.get('to'), d.get('text')
        if not to or not txt: return ok(self, {'error':'Pesan kosong'}, 400)
        cid = '_'.join(sorted([self.user, to]))
        chats = load_json('chats.json')
        chats.setdefault(cid, []).append({
            'sender':self.user, 'text':txt,
            'time':datetime.datetime.now().strftime('%H:%M'),
            'date':datetime.datetime.now().strftime('%Y-%m-%d'),
            'location':d.get('location')
        })
        save_json('chats.json', chats)
        ok(self, {'message':'Terkirim'}, 201)

    # Owner (tidak berubah)
    def owner_users(self):
        users = load_json('users.json')
        today = datetime.date.today().isoformat()
        return ok(self, [{
            'username':n, 'role':u['role'],
            'limit':u['custom_limit'] or (300 if u['role']=='premium' else 10),
            'daily_deploy':u['daily_deploy'] if u['daily_date']==today else 0,
            'banned':u['banned'], 'ban_reason':u['ban_reason']
        } for n,u in users.items() if n!=OWNER_EMAIL])

    def owner_update(self):
        name = self.path.split('/')[-1]
        d = body(self)
        users = load_json('users.json')
        if name not in users: return ok(self, {'error':'User not found'}, 404)
        if 'role' in d: users[name]['role'] = d['role']
        if 'limit' in d: users[name]['custom_limit'] = d['limit']
        save_json('users.json', users)
        ok(self, {'message':'Updated'})

    def owner_ban(self):
        name = self.path.split('/')[-2]
        reason = body(self).get('reason','')
        users = load_json('users.json')
        if name in users:
            users[name]['banned'] = True
            users[name]['ban_reason'] = reason
            save_json('users.json', users)
        ok(self, {'message':'Banned'})

    def owner_unban(self):
        name = self.path.split('/')[-2]
        users = load_json('users.json')
        if name in users:
            users[name]['banned'] = False
            users[name]['ban_reason'] = ''
            save_json('users.json', users)
        ok(self, {'message':'Unbanned'})

    def owner_create(self):
        d = body(self)
        email, pw, name = d.get('email'), d.get('password'), d.get('name')
        if not email or not pw: return ok(self, {'error':'Data tidak lengkap'}, 400)
        users = load_json('users.json')
        if email in users: return ok(self, {'error':'Email sudah ada'}, 400)
        users[email] = {
            'password_hash':hash_pw(pw), 'name':name,
            'security_question':'', 'security_answer_hash':'',
            'role':'user', 'trial_start':time.time(),
            'total_deploy':0, 'daily_deploy':0, 'daily_date':'',
            'banned':False, 'ban_reason':'', 'custom_limit':None, 'messages':[]
        }
        save_json('users.json', users)
        ok(self, {'message':'User dibuat'}, 201)

    def owner_broadcast(self):
        msg = body(self).get('message','')
        if not msg: return ok(self, {'error':'Pesan kosong'}, 400)
        users = load_json('users.json')
        for n in users:
            if n != OWNER_EMAIL:
                users[n].setdefault('messages', []).append(msg)
        save_json('users.json', users)
        ok(self, {'message':'Broadcast terkirim'})

    def owner_del(self):
        pid = body(self).get('project_id','')
        token = os.environ.get('VERCEL_TOKEN')
        if token:
            try:
                import requests
                requests.delete(f'https://api.vercel.com/v9/projects/{pid}',
                                headers={'Authorization':f'Bearer {token}'})
            except: pass
        ok(self, {'message':'Project dihapus'})

    def export_users(self):
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Disposition','attachment; filename=users.json')
        self.send_header('Access-Control-Allow-Origin','*')
        self.end_headers()
        self.wfile.write(json.dumps(load_json('users.json'), indent=2).encode())

    def import_users(self):
        try:
            imported = json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))))
            users = load_json('users.json')
            for n,d in imported.items():
                if n not in users: users[n] = d
                else:
                    for k in ['password_hash','security_question','security_answer_hash','role','trial_start','total_deploy','custom_limit']:
                        if k in d: users[n][k] = d[k]
            save_json('users.json', users)
            ok(self, {'message':'Import berhasil'})
        except:
            ok(self, {'error':'Format tidak valid'}, 400)

if __name__ == '__main__':
    server = HTTPServer((HOST, PORT), H)
    print(f'Server running on port {PORT}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()