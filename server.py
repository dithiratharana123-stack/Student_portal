#!/usr/bin/env python3
import os, re, json, time, hmac, base64, hashlib, secrets, sqlite3, urllib.parse, urllib.request, urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def load_dotenv():
    f=ROOT / '.env'
    if not f.exists(): return
    for line in f.read_text(encoding='utf-8').splitlines():
        line=line.strip()
        if not line or line.startswith('#') or '=' not in line: continue
        k,v=line.split('=',1); k=k.strip(); v=v.strip().strip('\"').strip("'")
        os.environ.setdefault(k,v)


load_dotenv()
DATA = ROOT / 'data'; DATA.mkdir(exist_ok=True)
DB_PATH = DATA / 'kcss.sqlite'
HOST = os.getenv('HOST', '127.0.0.1')
PORT = int(os.getenv('PORT', '3000'))
BASE_URL = os.getenv('BASE_URL', f'http://{HOST}:{PORT}').rstrip('/')
SESSION_SECRET = os.getenv('SESSION_SECRET', 'change-this-secret-in-production').encode()
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@kcss.local').lower()
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'ChangeMe123!')
ADMIN_NAME = os.getenv('ADMIN_NAME', 'KCSS Administrator')

ASSETS = ROOT / 'assets'; PUBLIC = ROOT / 'public'


def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    return c


def phash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    out = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 180_000)
    return 'pbkdf2$180000$%s$%s' % (base64.urlsafe_b64encode(salt).decode(), base64.urlsafe_b64encode(out).decode())


def verify(password, stored):
    try:
        _, iters, s, h = stored.split('$', 3)
        salt = base64.urlsafe_b64decode(s.encode()); expected = base64.urlsafe_b64decode(h.encode())
        got = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, int(iters))
        return hmac.compare_digest(got, expected)
    except Exception:
        return False


def init_db():
    c = db()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        role TEXT NOT NULL DEFAULT 'student' CHECK(role IN ('admin','student')),
        provider TEXT,
        provider_id TEXT,
        class_name TEXT,
        stream TEXT,
        phone TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS marks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL,
        grade INTEGER NOT NULL CHECK(grade IN (12,13)),
        test_name TEXT NOT NULL,
        subject TEXT NOT NULL,
        mark REAL NOT NULL CHECK(mark >= 0 AND mark <= 100000),
        max_mark REAL NOT NULL DEFAULT 100,
        term TEXT,
        recorded_by INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(student_id, grade, test_name, subject),
        FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(recorded_by) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS oauth_states (
        state TEXT PRIMARY KEY, provider TEXT NOT NULL, created_at INTEGER NOT NULL
    );
    ''')
    row = c.execute('SELECT id FROM users WHERE lower(email)=?', (ADMIN_EMAIL,)).fetchone()
    if not row:
        c.execute('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)', (ADMIN_NAME, ADMIN_EMAIL, phash(ADMIN_PASSWORD), 'admin'))
    c.commit(); c.close()


def q(s): return urllib.parse.quote(str(s), safe='')

def esc(v):
    s = '' if v is None else str(v)
    return (s.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;').replace("'",'&#39;'))


def signed_session(uid):
    raw = str(uid).encode(); sig = hmac.new(SESSION_SECRET, raw, hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(raw).decode() + '.' + sig


def unsign_session(token):
    try:
        a, sig = token.split('.', 1); raw = base64.urlsafe_b64decode(a.encode())
        if hmac.compare_digest(sig, hmac.new(SESSION_SECRET, raw, hashlib.sha256).hexdigest()): return int(raw.decode())
    except Exception: pass
    return None


def stats_for(marks):
    if not marks:
        return {'average':0,'best':0,'count':0,'subjects':[]}
    vals=[]; by={}
    for m in marks:
        maxm=float(m['max_mark']) or 0
        pct=(float(m['mark'])/maxm)*100 if maxm else 0
        vals.append(pct); by.setdefault(m['subject'],[]).append(pct)
    subs=[{'subject':k,'average':round(sum(v)/len(v),1)} for k,v in by.items()]
    subs.sort(key=lambda x:x['average'], reverse=True)
    return {'average':round(sum(vals)/len(vals),1),'best':round(max(vals),1),'count':len(vals),'subjects':subs}

def calculate_rankings(student_id=None):
    """Calculate grade-wise school ranking and z-score from each student's average percentage."""
    c=db()
    rows=c.execute("SELECT u.id,u.name,m.grade,m.mark,m.max_mark FROM users u JOIN marks m ON m.student_id=u.id WHERE u.role='student' ORDER BY m.grade,u.id").fetchall()
    c.close()
    by_grade={}
    for r in rows:
        g=int(r['grade']); maxm=float(r['max_mark']) or 0
        pct=(float(r['mark'])/maxm)*100 if maxm else 0
        by_grade.setdefault(g,{}).setdefault(r['id'],{'name':r['name'],'values':[]})['values'].append(pct)
    result={}
    for g, students in by_grade.items():
        scores=[]
        for sid,v in students.items():
            if v['values']:
                scores.append((sid, sum(v['values'])/len(v['values'])))
        if not scores: continue
        all_scores=[score for _,score in scores]
        mean=sum(all_scores)/len(all_scores)
        variance=sum((x-mean)**2 for x in all_scores)/len(all_scores)
        sd=variance**0.5
        ordered=sorted(scores, key=lambda x:(-x[1], x[0]))
        rank_map={}; prev=None; rank=0
        for idx,(sid,score) in enumerate(ordered,1):
            if prev is None or abs(score-prev)>1e-9: rank=idx
            rank_map[sid]=rank; prev=score
        for sid,score in ordered:
            result[(sid,g)]={'average':round(score,1),'rank':rank_map[sid],'total_students':len(ordered),'z_score':round((score-mean)/sd,2) if sd else 0.0,'mean':round(mean,1),'sd':round(sd,1)}
    if student_id is None: return result
    return {g:result[(student_id,g)] for (sid,g) in result if sid==student_id}


def term_summary(marks, grade, term):
    subset=[m for m in marks if int(m['grade'])==int(grade) and (m['term'] or '').strip().lower()==term.lower()]
    st=stats_for(subset)
    avg=st['average']
    if not subset:
        readiness='Waiting for marks'; pass_est='—'; grade_hint='—'
    elif avg >= 75:
        readiness='Strong readiness'; pass_est='High'; grade_hint='A / B range'
    elif avg >= 60:
        readiness='Good readiness'; pass_est='Moderate–High'; grade_hint='B / C range'
    elif avg >= 45:
        readiness='Needs improvement'; pass_est='Moderate'; grade_hint='C / S range'
    else:
        readiness='Needs strong improvement'; pass_est='Low'; grade_hint='Below S-range target'
    return {'marks':subset,'stats':st,'readiness':readiness,'pass_est':pass_est,'grade_hint':grade_hint}


def render_term_sheet(grade, term_label, info):
    rows=''.join(f'''<tr><td>{esc(m['test_name'])}</td><td>{esc(m['subject'])}</td><td><strong>{esc(m['mark'])} / {esc(m['max_mark'])}</strong></td><td>{esc(m['created_at'])}</td></tr>''' for m in info['marks'])
    if not rows:
        rows='<tr><td colspan="4" class="empty">No marks have been published for this term yet.</td></tr>'
    return f'''<section class="panel term-sheet"><div class="panel-head"><div><span class="term-tag">Grade {grade} · {esc(term_label)}</span><h2>{esc(term_label)} Mark Sheet</h2><p class="muted">This sheet remains visible even before the admin publishes marks for the term.</p></div><div class="analytics-kpis"><span>Average <b>{info['stats']['average']}%</b></span><span>Best <b>{info['stats']['best']}%</b></span><span>Readiness <b>{esc(info['readiness'])}</b></span></div></div><div class="table"><table><thead><tr><th>Assessment</th><th>Subject</th><th>Mark</th><th>Updated</th></tr></thead><tbody>{rows}</tbody></table></div><div class="term-insight"><div><span>Pass-readiness estimate</span><strong>{esc(info['pass_est'])}</strong></div><div><span>Likely grade zone</span><strong>{esc(info['grade_hint'])}</strong></div><div><span>A/L readiness</span><strong>{esc(info['readiness'])}</strong></div><small>Portal estimate only; actual A/L eligibility/results depend on the official examination and school requirements.</small></div></section>'''


def edit_mark_form(uid, marks, selected_id=None):
    selected=None
    if selected_id:
        selected=next((m for m in marks if int(m['id'])==int(selected_id)), None)
    s=dict(selected) if selected else {'grade':12,'term':'Term 1','test_name':'Term Test 1','subject':'','mark':'','max_mark':100}
    mode='Update Mark' if selected else 'Add / Update Mark'
    hidden=f'<input type="hidden" name="mark_id" value="{int(s["id"])}">' if selected else ''
    cancel=f' <a class="ghost" href="/admin/student/{uid}">Cancel edit</a>' if selected else ''
    return f'''<div class="panel"><div class="panel-head"><div><h2>{mode}</h2><p class="muted">Save a new assessment or edit an existing one.</p></div></div><form method="post" action="/admin/student/{uid}/mark" class="form-grid">{hidden}<div class="two"><label>Grade<select name="grade"><option value="12" {'selected' if int(s.get('grade',12))==12 else ''}>Grade 12</option><option value="13" {'selected' if int(s.get('grade',12))==13 else ''}>Grade 13</option></select></label><label>Term<select name="term"><option {'selected' if (s.get('term') or '').lower()=='term 1' else ''}>Term 1</option><option {'selected' if (s.get('term') or '').lower()=='term 2' else ''}>Term 2</option><option {'selected' if (s.get('term') or '').lower()=='term 3' else ''}>Term 3</option></select></label></div><label>Test name<input name="test_name" value="{esc(s.get('test_name',''))}" placeholder="Term Test 1" required></label><label>Subject<input name="subject" value="{esc(s.get('subject',''))}" placeholder="Chemistry" required></label><div class="two"><label>Mark<input type="number" name="mark" min="0" step="0.01" value="{esc(s.get('mark',''))}" required></label><label>Max mark<input type="number" name="max_mark" min="1" step="0.01" value="{esc(s.get('max_mark',100))}" required></label></div><div class="btn-row"><button class="primary">{'Update mark' if selected else 'Save mark'}</button>{cancel}</div></form></div>'''

CSS = '''
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700;800&display=swap');
:root{--blue:#1677ff;--blue2:#0c4ec4;--ink:#0a1b36;--muted:#637794;--line:rgba(30,95,170,.14);--glass:rgba(255,255,255,.68);--shadow:0 24px 70px rgba(27,79,145,.16)}
*{box-sizing:border-box}body{margin:0;font-family:Poppins,system-ui,sans-serif;color:var(--ink);background:linear-gradient(135deg,#fff 0%,#f4f9ff 48%,#edf6ff 100%);min-height:100vh}
body:before,body:after{content:"";position:fixed;border-radius:50%;filter:blur(4px);pointer-events:none;z-index:-1}.before{ }
body:before{width:420px;height:420px;left:-160px;top:-120px;background:radial-gradient(circle,rgba(22,119,255,.18),transparent 65%);animation:float 10s ease-in-out infinite}.body:after{width:380px;height:380px}
@keyframes float{50%{transform:translate(80px,60px) scale(1.06)}to{transform:translate(0,0)}}
.auth{display:grid;place-items:center;min-height:100vh;padding:24px;position:relative;overflow:hidden}.orb{position:absolute;border-radius:50%;filter:blur(1px);opacity:.4;animation:drift 12s ease-in-out infinite}.o1{width:300px;height:300px;background:radial-gradient(circle,rgba(18,107,255,.35),transparent 68%);top:5%;left:4%}.o2{width:280px;height:280px;background:radial-gradient(circle,rgba(77,166,255,.22),transparent 68%);bottom:0;right:3%;animation-delay:-4s}.o3{width:180px;height:180px;background:radial-gradient(circle,rgba(120,198,255,.18),transparent 70%);top:45%;right:28%;animation-delay:-7s}@keyframes drift{50%{transform:translate(25px,-20px) scale(1.08)}}
.login-shell{width:min(1080px,100%);display:grid;grid-template-columns:1.05fr .95fr;gap:22px;position:relative}.brand-card,.login-card,.panel,.metric{background:var(--glass);border:1px solid rgba(255,255,255,.95);box-shadow:var(--shadow);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px)}
.brand-card{border-radius:32px;padding:48px;min-height:620px;display:flex;flex-direction:column;justify-content:center;position:relative;overflow:hidden}.brand-card:after{content:"";position:absolute;width:320px;height:320px;border:1px solid rgba(22,119,255,.14);border-radius:50%;right:-120px;bottom:-120px;box-shadow:0 0 0 42px rgba(22,119,255,.04),0 0 0 84px rgba(22,119,255,.025)}
.logo{width:94px;height:94px;border-radius:24px;object-fit:contain;background:#fff;padding:10px;box-shadow:0 18px 45px rgba(15,92,177,.14);animation:pulse 4s ease-in-out infinite}.logo.small{width:48px;height:48px;border-radius:14px;padding:4px}@keyframes pulse{50%{transform:translateY(-4px);box-shadow:0 22px 55px rgba(15,92,177,.18)}}
.eyebrow{font-size:12px;font-weight:800;letter-spacing:2px;color:var(--blue);margin:18px 0 8px}.brand-card h1{font-size:clamp(36px,5vw,62px);line-height:1.02;margin:0 0 16px}.muted{color:var(--muted)}.brand-points{display:grid;gap:10px;margin-top:28px}.brand-points span{padding:12px 15px;border-radius:14px;background:rgba(247,252,255,.7);border:1px solid var(--line);font-size:13px}.login-card{border-radius:32px;padding:42px}.login-card h2{margin:0 0 8px;font-size:30px}.sub{color:var(--muted);font-size:13px;margin-bottom:26px}.field{display:grid;gap:7px;margin-bottom:14px}.field label,label{font-size:12px;font-weight:700}.field input,input,select{width:100%;border:1px solid var(--line);background:rgba(255,255,255,.82);border-radius:14px;padding:13px 14px;font:inherit;outline:0;color:var(--ink)}.field input:focus,input:focus,select:focus{border-color:rgba(22,119,255,.45);box-shadow:0 0 0 4px rgba(22,119,255,.09)}
.primary{width:100%;border:0;border-radius:14px;padding:14px 16px;background:linear-gradient(135deg,var(--blue),var(--blue2));color:white;font:700 14px Poppins;cursor:pointer;box-shadow:0 15px 28px rgba(22,119,255,.22);transition:.2s}.primary:hover{transform:translateY(-2px)}.socials{display:grid;grid-template-columns:1fr 1fr 1fr;gap:9px;margin-top:14px}.social{display:flex;justify-content:center;align-items:center;gap:7px;text-decoration:none;padding:12px;border:1px solid var(--line);border-radius:13px;background:rgba(255,255,255,.72);font-size:12px;font-weight:700;color:var(--ink);transition:.2s}.social:hover{transform:translateY(-2px);box-shadow:0 10px 22px rgba(20,77,135,.1)}.note{font-size:11px;color:var(--muted);margin-top:14px}.error{background:#fff0f2;color:#b42318;border:1px solid #ffd4da;padding:11px 13px;border-radius:12px;font-size:12px;margin-bottom:14px}
.topbar{position:sticky;top:0;z-index:10;display:flex;justify-content:space-between;align-items:center;padding:14px 24px;background:rgba(255,255,255,.72);backdrop-filter:blur(18px);border-bottom:1px solid var(--line)}.brand-mini{display:flex;align-items:center;gap:11px}.brand-mini b{display:block;font-size:14px}.brand-mini small{display:block;font-size:10px;color:var(--muted)}.top-actions{display:flex;align-items:center;gap:10px}.pill{padding:9px 12px;border:1px solid var(--line);border-radius:12px;background:rgba(255,255,255,.72);font-size:12px}.ghost,.danger{border:1px solid var(--line);border-radius:11px;padding:9px 12px;background:rgba(255,255,255,.72);font:600 12px Poppins;cursor:pointer}.danger{color:#b42318;border-color:#ffd3d9}
.dashboard{width:min(1240px,calc(100% - 32px));margin:22px auto 54px}.hero{display:flex;justify-content:space-between;gap:16px;align-items:center;margin-bottom:18px}.hero h1{font-size:clamp(28px,4vw,46px);margin:0 0 5px}.score{width:110px;height:110px;border-radius:50%;background:conic-gradient(var(--blue) calc(var(--score)*1%),rgba(22,119,255,.09) 0);display:grid;place-items:center;position:relative;flex:0 0 auto}.score:before{content:"";position:absolute;inset:9px;border-radius:50%;background:white}.score strong,.score span{position:relative;z-index:1}.score span{font-size:8px;display:block;text-align:center;color:var(--muted)}.score strong{font-size:17px}
.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:16px}.metric{border-radius:20px;padding:18px}.metric span{font-size:11px;color:var(--muted)}.metric strong{display:block;font-size:28px;margin-top:4px}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}.panel{border-radius:24px;padding:22px;margin-bottom:16px}.panel h2{margin:0 0 5px;font-size:19px}.panel-head{display:flex;justify-content:space-between;gap:15px;align-items:flex-start;margin-bottom:16px}.form-grid{display:grid;gap:12px}.two{display:grid;grid-template-columns:1fr 1fr;gap:12px}.btn-row{display:flex;gap:8px;flex-wrap:wrap}.table{overflow:auto}.table table{border-collapse:collapse;width:100%;font-size:12px}.table th,.table td{text-align:left;padding:12px 9px;border-bottom:1px solid var(--line);white-space:nowrap}.table th{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.8px}.name-link{color:var(--blue);text-decoration:none;font-weight:700}.chip{display:inline-flex;padding:6px 9px;border-radius:999px;background:rgba(22,119,255,.08);color:var(--blue);font-weight:700}.bars{display:grid;gap:12px}.bar-line{display:grid;grid-template-columns:100px 1fr 52px;gap:10px;align-items:center;font-size:11px}.bar{height:11px;border-radius:99px;background:#edf4ff;overflow:hidden}.bar i{display:block;height:100%;width:0;border-radius:99px;background:linear-gradient(90deg,#4ea5ff,#126dfb);animation:grow 1.1s ease forwards}@keyframes grow{to{width:var(--w)}}.empty{padding:30px;text-align:center;color:var(--muted);font-size:13px}.small-note{font-size:11px;color:var(--muted)}
@media(max-width:860px){.login-shell,.grid2{grid-template-columns:1fr}.brand-card{min-height:auto;padding:34px}.login-card{padding:30px}.metrics{grid-template-columns:1fr}.hero{align-items:flex-start}.dashboard{width:min(100% - 20px,1240px)}.topbar{padding:12px 14px}.pill{display:none}}
@media(max-width:520px){.brand-card{display:none}.auth{padding:12px}.login-card{border-radius:24px;padding:22px}.socials{grid-template-columns:1fr}.two{grid-template-columns:1fr}.panel{padding:17px}.score{width:86px;height:86px}.hero h1{font-size:30px}}.brand-mark{width:42px;height:42px;border-radius:14px;display:grid;place-items:center;background:linear-gradient(135deg,#0b63ce,#58b6ff);color:#fff;font-weight:800;box-shadow:0 10px 24px rgba(16,110,210,.22)}.brand-emblem{width:72px;height:72px;border-radius:24px;display:grid;place-items:center;background:linear-gradient(135deg,#0b63ce,#55baff);color:#fff;font-size:30px;box-shadow:0 18px 38px rgba(16,110,210,.22);animation:pulse 4s ease-in-out infinite}.login-shell.single{grid-template-columns:minmax(320px,620px);justify-content:center}.login-tabs{display:grid;grid-template-columns:1fr 1fr;background:#edf6ff;border-radius:14px;padding:4px;margin:0 0 18px}.login-tabs a{text-decoration:none;text-align:center;padding:10px;border-radius:10px;color:#5b7892;font-size:12px;font-weight:700}.login-tabs a.active{background:#fff;color:#126dcc;box-shadow:0 5px 16px rgba(18,108,204,.08)}.create-account{font-size:12px;text-align:center;color:#6f8296;margin:14px 0}.create-account a{color:#0d68c5;text-decoration:none;font-weight:700}.rank-card{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.rank-item{padding:15px;border-radius:18px;background:linear-gradient(145deg,rgba(245,250,255,.9),rgba(229,242,255,.65));border:1px solid rgba(73,145,214,.13)}.rank-item span{display:block;font-size:10px;color:#71879a;text-transform:uppercase;letter-spacing:.08em}.rank-item strong{display:block;font-size:24px;margin-top:4px;color:#0b63ce}.rank-item small{display:block;color:#71879a;font-size:10px;margin-top:3px}.term-tag{display:inline-flex;padding:6px 10px;border-radius:999px;background:#eaf5ff;color:#176fc0;font-size:10px;font-weight:800;letter-spacing:.08em;text-transform:uppercase}.term-sheet{border:1px solid rgba(64,141,214,.14);box-shadow:0 18px 44px rgba(30,94,160,.08)}.section-title{margin-top:24px;background:rgba(245,250,255,.72)}.term-insight{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:16px}.term-insight>div{padding:13px;border-radius:15px;background:rgba(238,247,255,.7);border:1px solid var(--line)}.term-insight span{display:block;font-size:9px;color:#71879a;text-transform:uppercase;letter-spacing:.08em}.term-insight strong{display:block;margin-top:4px;font-size:15px;color:#0c63be}.term-insight small{grid-column:1/-1;color:#8090a0;font-size:10px}.analytics-kpis{display:flex;gap:8px;flex-wrap:wrap}.analytics-kpis span{padding:8px 10px;border-radius:999px;background:#f3f8fd;color:#72859a;font-size:10px}.analytics-kpis b{color:#1168bd}.admin-back{margin-bottom:14px}.back-btn{text-decoration:none;display:inline-flex;align-items:center}.edit-link{color:#0b68c8;text-decoration:none;font-weight:800;margin-right:10px}.row-actions{display:flex;align-items:center;gap:4px}.row-actions form{display:inline}.link-danger{border:0;background:transparent;color:#c23838;font:700 11px Poppins;cursor:pointer;padding:0}.ghost{display:inline-flex;align-items:center;justify-content:center;text-decoration:none;color:#2a5b83;background:#f2f7fc;border:1px solid var(--line);border-radius:12px;padding:11px 14px;font:700 12px Poppins}@media(max-width:900px){.rank-card{grid-template-columns:repeat(2,1fr)}}@media(max-width:560px){.rank-card{grid-template-columns:1fr}.term-insight{grid-template-columns:1fr}.term-insight small{grid-column:auto}}
'''


def layout(title, body, session_user=None):
    nav = ''
    if session_user:
        nav = f'''<header class="topbar"><div class="brand-mini"><div class="brand-mark">KCSS</div><div><b>KCSS Science Society</b><small>Student Portal</small></div></div><div class="top-actions"><span class="pill">{esc(session_user['name'])}</span><form method="post" action="/logout"><button class="ghost">Logout</button></form></div></header>'''
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title><style>{CSS}</style></head><body>{nav}{body}</body></html>'''


def login_page(error=None, mode='student'):
    mode = 'admin' if mode == 'admin' else 'student'
    oauth = {'google': bool(os.getenv('GOOGLE_CLIENT_ID')), 'facebook': bool(os.getenv('FACEBOOK_APP_ID')), 'apple': bool(os.getenv('APPLE_CLIENT_ID'))}
    social = ''
    social += f'<a class="social" href="/auth/google">Google</a>' if oauth['google'] else '<a class="social" href="/login?oauth=google">Google</a>'
    social += f'<a class="social" href="/auth/facebook">Facebook</a>' if oauth['facebook'] else '<a class="social" href="/login?oauth=facebook">Facebook</a>'
    social += f'<a class="social" href="/auth/apple">Apple</a>' if oauth['apple'] else '<a class="social" href="/login?oauth=apple">Apple</a>'
    msg = f'<div class="error">{esc(error)}</div>' if error else ''
    tabs = f'''<div class="login-tabs"><a class="{'active' if mode=='student' else ''}" href="/login?mode=student">Student Login</a><a class="{'active' if mode=='admin' else ''}" href="/login?mode=admin">Admin Login</a></div>'''
    create_link = '<p class="create-account">New student? <a href="/register">Create an account</a></p>' if mode=='student' else ''
    body=f'''
    <main class="auth"><div class="orb o1"></div><div class="orb o2"></div><div class="orb o3"></div>
    <section class="login-shell"><div class="brand-card"><div class="brand-emblem">✦</div><div class="eyebrow">KCSS • SCIENCE SOCIETY</div><h1>Learn.<br>Explore.<br>Innovate.</h1><p class="muted">A premium academic portal for students, assessment records and Science Society activities.</p><div class="brand-points"><span>✦ Grade 12 & 13 mark sheets</span><span>✦ Animated performance analysis</span><span>✦ Secure student & admin access</span></div></div>
    <div class="login-card"><h2>{'Student' if mode=='student' else 'Admin'} Login</h2><div class="sub">Sign in to your KCSS Science Society portal.</div>{tabs}{msg}<form method="post" action="/login"><input type="hidden" name="login_role" value="{mode}"><div class="field"><label>Email</label><input type="email" name="email" autocomplete="username" required></div><div class="field"><label>Password</label><input type="password" name="password" autocomplete="current-password" required></div><button class="primary">Sign in securely</button></form>{create_link}<div class="note">Or continue with</div><div class="socials">{social}</div><div class="note">OAuth buttons become fully live after you add provider credentials in <b>.env</b>.</div></div></section></main>'''
    return layout('KCSS • Login', body)

def register_page(error=None):
    msg = f'<div class="error">{esc(error)}</div>' if error else ''
    body=f'''<main class="auth"><div class="orb o1"></div><div class="orb o2"></div><section class="login-shell single"><div class="login-card register-card"><div class="eyebrow">KCSS • SCIENCE SOCIETY</div><h2>Create Student Account</h2><div class="sub">Register your own student portal account.</div>{msg}<form method="post" action="/register" class="profile-form"><div class="two"><label>Full name<input name="name" required></label><label>Email<input type="email" name="email" required></label></div><div class="two"><label>Password<input type="password" name="password" minlength="8" required></label><label>Confirm password<input type="password" name="confirm_password" minlength="8" required></label></div><div class="two"><label>Class<input name="class_name" placeholder="12-A"></label><label>Stream<input name="stream" placeholder="Physical Science"></label></div><label>Phone<input name="phone" placeholder="07x xxx xxxx"></label><button class="primary">Create student account</button></form><p class="create-account">Already have an account? <a href="/login?mode=student">Student Login</a></p></div></section></main>'''
    return layout('KCSS • Create Account', body)


def get_user(uid):
    if not uid: return None
    c=db(); row=c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone(); c.close(); return row


def login_required(handler, admin=False):
    def wrapped(self, *args, **kwargs):
        u=self.current_user()
        if not u: return self.redirect('/login')
        if admin and u['role']!='admin': return self.send(403, 'Forbidden')
        return handler(self, *args, **kwargs)
    return wrapped

class App(BaseHTTPRequestHandler):
    def send(self, code, body, content_type='text/html; charset=utf-8', headers=None, cookies=None):
        data = body.encode('utf-8') if isinstance(body,str) else body
        self.send_response(code); self.send_header('Content-Type', content_type); self.send_header('Content-Length',str(len(data))); self.send_header('Cache-Control','no-store')
        if headers:
            for k,v in headers.items(): self.send_header(k,v)
        if cookies:
            for c in cookies: self.send_header('Set-Cookie',c)
        self.end_headers(); self.wfile.write(data)
    def redirect(self, path, cookies=None): self.send(302,'',headers={'Location':path},cookies=cookies)
    def parse_body(self):
        n=int(self.headers.get('Content-Length','0')); raw=self.rfile.read(n).decode('utf-8'); return {k:v[-1] for k,v in urllib.parse.parse_qs(raw,keep_blank_values=True).items()}
    def current_user(self):
        cookie=SimpleCookie(self.headers.get('Cookie','')); token=cookie.get('kcss_session'); uid=unsign_session(token.value) if token else None; return get_user(uid)
    def cookie(self, value, max_age=28800): return f'kcss_session={value}; Max-Age={max_age}; Path=/; HttpOnly; SameSite=Lax'
    def do_GET(self):
        p=urllib.parse.urlparse(self.path); path=p.path; qs=urllib.parse.parse_qs(p.query)
        if path=='/' : return self.redirect('/admin' if self.current_user() and self.current_user()['role']=='admin' else '/portal' if self.current_user() else '/login')
        if path=='/login':
            msg=None
            if qs.get('oauth'): msg='OAuth provider is not configured yet. Add its credentials to .env to activate this button.'
            return self.send(200,login_page(msg, qs.get('mode',['student'])[0]))
        if path=='/register': return self.send(200,register_page())
        if path.startswith('/assets/'):
            return self.serve_file(ASSETS / Path(path[len('/assets/'):]).name)
        if path.startswith('/admin/student/') and path.endswith('/analysis'):
            uid=int(path.split('/')[3]); return self.json_analysis(uid)
        if path.startswith('/admin/student/') and path.count('/')==3:
            uid=int(path.split('/')[3]); return self.admin_student(uid)
        if path=='/admin': return self.admin_dashboard()
        if path=='/portal': return self.portal()
        if path=='/auth/google/callback': return self.oauth_callback('google', qs)
        if path=='/auth/facebook/callback': return self.oauth_callback('facebook', qs)
        if path=='/auth/google': return self.oauth_start('google')
        if path=='/auth/facebook': return self.oauth_start('facebook')
        if path=='/auth/apple': return self.oauth_start('apple')
        return self.send(404,'Not found')
    def serve_file(self, f):
        if not f.exists(): return self.send(404,'Not found')
        data=f.read_bytes(); ext=f.suffix.lower(); ct={'.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.svg':'image/svg+xml'}.get(ext,'application/octet-stream'); return self.send(200,data,ct,headers={'Cache-Control':'public, max-age=3600'})
    def do_POST(self):
        path=urllib.parse.urlparse(self.path).path; data=self.parse_body(); u=self.current_user()
        if path=='/login':
            requested_role='admin' if data.get('login_role')=='admin' else 'student'
            c=db(); row=c.execute('SELECT * FROM users WHERE lower(email)=lower(?)',(data.get('email',''),)).fetchone(); c.close()
            if not row or row['role']!=requested_role or not row['password_hash'] or not verify(data.get('password',''),row['password_hash']): return self.send(401,login_page('Invalid credentials for the selected login type.', requested_role))
            return self.redirect('/admin' if row['role']=='admin' else '/portal', cookies=[self.cookie(signed_session(row['id']))])
        if path=='/register': return self.register_student(data)
        if path=='/logout': return self.redirect('/login', cookies=[self.cookie('',0)])
        if path=='/portal/profile':
            if not u: return self.redirect('/login')
            c=db(); c.execute('UPDATE users SET name=?,class_name=?,stream=?,phone=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(data.get('name',''),data.get('class_name',''),data.get('stream',''),data.get('phone',''),u['id'])); c.commit(); c.close(); return self.redirect('/portal')
        if path=='/admin/student/create': return self.create_student(data,u)
        m=re.match(r'^/admin/student/(\d+)/profile$',path)
        if m: return self.update_student(int(m.group(1)),data,u)
        m=re.match(r'^/admin/student/(\d+)/mark$',path)
        if m: return self.save_mark(int(m.group(1)),data,u)
        m=re.match(r'^/admin/student/(\d+)/mark/(\d+)/delete$',path)
        if m: return self.delete_mark(int(m.group(1)), int(m.group(2)), u)
        m=re.match(r'^/admin/student/(\d+)/delete$',path)
        if m: return self.delete_student(int(m.group(1)),u)
        if path=='/auth/apple/callback': return self.oauth_callback('apple',data)
        if path.startswith('/auth/') and path.endswith('/callback'): return self.oauth_callback(path.split('/')[2], urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query))
        return self.send(404,'Not found')
    @login_required
    def portal(self):
        u=self.current_user()
        c=db(); marks=c.execute('SELECT * FROM marks WHERE student_id=? ORDER BY grade, CASE term WHEN "Term 1" THEN 1 WHEN "Term 2" THEN 2 WHEN "Term 3" THEN 3 ELSE 9 END, created_at DESC',(u['id'],)).fetchall(); c.close()
        stats=stats_for(marks); rankings=calculate_rankings(u['id'])
        bars=''.join(f'<div class="bar-line"><span>{esc(x["subject"])}</span><div class="bar"><i style="--w:{x["average"]}%"></i></div><b>{x["average"]}%</b></div>' for x in stats['subjects']) or '<div class="empty">No marks recorded yet.</div>'
        rank_cards=''.join(f'<div class="rank-item"><span>Grade {g} School Rank</span><strong>#{r["rank"]}</strong><small>of {r["total_students"]} · Avg {r["average"]}%</small></div><div class="rank-item"><span>Grade {g} Z-score</span><strong>{r["z_score"]:+.2f}</strong><small>Mean {r["mean"]}% · SD {r["sd"]}%</small></div>' for g,r in sorted(rankings.items())) or '<div class="empty">Rank and Z-score will appear after marks are published.</div>'
        grade12=''.join(render_term_sheet(12,t,term_summary(marks,12,t)) for t in ('Term 1','Term 2','Term 3'))
        grade13=''.join(render_term_sheet(13,t,term_summary(marks,13,t)) for t in ('Term 1','Term 2','Term 3'))
        body=f'''<main class="dashboard"><section class="hero"><div><div class="eyebrow">WELCOME BACK</div><h1>{esc(u['name'])}</h1><p class="muted">Your Science Society academic record, in one place.</p></div><div class="score" style="--score:{stats['average']}"><div><strong>{stats['average']}%</strong><span>Overall average</span></div></div></section><section class="metrics"><div class="metric"><span>Assessments</span><strong>{stats['count']}</strong></div><div class="metric"><span>Best score</span><strong>{stats['best']}%</strong></div><div class="metric"><span>Access</span><strong>STUDENT</strong></div></section><section class="panel"><div class="panel-head"><div><h2>School ranking &amp; Z-score</h2><p class="muted">Calculated separately within your Grade using the marks currently published.</p></div></div><div class="rank-card">{rank_cards}</div></section><section class="grid2"><div class="panel"><div class="panel-head"><div><h2>My profile</h2><p class="muted">Keep your details up to date.</p></div></div><form method="post" action="/portal/profile" class="form-grid"><label>Full name<input name="name" value="{esc(u['name'])}" required></label><label>Class<input name="class_name" value="{esc(u['class_name'] or '')}" placeholder="12-A"></label><label>Stream<input name="stream" value="{esc(u['stream'] or '')}" placeholder="Physical Science"></label><label>Phone<input name="phone" value="{esc(u['phone'] or '')}" placeholder="07x xxx xxxx"></label><button class="primary">Update profile</button></form></div><div class="panel"><div class="panel-head"><div><h2>Subject analysis</h2><p class="muted">Animated average by subject from all published assessments.</p></div></div><div class="bars">{bars}</div></div></section><section class="panel section-title"><div class="panel-head"><div><span class="term-tag">GRADE 12</span><h2>Grade 12 Term Mark Sheets</h2><p class="muted">All three terms are always visible. A term fills with data as soon as the admin publishes marks for that term.</p></div></div></section>{grade12}<section class="panel section-title"><div class="panel-head"><div><span class="term-tag">GRADE 13</span><h2>Grade 13 Term Mark Sheets</h2><p class="muted">All three terms are always visible, with the same per-term analysis and readiness estimate.</p></div></div></section>{grade13}</main>'''
        return self.send(200,layout('KCSS • Student Portal',body,u))
    def admin_dashboard(self):
        u=self.current_user()
        if not u: return self.redirect('/login')
        if u['role']!='admin': return self.send(403,'Forbidden')
        c=db(); students=c.execute('''SELECT u.*,COUNT(m.id) mark_count FROM users u LEFT JOIN marks m ON m.student_id=u.id WHERE u.role='student' GROUP BY u.id ORDER BY u.name''').fetchall(); totals=c.execute("SELECT COUNT(*) n FROM users WHERE role='student'").fetchone()['n']; marks=c.execute('SELECT COUNT(*) n FROM marks').fetchone()['n']; c.close()
        rows=''.join(f'''<tr><td><a class="name-link" href="/admin/student/{s['id']}">{esc(s['name'])}</a></td><td>{esc(s['email'])}</td><td>{esc(s['class_name'] or '—')}</td><td>{esc(s['stream'] or '—')}</td><td>{esc(s['phone'] or '—')}</td><td><span class="chip">{s['mark_count']}</span></td><td><form method="post" action="/admin/student/{s['id']}/delete" onsubmit="return confirm('Delete this student account?')"><button class="danger">Delete</button></form></td></tr>''' for s in students) or '<tr><td colspan="7" class="empty">No students yet.</td></tr>'
        body=f'''<main class="dashboard"><section class="hero"><div><div class="eyebrow">ADMIN DASHBOARD</div><h1>Manage the society portal.</h1><p class="muted">Students, accounts, marks and performance analysis.</p></div><div class="score" style="--score:100"><div><strong>ADMIN</strong><span>CONTROL</span></div></div></section><section class="metrics"><div class="metric"><span>Students</span><strong>{totals}</strong></div><div class="metric"><span>Marks recorded</span><strong>{marks}</strong></div><div class="metric"><span>Access level</span><strong>ADMIN</strong></div></section><section class="grid2"><div class="panel"><div class="panel-head"><div><h2>Create student</h2><p class="muted">Add a new portal account.</p></div></div><form method="post" action="/admin/student/create" class="form-grid"><label>Full name<input name="name" required></label><label>Email<input type="email" name="email" required></label><label>Temporary password<input type="password" name="password" minlength="8" required></label><div class="two"><label>Class<input name="class_name" placeholder="12-A"></label><label>Stream<input name="stream" placeholder="Physical Science"></label></div><label>Phone<input name="phone" placeholder="07x xxx xxxx"></label><button class="primary">Create student account</button></form></div><div class="panel"><div class="panel-head"><div><h2>Access model</h2><p class="muted">Student records and admin controls.</p></div></div><div class="brand-points"><span>Student → view marks · update profile · see analysis</span><span>Admin → create / delete users · update profiles · enter marks</span><span>Grade 12 + Grade 13 → separate records in the same mark sheet</span></div></div></section><section class="panel"><div class="panel-head"><div><h2>Student accounts</h2><p class="muted">Click a student's full name to enter marks and inspect analysis.</p></div></div><div class="table"><table><thead><tr><th>Student</th><th>Email</th><th>Class</th><th>Stream</th><th>Phone</th><th>Marks</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table></div></section></main>'''
        return self.send(200,layout('KCSS • Admin Dashboard',body,u))
    def admin_student(self, uid):
        u=self.current_user()
        if not u: return self.redirect('/login')
        if u['role']!='admin': return self.send(403,'Forbidden')
        parsed=urllib.parse.urlparse(self.path); qs=urllib.parse.parse_qs(parsed.query); edit_id=qs.get('edit',[''])[0]
        c=db(); s=c.execute("SELECT * FROM users WHERE id=? AND role='student'",(uid,)).fetchone(); marks=c.execute('SELECT * FROM marks WHERE student_id=? ORDER BY grade, CASE term WHEN "Term 1" THEN 1 WHEN "Term 2" THEN 2 WHEN "Term 3" THEN 3 ELSE 9 END, created_at DESC',(uid,)).fetchall(); c.close()
        if not s:return self.send(404,'Student not found')
        rankings=calculate_rankings(uid)
        rank_cards=''.join(f'<div class="rank-item"><span>Grade {g} School Rank</span><strong>#{r["rank"]}</strong><small>of {r["total_students"]} · Avg {r["average"]}%</small></div><div class="rank-item"><span>Grade {g} Z-score</span><strong>{r["z_score"]:+.2f}</strong><small>Mean {r["mean"]}% · SD {r["sd"]}%</small></div>' for g,r in sorted(rankings.items())) or '<div class="empty">Rank and Z-score will appear after marks are recorded.</div>'
        st=stats_for(marks); bars=''.join(f'<div class="bar-line"><span>{esc(x["subject"])}</span><div class="bar"><i style="--w:{x["average"]}%"></i></div><b>{x["average"]}%</b></div>' for x in st['subjects']) or '<div class="empty">No marks yet.</div>'
        row_parts=[]
        for m in marks:
            row_parts.append(f"""<tr><td>G{m['grade']}</td><td>{esc(m['term'] or '—')}</td><td>{esc(m['test_name'])}</td><td>{esc(m['subject'])}</td><td><strong>{esc(m['mark'])} / {esc(m['max_mark'])}</strong></td><td class="row-actions"><a class="edit-link" href="/admin/student/{uid}?edit={int(m['id'])}">Edit</a><form method="post" action="/admin/student/{uid}/mark/{int(m['id'])}/delete" onsubmit="return confirm('Delete this mark?')"><button class="link-danger">Delete</button></form></td></tr>""")
        rows=''.join(row_parts) or '<tr><td colspan="6" class="empty">No assessments yet.</td></tr>'
        # Fix route typo defensively in generated row.
        rows=rows.replace(f'/admin/student/{uid}/mark/', f'/admin/student/{uid}/mark/').replace("'/delete", "/delete")
        grade12=''.join(render_term_sheet(12,t,term_summary(marks,12,t)) for t in ('Term 1','Term 2','Term 3'))
        grade13=''.join(render_term_sheet(13,t,term_summary(marks,13,t)) for t in ('Term 1','Term 2','Term 3'))
        body=f'''<main class="dashboard"><div class="admin-back"><a class="ghost back-btn" href="/admin">← Back to Admin Dashboard</a></div><section class="hero"><div><div class="eyebrow">STUDENT RECORD</div><h1>{esc(s['name'])}</h1><p class="muted">{esc(s['class_name'] or 'Class not set')} · {esc(s['stream'] or 'Stream not set')} · {esc(s['email'])}</p></div><div class="score" style="--score:{st['average']}"><div><strong>{st['average']}%</strong><span>Overall average</span></div></div></section><section class="grid2"><div class="panel"><div class="panel-head"><div><h2>Profile</h2><p class="muted">Update this student's details.</p></div></div><form method="post" action="/admin/student/{uid}/profile" class="form-grid"><label>Full name<input name="name" value="{esc(s['name'])}" required></label><label>Email<input type="email" name="email" value="{esc(s['email'])}" required></label><label>Class<input name="class_name" value="{esc(s['class_name'] or '')}" placeholder="12-A"></label><label>Stream<input name="stream" value="{esc(s['stream'] or '')}" placeholder="Physical Science"></label><label>Phone<input name="phone" value="{esc(s['phone'] or '')}" placeholder="07x xxx xxxx"></label><button class="primary">Save profile</button></form></div>{edit_mark_form(uid,marks,int(edit_id) if edit_id.isdigit() else None)}</section><section class="panel"><div class="panel-head"><div><h2>School rank &amp; Z-score</h2><p class="muted">Rankings recalculate immediately after mark updates.</p></div></div><div class="rank-card">{rank_cards}</div></section><section class="panel"><div class="panel-head"><div><h2>Performance analysis</h2><p class="muted">Animated analysis from recorded assessments.</p></div></div><div class="bars">{bars}</div></section><section class="panel"><div class="panel-head"><div><h2>Current marks</h2><p class="muted">Click Edit on any row to replace the existing mark.</p></div></div><div class="table"><table><thead><tr><th>Grade</th><th>Term</th><th>Test</th><th>Subject</th><th>Mark</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table></div></section><section class="panel section-title"><div class="panel-head"><div><span class="term-tag">GRADE 12</span><h2>Grade 12 Term Mark Sheets</h2></div></div></section>{grade12}<section class="panel section-title"><div class="panel-head"><div><span class="term-tag">GRADE 13</span><h2>Grade 13 Term Mark Sheets</h2></div></div></section>{grade13}</main>'''
        return self.send(200,layout(f'{s["name"]} • KCSS Admin',body,u))
    def register_student(self,data):
        name=data.get('name','').strip(); email=data.get('email','').strip().lower(); password=data.get('password',''); confirm=data.get('confirm_password','')
        if not name or not email or len(password)<8 or password!=confirm:
            return self.send(400,register_page('Please enter a valid name/email, use at least 8 password characters, and make both passwords match.'))
        try:
            c=db(); c.execute('INSERT INTO users(name,email,password_hash,role,class_name,stream,phone) VALUES(?,?,?,?,?,?,?)',(name,email,phash(password),'student',data.get('class_name','').strip(),data.get('stream','').strip(),data.get('phone','').strip())); c.commit(); uid=c.execute('SELECT last_insert_rowid()').fetchone()[0]; c.close()
            return self.redirect('/portal', cookies=[self.cookie(signed_session(uid))])
        except sqlite3.IntegrityError:
            return self.send(400,register_page('An account with that email already exists.'))

    def create_student(self,data,u):
        if not u or u['role']!='admin': return self.send(403,'Forbidden')
        try:
            c=db(); c.execute('INSERT INTO users(name,email,password_hash,role,class_name,stream,phone) VALUES(?,?,?,?,?,?,?)',(data.get('name','').strip(),data.get('email','').strip().lower(),phash(data.get('password','')), 'student',data.get('class_name',''),data.get('stream',''),data.get('phone',''))); c.commit(); c.close(); return self.redirect('/admin')
        except sqlite3.IntegrityError as e: return self.send(400,layout('Error',f'<main class="dashboard"><div class="panel"><h2>Could not create student</h2><p class="muted">That email may already exist.</p><a class="name-link" href="/admin">Back</a></div></main>',u))
    def update_student(self,uid,data,u):
        if not u or u['role']!='admin': return self.send(403,'Forbidden')
        c=db(); c.execute('UPDATE users SET name=?,email=?,class_name=?,stream=?,phone=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND role=\'student\'',(data.get('name',''),data.get('email','').lower(),data.get('class_name',''),data.get('stream',''),data.get('phone',''),uid)); c.commit(); c.close(); return self.redirect(f'/admin/student/{uid}')
    def save_mark(self,uid,data,u):
        if not u or u['role']!='admin': return self.send(403,'Forbidden')
        try:
            grade=int(data.get('grade','12')); mark=float(data.get('mark','0')); maxm=float(data.get('max_mark','100')); test=data.get('test_name','').strip(); subject=data.get('subject','').strip(); term=data.get('term','Term 1').strip(); mark_id=int(data.get('mark_id','0') or 0)
        except Exception:
            return self.send(400,'Invalid mark')
        if grade not in (12,13) or term not in ('Term 1','Term 2','Term 3') or maxm<=0 or mark<0 or mark>maxm or not test or not subject: return self.send(400,'Invalid mark')
        c=db()
        try:
            if mark_id:
                row=c.execute('SELECT id FROM marks WHERE id=? AND student_id=?',(mark_id,uid)).fetchone()
                if not row:
                    c.close(); return self.send(404,'Mark record not found')
                conflict=c.execute('SELECT id FROM marks WHERE student_id=? AND grade=? AND test_name=? AND subject=? AND id<>?',(uid,grade,test,subject,mark_id)).fetchone()
                if conflict:
                    c.close(); return self.send(400,'Another mark already uses the same grade, test and subject. Edit that record instead.')
                c.execute('UPDATE marks SET grade=?,test_name=?,subject=?,mark=?,max_mark=?,term=?,recorded_by=?,created_at=CURRENT_TIMESTAMP WHERE id=? AND student_id=?',(grade,test,subject,mark,maxm,term,u['id'],mark_id,uid))
            else:
                c.execute('''INSERT INTO marks(student_id,grade,test_name,subject,mark,max_mark,term,recorded_by) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(student_id,grade,test_name,subject) DO UPDATE SET mark=excluded.mark,max_mark=excluded.max_mark,term=excluded.term,recorded_by=excluded.recorded_by,created_at=CURRENT_TIMESTAMP''',(uid,grade,test,subject,mark,maxm,term,u['id']))
            c.commit()
        except sqlite3.IntegrityError:
            c.rollback(); c.close(); return self.send(400,'Could not save the mark. Check for duplicate assessment details.')
        c.close(); return self.redirect(f'/admin/student/{uid}')
    def delete_mark(self,uid,mark_id,u):
        if not u or u['role']!='admin': return self.send(403,'Forbidden')
        c=db(); c.execute('DELETE FROM marks WHERE id=? AND student_id=?',(mark_id,uid)); c.commit(); c.close(); return self.redirect(f'/admin/student/{uid}')
    def delete_student(self,uid,u):
        if not u or u['role']!='admin': return self.send(403,'Forbidden')
        c=db(); c.execute("DELETE FROM users WHERE id=? AND role='student'",(uid,)); c.commit(); c.close(); return self.redirect('/admin')
    def json_analysis(self,uid):
        u=self.current_user();
        if not u or u['role']!='admin': return self.send(403,'Forbidden')
        c=db(); marks=c.execute('SELECT * FROM marks WHERE student_id=? ORDER BY grade,created_at',(uid,)).fetchall(); c.close(); return self.send(200,json.dumps(stats_for(marks)), 'application/json')
    def oauth_start(self,provider):
        cfg={'google':os.getenv('GOOGLE_CLIENT_ID'),'facebook':os.getenv('FACEBOOK_APP_ID'),'apple':os.getenv('APPLE_CLIENT_ID')}
        client=cfg.get(provider)
        if not client: return self.redirect('/login?oauth='+provider)
        state=secrets.token_urlsafe(24); c=db(); c.execute('INSERT INTO oauth_states(state,provider,created_at) VALUES(?,?,?)',(state,provider,int(time.time()))); c.commit(); c.close()
        if provider=='google': url='https://accounts.google.com/o/oauth2/v2/auth?'+urllib.parse.urlencode({'client_id':client,'redirect_uri':BASE_URL+'/auth/google/callback','response_type':'code','scope':'openid email profile','state':state,'access_type':'offline'})
        elif provider=='facebook': url='https://www.facebook.com/v20.0/dialog/oauth?'+urllib.parse.urlencode({'client_id':client,'redirect_uri':BASE_URL+'/auth/facebook/callback','response_type':'code','scope':'email,public_profile','state':state})
        else: url='https://appleid.apple.com/auth/authorize?'+urllib.parse.urlencode({'client_id':client,'redirect_uri':BASE_URL+'/auth/apple/callback','response_type':'code id_token','response_mode':'form_post','scope':'name email','state':state})
        return self.redirect(url)
    def oauth_callback(self,provider,data):
        code=(data.get('code',[''])[0] if isinstance(data.get('code'),list) else data.get('code',''))
        state=(data.get('state',[''])[0] if isinstance(data.get('state'),list) else data.get('state',''))
        if not code: return self.redirect('/login')
        c=db(); st=c.execute('SELECT provider,created_at FROM oauth_states WHERE state=?',(state,)).fetchone(); c.execute('DELETE FROM oauth_states WHERE state=?',(state,)); c.commit(); c.close()
        if not st or st['provider']!=provider or int(time.time())-st['created_at']>600: return self.send(400,login_page('OAuth session expired. Please try again.'))
        try:
            if provider=='google':
                token=self.form_post('https://oauth2.googleapis.com/token', {'code':code,'client_id':os.getenv('GOOGLE_CLIENT_ID',''),'client_secret':os.getenv('GOOGLE_CLIENT_SECRET',''),'redirect_uri':BASE_URL+'/auth/google/callback','grant_type':'authorization_code'})
                prof=self.http_json('https://openidconnect.googleapis.com/v1/userinfo', {'Authorization':'Bearer '+token['access_token']})
                user=self.oauth_user(prof.get('email'),prof.get('sub'),prof.get('name') or 'KCSS Student','google')
            elif provider=='facebook':
                tok=self.http_json('https://graph.facebook.com/v20.0/oauth/access_token?'+urllib.parse.urlencode({'client_id':os.getenv('FACEBOOK_APP_ID',''),'client_secret':os.getenv('FACEBOOK_APP_SECRET',''),'redirect_uri':BASE_URL+'/auth/facebook/callback','code':code}))
                prof=self.http_json('https://graph.facebook.com/me?'+urllib.parse.urlencode({'fields':'id,name,email','access_token':tok['access_token']}))
                user=self.oauth_user(prof.get('email'),prof.get('id'),prof.get('name') or 'KCSS Student','facebook')
            elif provider=='apple':
                secret=self.apple_client_secret()
                token=self.form_post('https://appleid.apple.com/auth/token', {'client_id':os.getenv('APPLE_CLIENT_ID',''),'client_secret':secret,'code':code,'grant_type':'authorization_code','redirect_uri':BASE_URL+'/auth/apple/callback'})
                payload=self.decode_unverified_jwt_payload(token.get('id_token',''))
                email=payload.get('email'); pid=payload.get('sub'); user=self.oauth_user(email,pid,email.split('@')[0] if email else 'KCSS Student','apple')
            else:
                return self.redirect('/login')
            return self.redirect('/admin' if user['role']=='admin' else '/portal', cookies=[self.cookie(signed_session(user['id']))])
        except Exception as e:
            print('OAuth error:',provider,e)
            return self.send(400,login_page(f'{provider.title()} login could not be completed. Check the provider credentials and callback URL.'))
    def form_post(self,url,form):
        req=urllib.request.Request(url,data=urllib.parse.urlencode(form).encode(),headers={'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'})
        with urllib.request.urlopen(req,timeout=12) as r: return json.loads(r.read().decode())
    def http_json(self,url,headers=None):
        req=urllib.request.Request(url,headers=headers or {})
        with urllib.request.urlopen(req,timeout=12) as r: return json.loads(r.read().decode())
    def oauth_user(self,email,provider_id,name,provider):
        c=db(); user=c.execute('SELECT * FROM users WHERE provider=? AND provider_id=?',(provider,provider_id)).fetchone() if provider_id else None
        if not user and email: user=c.execute('SELECT * FROM users WHERE lower(email)=lower(?)',(email,)).fetchone()
        if not user:
            c.execute('INSERT INTO users(name,email,role,provider,provider_id) VALUES(?,?,?,?,?)',(name,email or f'{provider_id}@{provider}.local','student',provider,provider_id)); c.commit(); user=c.execute('SELECT * FROM users WHERE id=?',(c.execute('SELECT last_insert_rowid()').fetchone()[0],)).fetchone()
        elif not user['provider_id']:
            c.execute('UPDATE users SET provider=?,provider_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(provider,provider_id,user['id'])); c.commit(); user=c.execute('SELECT * FROM users WHERE id=?',(user['id'],)).fetchone()
        c.close(); return user
    def apple_client_secret(self):
        try:
            import jwt
        except ImportError: raise RuntimeError('Install PyJWT for Apple login')
        key=os.getenv('APPLE_PRIVATE_KEY','').replace('\\n','\n')
        now=int(time.time())
        return jwt.encode({'iss':os.getenv('APPLE_TEAM_ID'),'iat':now,'exp':now+86400*180,'aud':'https://appleid.apple.com','sub':os.getenv('APPLE_CLIENT_ID')}, key, algorithm='ES256', headers={'kid':os.getenv('APPLE_KEY_ID','')})
    def decode_unverified_jwt_payload(self,token):
        try:
            import jwt
            jwks=jwt.PyJWKClient('https://appleid.apple.com/auth/keys')
            key=jwks.get_signing_key_from_jwt(token).key
            return jwt.decode(token,key=key,algorithms=['RS256','ES256'],audience=os.getenv('APPLE_CLIENT_ID'),issuer='https://appleid.apple.com')
        except ImportError: raise RuntimeError('Install PyJWT and cryptography for Apple login')

init_db()

if __name__=='__main__':
    print(f'KCSS Science Society Portal running at {BASE_URL}')
    print(f'Admin: {ADMIN_EMAIL} / {ADMIN_PASSWORD}')
    ThreadingHTTPServer((HOST,PORT),App).serve_forever()
