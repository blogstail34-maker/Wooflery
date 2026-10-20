const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');


// Load local .env settings without requiring an extra package. Existing shell
// environment variables take precedence over values in the .env file.
const envFile = path.join(__dirname, '.env');
if (fs.existsSync(envFile)) {
  for (const rawLine of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match || Object.prototype.hasOwnProperty.call(process.env, match[1])) continue;
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    process.env[match[1]] = value;
  }
}

const app = express();
app.use((req, res, next) => {
  const allowedOrigin = 'https://blogstail34-maker.github.io';

  if (req.headers.origin === allowedOrigin) {
    res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET, POST, PUT, PATCH, DELETE, OPTIONS'
    );
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization'
    );
  }

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  next();
});

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET;
// Only this configured username may publish or manage artist-gallery works.
const ARTIST_USERNAME = String(process.env.ARTIST_USERNAME || '').trim().toLowerCase();
console.log(`[artist-gallery] Publishing ${ARTIST_USERNAME ? `enabled for @${ARTIST_USERNAME}` : 'disabled — set ARTIST_USERNAME in .env'}.`);
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.warn('WARNING: Set SESSION_SECRET to a random value of at least 32 characters in .env before production use.');
}
const root = __dirname;
const uploadDir = path.join(root, 'uploads');
fs.mkdirSync(uploadDir, {recursive:true});
fs.mkdirSync(path.join(root,'data'), {recursive:true});
const db = new Database(path.join(root,'data','wooflery.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL,
 display_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
 bio TEXT NOT NULL DEFAULT '', avatar TEXT, status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS dogs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id), name TEXT NOT NULL,
 breed TEXT NOT NULL DEFAULT '', age TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
 image TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'published' CHECK(status IN ('published','hidden','pending_deletion')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS artworks (
 id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', image TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'published' CHECK(status IN ('published','hidden')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_artworks_status_date ON artworks(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_artworks_owner_date ON artworks(owner_id, created_at DESC);
CREATE TABLE IF NOT EXISTS likes (
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 dog_id INTEGER NOT NULL REFERENCES dogs(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(user_id,dog_id)
);
CREATE TABLE IF NOT EXISTS comments (
 id INTEGER PRIMARY KEY AUTOINCREMENT, dog_id INTEGER NOT NULL REFERENCES dogs(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id), content TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'visible' CHECK(status IN ('visible','hidden','deleted')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS reports (
 id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_id INTEGER NOT NULL REFERENCES users(id), target_type TEXT NOT NULL,
 target_id INTEGER NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','resolved','rejected')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER REFERENCES users(id), action TEXT NOT NULL,
 entity_type TEXT NOT NULL, entity_id INTEGER, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_dogs_status_date ON dogs(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comments_dog ON comments(dog_id, status, created_at DESC);
`);

// Seed sample dogs only once, retaining the original artwork and visual identity.
if (db.prepare('SELECT COUNT(*) n FROM dogs').get().n === 0) {
  const seed = [
    ['Roblox Srt','my BF','- years','Рисунок скина из роблокса','img/Pict1.jpg'],
    ['Luna','Mixed breed','4 years','Gentle, curious, and happiest when she has a soft place to nap.','img/Pict2.jpg'],
    ['Biscuit','Corgi','1 year','Small paws, big opinions, and an endless supply of joy.','img/Pict3.jpg'],
    ['Pepper','Border collie','3 years','A clever companion who loves games and new friends.','img/Pict4.jpg'],
    ['Coco','Poodle mix','5 years','A little elegance with a whole lot of personality.','img/Pict5.jpg'],
    ['Scout','Beagle','8 months','Professional sniff-explorer and amateur cuddle expert.','img/Pict6.jpg']
  ];
  const ins = db.prepare("INSERT INTO dogs(owner_id,name,breed,age,description,image) VALUES(1,?,?,?,?,?)");
  // A demo owner is created with a random password and cannot be used to log in.
  db.prepare("INSERT OR IGNORE INTO users(id,username,email,password_hash,display_name,role) VALUES(1,'wooflery-demo','demo@wooflery.invalid',?,'Wooflery Community','admin')").run(bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), 10));
  for (const dog of seed) ins.run(...dog);
}

app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'","https://fonts.googleapis.com"],fontSrc:["'self'","https://fonts.gstatic.com","data:"],imgSrc:["'self'","data:","https:"],scriptSrc:["'self'"],connectSrc:["'self'","https://wooflery.onrender.com"]}}}));
app.use(express.json({limit:'100kb'}));
app.use(express.urlencoded({extended:false, limit:'20kb'}));
app.use(session({store:new SQLiteStore({db:'sessions.sqlite',dir:path.join(root,'data')}),secret:SESSION_SECRET || crypto.randomBytes(48).toString('hex'),resave:false,saveUninitialized:false,cookie:{
  httpOnly:true,
  sameSite:'none',
  secure:true,
  maxAge:7*24*60*60*1000
}}));
app.use('/css', express.static(path.join(root,'css'), {fallthrough:false, maxAge:'1d'}));
app.use('/js', express.static(path.join(root,'js'), {fallthrough:false, maxAge:'1d'}));
app.use('/img', express.static(path.join(root,'img'), {fallthrough:false, maxAge:'7d'}));
app.use('/uploads', express.static(uploadDir, {fallthrough:false, maxAge:'1d'}));
for (const page of ['index.html','Gallery.html','Join.html','Contact.html','admin.html','my-dogs.html','my-works.html','Works.html','privacy.html']) app.get('/'+page, (req,res)=>res.sendFile(path.join(root,page)));
app.get('/', (req,res)=>res.sendFile(path.join(root,'index.html')));
const authLimiter = rateLimit({windowMs:15*60*1000, limit:15, standardHeaders:true, legacyHeaders:false, message:{error:'Too many attempts. Please try again later.'}});
const writeLimiter = rateLimit({windowMs:60*1000, limit:30, standardHeaders:true, legacyHeaders:false, message:{error:'You are doing that too often. Please slow down.'}});
const upload = multer({storage:multer.diskStorage({destination:uploadDir,filename:(req,file,cb)=>cb(null,crypto.randomUUID()+path.extname(file.originalname).toLowerCase())}),limits:{fileSize:5*1024*1024, files:1},fileFilter:(req,file,cb)=>{const ext=path.extname(file.originalname).toLowerCase(); const mimeOk=['image/jpeg','image/png','image/webp'].includes(file.mimetype); const extOk=['.jpg','.jpeg','.png','.webp'].includes(ext); cb(mimeOk&&extOk?null:new Error('Only JPEG, PNG and WebP images are allowed.'), mimeOk&&extOk);}});
function currentUser(req){ if(!req.session.userId) return null; return db.prepare('SELECT id,username,email,display_name,role,bio,avatar,status,created_at FROM users WHERE id=?').get(req.session.userId) || null; }
function requireAuth(req,res,next){const u=currentUser(req); if(!u) return res.status(401).json({error:'Please sign in to continue.'}); if(u.status!=='active') return res.status(403).json({error:'This account is suspended.'}); req.user=u; next();}
function requireAdmin(req,res,next){const u=currentUser(req); if(!u || u.role!=='admin' || u.status!=='active') return res.status(403).json({error:'Administrator access required.'}); req.user=u; next();}
function isArtist(user){return !!(user && ARTIST_USERNAME && user.username.toLowerCase()===ARTIST_USERNAME && user.status==='active');}
function requireArtist(req,res,next){const u=currentUser(req);if(!u || u.status!=='active')return res.status(401).json({error:'Please sign in to continue.'});if(!isArtist(u))return res.status(403).json({error:'Only the designated artist account can publish and manage artworks.'});req.user=u;next();}
function audit(actor,action,type,id){db.prepare('INSERT INTO audit_logs(actor_id,action,entity_type,entity_id) VALUES(?,?,?,?)').run(actor||null,action,type,id||null);}
function safeDog(row, userId){return {...row, liked:!!(userId && db.prepare('SELECT 1 FROM likes WHERE user_id=? AND dog_id=?').get(userId,row.id)), like_count:db.prepare('SELECT COUNT(*) n FROM likes WHERE dog_id=?').get(row.id).n, comment_count:db.prepare("SELECT COUNT(*) n FROM comments WHERE dog_id=? AND status='visible'").get(row.id).n};}
app.get('/api/me',(req,res)=>{const user=currentUser(req);res.json({user,canPublishWorks:isArtist(user)});});
app.post('/api/register',authLimiter,async(req,res)=>{
 const {username,email,password,displayName}=req.body||{};
 if(typeof username!=='string'||! /^[a-zA-Z0-9_]{3,24}$/.test(username)) return res.status(400).json({error:'Username must be 3–24 letters, numbers or underscores.'});
 if(typeof email!=='string'||! /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>254) return res.status(400).json({error:'Enter a valid email address.'});
 if(typeof password!=='string'||password.length<10||password.length>128) return res.status(400).json({error:'Password must contain 10–128 characters.'});
 const name=String(displayName||username).trim().slice(0,60); if(!name) return res.status(400).json({error:'Enter a display name.'});
 try {const hash=await bcrypt.hash(password,12); const r=db.prepare('INSERT INTO users(username,email,password_hash,display_name) VALUES(?,?,?,?)').run(username,email,hash,name); req.session.userId=r.lastInsertRowid; res.status(201).json({user:currentUser(req)});} catch(e){if(String(e.message).includes('UNIQUE')) return res.status(409).json({error:'That username or email is already registered.'}); throw e;}
});
app.post('/api/login',authLimiter,async(req,res)=>{const {login,password}=req.body||{}; if(typeof login!=='string'||typeof password!=='string') return res.status(400).json({error:'Enter your username/email and password.'}); const u=db.prepare('SELECT * FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE').get(login,login); if(!u||!(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:'Incorrect sign-in details.'}); if(u.status!=='active') return res.status(403).json({error:'This account is suspended.'}); req.session.userId=u.id; res.json({user:currentUser(req)});});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/dogs',(req,res)=>{const q=String(req.query.q||'').trim().slice(0,100); const sort=['newest','popular','name'].includes(req.query.sort)?req.query.sort:'newest'; const where="d.status='published' AND (d.name LIKE ? OR d.breed LIKE ? OR d.description LIKE ?)"; const order=sort==='popular'?'likes DESC, d.created_at DESC':sort==='name'?'d.name COLLATE NOCASE ASC':'d.created_at DESC'; const rows=db.prepare(`SELECT d.*,u.username owner_username,u.display_name owner_name,(SELECT COUNT(*) FROM likes l WHERE l.dog_id=d.id) likes FROM dogs d JOIN users u ON u.id=d.owner_id WHERE ${where} ORDER BY ${order}`).all(`%${q}%`,`%${q}%`,`%${q}%`); res.json({dogs:rows.map(r=>safeDog(r,req.session.userId))});});
app.get('/api/dogs/:id',(req,res)=>{const row=db.prepare("SELECT d.*,u.username owner_username,u.display_name owner_name FROM dogs d JOIN users u ON u.id=d.owner_id WHERE d.id=? AND d.status='published'").get(Number(req.params.id)); if(!row)return res.status(404).json({error:'Dog profile not found.'}); const comments=db.prepare("SELECT c.id,c.content,c.created_at,u.username,u.display_name FROM comments c JOIN users u ON u.id=c.user_id WHERE c.dog_id=? AND c.status='visible' ORDER BY c.created_at DESC LIMIT 100").all(row.id); res.json({dog:safeDog(row,req.session.userId),comments});});
app.post('/api/dogs',requireAuth,writeLimiter,upload.single('image'),(req,res)=>{if(!req.file)return res.status(400).json({error:'Choose a dog photo to upload.'}); const {name,breed,age,description}=req.body; if(!String(name||'').trim()||String(name).length>80){fs.unlinkSync(req.file.path);return res.status(400).json({error:'Dog name is required (up to 80 characters).'});} const result=db.prepare('INSERT INTO dogs(owner_id,name,breed,age,description,image) VALUES(?,?,?,?,?,?)').run(req.user.id,String(name).trim(),String(breed||'').slice(0,80),String(age||'').slice(0,40),String(description||'').slice(0,1200),'/uploads/'+req.file.filename); audit(req.user.id,'created','dog',result.lastInsertRowid); res.status(201).json({id:result.lastInsertRowid});});
app.post('/api/dogs/:id/like',requireAuth,writeLimiter,(req,res)=>{const id=Number(req.params.id); const dog=db.prepare("SELECT id FROM dogs WHERE id=? AND status='published'").get(id); if(!dog)return res.status(404).json({error:'Dog profile not found.'}); const existing=db.prepare('SELECT 1 FROM likes WHERE user_id=? AND dog_id=?').get(req.user.id,id); if(existing)db.prepare('DELETE FROM likes WHERE user_id=? AND dog_id=?').run(req.user.id,id); else db.prepare('INSERT OR IGNORE INTO likes(user_id,dog_id) VALUES(?,?)').run(req.user.id,id); res.json({liked:!existing,count:db.prepare('SELECT COUNT(*) n FROM likes WHERE dog_id=?').get(id).n});});
app.post('/api/dogs/:id/comments',requireAuth,writeLimiter,(req,res)=>{const id=Number(req.params.id), content=String(req.body.content||'').trim(); if(content.length<2||content.length>1000)return res.status(400).json({error:'Comment must be between 2 and 1,000 characters.'}); if(!db.prepare("SELECT 1 FROM dogs WHERE id=? AND status='published'").get(id))return res.status(404).json({error:'Dog profile not found.'}); const r=db.prepare('INSERT INTO comments(dog_id,user_id,content) VALUES(?,?,?)').run(id,req.user.id,content); res.status(201).json({id:r.lastInsertRowid});});
app.post('/api/reports',requireAuth,writeLimiter,(req,res)=>{const type=String(req.body.targetType||''), id=Number(req.body.targetId), reason=String(req.body.reason||'').trim().slice(0,500); if(!['dog','comment'].includes(type)||!Number.isInteger(id)||id<1||reason.length<3)return res.status(400).json({error:'Choose a reason for your report.'}); db.prepare('INSERT INTO reports(reporter_id,target_type,target_id,reason) VALUES(?,?,?,?)').run(req.user.id,type,id,reason); res.status(201).json({ok:true});});
app.get('/api/my/dogs',requireAuth,(req,res)=>res.json({dogs:db.prepare('SELECT d.*,(SELECT COUNT(*) FROM likes l WHERE l.dog_id=d.id) like_count FROM dogs d WHERE owner_id=? ORDER BY created_at DESC').all(req.user.id)}));
// Artist portfolio: every upload is tied to the authenticated account.
app.get('/api/works',(req,res)=>{const q=String(req.query.q||'').trim().slice(0,100);const works=db.prepare("SELECT a.id,a.owner_id,a.title,a.description,a.image,a.created_at,u.username owner_username,u.display_name owner_name FROM artworks a JOIN users u ON u.id=a.owner_id WHERE a.status='published' AND (a.title LIKE ? OR a.description LIKE ? OR u.display_name LIKE ? OR u.username LIKE ?) ORDER BY a.created_at DESC").all(`%${q}%`,`%${q}%`,`%${q}%`,`%${q}%`);res.json({works});});
app.get('/api/my/works',requireArtist,(req,res)=>res.json({works:db.prepare('SELECT id,owner_id,title,description,image,status,created_at FROM artworks WHERE owner_id=? ORDER BY created_at DESC').all(req.user.id)}));
app.post('/api/works',requireArtist,writeLimiter,upload.single('image'),(req,res)=>{if(!req.file)return res.status(400).json({error:'Choose an image of your artwork to upload.'});const title=String(req.body.title||'').trim(),description=String(req.body.description||'').trim();if(!title||title.length>100){fs.unlinkSync(req.file.path);return res.status(400).json({error:'Artwork title is required (up to 100 characters).'});}if(description.length>1500){fs.unlinkSync(req.file.path);return res.status(400).json({error:'Description must be 1,500 characters or fewer.'});}const r=db.prepare('INSERT INTO artworks(owner_id,title,description,image) VALUES(?,?,?,?)').run(req.user.id,title,description,'/uploads/'+req.file.filename);audit(req.user.id,'created','artwork',r.lastInsertRowid);res.status(201).json({id:r.lastInsertRowid});});
app.delete('/api/my/works/:id',requireArtist,writeLimiter,(req,res)=>{const id=Number(req.params.id);const work=db.prepare('SELECT id,image FROM artworks WHERE id=? AND owner_id=?').get(id,req.user.id);if(!work)return res.status(404).json({error:'Artwork not found in your account.'});db.prepare('DELETE FROM artworks WHERE id=? AND owner_id=?').run(id,req.user.id);if(work.image.startsWith('/uploads/')){const file=path.join(uploadDir,path.basename(work.image));if(fs.existsSync(file))fs.unlinkSync(file);}audit(req.user.id,'deleted','artwork',id);res.json({ok:true});});
app.get('/api/admin/summary',requireAdmin,(req,res)=>res.json({users:db.prepare('SELECT COUNT(*) n FROM users').get().n,dogs:db.prepare('SELECT COUNT(*) n FROM dogs').get().n,published:db.prepare("SELECT COUNT(*) n FROM dogs WHERE status='published'").get().n,pending:db.prepare("SELECT COUNT(*) n FROM dogs WHERE status='pending_deletion'").get().n,comments:db.prepare("SELECT COUNT(*) n FROM comments WHERE status='visible'").get().n,reports:db.prepare("SELECT COUNT(*) n FROM reports WHERE status='open'").get().n,logs:db.prepare('SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT 15').all()}));
app.get('/api/admin/dogs',requireAdmin,(req,res)=>res.json({dogs:db.prepare('SELECT d.*,u.username owner_username FROM dogs d JOIN users u ON u.id=d.owner_id ORDER BY d.created_at DESC').all()}));
app.patch('/api/admin/dogs/:id',requireAdmin,(req,res)=>{const status=String(req.body.status||'');if(!['published','hidden','pending_deletion'].includes(status))return res.status(400).json({error:'Invalid status.'});const id=Number(req.params.id);db.prepare('UPDATE dogs SET status=? WHERE id=?').run(status,id);audit(req.user.id,'set_status_'+status,'dog',id);res.json({ok:true});});
app.delete('/api/admin/dogs/:id',requireAdmin,(req,res)=>{const id=Number(req.params.id);const dog=db.prepare('SELECT image FROM dogs WHERE id=?').get(id);if(!dog)return res.status(404).json({error:'Dog profile not found.'});db.prepare('DELETE FROM dogs WHERE id=?').run(id);if(dog.image.startsWith('/uploads/')){const file=path.join(uploadDir,path.basename(dog.image));if(fs.existsSync(file))fs.unlinkSync(file);}audit(req.user.id,'deleted','dog',id);res.json({ok:true});});
app.get('/api/admin/users',requireAdmin,(req,res)=>res.json({users:db.prepare('SELECT id,username,email,display_name,role,status,created_at FROM users ORDER BY created_at DESC').all()}));
app.patch('/api/admin/users/:id',requireAdmin,(req,res)=>{const id=Number(req.params.id), status=String(req.body.status||'');if(id===req.user.id)return res.status(400).json({error:'You cannot suspend your own account.'});if(!['active','suspended'].includes(status))return res.status(400).json({error:'Invalid status.'});db.prepare('UPDATE users SET status=? WHERE id=?').run(status,id);audit(req.user.id,'set_user_'+status,'user',id);res.json({ok:true});});
app.get('/api/admin/reports',requireAdmin,(req,res)=>res.json({reports:db.prepare('SELECT r.*,u.username reporter FROM reports r JOIN users u ON u.id=r.reporter_id ORDER BY r.created_at DESC').all()}));
app.patch('/api/admin/reports/:id',requireAdmin,(req,res)=>{const status=String(req.body.status||'');if(!['resolved','rejected','open'].includes(status))return res.status(400).json({error:'Invalid report status.'});db.prepare('UPDATE reports SET status=? WHERE id=?').run(status,Number(req.params.id));audit(req.user.id,'report_'+status,'report',Number(req.params.id));res.json({ok:true});});
app.get('/api/admin/comments',requireAdmin,(req,res)=>res.json({comments:db.prepare('SELECT c.*,u.username,d.name dog_name FROM comments c JOIN users u ON u.id=c.user_id JOIN dogs d ON d.id=c.dog_id ORDER BY c.created_at DESC LIMIT 300').all()}));
app.patch('/api/admin/comments/:id',requireAdmin,(req,res)=>{const status=String(req.body.status||'');if(!['visible','hidden','deleted'].includes(status))return res.status(400).json({error:'Invalid status.'});db.prepare('UPDATE comments SET status=? WHERE id=?').run(status,Number(req.params.id));audit(req.user.id,'comment_'+status,'comment',Number(req.params.id));res.json({ok:true});});
app.get('/api/admin/audit',(req,res)=>{if(!currentUser(req)||currentUser(req).role!=='admin')return res.status(403).json({error:'Administrator access required.'});res.json({logs:db.prepare('SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT 300').all()});});
app.use((err,req,res,next)=>{console.error(err.message);if(err instanceof multer.MulterError)return res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?'Image must be 5 MB or smaller.':'Upload limit exceeded.'});if(err.message&&err.message.includes('Only JPEG'))return res.status(400).json({error:err.message});res.status(500).json({error:'Something went wrong. Please try again.'});});
app.listen(PORT,()=>console.log(`Wooflery running at http://localhost:${PORT}`));
