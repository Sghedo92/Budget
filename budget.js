const {neon}=require('@neondatabase/serverless');
const {randomUUID,createHmac,timingSafeEqual,createHash}=require('node:crypto');
const users={Marco:'MARCO_CODE',Sara:'SARA_CODE'};
const hash=s=>createHash('sha256').update(s).digest();
const equal=(a,b)=>timingSafeEqual(hash(a),hash(b));
const code=u=>process.env[users[u]];
const validUser=u=>typeof u==='string'&&Object.hasOwn(users,u);
const validCode=x=>typeof x==='string'&&/^[a-f0-9]{32}$/.test(x);
const mac=(u,msg)=>createHmac('sha256',code(u)).update('budget-session:'+msg).digest('base64url');
const cookie=(v,age)=>`__Host-budget=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
function account(req){const raw=(req.headers.cookie||'').match(/(?:^|;\s*)__Host-budget=([^;]+)/)?.[1]||'';const [u,exp,signature,extra]=raw.split('.');return !extra&&validUser(u)&&/^\d{10}$/.test(exp||'')&&Number(exp)>Date.now()/1000&&signature&&equal(signature,mac(u,`${u}.${exp}`))?u:null;}
let ready;
async function ensure(sql){if(!ready)ready=sql`CREATE TABLE IF NOT EXISTS budget_movimenti (
 id uuid PRIMARY KEY, owner text NOT NULL CHECK(owner IN ('Marco','Sara')), d date NOT NULL,
 t text NOT NULL CHECK(t IN ('Entrata','Uscita')), c varchar(100) NOT NULL,
 n varchar(200) NOT NULL, a integer NOT NULL CHECK(a>0)
)`.catch(e=>{ready=null;throw e;});await ready;}
function row(r){if(!r||typeof r.d!=='string'||!/^\d{4}-\d\d-\d\d$/.test(r.d)||r.d.startsWith('0000'))return false;const dt=new Date(r.d+'T00:00:00Z');return Number.isFinite(+dt)&&dt.toISOString().slice(0,10)===r.d&&['Entrata','Uscita'].includes(r.t)&&typeof r.c==='string'&&r.c.length>0&&r.c.length<=100&&typeof r.n==='string'&&r.n.length<=200&&Number.isInteger(r.a)&&r.a>0&&r.a<=2147483647;}
module.exports=async(req,res)=>{
 res.setHeader('Cache-Control','private, no-store');
 const send=(status,body={})=>res.status(status).json(body);
 const method=req.method;
 if(!['GET','POST','PATCH','DELETE'].includes(method))return send(405);
 if(method!=='GET'&&(req.headers['sec-fetch-site']!=='same-origin'||!/^application\/json(?:;|$)/i.test(req.headers['content-type']||'')))return send(403);
 const url=process.env.DATABASE_URL||process.env.POSTGRES_URL;
 if(!url||!validCode(code('Marco'))||!validCode(code('Sara'))||code('Marco')===code('Sara'))return send(503);
 try{
 const b=req.body||{};
 if(method==='POST'&&b.action==='logout'){res.setHeader('Set-Cookie',cookie('',0));return send(200);}
 if(method==='POST'&&b.action==='login'){
  if(!validUser(b.user)||!validCode(b.code)||!equal(code(b.user),b.code))return send(401);
  const age=7*24*60*60,token=`${b.user}.${Math.floor(Date.now()/1000)+age}`;
  res.setHeader('Set-Cookie',cookie(`${token}.${mac(b.user,token)}`,age));return send(200);
 }
 const u=account(req);if(!u)return send(401);
 const sql=neon(url);await ensure(sql);
 if(method==='GET'){
  const rows=await sql`SELECT id, owner, to_char(d,'YYYY-MM-DD') AS d, t,c,n,a FROM budget_movimenti ORDER BY d DESC,id`;
  return send(200,{user:u,rows});
 }
 if(b.action!=='movement')return send(400);
 const {r,id}=b;
 if(method!=='DELETE'&&!row(r))return send(400);
 if(method==='POST'){
  await sql`INSERT INTO budget_movimenti(id,owner,d,t,c,n,a) VALUES (${randomUUID()},${u},${r.d},${r.t},${r.c},${r.n},${r.a})`;
  return send(201);
 }
 if(typeof id!=='string'||!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(id))return send(400);
 const changed=method==='PATCH'?await sql`UPDATE budget_movimenti SET d=${r.d},t=${r.t},c=${r.c},n=${r.n},a=${r.a} WHERE id=${id} AND owner=${u} RETURNING id`:await sql`DELETE FROM budget_movimenti WHERE id=${id} AND owner=${u} RETURNING id`;
 return send(changed.length?200:404);
 }catch(e){if(e.code==='23505'&&method==='GET'){ready=null;return send(409);}console.error('Budget request failed:',e.code||e.name);return send(500);}
};
