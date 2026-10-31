// Serveur de comptes Mesinter (Cloudflare Worker + KV, gratuit).
// Il ne stocke qu'un bloc chiffré : il ne peut pas lire tes données.
const CORS={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,PUT,OPTIONS','Access-Control-Allow-Headers':'X-Auth,Content-Type'};
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
export default{async fetch(req,env){
  if(req.method==='OPTIONS')return new Response(null,{headers:CORS});
  const u=new URL(req.url),m=u.pathname.match(/^\/a\/([0-9a-f]{32})$/),t=req.headers.get('X-Auth')||'';
  if(!m||!/^[0-9a-f]{64}$/.test(t))return new Response('bad',{status:400,headers:CORS});
  const id=m[1],h=hex(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(t)));
  const stored=await env.DB.get('m:'+id);
  if(req.method==='GET'){
    if(!stored)return new Response('none',{status:404,headers:CORS});
    if(stored!==h)return new Response('denied',{status:403,headers:CORS});
    return new Response(await env.DB.get('b:'+id,'arrayBuffer'),{headers:{...CORS,'Content-Type':'application/octet-stream'}});
  }
  if(req.method==='PUT'){
    if(stored&&stored!==h)return new Response('denied',{status:403,headers:CORS});
    const body=await req.arrayBuffer();
    if(body.byteLength>4000000)return new Response('big',{status:413,headers:CORS});
    if(!stored)await env.DB.put('m:'+id,h);
    await env.DB.put('b:'+id,body);
    return new Response('ok',{headers:CORS});
  }
  return new Response('no',{status:405,headers:CORS});
}};
