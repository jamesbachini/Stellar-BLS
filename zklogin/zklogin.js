import express from 'express';
import * as bls from '@noble/bls12-381';
import StellarSdk from '@stellar/stellar-sdk';

// Deploy ../contracts/ringsignatures.rs to testnet
const CONTRACT_ID = "CCGODMFRVEVNZJGMOY7LWN3DGLT65BK56Q5W5WQX6NPDX2QBJKOLF264";

const CURVE_R = bls.CURVE.r;
const hex     = u8 => Buffer.from(u8).toString('hex');
const modR    = x  => ((x % CURVE_R) + CURVE_R) % CURVE_R;
const canon   = (u8)=>{const b=Uint8Array.from(u8); b[0]&=0x1f; return b;};
const RpcServer = StellarSdk.SorobanRpc?.Server || StellarSdk.rpc.Server;
const rpc       = new RpcServer("https://soroban-testnet.stellar.org");
const NETWORK  = StellarSdk.Networks.TESTNET;
const payer    = StellarSdk.Keypair.random();
fetch(`https://friendbot-testnet.stellar.org?addr=${payer.publicKey()}`);
const PORT = 3000;

const G1_GEN_BYTES = Uint8Array.from([
  0x17,0xf1,0xd3,0xa7,0x31,0x97,0xd7,0x94,0x26,0x95,0x63,0x8c,0x4f,0xa9,0xac,0x0f,
  0xc3,0x68,0x8c,0x4f,0x97,0x74,0xb9,0x05,0xa1,0x4e,0x3a,0x3f,0x17,0x1b,0xac,0x58,
  0x6c,0x55,0xe8,0x3f,0xf9,0x7a,0x1a,0xef,0xfb,0x3a,0xf0,0x0a,0xdb,0x22,0xc6,0xbb,
  0x11,0x4d,0x1d,0x68,0x55,0xd5,0x45,0xa8,0xaa,0x7d,0x76,0xc8,0xcf,0x2e,0x21,0xf2,
  0x67,0x81,0x6a,0xef,0x1d,0xb5,0x07,0xc9,0x66,0x55,0xb9,0xd5,0xca,0xac,0x42,0x36,
  0x4e,0x6f,0x38,0xba,0x0e,0xcb,0x75,0x1b,0xad,0x54,0xdc,0xd6,0xb9,0x39,0xc2,0xca
]);
const G1_GEN = bls.PointG1.fromHex(G1_GEN_BYTES);

const ALLOWED_PUB_KEYS = [];
const NOTALLOWED_PUB_KEYS = [];
const ALLOWED_PRIV_KEYS   = [];
const NOTALLOWED_PRIV_KEYS = [];

for (let i=0;i<3;i++){
  const sk = modR(BigInt('0x'+hex(bls.utils.randomBytes(32))));
  const pk = canon(G1_GEN.multiply(sk).toRawBytes(false));
  ALLOWED_PUB_KEYS.push(hex(pk)); // Ring
  ALLOWED_PRIV_KEYS.push(sk);
}
for (let i=0;i<3;i++){
  const sk = modR(BigInt('0x'+hex(bls.utils.randomBytes(32))));
  const pk = canon(G1_GEN.multiply(sk).toRawBytes(false));
  NOTALLOWED_PUB_KEYS.push(hex(pk));
  NOTALLOWED_PRIV_KEYS.push(sk);
}

const app = express();
app.use(express.json());

const style = `<style>
body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f5f7fb;margin:0;color:#172b4d;text-align:center}
.wrap{max-width:660px;margin:60px auto;padding:30px;background:#fff;border-radius:12px;box-shadow:0 6px 18px rgba(0,0,0,.1)}
button{cursor:pointer;background:#0064ff;color:#fff;border:none;padding:10px 22px;margin:10px;border-radius:6px;font-size:1rem}
pre{background:#eef2ff;padding:12px;border-radius:8px;text-align:left;overflow:auto}
.good{color:#128200;font-weight:600} .bad{color:#c90d0d;font-weight:600}
</style>`;

app.get('/',(_,res)=>res.send(`<!doctype html><html>
<head><meta charset=utf-8><title>zkLogin demo</title>${style}</head>
<body><div class=wrap>
<h1>Select a wallet to claim</h1>
<p><b>Invalid Wallet</b><br><code>${NOTALLOWED_PUB_KEYS[0].slice(0,18)}…</code></p>
<p>This wallet is not part of the ring signatures</p>
<a href="/claim/${NOTALLOWED_PRIV_KEYS[1]}"><button>Claim This Key</button></a><hr>
<p><b>Valid Wallet</b><br><code>${ALLOWED_PUB_KEYS[1].slice(0,18)}…</code></p>
<p>This wallet is not part of the ring signatures</p>
<a href="/claim/${ALLOWED_PRIV_KEYS[1]}"><button>Claim This Key</button></a><hr>
</div></body></html>`));

app.get('/claim/:sk',(req,res)=>{
    let secretKey;
    try {
    secretKey = BigInt(req.params.sk);
    } catch {
    return res.status(400).send('Invalid secret key');
    }
    if (secretKey <= 0n || secretKey >= CURVE_R) {
    return res.status(400).send('Secret key out of range');
    }
    const pubKeyBytes = canon(G1_GEN.multiply(secretKey).toRawBytes(false));
    const pubKeyHex   = hex(pubKeyBytes);
    const idx         = ALLOWED_PUB_KEYS.indexOf(pubKeyHex); // –1 if unknown
    const allowed     = idx !== -1;
    const skHex = allowed? secretKey.toString(16).padStart(64, '0') : null;
  res.send(`<!doctype html><html>
<head><meta charset=utf-8><title>zkLogin – wallet ${idx}</title>${style}
<script type=module src="https://cdn.jsdelivr.net/npm/@stellar/stellar-sdk/+esm"></script>
<script type=module src="https://cdn.jsdelivr.net/npm/@noble/bls12-381/+esm"></script>
</head>
<body><div class=wrap>
<h1>Wallet ${pubKeyHex.slice(0,18)}</h1>
<p>Your public key (hex):<br><code style="word-wrap: break-word;">${pubKeyHex}</code></p>
<p>The ring is hard-coded in this page – a verifier can’t tell which key
signed the message.</p>
<button id=loginBtn>Generate&nbsp;ring-signature&nbsp;&amp;&nbsp;Login</button>
<pre id=out></pre>
<script type=module>
import * as bls   from "https://cdn.jsdelivr.net/npm/@noble/bls12-381/+esm";
import StellarSdk from "https://cdn.jsdelivr.net/npm/@stellar/stellar-sdk/+esm";
const idx     = ${Math.max(idx, 0)};
const ringHex = ${JSON.stringify(ALLOWED_PUB_KEYS)};
const skHex   = ${skHex === null ? 'null' : `"${skHex}"`};
const CURVE_R = bls.CURVE.r;
const canon   = u8=>{const b=Uint8Array.from(u8); b[0]&=0x1f; return b;};
const modR    = x=>((x%CURVE_R)+CURVE_R)%CURVE_R;
const to32    = bi=>{let h=bi.toString(16).padStart(64,"0");
                     return Uint8Array.from(h.match(/../g).map(b=>parseInt(b,16)));};
const hex     = u8=>Array.from(u8).map(b=>b.toString(16).padStart(2,"0")).join("");
const sha256  = async bytes=>new Uint8Array(await crypto.subtle.digest("SHA-256",bytes));
const G1_GEN_BYTES = Uint8Array.from(${JSON.stringify(Array.from(G1_GEN_BYTES))});
const G1_GEN = bls.PointG1.fromHex(G1_GEN_BYTES);
document.getElementById("loginBtn").onclick = async ()=>{
  const out = document.getElementById("out");
  if(!skHex){ out.textContent="❌  No secret key – you cannot form a valid signature."; return; }
  const n   = ringHex.length;
  const msg = new TextEncoder().encode("login::"+Date.now());
  const pkU8= ringHex.map(h=>Uint8Array.from(h.match(/../g).map(b=>parseInt(b,16))));
  const priv= modR(BigInt("0x"+skHex));
  pkU8[idx] = canon(G1_GEN.multiply(priv).toRawBytes(false));
  const randFr = ()=>modR(BigInt("0x"+hex(bls.utils.randomBytes(32))));
  const a      = randFr();
  const resp   = Array.from({length:n},randFr);
  const base = new Uint8Array(n*96 + msg.length);
  pkU8.forEach((pk,i)=>base.set(pk,96*i));  base.set(msg,n*96);
  const xs  = canon(G1_GEN.multiply(a).toRawBytes(false));
  const pre = new Uint8Array(base.length+xs.length); pre.set(base); pre.set(xs,base.length);
  const c   = Array(n).fill(0n);
  let j=(idx+1)%n;
  c[j] = modR(BigInt("0x"+hex(await sha256(pre))));
  while(j!==idx){
    const rj = resp[j];
    const pj = bls.PointG1.fromHex(pkU8[j]);
    const x1 = G1_GEN.multiply(rj);
    const x2 = pj.multiply(c[j]);
    const xj = canon(x1.add(x2).toRawBytes(false));
    const pre2=new Uint8Array(base.length+xj.length); pre2.set(base); pre2.set(xj,base.length);
    c[(j+1)%n] = modR(BigInt("0x"+hex(await sha256(pre2))));
    j=(j+1)%n;
  }
  resp[idx]=modR(a - c[idx]*priv);
  const sig = {
    challenge: hex(to32(c[0])),
    responses: resp.map(r=>hex(to32(r)))
  };
  out.textContent="🔏  signature generated – sending to server …";
  const res = await fetch("/login",{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({msg:hex(msg),ring:ringHex,sig})
  }).then(r=>r.json());
  if(res.ok){ window.location="/access"; }
  else { out.textContent="❌  "+res.error; }
};
</script>
</div></body></html>`);
});

app.get('/access',(_ ,res)=>res.send(`<!doctype html><html>
<head><meta charset=utf-8><title>Access granted</title>${style}</head>
<body><div class=wrap><h1 class=good>✅ Access Granted</h1>
<p>You proved knowledge of one secret key in the ring without revealing which one.</p>
<a href="/"><button>Start over</button></a>
</div></body></html>`));

app.post('/login',async (req,res)=>{
  try{
    const {msg,ring,sig} = req.body;
    if(!msg||!ring||!sig) throw Error("missing fields");
    const B   = StellarSdk.xdr.ScVal.scvBytes;
    const Vec = a=>StellarSdk.xdr.ScVal.scvVec(a);
    const Sym = s=>StellarSdk.xdr.ScVal.scvSymbol(s);
    const Map = ent=>StellarSdk.xdr.ScVal.scvMap(ent.map(([k,v])=>new StellarSdk.xdr.ScMapEntry({key:Sym(k),val:v})));
    const ringVal = Vec(ring.map(h=>B(Buffer.from(h,"hex"))));
    const sigVal  = Map([
      ["challenge", B(Buffer.from(sig.challenge,"hex"))],
      ["responses", Vec(sig.responses.map(r=>B(Buffer.from(r,"hex"))))]
    ]);
    const msgVal  = B(Buffer.from(msg,"hex"));
    const contract = new StellarSdk.Contract(CONTRACT_ID);
    let tx = new StellarSdk.TransactionBuilder(
              await rpc.getAccount(payer.publicKey()),
              {fee:StellarSdk.BASE_FEE,networkPassphrase:NETWORK})
            .addOperation(contract.call("verify",msgVal,ringVal,sigVal))
            .setTimeout(30).build();
    const sim = await rpc.simulateTransaction(tx);
    console.log(sim)
    const ok  = StellarSdk.scValToNative(sim.result.retval);
    if(ok) res.json({ok:true});
    else   res.json({ok:false,error:"Signature invalid – key not verified"});
  }
  catch(e){ res.json({ok:false,error:e.message}); }
});


app.listen(PORT,()=>console.log(`zkLogin demo running  →  http://localhost:${PORT}`));