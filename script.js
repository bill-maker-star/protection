// --------------- Tab Navigation ---------------
function openTab(tabId) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(tabId).classList.add('active');
  const btn = Array.from(document.querySelectorAll('.tab-btn'))
    .find(b => (b.getAttribute('onclick') || '').includes(tabId));
  if (btn) btn.classList.add('active');
}

// --------------- Utilities ---------------
function copyToClipboard(id){
  const text = document.getElementById(id).innerText || '';
  navigator.clipboard.writeText(text).then(()=>alert('Copied!')).catch(()=>alert('Copy failed'));
}

// --------------- Password Generator ---------------
async function generatePassword(){
  const arr = new Uint8Array(20);
  crypto.getRandomValues(arr);
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?@#$%^&*()_+{}/';
  const pwd = Array.from(arr).map(x => chars[x % chars.length]).join('');
  document.getElementById('generated-password').innerText = pwd;
}

// --------------- Crypto Helpers (PBKDF2 + AES-GCM) ---------------
async function deriveKey(password, salt){
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations:200000, hash:'SHA-512' },
    keyMaterial,
    { name:'AES-GCM', length:256 },
    false,
    ['encrypt','decrypt']
  );
}

// [salt(16)][iv(12)][cipher]
function concatU8(a,b,c){ const o=new Uint8Array(a.length+b.length+c.length); o.set(a,0); o.set(b,a.length); o.set(c,a.length+b.length); return o; }
async function encryptBytes(plainU8, password){
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const cipher = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, plainU8));
  return concatU8(salt, iv, cipher);
}
async function decryptBytes(encU8, password){
  if (encU8.length < 28) throw new Error('Data too small');
  const salt = encU8.slice(0,16), iv = encU8.slice(16,28), ct = encU8.slice(28);
  const key = await deriveKey(password, salt);
  const plain = new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct));
  return plain;
}

// Text helpers
function toBase64(u8){ let s=''; for(let i=0;i<u8.length;i++) s+=String.fromCharCode(u8[i]); return btoa(s); }
function fromBase64(b64){ const s=atob(b64); const u8=new Uint8Array(s.length); for(let i=0;i<s.length;i++) u8[i]=s.charCodeAt(i); return u8; }

// --------------- Password Protector (Text) ---------------
async function encryptText(){
  const val = document.getElementById('encrypt-input').value;
  if (!val) return alert('Enter text');
  const data = new TextEncoder().encode(val);
  try {
    const enc = await encryptBytes(data, val); // demo: same text as key; customize if needed
    document.getElementById('encrypted-output').innerText = toBase64(enc);
  } catch(e){ document.getElementById('encrypted-output').innerText = `Error: ${e.message}`; }
}
async function decryptText(){
  const b64 = document.getElementById('decrypt-input').value.trim();
  if (!b64) return alert('Enter base64 text');
  try{
    const enc = fromBase64(b64);
    const pwd = prompt('Enter password used for encryption:') || '';
    const plain = await decryptBytes(enc, pwd);
    document.getElementById('decrypted-output').innerText = new TextDecoder().decode(plain);
  }catch(e){ document.getElementById('decrypted-output').innerText = `Error: ${e.message}`; }
}

// --------------- File Protector ---------------
function readFileAsArrayBuffer(file){
  return new Promise((res,rej)=>{ const fr=new FileReader(); fr.onload=e=>res(e.target.result); fr.onerror=()=>rej(new Error('Read error')); fr.readAsArrayBuffer(file); });
}

async function encryptFile(){
  const f = document.getElementById('file-encrypt-input').files[0];
  const pwd = document.getElementById('file-encrypt-key').value;
  const status = document.getElementById('file-encrypt-status');
  if (!f || !pwd) return alert('Select file and enter password');
  try{
    const buf = await readFileAsArrayBuffer(f);
    const enc = await encryptBytes(new Uint8Array(buf), pwd);
    const blob = new Blob([enc], { type:'application/octet-stream' });
    const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=f.name+'.enc'; a.click();
    status.innerText='File encrypted and downloaded.';
  }catch(e){ status.innerText=`Error: ${e.message}`; }
}

async function decryptFile(){
  const f = document.getElementById('file-decrypt-input').files[0];
  const pwd = document.getElementById('file-decrypt-key').value;
  const status = document.getElementById('file-decrypt-status');
  if (!f || !pwd) return alert('Select encrypted file and enter password');
  try{
    const buf = await readFileAsArrayBuffer(f);
    const plain = await decryptBytes(new Uint8Array(buf), pwd);
    const blob = new Blob([plain], { type:'application/octet-stream' });
    const a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=f.name.replace(/\.enc$/i,'')||'decrypted.bin'; a.click();
    status.innerText='File decrypted and downloaded.';
  }catch(e){ status.innerText=`Error: ${e.message}`; }
}

// --------------- Folder Protector (Folder or ZIP input) ---------------
const MAX_TOTAL_SIZE = 10 * 1024 * 1024 * 1024; // 1 GB
let encZipUrl=null, encZipName=null, decZipUrl=null, decZipName=null;

function onEncSourceTypeChange(){
  const mode = document.getElementById('enc-source-type').value;
  document.getElementById('enc-folder-wrap').style.display = mode==='folder' ? '' : 'none';
  document.getElementById('enc-zip-wrap').style.display = mode==='zip' ? '' : 'none';
}

function getRootFolderName(files){
  const p = files[0].webkitRelativePath || files[0].name || 'FOLDER';
  return p.split('/')[0] || 'FOLDER';
}
function sanitizePath(p){ return p.replace(/\\/g,'/'); }

async function addEncryptedFileToZip(zipFolder, pathInZip, arrayBuffer, password){
  const encU8 = await encryptBytes(new Uint8Array(arrayBuffer), password);
  zipFolder.file(pathInZip + '.enc', encU8, { binary:true });
}

async function encryptFolderOrZip(){
  const mode = document.getElementById('enc-source-type').value;
  const pwd = document.getElementById('enc-folder-key').value;
  const out = document.getElementById('enc-folder-output');
  const btn = document.getElementById('enc-folder-btn');
  const dl = document.getElementById('download-enc-zip-btn');

  if (!pwd) return alert('Enter password');

  btn.disabled = true; dl.style.display='none'; out.innerText='Processing...';
  if (encZipUrl) URL.revokeObjectURL(encZipUrl);

  try{
    const JSZipRef = window.JSZip; if (!JSZipRef) throw new Error('JSZip not loaded');
    const zip = new JSZipRef();

    if (mode === 'folder'){
      const files = document.getElementById('enc-folder-input').files;
      if (!files.length) throw new Error('Select a folder');
      const root = getRootFolderName(files);
      const encRoot = zip.folder(`${root}_ENC`);
      let total=0;

      for (const file of files){
        const rel = file.webkitRelativePath ? file.webkitRelativePath.split('/').slice(1).join('/') : file.name;
        const norm = sanitizePath(rel);
        const buf = await readFileAsArrayBuffer(file);
        total += buf.byteLength; if (total > MAX_TOTAL_SIZE) throw new Error('Total exceeds 1 GB');
        await addEncryptedFileToZip(encRoot, norm, buf, pwd);
      }

      const blob = await zip.generateAsync({ type:'blob', compression:'DEFLATE', compressionOptions:{ level:6 } });
      encZipUrl = URL.createObjectURL(blob);
      encZipName = `${root}_ENC.zip`;
    } else {
      // mode === 'zip'
      const zfile = document.getElementById('enc-zip-input').files[0];
      if (!zfile) throw new Error('Select a ZIP file');
      const inBuf = await readFileAsArrayBuffer(zfile);
      const inZip = await JSZipRef.loadAsync(inBuf);

      const base = zfile.name.replace(/\.zip$/i,'');
      const encRoot = zip.folder(`${base}_ENC`);

      let total=0;
      for (const [path, zf] of Object.entries(inZip.files)){
        if (zf.dir) continue;
        const u8 = new Uint8Array(await zf.async('uint8array'));
        total += u8.byteLength; if (total > MAX_TOTAL_SIZE) throw new Error('Total exceeds 1 GB');
        await addEncryptedFileToZip(encRoot, sanitizePath(path), u8.buffer, pwd);
      }

      const blob = await zip.generateAsync({ type:'blob', compression:'DEFLATE', compressionOptions:{ level:6 } });
      encZipUrl = URL.createObjectURL(blob);
      encZipName = `${base}_ENC.zip`;
    }

    out.innerText = `Encrypted folder ready: ${encZipName}`;
    dl.style.display='block';
  }catch(e){
    out.innerText = `Error: ${e.message}`;
  }finally{
    btn.disabled = false;
  }
}

function downloadEncZip(){
  if (!encZipUrl || !encZipName) return alert('No encrypted ZIP available');
  const a=document.createElement('a'); a.href=encZipUrl; a.download=encZipName; a.click();
}

async function decryptFolderOrZip(){
  const mode = document.getElementById('dec-source-type').value; // 'enczip' or 'zip'
  const pwd = document.getElementById('dec-folder-key').value;
  const zinput = document.getElementById('dec-zip-input');
  const out = document.getElementById('dec-folder-output');
  const btn = document.getElementById('dec-folder-btn');
  const dl = document.getElementById('download-dec-zip-btn');

  if (!zinput.files.length) return alert('Select a ZIP file');
  if (!pwd) return alert('Enter password');

  btn.disabled = true; dl.style.display='none'; out.innerText='Processing...';
  if (decZipUrl) URL.revokeObjectURL(decZipUrl);

  try{
    const JSZipRef = window.JSZip; if (!JSZipRef) throw new Error('JSZip not loaded');

    const inBuf = await readFileAsArrayBuffer(zinput.files[0]);
    const inZip = await JSZipRef.loadAsync(inBuf);
    const outZip = new JSZipRef();

    // Detect ENC root like "X_ENC/"
    let encRootFolder = null;
    Object.keys(inZip.files).forEach(k => { if (inZip.files[k].dir && /_ENC\/$/i.test(k)) encRootFolder = k; });

    const inBase = zinput.files[0].name.replace(/\.zip$/i,'');
    let outRoot;
    if (mode === 'enczip' || encRootFolder){
      const root = encRootFolder || `${inBase}/`;
      outRoot = root.replace(/_ENC\/?$/i,'/');
    } else {
      outRoot = `${inBase}_DECRYPTED/`;
    }

    let totalPlain = 0;

    for (const [path, zf] of Object.entries(inZip.files)){
      if (zf.dir) continue;

      let rel = path;
      if (encRootFolder && path.startsWith(encRootFolder)) rel = path.slice(encRootFolder.length);
      if (!rel) continue;

      const u8 = new Uint8Array(await zf.async('uint8array'));

      if (/\.enc$/i.test(rel)){
        // decrypt
        let plain;
        try{
          plain = await decryptBytes(u8, pwd);
        }catch(err){
          throw new Error(`Wrong password or corrupted file: ${rel}`);
        }
        totalPlain += plain.byteLength; if (totalPlain > MAX_TOTAL_SIZE) throw new Error('Decrypted total exceeds 1 GB');
        const cleanPath = rel.replace(/\.enc$/i,'');
        outZip.file(`${outRoot}${sanitizePath(cleanPath)}`, plain, { binary:true });
      } else {
        // copy as-is
        totalPlain += u8.byteLength; if (totalPlain > MAX_TOTAL_SIZE) throw new Error('Output total exceeds 1 GB');
        outZip.file(`${outRoot}${sanitizePath(rel)}`, u8, { binary:true });
      }
    }

    const blob = await outZip.generateAsync({ type:'blob', compression:'DEFLATE', compressionOptions:{ level:6 } });
    decZipUrl = URL.createObjectURL(blob);

    const decBase = encRootFolder ? inBase.replace(/_ENC$/i,'') : inBase;
    decZipName = `${decBase}_DECRYPTED.zip`;

    out.innerText = `Decrypted folder ready: ${decZipName}`;
    dl.style.display='block';
  }catch(e){
    out.innerText = `Decryption failed: ${e.message}`;
  }finally{
    btn.disabled = false;
  }
}

function downloadDecZip(){
  if (!decZipUrl || !decZipName) return alert('No decrypted ZIP available');
  const a=document.createElement('a'); a.href=decZipUrl; a.download=decZipName; a.click();
}
