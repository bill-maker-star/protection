// Tab Navigation
function openTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    document.querySelector(`[onclick="openTab('${tabId}')"]`).classList.add('active');
}

// Copy to Clipboard
function copyToClipboard(elementId) {
    const text = document.getElementById(elementId).innerText;
    navigator.clipboard.writeText(text).then(() => alert('Copied to clipboard!'));
}

// Page 1: Password Generator
async function generatePassword() {
    const array = new Uint8Array(20);
    crypto.getRandomValues(array);
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+{}:"<>?/|';
    const password = Array.from(array).map(x => chars[x % chars.length]).join('');
    document.getElementById('generated-password').innerText = password;
}

// Encryption/Decryption Helpers
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 2000000, hash: 'SHA-512' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

async function encryptPassword() {
    const input = document.getElementById('encrypt-input').value;
    const password = document.getElementById('encrypt-key').value;
    if (!input || !password) return alert('Please enter both text and password!');

    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);

    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv }, key, encoder.encode(input)
    );
    const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encrypted), salt.length + iv.length);

    const base64Encrypted = btoa(String.fromCharCode.apply(null, combined));
    document.getElementById('encrypted-output').innerText = base64Encrypted;
}

async function decryptPassword() {
    const input = document.getElementById('decrypt-input').value;
    const password = document.getElementById('decrypt-key').value;
    if (!input || !password) return alert('Please enter both encrypted text and password!');

    try {
        const data = Uint8Array.from(atob(input), c => c.charCodeAt(0));
        const salt = data.slice(0, 16);
        const iv = data.slice(16, 28);
        const ciphertext = data.slice(28);

        const key = await deriveKey(password, salt);
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv }, key, ciphertext
        );
        const decoder = new TextDecoder();
        document.getElementById('decrypted-output').innerText = decoder.decode(decrypted);
    } catch (e) {
        alert('Decryption failed: Invalid data or password!');
    }
}

// File Encryption/Decryption
let encryptedFileUrl = null;
let encryptedFileName = null;
const MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024; // 1GB in bytes

async function encryptFile() {
    const fileInput = document.getElementById('encrypt-file-input').files[0];
    const password = document.getElementById('encrypt-file-key').value;
    const encryptBtn = document.getElementById('encrypt-file-btn');
    const downloadBtn = document.getElementById('download-encrypted-btn');
    const outputBox = document.getElementById('encrypted-file-output');

    if (!fileInput || !password) return alert('Please upload a file and enter a password!');

    encryptBtn.disabled = true;
    downloadBtn.style.display = 'none';
    outputBox.innerText = 'Processing...';

    if (encryptedFileUrl) URL.revokeObjectURL(encryptedFileUrl);

    const reader = new FileReader();
    reader.onload = async function(e) {
        try {
            if (e.target.result.byteLength > MAX_FILE_SIZE) {
                throw new Error('File exceeds 1GB limit!');
            }

            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const key = await deriveKey(password, salt);

            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv }, key, e.target.result
            );
            const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
            combined.set(salt, 0);
            combined.set(iv, salt.length);
            combined.set(new Uint8Array(encrypted), salt.length + iv.length);

            if (combined.byteLength > MAX_FILE_SIZE) {
                throw new Error('Encrypted file exceeds 1GB limit!');
            }

            const blob = new Blob([combined], { type: 'application/octet-stream' });
            encryptedFileUrl = URL.createObjectURL(blob);
            encryptedFileName = fileInput.name;

            outputBox.innerText = `Encrypted: ${encryptedFileName}.enc`;
            downloadBtn.style.display = 'block';
        } catch (e) {
            outputBox.innerText = `Error: ${e.message}`;
        } finally {
            encryptBtn.disabled = false;
        }
    };
    reader.onerror = () => {
        outputBox.innerText = 'Error reading file!';
        encryptBtn.disabled = false;
    };
    reader.readAsArrayBuffer(fileInput);
}

function downloadEncryptedFile() {
    if (encryptedFileUrl && encryptedFileName) {
        const link = document.createElement('a');
        link.href = encryptedFileUrl;
        link.download = `${encryptedFileName}.enc`;
        link.click();
    } else {
        alert('No encrypted file available to download!');
    }
}

async function decryptFile() {
    const fileInput = document.getElementById('decrypt-file-input').files[0];
    const password = document.getElementById('decrypt-file-key').value;
    const decryptBtn = document.getElementById('decrypt-file-btn');
    const outputBox = document.getElementById('decrypted-file-output');

    if (!fileInput || !password) return alert('Please upload a file and enter a password!');

    decryptBtn.disabled = true;
    outputBox.innerText = 'Processing...';

    const reader = new FileReader();
    reader.onload = async function(e) {
        try {
            const data = new Uint8Array(e.target.result);
            if (data.length < 28) throw new Error('File too small to be valid encrypted data!');

            const salt = data.slice(0, 16);
            const iv = data.slice(16, 28);
            const ciphertext = data.slice(28);

            const key = await deriveKey(password, salt);
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv }, key, ciphertext
            );

            if (decrypted.byteLength > MAX_FILE_SIZE) {
                throw new Error('Decrypted file exceeds 1GB limit!');
            }

            const blob = new Blob([decrypted], { type: 'application/octet-stream' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = fileInput.name.replace('.enc', '');
            link.click();
            outputBox.innerText = `Decrypted: ${fileInput.name.replace('.enc', '')}`;
        } catch (e) {
            outputBox.innerText = `Decryption failed: ${e.message}`;
        } finally {
            decryptBtn.disabled = false;
        }
    };
    reader.onerror = () => {
        outputBox.innerText = 'Error reading file!';
        decryptBtn.disabled = false;
    };
    reader.readAsArrayBuffer(fileInput);
}
