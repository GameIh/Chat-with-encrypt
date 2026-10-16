// Web Crypto API: шифрование выполняется только на клиенте.
const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
export function base64(bytes) {
  const data = new Uint8Array(bytes);
  let result = '';
  for (let i = 0; i < data.length; i += 8192) result += String.fromCharCode(...data.subarray(i, i + 8192));
  return btoa(result);
}
export function bytes(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}
async function phraseKey(phrase, salt) {
  const material = await subtle.importKey('raw', encoder.encode(phrase), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({
    name: 'PBKDF2',
    salt,
    iterations: 600000,
    hash: 'SHA-256'
  }, material, {
    name: 'AES-GCM',
    length: 256
  }, false, ['encrypt', 'decrypt']);
}
export async function createKeys(phrase) {
  const pair = await subtle.generateKey({
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256'
  }, true, ['encrypt', 'decrypt']);
  const salt = crypto.getRandomValues(new Uint8Array(16)),
    iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await phraseKey(phrase, salt);
  const privateData = await subtle.exportKey('pkcs8', pair.privateKey);
  const data = await subtle.encrypt({
    name: 'AES-GCM',
    iv
  }, key, privateData);
  return {
    privateKey: pair.privateKey,
    public_key: await subtle.exportKey('jwk', pair.publicKey),
    vault: {
      salt: base64(salt),
      iv: base64(iv),
      data: base64(data)
    }
  };
}
export async function unlockKeys(phrase, vault) {
  const key = await phraseKey(phrase, bytes(vault.salt));
  const raw = await subtle.decrypt({
    name: 'AES-GCM',
    iv: bytes(vault.iv)
  }, key, bytes(vault.data));
  return subtle.importKey('pkcs8', raw, {
    name: 'RSA-OAEP',
    hash: 'SHA-256'
  }, false, ['decrypt']);
}

function context(chatId, id, senderId, replyTo) {
  return encoder.encode(`${chatId}|${id}|${senderId}|${replyTo||''}`);
}
export async function encryptMessage(content, members, chatId, id, senderId, replyTo) {
  const key = await subtle.generateKey({
    name: 'AES-GCM',
    length: 256
  }, true, ['encrypt', 'decrypt']);
  const raw = await subtle.exportKey('raw', key),
    iv = crypto.getRandomValues(new Uint8Array(12)),
    keys = {};
  for (const member of members) {
    const pub = await subtle.importKey('jwk', member.public_key, {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    }, false, ['encrypt']);
    keys[member.id] = base64(await subtle.encrypt({
      name: 'RSA-OAEP'
    }, pub, raw));
  }
  const data = await subtle.encrypt({
    name: 'AES-GCM',
    iv,
    additionalData: context(chatId, id, senderId, replyTo)
  }, key, encoder.encode(JSON.stringify(content)));
  return {
    iv: base64(iv),
    data: base64(data),
    keys
  };
}
export async function decryptMessage(message, userId, privateKey) {
  const packet = message.payload;
  if (!packet.keys[userId]) return {
    text: 'Это сообщение отправлено до вашего вступления в группу.'
  };
  const raw = await subtle.decrypt({
    name: 'RSA-OAEP'
  }, privateKey, bytes(packet.keys[userId]));
  const key = await subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  const data = await subtle.decrypt({
    name: 'AES-GCM',
    iv: bytes(packet.iv),
    additionalData: context(message.chat_id, message.id, message.sender_id, message.reply_to)
  }, key, bytes(packet.data));
  return JSON.parse(decoder.decode(data));
}
export async function fingerprint(key) {
  const raw = encoder.encode(JSON.stringify({
    e: key.e,
    kty: key.kty,
    n: key.n
  }));
  return [...new Uint8Array(await subtle.digest('SHA-256', raw))].map(x => x.toString(16).padStart(2, '0')).join(':');
}
