// IndexedDB хранит только полученные с сервера зашифрованные пакеты.
function database() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('messenger-encrypted-history', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('chats');
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
export async function saveHistory(userId, chatId, rows) {
  try {
    const db = await database();
    await new Promise((resolve, reject) => {
      const tx = db.transaction('chats', 'readwrite');
      tx.objectStore('chats').put(rows, `${userId}:${chatId}`);
      tx.oncomplete = resolve;
      tx.onerror = () => reject(tx.error);
    });
    db.close();
  } catch {
    /* Квота браузера не препятствует отправке. */ }
}
export async function loadHistory(userId, chatId) {
  try {
    const db = await database();
    const rows = await new Promise((resolve, reject) => {
      const req = db.transaction('chats').objectStore('chats').get(`${userId}:${chatId}`);
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });
    db.close();
    return rows;
  } catch {
    return [];
  }
}
