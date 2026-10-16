import {
  createKeys,
  unlockKeys,
  encryptMessage,
  decryptMessage,
  fingerprint,
  base64,
  bytes
} from './crypto.js';
import {
  saveHistory,
  loadHistory
} from './history.js';

const $ = id => document.getElementById(id);
let token = null,
  me = null,
  vault = null,
  privateKey = null,
  chats = [],
  active = null,
  replyTo = null;
let timer = null,
  busy = false,
  sending = false,
  messageRows = [],
  signature = '',
  noticeTimer;
const decoded = new Map();

function el(tag, text = '', className = '') {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) node.className = className;
  return node;
}

function button(text, fn, className = '') {
  const b = el('button', text, className);
  b.type = 'button';
  b.onclick = () => Promise.resolve().then(fn).catch(notice);
  return b;
}

function notice(error) {
  $('notice').textContent = error.message || error;
  $('notice').hidden = false;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => $('notice').hidden = true, 7000);
}

function name(u) {
  return `${u.first_name} ${u.last_name}`;
}

function online(u) {
  return !u.blocked && !u.deleted && u.last_seen && Date.now() - new Date(u.last_seen).getTime() < 35000;
}

function title(chat) {
  return chat.is_group ? chat.title : name(chat.members.find(m => m.id !== me.id) || me);
}

function show(id) {
  for (const key of ['login-screen', 'key-screen', 'workspace']) $(key).hidden = key !== id;
}
async function api(path, method = 'GET', data) {
  const response = await fetch('/api' + path, {
    method,
    headers: {
      ...(token ? {
        Authorization: `Bearer ${token}`
      } : {}),
      ...(data !== undefined ? {
        'Content-Type': 'application/json'
      } : {})
    },
    body: data === undefined ? undefined : JSON.stringify(data)
  });
  const result = await response.json();
  if (!response.ok) {
    const error = new Error(typeof result.detail === 'string' ? result.detail : 'Ошибка запроса');
    error.status = response.status;
    if (response.status === 401 && token) {
      clearSession();
    }
    throw error;
  }
  return result;
}

function clearSession() {
  clearTimeout(timer);
  token = null;
  privateKey = null;
  me = null;
  vault = null;
  chats = [];
  active = null;
  $('workspace').classList.remove('chat-open');
  decoded.clear();
  messageRows = [];
  $('dialog').close();
  $('messages').replaceChildren();
  $('chat-list').replaceChildren();
  $('active-chat').hidden = true;
  $('empty-chat').hidden = false;
  $('dialog-content').replaceChildren();
  $('text').value = '';
  $('file').value = '';
  $('password').value = '';
  $('phrase').value = '';
  $('phrase-repeat').value = '';
  show('login-screen');
}
$('login-form').onsubmit = async event => {
  event.preventDefault();
  $('login-error').textContent = '';
  const submit = event.submitter;
  submit.disabled = true;
  try {
    const result = await api('/login', 'POST', {
      login: $('login').value.trim(),
      password: $('password').value
    });
    token = result.token;
    me = result.user;
    vault = result.vault;
    $('password').value = '';
    $('key-title').textContent = vault ? 'Открыть переписку' : 'Создать ключ шифрования';
    $('key-help').textContent = vault ? 'Введите вашу секретную фразу. На другом устройстве используйте ту же фразу — история загрузится автоматически.' : 'Придумайте отдельную секретную фразу от 12 символов. Не используйте пароль учётной записи.';
    $('phrase-repeat-label').hidden = !!vault;
    $('phrase-repeat').required = !vault;
    $('key-error').textContent = '';
    show('key-screen');
    $('phrase').focus();
  } catch (error) {
    $('login-error').textContent = error.message;
  } finally {
    submit.disabled = false;
  }
};
$('key-form').onsubmit = async event => {
  event.preventDefault();
  $('key-error').textContent = '';
  const submit = event.submitter;
  submit.disabled = true;
  try {
    const phrase = $('phrase').value;
    if (vault) privateKey = await unlockKeys(phrase, vault);
    else {
      if (phrase !== $('phrase-repeat').value) throw new Error('Фразы не совпадают');
      const keys = await createKeys(phrase);
      await api('/keys', 'PUT', {
        public_key: keys.public_key,
        vault: keys.vault
      });
      privateKey = keys.privateKey;
      me.public_key = keys.public_key;
      vault = keys.vault;
    }
    $('phrase').value = '';
    $('phrase-repeat').value = '';
    $('identity').textContent = name(me);
    $('admin-btn').hidden = me.role !== 'admin';
    show('workspace');
    await refreshChats();
    poll();
  } catch (error) {
    $('key-error').textContent = error.name === 'OperationError' ? 'Не удалось открыть ключ. Проверьте секретную фразу.' : error.message;
  } finally {
    submit.disabled = false;
  }
};
async function logout() {
  try {
    await api('/logout', 'POST');
  } finally {
    clearSession();
  }
}
$('logout-btn').onclick = () => logout().catch(notice);
$('key-back').onclick = () => logout().catch(notice);

async function refreshChats() {
  chats = await api('/chats');
  if (active) {
    active = chats.find(c => c.id === active.id) || null;
    if (active) updateChatHeader();
    else {
      $('active-chat').hidden = true;
      $('empty-chat').hidden = false;
      $('workspace').classList.remove('chat-open');
      $('messages').replaceChildren();
    }
  }
  renderChats();
}

function renderChats() {
  const scrollTop = $('chat-list').scrollTop;
  $('chat-list').replaceChildren();
  const query = $('chat-search').value.toLowerCase();
  for (const chat of chats.filter(c => title(c).toLowerCase().includes(query))) {
    const node = button('', () => selectChat(chat.id), 'chat-item' + (active?.id === chat.id ? ' selected' : ''));
    const avatar = el('span', chat.is_group ? '' : title(chat).split(' ').filter(Boolean).slice(0, 2).map(part => part[0]).join('').toUpperCase(), 'chat-avatar');
    if (chat.is_group) {
      const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      icon.setAttribute('viewBox', '0 0 24 24');
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M17 4a4 4 0 0 1 0 8M22 21v-2a4 4 0 0 0-3-3.87M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0');
      icon.append(path);
      avatar.append(icon);
    }
    avatar.setAttribute('aria-hidden', 'true');
    const copy = el('span', '', 'chat-copy');
    copy.append(el('strong', title(chat)), el('small', chat.is_group ? `Группа · ${chat.members.length} участников` : (online(chat.members.find(m => m.id !== me.id) || {}) ? 'В сети' : 'Не в сети')));
    node.append(avatar, copy);
    $('chat-list').append(node);
  }
  if (!chats.length) $('chat-list').append(el('p', 'Пока нет чатов', 'muted'));
  $('chat-list').scrollTop = scrollTop;
}
$('chat-search').oninput = renderChats;

function updateChatHeader() {
  $('chat-title').textContent = title(active);
  $('chat-subtitle').textContent = active.is_group ? `${active.members.length} участников` : (online(active.members.find(m => m.id !== me.id) || {}) ? 'В сети' : 'Не в сети');
}
$('back-chats').onclick = () => {
  active = null;
  $('workspace').classList.remove('chat-open');
  $('active-chat').hidden = true;
  $('empty-chat').hidden = false;
  renderChats();
};
async function selectChat(id) {
  active = chats.find(c => c.id === id);
  replyTo = null;
  messageRows = [];
  signature = '';
  decoded.clear();
  $('reply-banner').hidden = true;
  $('messages').replaceChildren();
  $('empty-chat').hidden = true;
  $('active-chat').hidden = false;
  $('workspace').classList.add('chat-open');
  updateChatHeader();
  renderChats();
  const cached = await loadHistory(me.id, id);
  if (active?.id !== id) return;
  messageRows = cached;
  await renderMessages();
  await refreshMessages();
}
async function renderMessages() {
  const chatId = active?.id,
    owner = me?.id,
    key = privateKey;
  if (!chatId || !key) return;
  const view = $('messages');
  const atBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 100;
  const fragment = document.createDocumentFragment();
  let previousDate = '';
  for (const message of messageRows) {
    let content = {
      text: 'Сообщение удалено'
    };
    if (!message.deleted) {
      try {
        content = decoded.get(message.id) || await decryptMessage(message, owner, key);
        decoded.set(message.id, content);
      } catch {
        content = {
          text: 'Не удалось расшифровать сообщение: ключ не подходит или данные повреждены.'
        };
      }
    }
    if (active?.id !== chatId || me?.id !== owner) return;
    const date = new Date(message.created_at).toLocaleDateString('ru-RU', {day: 'numeric', month: 'long', year: 'numeric'});
    if (date !== previousDate) {
      fragment.append(el('div', date, 'date-divider'));
      previousDate = date;
    }
    const mine = message.sender_id === owner,
      node = el('article', '', `message${mine?' mine':''}`);
    const sender = active.members.find(m => m.id === message.sender_id);
    if (active.is_group && !mine) node.append(el('div', sender ? name(sender) : 'Бывший участник', 'sender'));
    if (message.reply_to) {
      const original = decoded.get(message.reply_to);
      const deleted = messageRows.find(m => m.id === message.reply_to)?.deleted;
      node.append(el('div', deleted ? 'Ответ на удалённое сообщение' : `Ответ: ${(original?.text||original?.file?.name||'более раннее сообщение').slice(0,100)}`, 'reply'));
    }
    node.append(el('div', content.text || '', 'body'));
    if (content.file && !message.deleted) {
      node.append(button(`↓ ${content.file.name} (${Math.ceil(bytes(content.file.data).length/1024)} КБ)`, () => {
        const url = URL.createObjectURL(new Blob([bytes(content.file.data)], {
          type: 'application/octet-stream'
        }));
        const link = el('a');
        link.href = url;
        link.download = content.file.name;
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      }));
    }
    const footer = el('footer');
    footer.append(el('span', new Date(message.created_at).toLocaleString('ru-RU', {
      hour: '2-digit',
      minute: '2-digit'
    })));
    if (mine && !message.deleted) {
      const count = Object.keys(message.payload.keys).length - 1,
        read = message.receipts.filter(r => r.read_at).length,
        delivered = message.receipts.length;
      footer.append(el('span', read >= count ? 'Прочитано' : delivered >= count ? 'Доставлено' : read ? `Прочитано ${read}/${count}` : delivered ? `Доставлено ${delivered}/${count}` : 'Отправлено'));
    }
    if (!message.deleted) {
      const menu = el('details', '', 'message-menu');
      const toggle = el('summary', '⋯');
      toggle.setAttribute('aria-label', 'Действия с сообщением');
      toggle.title = 'Действия с сообщением';
      const actions = el('div', '', 'message-actions');
      actions.append(button('Ответить', () => {
        menu.open = false;
        replyTo = message.id;
        $('reply-banner').textContent = `Ответ: ${(content.text||content.file?.name||'сообщение').slice(0,80)} · нажмите для отмены`;
        $('reply-banner').hidden = false;
        $('text').focus();
      }));
      if (mine) actions.append(button('Удалить', async () => {
        menu.open = false;
        await api('/messages/' + message.id, 'DELETE');
        decoded.delete(message.id);
        await refreshMessages();
      }));
      menu.append(toggle, actions);
      footer.append(menu);
    }
    node.append(footer);
    fragment.append(node);
  }
  view.replaceChildren(fragment);
  if (atBottom) view.scrollTop = view.scrollHeight;
}
async function refreshMessages(before = null) {
  const id = active?.id;
  if (!id) return;
  let rows = await api(`/chats/${id}/messages${before?'?before='+encodeURIComponent(before):''}`);
  if (active?.id !== id) return;
  // Обновляем также загруженные старые страницы: удаление видно во всей открытой истории.
  if (!before) {
    let page = rows;
    while (page.length === 100 && rows.length < messageRows.length) {
      page = await api(`/chats/${id}/messages?before=${encodeURIComponent(page[0].created_at)}`);
      if (active?.id !== id) return;
      rows = [...page, ...rows];
    }
  }
  if (before) {
    messageRows = [...rows, ...messageRows.filter(m => !rows.some(n => n.id === m.id))];
    $('older-btn').hidden = rows.length < 100;
  } else {
    const latest = new Map(rows.map(m => [m.id, m]));
    messageRows = [...messageRows.filter(m => !latest.has(m.id)), ...rows].sort((a, b) => a.created_at.localeCompare(b.created_at));
    $('older-btn').hidden = messageRows.length < 100;
  }
  const next = JSON.stringify(messageRows.map(m => [m.id, m.deleted, m.receipts]));
  if (next !== signature) {
    signature = next;
    await saveHistory(me.id, id, messageRows);
    await renderMessages();
  }
  const ids = rows.filter(m => !m.deleted && m.sender_id !== me.id && m.payload?.keys[me.id] && (!m.receipts.some(r => r.user_id === me.id && (document.hidden ? true : r.read_at)))).map(m => m.id);
  for (let offset = 0; offset < ids.length; offset += 100) await api(`/chats/${id}/receipts`, 'POST', {
    ids: ids.slice(offset, offset + 100),
    read: !document.hidden
  });
}
$('older-btn').onclick = () => refreshMessages(messageRows[0]?.created_at).catch(notice);
$('reply-banner').onclick = () => {
  replyTo = null;
  $('reply-banner').hidden = true;
};
async function poll() {
  if (!token || !privateKey) return;
  try {
    if (!busy) {
      busy = true;
      await refreshChats();
      await refreshMessages();
      // Неоткрытые чаты подтверждают доставку, но не прочтение.
      for (const chat of chats.filter(c => c.id !== active?.id)) {
        const rows = await api(`/chats/${chat.id}/messages`);
        const ids = rows.filter(m => !m.deleted && m.sender_id !== me.id && m.payload?.keys[me.id] && !m.receipts.some(r => r.user_id === me.id)).map(m => m.id);
        if (ids.length) await api(`/chats/${chat.id}/receipts`, 'POST', {
          ids,
          read: false
        });
      }
      $('connection').textContent = 'Подключено';
    }
  } catch (error) {
    if (token) $('connection').textContent = 'Нет связи';
  } finally {
    busy = false;
    if (token && privateKey) timer = setTimeout(poll, 1000);
  }
}

function resetFile() {
  $('file').value = '';
  $('file-name').textContent = '';
  $('clear-file').hidden = true;
}
$('file').onchange = () => {
  const file = $('file').files[0];
  if (file && file.size > 8 * 1024 * 1024) {
    resetFile();
    notice('Файл должен быть не больше 8 МБ');
    return;
  }
  $('file-name').textContent = file ? file.name : '';
  $('clear-file').hidden = !file;
};
$('clear-file').onclick = resetFile;
$('message-form').onsubmit = async event => {
  event.preventDefault();
  if (sending || !active) return;
  const text = $('text').value,
    file = $('file').files[0];
  if (!text.trim() && !file) return;
  if ([...text].length > 5000) {
    notice('Не более 5000 символов');
    return;
  }
  const chat = active,
    reply = replyTo;
  sending = true;
  $('send-btn').disabled = true;
  try {
    const content = {
      text
    };
    if (file) content.file = {
      name: file.name,
      data: base64(await file.arrayBuffer())
    };
    const id = crypto.randomUUID();
    const payload = await encryptMessage(content, chat.members, chat.id, id, me.id, reply);
    const packet = {
      id,
      revision: chat.revision,
      payload,
      reply_to: reply
    };
    let sent = false;
    for (let attempt = 0; attempt < 4; attempt++) {
      try {
        await api(`/chats/${chat.id}/messages`, 'POST', packet);
        sent = true;
        break;
      } catch (error) {
        if (error.status && error.status < 500) throw error;
        if (attempt < 3) await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)));
      }
    }
    if (!sent) throw new Error('Ошибка отправки сообщения');
    $('text').value = '';
    resetFile();
    replyTo = null;
    $('reply-banner').hidden = true;
    if (active?.id === chat.id) await refreshMessages();
  } catch (error) {
    notice(error);
  } finally {
    sending = false;
    $('send-btn').disabled = false;
  }
};
$('text').onkeydown = event => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    $('message-form').requestSubmit();
  }
};

function modal(titleText) {
  $('dialog-title').textContent = titleText;
  const body = $('dialog-content');
  body.replaceChildren();
  if (!$('dialog').open) $('dialog').showModal();
  return body;
}
$('dialog-close').onclick = () => $('dialog').close();
async function contacts(group = false) {
  const body = modal(group ? 'Создать группу' : 'Контакты');
  const users = (await api('/users')).filter(u => u.id !== me.id && !u.blocked);
  const chosen = new Set();
  const input = el('input');
  input.placeholder = 'Имя или логин';
  input.setAttribute('aria-label', 'Поиск контактов');
  const list = el('div');
  body.append(input, list);
  let groupTitle;
  if (group) {
    groupTitle = el('input');
    groupTitle.placeholder = 'Название группы';
    groupTitle.maxLength = 100;
    groupTitle.setAttribute('aria-label', 'Название группы');
    body.prepend(groupTitle);
  }

  function render() {
    list.replaceChildren();
    for (const u of users.filter(u => (name(u) + ' ' + u.login).toLowerCase().includes(input.value.toLowerCase()))) {
      const row = el('div', '', 'person'),
        info = el('div', name(u));
      info.append(el('small', `@${u.login} · ${u.public_key?(online(u)?'В сети':'Не в сети'):'Ещё не созданы ключи'}`));
      row.append(info);
      if (group) {
        const cb = el('input');
        cb.type = 'checkbox';
        cb.setAttribute('aria-label', name(u));
        cb.disabled = !u.public_key;
        cb.checked = chosen.has(u.id);
        cb.onchange = () => cb.checked ? chosen.add(u.id) : chosen.delete(u.id);
        cb.style.width = 'auto';
        row.append(cb);
      } else {
        const start = button('Написать', async () => {
          const chat = await api('/chats', 'POST', {
            title: 'Личный чат',
            is_group: false,
            user_ids: [u.id]
          });
          $('dialog').close();
          await refreshChats();
          await selectChat(chat.id);
        });
        start.disabled = !u.public_key;
        row.append(start);
      }
      list.append(row);
    }
  }
  input.oninput = render;
  render();
  if (group) body.append(button('Создать группу', async () => {
    if (!groupTitle.value.trim()) throw new Error('Введите название группы');
    if (chosen.size < 1 || chosen.size > 9) throw new Error('Выберите от 1 до 9 собеседников');
    const chat = await api('/chats', 'POST', {
      title: groupTitle.value.trim(),
      is_group: true,
      user_ids: [...chosen]
    });
    $('dialog').close();
    await refreshChats();
    await selectChat(chat.id);
  }, 'primary'));
}
$('contacts-btn').onclick = () => contacts().catch(notice);
$('group-btn').onclick = () => contacts(true).catch(notice);
async function members() {
  const body = modal('Участники чата'),
    chat = active;
  for (const u of chat.members) {
    const row = el('div', '', 'person'),
      info = el('div', name(u));
    info.append(el('small', `@${u.login}${u.is_admin&&chat.is_group?' · Администратор группы':''}`));
    row.append(info);
    const actions = el('div', '', 'actions');
    actions.append(button('Отпечаток ключа', async () => {
      const box = modal('Отпечаток ключа · ' + name(u));
      box.append(el('p', 'Сравните этот отпечаток с собеседником по другому каналу связи.'), el('p', await fingerprint(u.public_key), 'fingerprint'));
    }));
    if (chat.is_group && chat.is_admin) {
      for (const [action, label] of [
          [u.is_admin ? 'demote' : 'promote', u.is_admin ? 'Снять права' : 'Назначить админом'],
          ['remove', 'Исключить']
        ]) actions.append(button(label, async () => {
        await api(`/chats/${chat.id}/members`, 'POST', {
          user_id: u.id,
          action
        });
        await refreshChats();
        if (active) await members();
        else $('dialog').close();
      }));
    }
    row.append(actions);
    body.append(row);
  }
  if (chat.is_group && chat.is_admin) {
    const users = (await api('/users')).filter(u => !u.blocked && u.public_key && !chat.members.some(m => m.id === u.id));
    const select = el('select');
    select.setAttribute('aria-label', 'Пригласить участника');
    for (const u of users) {
      const option = el('option', name(u));
      option.value = u.id;
      select.append(option);
    }
    body.append(el('p', 'Пригласить участника'), select, button('Добавить', async () => {
      if (!select.value) throw new Error('Нет доступных пользователей');
      await api(`/chats/${chat.id}/members`, 'POST', {
        user_id: Number(select.value),
        action: 'add'
      });
      await refreshChats();
      await members();
    }));
    body.append(el('p', 'Новые участники видят только сообщения, отправленные после приглашения.', 'hint'));
  }
}
$('members-btn').onclick = () => members().catch(notice);
$('security-btn').onclick = async () => {
  const body = modal('Мой ключ шифрования');
  body.append(el('p', 'Ваш отпечаток ключа. Сравните его с тем, что видят собеседники.'), el('p', await fingerprint(me.public_key), 'fingerprint'), el('p', 'Для входа с другого устройства используйте логин, пароль и прежнюю секретную фразу. Закрытый ключ хранится на сервере только в зашифрованном виде. Открытая история и ключи существуют только в памяти вкладки.', 'hint'));
};

const events = {
  login: 'Вход',
  login_failed: 'Ошибка входа',
  keys_created: 'Создание ключей',
  account_created: 'Создание учётной записи',
  account_edited: 'Изменение учётной записи',
  account_block: 'Блокировка',
  account_unblock: 'Разблокировка',
  account_delete: 'Удаление учётной записи',
  account_revoke: 'Завершение сеансов',
  account_reset_password: 'Сброс пароля',
  group_add: 'Приглашение в группу',
  group_remove: 'Исключение из группы',
  group_promote: 'Назначение администратора группы',
  group_demote: 'Снятие прав в группе'
};
async function admin() {
  const body = modal('Управление системой'),
    tabs = el('div', '', 'tabs');
  tabs.append(button('Пользователи', admin), button('Создать пользователя', () => accountForm()), button('Журнал событий', auditLog));
  body.append(tabs);
  for (const u of await api('/admin/users')) {
    const row = el('div', '', 'person'),
      info = el('div', name(u));
    info.append(el('small', `@${u.login} · ${u.role==='admin'?'Администратор':'Пользователь'}${u.deleted?' · Удалён':u.blocked?' · Заблокирован':''}`));
    row.append(info);
    if (!u.deleted) {
      const actions = el('div', '', 'actions');
      actions.append(button('Изменить', () => accountForm(u)), button(u.blocked ? 'Разблокировать' : 'Заблокировать', () => accountAction(u, u.blocked ? 'unblock' : 'block')), button('Завершить сеансы', () => accountAction(u, 'revoke')), button('Сбросить пароль', () => resetPassword(u)), button('Удалить', () => confirmDelete(u), 'danger'));
      row.append(actions);
    }
    body.append(row);
  }
}
async function accountAction(u, action, password = '') {
  await api(`/admin/users/${u.id}/action`, 'POST', {
    action,
    password
  });
  notice('Изменения сохранены');
  if (token) await admin();
}

function field(form, label, type, value = '') {
  const wrap = el('label', label),
    input = el('input');
  input.type = type;
  input.value = value;
  input.required = true;
  wrap.append(input);
  form.append(wrap);
  return input;
}

function accountForm(u = null) {
  const body = modal(u ? 'Изменить пользователя' : 'Создать пользователя'),
    form = el('form');
  const first = field(form, 'Имя', 'text', u?.first_name),
    last = field(form, 'Фамилия', 'text', u?.last_name),
    login = field(form, 'Логин (латинские буквы, цифры, . _ -)', 'text', u?.login);
  first.maxLength = last.maxLength = 80;
  login.maxLength = 40;
  login.pattern = '[a-zA-Z0-9_.-]{3,40}';
  let password;
  if (!u) {
    password = field(form, 'Пароль (от 8 символов, буквы и цифры)', 'password');
    password.minLength = 8;
    password.autocomplete = 'new-password';
  }
  const label = el('label', 'Роль'),
    role = el('select');
  for (const [value, text] of [
      ['user', 'Пользователь'],
      ['admin', 'Администратор']
    ]) {
    const option = el('option', text);
    option.value = value;
    role.append(option);
  }
  role.value = u?.role || 'user';
  label.append(role);
  form.append(label);
  const submit = el('button', 'Сохранить', 'primary');
  submit.type = 'submit';
  form.append(submit);
  form.onsubmit = async event => {
    event.preventDefault();
    submit.disabled = true;
    try {
      await api('/admin/users' + (u ? '/' + u.id : ''), u ? 'PUT' : 'POST', {
        first_name: first.value.trim(),
        last_name: last.value.trim(),
        login: login.value.trim(),
        password: password?.value || '',
        role: role.value
      });
      await admin();
      notice('Учётная запись сохранена');
    } catch (error) {
      notice(error);
    } finally {
      submit.disabled = false;
    }
  };
  body.append(form);
}

function resetPassword(u) {
  const body = modal('Сбросить пароль · ' + name(u)),
    form = el('form');
  body.append(el('p', 'Сброс пароля завершит все сеансы. Секретная фраза и ключи переписки останутся прежними.'));
  const input = field(form, 'Новый пароль', 'password');
  input.minLength = 8;
  const submit = el('button', 'Сохранить', 'primary');
  form.append(submit);
  form.onsubmit = event => {
    event.preventDefault();
    accountAction(u, 'reset_password', input.value).catch(notice);
  };
  body.append(form);
}

function confirmDelete(u) {
  const body = modal('Удалить учётную запись');
  body.append(el('p', `Удалить ${name(u)} (@${u.login})? Вход будет закрыт, участие в чатах прекращено. Отправленные сообщения сохранятся у собеседников.`), button('Удалить пользователя', () => accountAction(u, 'delete'), 'danger'));
}
async function auditLog() {
  const body = modal('Журнал событий безопасности');
  body.append(button('Назад к пользователям', admin));
  for (const row of await api('/admin/audit')) body.append(el('div', `${new Date(row.created_at).toLocaleString('ru-RU')} · ${events[row.event]||row.event} · ${row.login||'Неизвестный пользователь'}${row.target_id?' · пользователь №'+row.target_id:''}`, 'audit'));
}
$('admin-btn').onclick = () => admin().catch(notice);
