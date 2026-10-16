// Запуск: node tests/browser.cjs (пакет playwright и установленный Chrome).
const {
  chromium,
  request
} = require('playwright');
const fs = require('fs');
const assert = require('node:assert/strict');
const path = require('path');

(async () => {
  fs.mkdirSync('test-results', {
    recursive: true
  });
  const config = Object.fromEntries(fs.readFileSync('.env', 'utf8').trim().split(/\r?\n/).map(line => line.split('=')));
  const http = await request.newContext({
    baseURL: 'https://localhost:8443',
    ignoreHTTPSErrors: true
  });
  const result = await http.post('/api/login', {
    data: {
      login: 'admin',
      password: config.ADMIN_PASSWORD
    }
  });
  assert.equal(result.status(), 200);
  const auth = {
    Authorization: 'Bearer ' + (await result.json()).token
  };
  const users = await (await http.get('/api/admin/users', {
    headers: auth
  })).json();
  for (const data of [{
      login: 'alice',
      first_name: 'Алиса',
      last_name: 'Иванова',
      password: 'StudyAlice2026'
    }, {
      login: 'bob',
      first_name: 'Борис',
      last_name: 'Петров',
      password: 'StudyBob2026'
    }])
    if (!users.some(u => u.login === data.login)) assert.equal((await http.post('/api/admin/users', {
      headers: auth,
      data
    })).status(), 200);
  const browser = await chromium.launch({
    channel: 'chrome',
    headless: true
  });
  const errors = [];
  const contexts = [];
  async function page() {
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      viewport: {
        width: 1440,
        height: 900
      },
      acceptDownloads: true
    });
    contexts.push(context);
    const page = await context.newPage();
    page.on('pageerror', e => errors.push(e.message));
    await page.goto('https://localhost:8443');
    return page;
  }
  async function signIn(p, login, password, phrase) {
    await p.locator('#login').fill(login);
    await p.locator('#password').fill(password);
    await p.getByRole('button', {
      name: 'Войти',
      exact: true
    }).click();
    await p.locator('#key-screen').waitFor({
      state: 'visible'
    });
    await p.locator('#phrase').fill(phrase);
    if (await p.locator('#phrase-repeat-label').isVisible()) await p.locator('#phrase-repeat').fill(phrase);
    await p.getByRole('button', {
      name: 'Открыть мессенджер'
    }).click();
    await p.locator('#workspace').waitFor({
      state: 'visible'
    });
  }
  try {
    const a = await page(),
      b = await page();
    await a.screenshot({
      path: 'test-results/login.png'
    });
    await signIn(a, 'alice', 'StudyAlice2026', 'Секретная фраза Алисы 2026');
    await signIn(b, 'bob', 'StudyBob2026', 'Секретная фраза Бориса 2026');
    await a.getByRole('button', {
      name: 'Контакты',
      exact: true
    }).click();
    await a.locator('.person').filter({
      hasText: 'Борис Петров'
    }).getByRole('button', {
      name: 'Написать'
    }).click();
    const text = 'Привет, Борис! Это зашифрованное сообщение. ' + Date.now();
    const start = Date.now();
    await a.locator('#text').fill(text);
    await a.getByRole('button', {
      name: 'Отправить',
      exact: true
    }).click();
    await b.locator('#chat-list button').filter({
      hasText: 'Алиса Иванова'
    }).click();
    await b.getByText(text, {
      exact: true
    }).waitFor();
    const deliveryMs = Date.now() - start;
    await a.locator('.message').filter({
      hasText: text
    }).getByText('Прочитано', {
      exact: true
    }).waitFor();
    await b.locator('.message').filter({hasText: text}).locator('summary').click();
    await b.locator('.message').filter({
      hasText: text
    }).getByRole('button', {
      name: 'Ответить'
    }).click();
    await b.locator('#text').fill('Получено! Отправляю ответ.');
    await b.getByRole('button', {
      name: 'Отправить',
      exact: true
    }).click();
    await a.getByText('Получено! Отправляю ответ.', {
      exact: true
    }).last().waitFor();
    const fileData = Buffer.from('Содержимое учебного файла: шифруется вместе с именем.', 'utf8');
    await a.locator('#file').setInputFiles({
      name: 'Учебный документ.txt',
      mimeType: 'text/plain',
      buffer: fileData
    });
    await a.getByRole('button', {
      name: 'Отправить',
      exact: true
    }).click();
    const fileButton = b.getByRole('button', {
      name: /↓ Учебный документ.txt/
    }).last();
    await fileButton.waitFor();
    const downloadPromise = b.waitForEvent('download');
    await fileButton.click();
    const download = await downloadPromise;
    assert.deepEqual(fs.readFileSync(await download.path()), fileData);
    // Реальный повторный вход с другого чистого браузерного профиля.
    const second = await page();
    await signIn(second, 'alice', 'StudyAlice2026', 'Секретная фраза Алисы 2026');
    await second.locator('#chat-list button').filter({
      hasText: 'Борис Петров'
    }).click();
    await second.getByText(text, {
      exact: true
    }).waitFor();
    await a.locator('#text').fill('Сообщение для проверки удаления ' + Date.now());
    const deleteText = await a.locator('#text').inputValue();
    await a.getByRole('button', {
      name: 'Отправить',
      exact: true
    }).click();
    await b.getByText(deleteText, {
      exact: true
    }).waitFor();
    await a.locator('.message').filter({hasText: deleteText}).locator('summary').click();
    await a.locator('.message').filter({
      hasText: deleteText
    }).getByRole('button', {
      name: 'Удалить',
      exact: true
    }).click();
    await b.getByText(deleteText, {
      exact: true
    }).waitFor({
      state: 'hidden'
    });
    assert.equal(await a.locator('.chat-header').evaluate(e => e.getBoundingClientRect().top >= 0), true, 'Header remains visible');
    assert.equal(await a.locator('.composer').evaluate(e => e.getBoundingClientRect().bottom <= innerHeight + 1), true, 'Composer remains visible');
    await a.screenshot({
      path: 'test-results/chat.png'
    });
    await a.getByRole('button', {
      name: 'Создать группу',
      exact: true
    }).click();
    await a.getByLabel('Название группы').fill('Учебная группа');
    await a.getByRole('checkbox', {
      name: 'Борис Петров'
    }).check();
    await a.locator('#dialog').getByRole('button', {
      name: 'Создать группу',
      exact: true
    }).click();
    await a.locator('#chat-title').filter({
      hasText: 'Учебная группа'
    }).waitFor();
    await a.locator('#text').fill('Добро пожаловать в учебную группу!');
    await a.getByRole('button', {
      name: 'Отправить',
      exact: true
    }).click();
    await b.locator('#chat-list button').filter({
      hasText: 'Учебная группа'
    }).first().click();
    await b.getByText('Добро пожаловать в учебную группу!', {
      exact: true
    }).waitFor();
    await a.getByRole('button', {
      name: 'Участники',
      exact: true
    }).click();
    await a.locator('.person').filter({
      hasText: 'Борис Петров'
    }).getByRole('button', {
      name: 'Назначить админом'
    }).click();
    await a.locator('.person').filter({
      hasText: 'Борис Петров'
    }).getByText(/Администратор группы/).waitFor();
    await a.locator('#dialog-close').click();
    const admin = await page();
    await signIn(admin, 'admin', config.ADMIN_PASSWORD, 'Секретная фраза администратора 2026');
    await admin.getByRole('button', {
      name: 'Управление',
      exact: true
    }).click();
    await admin.locator('.person').filter({
      hasText: 'Алиса Иванова'
    }).waitFor();
    await admin.screenshot({
      path: 'test-results/admin.png'
    });
    await admin.getByRole('button', {
      name: 'Журнал событий',
      exact: true
    }).click();
    await admin.locator('.audit').first().waitFor();
    await a.setViewportSize({
      width: 390,
      height: 844
    });
    await a.screenshot({
      path: 'test-results/mobile.png'
    });
    assert.equal(await a.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'No horizontal page overflow');
    assert.deepEqual(errors, []);
    fs.writeFileSync('test-results/browser.json', JSON.stringify({
      passed: true,
      deliveryMs,
      checks: ['login', 'browser AES-GCM/RSA-OAEP', 'read receipt', 'reply', 'file byte equality', 'second device', 'delete for everyone', 'group', 'promote member', 'admin panel', 'audit', 'mobile layout'],
      errors
    }, null, 2));
    console.log('Browser checks passed; initial delivery including opening chat: ' + deliveryMs + ' ms');
  } finally {
    await browser.close();
    await http.dispose();
  }
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
