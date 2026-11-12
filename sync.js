(() => {
  'use strict';

  const key = 'hybrid42-device-sync-v1';
  const progressKey = 'hybrid42-progress-v1';
  const dialog = document.getElementById('syncDialog');
  const button = document.getElementById('syncButton');
  const status = document.getElementById('syncStatus');
  const start = document.getElementById('syncStart');
  const connected = document.getElementById('syncConnected');
  const codeField = document.getElementById('syncCode');
  const reveal = document.getElementById('syncReveal');
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  let checkpointDb, connection, running = false, timer, retryDelay = 3000;

  const isObject = value => !!value && typeof value === 'object' && !Array.isArray(value);
  const equal = (a, b) => a === b || JSON.stringify(a) === JSON.stringify(b);
  const readProgress = () => JSON.parse(localStorage.getItem(progressKey) || 'null');
  function loadCode() {
    try { return localStorage.getItem(key); } catch { return null; }
  }

  // Merge independent changes and deletions against the last shared copy.
  // For two edits to the same field, the device writing this update wins.
  function mergeList(base, local, remote) {
    const localAdditions = local.slice();
    const remoteAdditions = remote.slice();
    const kept = [];
    for (const entry of Array.isArray(base) ? base : []) {
      const localIndex = localAdditions.findIndex(item => equal(item, entry));
      const remoteIndex = remoteAdditions.findIndex(item => equal(item, entry));
      if (localIndex >= 0) localAdditions.splice(localIndex, 1);
      if (remoteIndex >= 0) remoteAdditions.splice(remoteIndex, 1);
      if (localIndex >= 0 && remoteIndex >= 0) kept.push(entry);
    }
    return [...kept, ...remoteAdditions, ...localAdditions];
  }

  function merge(base, local, remote, field) {
    if (equal(local, base)) return remote;
    if (equal(remote, base) || equal(local, remote)) return local;
    if (Array.isArray(local) && Array.isArray(remote) && ['extras', 'archiveDates'].includes(field)) {
      return mergeList(base, local, remote);
    }
    if (isObject(local) && isObject(remote)) {
      const original = isObject(base) ? base : {};
      return Object.fromEntries([...new Set([...Object.keys(local), ...Object.keys(remote)])].flatMap(name => {
        const value = merge(
          Object.hasOwn(original, name) ? original[name] : undefined,
          Object.hasOwn(local, name) ? local[name] : undefined,
          Object.hasOwn(remote, name) ? remote[name] : undefined,
          name,
        );
        return value === undefined ? [] : [[name, value]];
      }));
    }
    return local;
  }

  // When pairing a second device, prefer the already synced value for a shared
  // field and keep the local device's independent entries.
  function combine(local, remote) {
    if (!isObject(local) || !isObject(remote)) return remote;
    return Object.fromEntries([...new Set([...Object.keys(local), ...Object.keys(remote)])].map(name => [
      name, Object.hasOwn(remote, name) ? combine(
        Object.hasOwn(local, name) ? local[name] : undefined, remote[name],
      ) : local[name],
    ]));
  }

  function updateStatus(message, label = 'Sync') {
    status.textContent = message;
    button.textContent = label;
  }

  function refreshDialog() {
    const paired = !!loadCode();
    start.hidden = paired;
    connected.hidden = !paired;
    document.querySelectorAll('#syncDialog button[data-sync-command]').forEach(control => {
      control.disabled = running;
    });
  }

  function newCode() {
    const random = crypto.getRandomValues(new Uint8Array(32));
    return 'H42-' + btoa(String.fromCharCode(...random)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  }

  async function credentials(code) {
    if (!/^H42-[A-Za-z0-9_-]{43}$/.test(code)) throw new Error('Enter the full sync code from your other device.');
    const raw = Uint8Array.from(atob(code.slice(4).replaceAll('-', '+').replaceAll('_', '/')), letter => letter.charCodeAt(0));
    // The server receives a separate access credential, never the encryption key.
    const digest = await crypto.subtle.digest('SHA-256', encoder.encode('hybrid42-sync-access-v1:' + code));
    const bearer = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
    const cipher = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
    return { code, bearer, cipher };
  }

  async function transform(bytes, stream) {
    return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(stream)).arrayBuffer());
  }

  async function seal(progress, cipher) {
    let bytes = encoder.encode(JSON.stringify(progress));
    const compressed = typeof CompressionStream === 'function' && bytes.length > 4096;
    if (compressed) bytes = await transform(bytes, new CompressionStream('gzip'));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const flag = Uint8Array.of(compressed ? 1 : 0);
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name:'AES-GCM', iv, additionalData:flag }, cipher, bytes));
    if (encrypted.length + 13 > 4_000_000) throw new Error('The saved log is too large to sync. Your local copy is still saved.');
    const payload = new Uint8Array(13 + encrypted.length);
    payload.set(flag);
    payload.set(iv, 1);
    payload.set(encrypted, 13);
    return payload;
  }

  async function openPayload(buffer, cipher) {
    const bytes = new Uint8Array(buffer);
    const flag = bytes.slice(0, 1);
    const iv = bytes.slice(1, 13);
    let plain = await crypto.subtle.decrypt({ name:'AES-GCM', iv, additionalData:flag }, cipher, bytes.slice(13));
    if (flag[0] === 1) {
      if (typeof DecompressionStream !== 'function') throw new Error('Update this browser to open the synced log.');
      plain = await transform(plain, new DecompressionStream('gzip'));
    }
    const progress = JSON.parse(decoder.decode(plain));
    if (!isObject(progress?.logs) || !Number.isInteger(progress.version)) throw new Error('Could not read the synced log.');
    return progress;
  }

  function openCheckpointDb() {
    if (!checkpointDb) {
      checkpointDb = new Promise((resolve, reject) => {
        const request = indexedDB.open('hybrid42-sync', 1);
        request.onupgradeneeded = () => request.result.createObjectStore('checkpoints');
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(new Error('This browser could not open sync storage.'));
      });
    }
    return checkpointDb;
  }

  async function checkpoint(bearer, value) {
    const db = await openCheckpointDb();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction('checkpoints', value ? 'readwrite' : 'readonly');
      const store = transaction.objectStore('checkpoints');
      const request = value ? store.put(value, bearer) : store.get(bearer);
      transaction.oncomplete = () => resolve(request.result);
      transaction.onabort = transaction.onerror = () => reject(new Error('This browser could not save the sync checkpoint.'));
    });
  }

  async function syncRequest(auth, method, headers = {}, body) {
    const response = await fetch('/api/sync', {
      method, headers: { Authorization: 'Bearer ' + auth.bearer, ...headers }, body, cache:'no-store',
      signal: AbortSignal.timeout(20000),
    });
    if (response.status === 413) throw new Error('The saved log is too large to sync. Your local copy is still saved.');
    if (!response.ok && ![304,404,409].includes(response.status)) {
      throw new Error('Sync is temporarily unavailable. Your local copy is still saved.');
    }
    return response;
  }

  function apply(progress) {
    const event = new CustomEvent('hybrid42:apply-sync', { detail:progress, cancelable:true });
    if (!window.dispatchEvent(event)) throw new Error('This browser ran out of room to save the synced log.');
  }

  function schedule(delay = 1600) {
    clearTimeout(timer);
    timer = setTimeout(() => synchronize(), delay);
  }

  async function synchronize(mode = 'resume', requestedCode) {
    if (running) {
      if (mode === 'resume') schedule();
      return;
    }
    const savedCode = loadCode();
    if (mode === 'resume' && !savedCode) return;

    running = true;
    refreshDialog();
    updateStatus('Syncing…', 'Sync…');
    try {
      const code = requestedCode ?? savedCode;
      const auth = connection?.code === code ? connection : await credentials(code);
      const last = mode === 'resume' ? await checkpoint(auth.bearer) : undefined;

      for (let attempt = 0; attempt < 4; attempt++) {
        if (mode === 'resume' && loadCode() !== savedCode) return;
        const download = await syncRequest(auth, 'GET', last ? { 'If-None-Match':last.etag } : {});
        const missing = download.status === 404;
        if (mode === 'join' && missing) throw new Error('No synced log found. Start sync on the device with your results first.');
        const remote = missing ? null : download.status === 304 ? last.progress : await openPayload(await download.arrayBuffer(), auth.cipher);
        let etag = missing ? null : download.headers.get('x-hybrid42-revision') || last?.etag;
        if (remote && !etag) throw new Error('The sync service did not return a saved version.');
        const local = readProgress();
        if (!local) throw new Error('This browser has no readable local progress.');
        const merged = !remote ? local : last ? merge(last.progress, local, remote) : combine(local, remote);
        if (!remote || !equal(merged, remote)) {
          const bytes = await seal(merged, auth.cipher);
          const headers = { 'Content-Type':'application/octet-stream' };
          if (etag) headers['If-Match'] = etag;
          else headers['If-None-Match'] = '*';
          const upload = await syncRequest(auth, 'PUT', headers, bytes);
          if (upload.status === 409 || upload.status === 404) continue;
          etag = upload.headers.get('x-hybrid42-revision');
          if (!etag) throw new Error('The sync service did not confirm the saved version.');
        }
        // A form or another tab can save while the upload is in flight.
        if (mode === 'resume' && loadCode() !== savedCode) return;
        const latest = readProgress();
        const reconciled = merge(local, latest, merged);
        if (!equal(latest, reconciled)) apply(reconciled);
        const saved = { etag, progress:merged };
        if (!last || last.etag !== etag) await checkpoint(auth.bearer, saved);
        if (mode !== 'resume') localStorage.setItem(key, code);
        connection = auth;
        retryDelay = 3000;
        updateStatus('Synced at ' + new Date().toLocaleTimeString([], {hour:'numeric', minute:'2-digit'}) + '.', 'Synced');
        if (!equal(readProgress(), merged)) schedule();
        return;
      }
      throw new Error('Another device is still updating. Try syncing again shortly.');
    } catch (error) {
      const message = error instanceof TypeError || error.name === 'TimeoutError'
        ? 'Could not reach sync. Your local copy is still saved.'
        : error.message;
      updateStatus(message, 'Sync');
      if (mode === 'resume' && navigator.onLine) {
        schedule(retryDelay);
        retryDelay = Math.min(120000, retryDelay * 2);
      }
    } finally {
      running = false;
      refreshDialog();
    }
  }

  button.addEventListener('click', () => {
    refreshDialog();
    dialog.showModal();
  });
  dialog.addEventListener('close', () => {
    reveal.hidden = true;
    codeField.value = '';
  });
  document.getElementById('syncCreate').addEventListener('click', async () => {
    await synchronize('create', newCode());
    if (loadCode() && dialog.open) document.getElementById('syncShowCode').click();
  });
  document.getElementById('syncJoin').addEventListener('submit', event => {
    event.preventDefault();
    synchronize('join', document.getElementById('syncJoinCode').value.trim());
  });
  document.getElementById('syncNow').addEventListener('click', () => synchronize());
  document.getElementById('syncShowCode').addEventListener('click', () => {
    codeField.value = loadCode() || '';
    reveal.hidden = false;
  });
  document.getElementById('syncCopy').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(codeField.value);
      status.textContent = 'Sync code copied.';
    } catch {
      codeField.select();
      status.textContent = 'Select and copy the sync code.';
    }
  });
  document.getElementById('syncDisconnect').addEventListener('click', () => {
    localStorage.removeItem(key);
    connection = undefined;
    reveal.hidden = true;
    codeField.value = '';
    updateStatus('Device disconnected. Your local progress is still here.');
    refreshDialog();
  });

  window.addEventListener('hybrid42:save', () => {
    if (!loadCode()) return;
    updateStatus('Changes saved here. Sync pending.', 'Sync…');
    schedule();
  });
  window.addEventListener('storage', event => {
    if (event.key === progressKey && loadCode()) schedule();
    if (event.key === key) {
      connection = undefined;
      refreshDialog();
      if (loadCode()) schedule();
      else updateStatus('Device disconnected. Your local progress is still here.');
    }
  });
  window.addEventListener('online', () => { if (loadCode()) synchronize(); });
  window.addEventListener('focus', () => { if (loadCode() && !running) schedule(250); });
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && loadCode()) synchronize();
  });
  setInterval(() => { if (!document.hidden && loadCode()) synchronize(); }, 120000);
  if (loadCode()) synchronize();
})();
