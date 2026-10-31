const fragment = location.hash.slice(1);
if (fragment) { sessionStorage.setItem('activation', fragment); history.replaceState(null, '', '/connect'); }
const token = sessionStorage.getItem('activation');
const message = document.getElementById('message');
async function api(path, method = 'GET') {
  const r = await fetch(path, {method, headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, ...(method === 'POST' ? {body: '{}'} : {})});
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw Error(e.error || 'Ошибка подключения'); }
  return r;
}
async function refresh() {
  const d = await (await api('/api/status')).json();
  document.getElementById('details').hidden = false;
  for (const k of ['name','dot','doh']) document.getElementById(k).textContent = d[k];
  document.getElementById('networks').replaceChildren(...d.networks.map(n => {
    const li = document.createElement('li'); li.textContent = n.ip + ' — до ' + new Date(n.expires * 1000).toLocaleString('ru-RU'); return li;
  }));
  if (!d.networks.length) {const li = document.createElement('li'); li.textContent = 'Пока нет активированных сетей'; document.getElementById('networks').append(li);}
  message.textContent = 'Сохрани адрес DNS в настройках устройства. Для доступа через Финляндию активируй текущую сеть.';
}
document.getElementById('activate').onclick = async e => {
  e.target.disabled = true;
  try { const d = await (await api('/api/activate', 'POST')).json(); await refresh(); message.textContent = 'Сеть ' + d.ip + ' добавлена. Правила применятся в течение 10 секунд.'; }
  catch (err) { message.textContent = err.message; }
  finally { e.target.disabled = false; }
};
document.getElementById('profile').onclick = async () => {
  try { const blob = await (await api('/api/profile', 'POST')).blob(); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'smartdns-dns.mobileconfig'; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000); }
  catch (err) { message.textContent = err.message; }
};
if (token) refresh().catch(err => { message.textContent = err.message; });
else message.textContent = 'Открой личную ссылку подключения, которую выдал владелец сервиса.';
