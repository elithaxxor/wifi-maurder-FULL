document.addEventListener('DOMContentLoaded', () => {
  const sections = document.querySelectorAll('.section');
  const items = document.querySelectorAll('#sidebar li');
  function show(sectionId) {
    sections.forEach(sec => {
      sec.classList.toggle('hidden', sec.id !== sectionId);
    });
    items.forEach(it => {
      it.classList.toggle('active', it.dataset.section === sectionId);
    });
  }
  items.forEach(it => {
    it.addEventListener('click', () => show(it.dataset.section));
  });
  // default
  show('interfaces');

  // Interfaces
  document.getElementById('refresh-interfaces').addEventListener('click', loadInterfaces);
  document.getElementById('enable-monitor').addEventListener('click', () => {
    const iface = document.querySelector('#interface-list input:checked');
    if (!iface) alert('Select an interface');
    else fetch('/monitor-mode', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({interface: iface.value})
    }).then(r => r.json()).then(() => alert('Monitor mode enabled'));
  });
  function loadInterfaces() {
    fetch('/interfaces').then(r => r.json()).then(data => {
      const list = document.getElementById('interface-list'); list.innerHTML = '';
      data.interfaces.forEach(i => {
        const li = document.createElement('li');
        li.innerHTML = `<label><input type="radio" name="iface" value="${i}"> ${i}</label>`;
        list.appendChild(li);
      });
    });
  }
  loadInterfaces();

  // Scan
  document.getElementById('start-scan').addEventListener('click', () => {
    const iface = document.querySelector('#interface-list input:checked')?.value;
    const duration = parseInt(document.getElementById('scan-duration').value);
    if (!iface) return alert('Select an interface');
    fetch('/scan/start', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({interface: iface, duration})
    });
    const interval = setInterval(() => {
      fetch('/scan/progress').then(r=>r.json()).then(p => {
        document.getElementById('scan-progress-bar').style.width = p.percent + '%';
        if (p.percent>=100) {
          clearInterval(interval);
          fetch('/scan/stop').then(r=>r.json()).then(res=>{
            const tbody = document.querySelector('#scan-results tbody'); tbody.innerHTML = '';
            res.networks.forEach(n=>{
              const row = document.createElement('tr');
              row.innerHTML = `<td>${n.bssid}</td><td>${n.essid}</td><td>${n.signal}</td><td>${n.channel}</td><td>${n.encryption}</td>`;
              tbody.appendChild(row);
            });
            loadLogs(); loadRaw();
          });
        } else loadRaw();
      });
    }, 1000);
  });
  function loadLogs() {
    fetch('/scan/logs').then(r=>r.json()).then(data=>{
      const tbody = document.querySelector('#scan-logs tbody'); tbody.innerHTML = '';
      data.logs.forEach(l=>{
        const row = document.createElement('tr');
        row.innerHTML = `<td>${l[0]}</td><td>${l[1]}</td><td>${l[2]}</td><td>${l[3]}</td><td>${l[4]}</td>`;
        tbody.appendChild(row);
      });
    });
  }
  function loadRaw() {
    fetch('/scan/raw').then(r=>r.json()).then(data=>{
      document.getElementById('scan-raw').textContent = data.raw;
    }).catch(()=>{});
  }
});