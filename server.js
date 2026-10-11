require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const yaml = require('js-yaml');
const util = require('util');
const { exec } = require('child_process');
const execAsync = util.promisify(exec);

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/vpsdashboard');

// ============ CONFIG ============
const {
  JWT_SECRET = 'change-me',
  PORT = 3000,
  HOST_IP = '127.0.0.1',
  TUNNEL_ID,
  BASE_DOMAIN,
  PANEL_HOSTNAME,
  CLOUDFLARED_CONFIG = '/root/.cloudflared/config.yml',
  CF_API_TOKEN,
  CF_ZONE_ID,
  PORT_RANGE_START = 2004,
  PORT_RANGE_END = 2200
} = process.env;

const TUNNEL_ENABLED = Boolean(TUNNEL_ID && BASE_DOMAIN);

// ============ MODELS ============
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  coins: { type: Number, default: 10 },
  completedTasks: [String],
  createdAt: { type: Date, default: Date.now }
}));

const VPS = mongoose.model('VPS', new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  name: String,
  containerName: { type: String, unique: true },
  ram: Number,
  cpu: Number,
  disk: Number,
  port: { type: Number, unique: true, sparse: true },   // host-side port
  hostname: String,                                     // for tunnel DNS
  password: String,
  status: { type: String, default: 'creating' },        // creating|running|stopped|failed
  createdAt: { type: Date, default: Date.now }
}));

const Task = mongoose.model('Task', new mongoose.Schema({
  taskId: { type: String, unique: true },
  title: String,
  description: String,
  reward: Number,
  type: String
}));

// ============ SEED TASKS ============
(async () => {
  if (await Task.countDocuments() === 0) {
    await Task.insertMany([
      { taskId: 'daily_login',    title: 'Daily Login',       description: 'Log in once a day',         reward: 5,  type: 'daily' },
      { taskId: 'watch_ad',       title: 'Watch an Ad',        description: 'Watch a 30-sec ad',         reward: 3,  type: 'daily' },
      { taskId: 'survey',         title: 'Complete a Survey',  description: 'Answer a short survey',     reward: 10, type: 'daily' },
      { taskId: 'twitter_follow', title: 'Follow on Twitter',  description: 'Follow @yourhandle',        reward: 20, type: 'once'  },
      { taskId: 'discord_join',   title: 'Join Discord',       description: 'Join the community server', reward: 15, type: 'once'  },
      { taskId: 'invite_friend',  title: 'Invite a Friend',    description: 'Share your referral link',  reward: 50, type: 'once'  }
    ]);
  }
})();

// ============ AUTH ============
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hash, coins: 10 });
    const token = jwt.sign({ id: user._id, username }, JWT_SECRET);
    res.json({ token, user: { username, coins: user.coins } });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user._id, username }, JWT_SECRET);
  res.json({ token, user: { username, coins: user.coins } });
});

app.get('/api/me', auth, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  const vps = await VPS.find({ userId: req.user.id });
  res.json({ user, vps, tunnelEnabled: TUNNEL_ENABLED, hostIp: HOST_IP });
});

// ============ TASKS ============
app.get('/api/tasks', auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  const tasks = await Task.find();
  const today = new Date().toDateString();
  res.json(tasks.map(t => {
    const key = t.type === 'daily' ? `${t.taskId}_${today}` : t.taskId;
    return { ...t.toObject(), completed: user.completedTasks.includes(key) };
  }));
});

app.post('/api/tasks/:taskId/complete', auth, async (req, res) => {
  const task = await Task.findOne({ taskId: req.params.taskId });
  if (!task) return res.status(404).json({ error: 'Task not found' });
  const user = await User.findById(req.user.id);
  const today = new Date().toDateString();
  const key = task.type === 'daily' ? `${task.taskId}_${today}` : task.taskId;
  if (user.completedTasks.includes(key))
    return res.status(400).json({ error: 'Already completed' });
  user.completedTasks.push(key);
  user.coins += task.reward;
  await user.save();
  res.json({ coins: user.coins, reward: task.reward });
});

// ============ PORT ALLOCATOR ============
async function allocatePort() {
  const used = new Set((await VPS.find({ port: { $ne: null } })).map(v => v.port));
  for (let p = +PORT_RANGE_START; p <= +PORT_RANGE_END; p++) {
    if (!used.has(p)) return p;
  }
  throw new Error('No ports available');
}

// ============ CLOUDFLARE TUNNEL MGMT ============
async function syncTunnelIngress() {
  if (!TUNNEL_ENABLED) return;

  const vpsList = await VPS.find({ status: { $in: ['running', 'stopped', 'creating'] }, port: { $ne: null } });

  const ingress = [{ hostname: PANEL_HOSTNAME, service: 'http://localhost:' + PORT }];
  for (const v of vpsList) {
    ingress.push({
      hostname: `${v.containerName}.${BASE_DOMAIN}`,
      service: `http://localhost:${v.port}`
    });
  }
  ingress.push({ service: 'http_status:404' });

  const cfg = {
    tunnel: TUNNEL_ID,
    'credentials-file': `/root/.cloudflared/${TUNNEL_ID}.json`,
    ingress
  };
  try {
    await fs.writeFile(CLOUDFLARED_CONFIG, yaml.dump(cfg));
    await execAsync('systemctl restart cloudflared').catch(e =>
      console.error('[cloudflared reload]', e.message));
    console.log('[tunnel] ingress synced:', ingress.length - 2, 'vps');
  } catch (e) { console.error('[tunnel sync]', e.message); }
}

async function createDnsRoute(hostname) {
  if (!CF_API_TOKEN || !CF_ZONE_ID || !TUNNEL_ENABLED) return;
  const res = await fetch(`https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${CF_API_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      type: 'CNAME', name: hostname,
      content: `${TUNNEL_ID}.cfargotunnel.com`,
      proxied: true, ttl: 1
    })
  });
  const data = await res.json();
  if (!data.success && data.errors?.[0]?.code !== 81057)   // 81057 = already exists
    console.error('[dns]', data.errors);
}

async function deleteDnsRoute(hostname) {
  if (!CF_API_TOKEN || !CF_ZONE_ID) return;
  const list = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records?name=${hostname}`,
    { headers: { Authorization: `Bearer ${CF_API_TOKEN}` } }
  ).then(r => r.json());
  const rec = list.result?.[0];
  if (!rec) return;
  await fetch(
    `https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records/${rec.id}`,
    { method: 'DELETE', headers: { Authorization: `Bearer ${CF_API_TOKEN}` } }
  );
}

// ============ LXD CONTAINER PROVISIONING ============
function generatePassword() {
  return Math.random().toString(36).slice(-12) + 'Aa1!';
}

async function createLXDContainer(vps) {
  const { containerName, ram, cpu, disk, port, password } = vps;

  try {
    // 1. Launch container on private bridge (10.x.x.x)
    //    limits.memory.enforce=hard → RAM cap really applies
    await execAsync(
      `lxc launch ubuntu:22.04 ${containerName} ` +
      `-c limits.cpu=${cpu} ` +
      `-c limits.memory=${ram}MB ` +
      `-c limits.memory.enforce=hard`
    );

    // 2. Wait for cloud-init / networking
    await new Promise(r => setTimeout(r, 20000));

    // 3. Root password
    await execAsync(`lxc exec ${containerName} -- bash -c "echo 'root:${password}' | chpasswd"`);

    // 4. Install nginx + ssh
    await execAsync(
      `lxc exec ${containerName} -- bash -c "export DEBIAN_FRONTEND=noninteractive; ` +
      `apt-get update -qq && apt-get install -y -qq openssh-server nginx"`
    );

    // 5. Make nginx listen on 2004 inside the container
    await execAsync(
      `lxc exec ${containerName} -- bash -c "` +
      `sed -i 's/listen 80 default_server;/listen 2004 default_server;/' /etc/nginx/sites-available/default; ` +
      `sed -i 's/listen \\[::\\]:80 default_server;/listen [::]:2004 default_server;/' /etc/nginx/sites-available/default; ` +
      `systemctl restart nginx"`
    );

    // 6. Enable SSH root login
    await execAsync(
      `lxc exec ${containerName} -- bash -c "` +
      `sed -i 's/#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config; ` +
      `systemctl restart ssh"`
    );

    // 7. Put a nice landing page (optional)
    await execAsync(
      `lxc exec ${containerName} -- bash -c "` +
      `echo '<h1>VPS ${containerName} is running 🚀</h1><p>Port 2004 is live.</p>' ` +
      `> /var/www/html/index.html"`
    );

    // 8. Publish the container's port to host on 127.0.0.1 (safer than 0.0.0.0)
    //    We'll still allow direct IPv4 access via a second proxy on 0.0.0.0 (step 9)
    await execAsync(
      `lxc config device add ${containerName} web-tunnel ` +
      `proxy listen=tcp:127.0.0.1:${port} connect=tcp:127.0.0.1:2004`
    );

    // 9. Public IPv4 exposure on 0.0.0.0:<port> for direct access
    //    (only if you want users to hit http://HOST_IP:2004 directly)
    await execAsync(
      `lxc config device add ${containerName} web-public ` +
      `proxy listen=tcp:0.0.0.0:${port} connect=tcp:127.0.0.1:2004`
    );

    // 10. Mark running
    vps.status = 'running';
    vps.hostname = TUNNEL_ENABLED ? `${containerName}.${BASE_DOMAIN}` : null;
    await vps.save();

    // 11. Tunnel: create DNS + resync ingress
    if (TUNNEL_ENABLED) {
      await createDnsRoute(vps.hostname);
      await syncTunnelIngress();
    }

    console.log(`✅ VPS ready — direct: http://${HOST_IP}:${port}` +
      (TUNNEL_ENABLED ? ` | tunnel: https://${vps.hostname}` : ''));
  } catch (e) {
    console.error('❌ LXD failed:', e.message);
    vps.status = 'failed';
    await vps.save();
  }
}

// ============ VPS API ============
const RAM_COST = 5, CPU_COST = 3, DISK_COST = 1;

app.post('/api/vps/create', auth, async (req, res) => {
  try {
    const { name, ram, cpu, disk } = req.body;
    if (!name || !/^[a-z0-9-]+$/.test(name)) return res.status(400).json({ error: 'Invalid name' });
    if (ram < 256 || ram > 4096) return res.status(400).json({ error: 'RAM 256-4096' });
    if (cpu < 1 || cpu > 4)       return res.status(400).json({ error: 'CPU 1-4' });
    if (disk < 2 || disk > 40)    return res.status(400).json({ error: 'Disk 2-40' });

    const cost = Math.ceil(ram / 256) * RAM_COST + cpu * CPU_COST + disk * DISK_COST;
    const user = await User.findById(req.user.id);
    if (user.coins < cost)
      return res.status(400).json({ error: `Need ${cost} coins, you have ${user.coins}` });

    const containerName = `${user.username}-${name}`.toLowerCase().replace(/[^a-z0-9-]/g, '');
    const exists = await VPS.findOne({ containerName });
    if (exists) return res.status(400).json({ error: 'Name already used' });

    const port = await allocatePort();
    const password = generatePassword();

    const vps = await VPS.create({
      userId: user.id, name, containerName,
      ram, cpu, disk, port, password, status: 'creating'
    });

    user.coins -= cost;
    await user.save();

    // async
    createLXDContainer(vps).catch(console.error);

    res.json({ vps, cost, coins: user.coins });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/vps/:id/action', auth, async (req, res) => {
  const vps = await VPS.findOne({ _id: req.params.id, userId: req.user.id });
  if (!vps) return res.status(404).json({ error: 'Not found' });
  const { action } = req.body;
  if (!['start', 'stop', 'restart'].includes(action))
    return res.status(400).json({ error: 'Invalid action' });
  try {
    await execAsync(`lxc ${action} ${vps.containerName}`);
    vps.status = action === 'stop' ? 'stopped' : 'running';
    await vps.save();
    res.json({ status: vps.status });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/vps/:id', auth, async (req, res) => {
  const vps = await VPS.findOne({ _id: req.params.id, userId: req.user.id });
  if (!vps) return res.status(404).json({ error: 'Not found' });
  try {
    await execAsync(`lxc delete ${vps.containerName} --force`).catch(() => {});
    if (vps.hostname) await deleteDnsRoute(vps.hostname);
    await VPS.deleteOne({ _id: vps._id });
    await syncTunnelIngress();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============ BOOT ============
app.listen(PORT, () => {
  console.log(`🚀 Dashboard: http://${HOST_IP}:${PORT}`);
  console.log(`   Tunnel: ${TUNNEL_ENABLED ? 'ENABLED (' + BASE_DOMAIN + ')' : 'disabled'}`);
  syncTunnelIngress().catch(console.error);
});
