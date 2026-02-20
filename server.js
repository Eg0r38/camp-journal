const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';
const JWT_SECRET = 'counselor-journal-super-secret-key-2024';
const DATA_FILE = path.join(__dirname, 'data.json');

app.use(helmet({ 
    contentSecurityPolicy: false, 
    crossOriginEmbedderPolicy: false 
}));
app.use(compression());

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Слишком много запросов' }
});
app.use('/api/', limiter);

app.use(cors({ 
    origin: true, 
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

function log(message, type = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    const colors = { 
        info: '\x1b[36m', 
        success: '\x1b[32m', 
        error: '\x1b[31m', 
        warn: '\x1b[33m' 
    };
    console.log(`${colors[type]}[${timestamp}] ${message}\x1b[0m`);
}

function getAllLocalIPs() {
    const interfaces = os.networkInterfaces();
    const ips = [];
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                ips.push(iface.address);
            }
        }
    }
    return ips;
}

async function initializeData() {
    try {
        await fs.access(DATA_FILE);
        const data = JSON.parse(await fs.readFile(DATA_FILE, 'utf8'));
        let updated = false;
        
        if (!data.users) { data.users = []; updated = true; }
        if (!data.groups) { data.groups = {}; updated = true; }
        if (!data.members) { data.members = {}; updated = true; }
        if (!data.marks) { data.marks = {}; updated = true; }
        if (!data.activities) { data.activities = {}; updated = true; }
        if (!data.counselors) { data.counselors = {}; updated = true; }
        if (!data.helpers) { data.helpers = {}; updated = true; }
        if (!data.books) { data.books = { list: [] }; updated = true; }
        if (!data.syncHistory) { data.syncHistory = []; updated = true; }
        if (!data.userData) { data.userData = {}; updated = true; }
        
        if (updated) {
            await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2));
            log('Структура данных обновлена', 'warn');
        }
        return data;
    } catch (error) {
        const hashedPassword = await bcrypt.hash('382154', 10);
        const initialData = {
            users: [{ 
                id: 1, 
                username: 'Егор', 
                password: hashedPassword, 
                role: 'admin', 
                createdAt: new Date().toISOString(), 
                lastLogin: null, 
                isActive: true 
            }],
            groups: {}, 
            members: {}, 
            marks: {}, 
            activities: {}, 
            counselors: {}, 
            helpers: {}, 
            books: { list: [] },
            userData: {
                "1": {
                    groups: {},
                    members: {},
                    marks: {},
                    activities: {},
                    counselors: {},
                    helpers: {},
                    books: { list: [] }
                }
            },
            syncHistory: [],
            settings: { 
                allowRegistration: true,
                lastSync: null
            }
        };
        await fs.writeFile(DATA_FILE, JSON.stringify(initialData, null, 2));
        log('Создан новый файл данных', 'success');
        return initialData;
    }
}

async function loadData() {
    try {
        return JSON.parse(await fs.readFile(DATA_FILE, 'utf8'));
    } catch (error) {
        return { 
            users: [], 
            groups: {}, 
            members: {}, 
            marks: {}, 
            activities: {}, 
            counselors: {}, 
            helpers: {}, 
            books: { list: [] },
            userData: {},
            syncHistory: []
        };
    }
}

async function saveData(data) {
    try {
        await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        return false;
    }
}

async function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const data = await loadData();
        const user = data.users.find(u => u.id === decoded.id);
        if (!user || user.isActive === false) {
            return res.status(401).json({ error: 'Пользователь не найден или заблокирован' });
        }
        req.user = user;
        next();
    } catch {
        return res.status(403).json({ error: 'Недействительный токен' });
    }
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Требуются права администратора' });
    }
    next();
}

app.get('/api/server-info', (req, res) => {
    const ips = getAllLocalIPs();
    res.json({
        name: 'Журнал вожатого',
        version: '2.0.0',
        ips: ips,
        port: PORT,
        timestamp: new Date().toISOString()
    });
});

app.get('/api/health', (req, res) => res.json({ 
    status: 'ok',
    time: new Date().toISOString()
}));

app.get('/api/public-data', async (req, res) => {
    try {
        const data = await loadData();
        res.json({
            groups: data.groups || {},
            members: data.members || {},
            marks: data.marks || {},
            activities: data.activities || {},
            counselors: data.counselors || {},
            helpers: data.helpers || {},
            books: data.books || { list: [] }
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка загрузки данных' });
    }
});

app.post('/api/register', async (req, res) => {
    try {
        const { username, password, role = 'user' } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Заполните все поля' });
        }
        
        const data = await loadData();
        if (data.users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
            return res.status(400).json({ error: 'Пользователь уже существует' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: data.users.length + 1,
            username,
            password: hashedPassword,
            role,
            createdAt: new Date().toISOString(),
            lastLogin: null,
            isActive: true
        };
        
        data.users.push(newUser);
        
        if (!data.userData) data.userData = {};
        data.userData[newUser.id] = {
            groups: {},
            members: {},
            marks: {},
            activities: {},
            counselors: {},
            helpers: {},
            books: { list: [] }
        };
        
        await saveData(data);
        log(`Новый пользователь: ${username} (${role})`, 'success');
        res.json({ success: true, message: 'Регистрация успешна' });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const data = await loadData();
        const user = data.users.find(u => u.username.toLowerCase() === username.toLowerCase());
        
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Неверное имя или пароль' });
        }
        
        if (user.isActive === false) {
            return res.status(403).json({ error: 'Учетная запись заблокирована' });
        }
        
        user.lastLogin = new Date().toISOString();
        await saveData(data);
        
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role }, 
            JWT_SECRET, 
            { expiresIn: '7d' }
        );
        
        res.json({ 
            success: true, 
            user: { id: user.id, username: user.username, role: user.role }, 
            token 
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/me', authenticateToken, (req, res) => {
    res.json({ user: { id: req.user.id, username: req.user.username, role: req.user.role } });
});

app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const data = await loadData();
        res.json(data.users.map(u => ({
            id: u.id, 
            username: u.username, 
            role: u.role, 
            createdAt: u.createdAt, 
            lastLogin: u.lastLogin, 
            isActive: u.isActive
        })));
    } catch (error) {
        res.status(500).json({ error: 'Ошибка загрузки' });
    }
});

app.delete('/api/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        if (userId === 1) {
            return res.status(400).json({ error: 'Нельзя удалить главного администратора' });
        }
        if (userId === req.user.id) {
            return res.status(400).json({ error: 'Нельзя удалить самого себя' });
        }
        
        const data = await loadData();
        const userIndex = data.users.findIndex(u => u.id === userId);
        if (userIndex === -1) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        data.users.splice(userIndex, 1);
        
        if (data.userData && data.userData[userId]) {
            delete data.userData[userId];
        }
        
        await saveData(data);
        log(`Пользователь ${userId} удален`, 'warn');
        res.json({ success: true, message: 'Пользователь удален' });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.put('/api/users/:id/toggle', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        if (userId === 1) {
            return res.status(400).json({ error: 'Нельзя заблокировать главного администратора' });
        }
        
        const data = await loadData();
        const user = data.users.find(u => u.id === userId);
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        
        user.isActive = !user.isActive;
        await saveData(data);
        res.json({ success: true, isActive: user.isActive });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.put('/api/users/:id/role', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const userId = parseInt(req.params.id);
        const { role } = req.body;
        const allowedRoles = ['admin', 'user', 'counselor', 'helper'];
        
        if (!allowedRoles.includes(role)) {
            return res.status(400).json({ error: 'Недопустимая роль' });
        }
        
        const data = await loadData();
        const user = data.users.find(u => u.id === userId);
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }
        if (userId === 1 && role !== 'admin') {
            return res.status(400).json({ error: 'Нельзя изменить роль главного администратора' });
        }
        
        user.role = role;
        await saveData(data);
        log(`Роль пользователя ${user.username} изменена на ${role}`, 'info');
        res.json({ success: true, role });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/data', authenticateToken, async (req, res) => {
    try {
        const data = await loadData();
        const user = req.user;
        const userId = user.id;
        
        let responseData = {};
        
        if (user.role === 'admin') {
            responseData = {
                groups: data.groups || {},
                members: data.members || {},
                marks: data.marks || {},
                activities: data.activities || {},
                counselors: data.counselors || {},
                helpers: data.helpers || {},
                books: data.books || { list: [] },
                allUsersData: data.userData || {},
                myData: data.userData?.[userId] || {
                    groups: {},
                    members: {},
                    marks: {},
                    activities: {},
                    counselors: {},
                    helpers: {},
                    books: { list: [] }
                }
            };
        } else {
            responseData = {
                groups: data.userData?.[userId]?.groups || {},
                members: data.userData?.[userId]?.members || {},
                marks: data.userData?.[userId]?.marks || {},
                activities: data.userData?.[userId]?.activities || {},
                counselors: data.userData?.[userId]?.counselors || {},
                helpers: data.userData?.[userId]?.helpers || {},
                books: data.userData?.[userId]?.books || { list: [] }
            };
        }
        
        responseData._meta = {
            userRole: user.role,
            username: user.username,
            userId: userId,
            isAdmin: user.role === 'admin',
            timestamp: new Date().toISOString()
        };
        
        res.json(responseData);
    } catch (error) {
        res.status(500).json({ error: 'Ошибка загрузки' });
    }
});

app.post('/api/data', authenticateToken, async (req, res) => {
    try {
        const newData = req.body;
        const data = await loadData();
        const user = req.user;
        const userId = user.id;
        
        if (user.role === 'admin') {
            if (newData.groups) data.groups = { ...data.groups, ...newData.groups };
            if (newData.members) data.members = { ...data.members, ...newData.members };
            if (newData.marks) data.marks = { ...data.marks, ...newData.marks };
            if (newData.activities) data.activities = { ...data.activities, ...newData.activities };
            if (newData.counselors) data.counselors = { ...data.counselors, ...newData.counselors };
            if (newData.helpers) data.helpers = { ...data.helpers, ...newData.helpers };
            if (newData.books) data.books = newData.books;
        }
        
        if (!data.userData) data.userData = {};
        if (!data.userData[userId]) {
            data.userData[userId] = {
                groups: {},
                members: {},
                marks: {},
                activities: {},
                counselors: {},
                helpers: {},
                books: { list: [] }
            };
        }
        
        if (newData.groups) data.userData[userId].groups = newData.groups;
        if (newData.members) data.userData[userId].members = newData.members;
        if (newData.marks) data.userData[userId].marks = newData.marks;
        if (newData.activities) data.userData[userId].activities = newData.activities;
        if (newData.counselors) data.userData[userId].counselors = newData.counselors;
        if (newData.helpers) data.userData[userId].helpers = newData.helpers;
        if (newData.books) data.userData[userId].books = newData.books;
        
        data.settings = data.settings || {};
        data.settings.lastSync = new Date().toISOString();
        
        await saveData(data);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сохранения' });
    }
});

app.post('/api/sync', authenticateToken, async (req, res) => {
    try {
        const mobileData = req.body;
        const data = await loadData();
        const user = req.user;
        const userId = user.id;
        
        if (!data.syncHistory) data.syncHistory = [];
        data.syncHistory.push({
            timestamp: new Date().toISOString(),
            user: user.username,
            userId: userId,
            action: 'sync_from_mobile'
        });
        
        if (data.syncHistory.length > 100) {
            data.syncHistory = data.syncHistory.slice(-100);
        }
        
        if (!data.userData) data.userData = {};
        if (!data.userData[userId]) {
            data.userData[userId] = {
                groups: {},
                members: {},
                marks: {},
                activities: {},
                counselors: {},
                helpers: {},
                books: { list: [] }
            };
        }
        
        if (mobileData.groups) data.userData[userId].groups = { ...data.userData[userId].groups, ...mobileData.groups };
        if (mobileData.members) data.userData[userId].members = { ...data.userData[userId].members, ...mobileData.members };
        if (mobileData.marks) data.userData[userId].marks = { ...data.userData[userId].marks, ...mobileData.marks };
        if (mobileData.activities) data.userData[userId].activities = { ...data.userData[userId].activities, ...mobileData.activities };
        if (mobileData.counselors) data.userData[userId].counselors = { ...data.userData[userId].counselors, ...mobileData.counselors };
        if (mobileData.helpers) data.userData[userId].helpers = { ...data.userData[userId].helpers, ...mobileData.helpers };
        if (mobileData.books) data.userData[userId].books = mobileData.books;
        
        data.settings = data.settings || {};
        data.settings.lastSync = new Date().toISOString();
        
        await saveData(data);
        res.json({ 
            success: true, 
            syncTime: new Date().toISOString(),
            message: 'Данные синхронизированы' 
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка синхронизации' });
    }
});

app.get('/api/sync/status', authenticateToken, async (req, res) => {
    try {
        const data = await loadData();
        res.json({
            lastSync: data.settings?.lastSync || null,
            syncHistory: data.syncHistory || [],
            serverTime: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка получения статуса' });
    }
});

app.post('/api/groups', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin' && req.user.role !== 'counselor') {
        return res.status(403).json({ error: 'Недостаточно прав' });
    }
    
    try {
        const { name } = req.body;
        if (!name) {
            return res.status(400).json({ error: 'Название группы обязательно' });
        }
        
        const data = await loadData();
        const user = req.user;
        const userId = user.id;
        
        if (!data.userData) data.userData = {};
        if (!data.userData[userId]) {
            data.userData[userId] = {
                groups: {},
                members: {},
                marks: {},
                activities: {},
                counselors: {},
                helpers: {},
                books: { list: [] }
            };
        }
        
        if (data.userData[userId].groups[name]) {
            return res.status(400).json({ error: 'Группа уже существует' });
        }
        
        data.userData[userId].groups[name] = { 
            createdAt: new Date().toISOString(), 
            createdBy: userId,
            createdByUsername: user.username
        };
        
        if (user.role === 'admin') {
            if (!data.groups) data.groups = {};
            data.groups[name] = { 
                createdAt: new Date().toISOString(), 
                createdBy: userId,
                createdByUsername: user.username
            };
        }
        
        await saveData(data);
        res.json({ success: true, group: name });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка создания' });
    }
});

app.delete('/api/groups/:name', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Недостаточно прав' });
    }
    
    try {
        const name = decodeURIComponent(req.params.name);
        const data = await loadData();
        const user = req.user;
        const userId = user.id;
        
        if (data.userData?.[userId]?.groups?.[name]) {
            delete data.userData[userId].groups[name];
        }
        
        if (data.groups?.[name]) {
            delete data.groups[name];
        }
        
        await saveData(data);
        res.json({ success: true, message: 'Группа удалена' });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка удаления' });
    }
});

app.post('/api/cleanup', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { type } = req.body;
        const data = await loadData();
        const user = req.user;
        const userId = user.id;
        
        let deleted = 0;
        let message = '';
        
        if (!data.userData?.[userId]) {
            return res.json({ success: true, deleted: 0, message: 'Нет данных для очистки' });
        }
        
        const userData = data.userData[userId];
        
        switch(type) {
            case 'empty-groups':
                for (const group in userData.groups) {
                    const hasMembers = userData.members?.[group]?.length > 0;
                    const hasMarks = userData.marks?.[group] && Object.keys(userData.marks[group]).length > 0;
                    
                    if (!hasMembers && !hasMarks) {
                        delete userData.groups[group];
                        if (data.groups?.[group]) {
                            delete data.groups[group];
                        }
                        deleted++;
                    }
                }
                message = `Удалено ${deleted} пустых групп`;
                break;
                
            case 'orphaned-marks':
                for (const group in userData.marks) {
                    if (!userData.members?.[group]) {
                        delete userData.marks[group];
                        deleted++;
                        continue;
                    }
                    
                    for (const studentId in userData.marks[group]) {
                        const studentExists = userData.members[group].some(s => s.id == studentId);
                        if (!studentExists) {
                            delete userData.marks[group][studentId];
                            deleted++;
                        }
                    }
                    
                    if (Object.keys(userData.marks[group]).length === 0) {
                        delete userData.marks[group];
                    }
                }
                message = `Удалено ${deleted} отметок без участников`;
                break;
                
            case 'old-activities':
                const cutoff = new Date();
                cutoff.setDate(cutoff.getDate() - 30);
                
                for (const date in userData.activities) {
                    if (new Date(date) < cutoff) {
                        deleted += userData.activities[date].length;
                        delete userData.activities[date];
                    }
                }
                message = `Удалено ${deleted} старых мероприятий`;
                break;
                
            case 'all':
                let groupCount = 0, markCount = 0, activityCount = 0;
                
                for (const group in userData.groups) {
                    const hasMembers = userData.members?.[group]?.length > 0;
                    const hasMarks = userData.marks?.[group] && Object.keys(userData.marks[group]).length > 0;
                    
                    if (!hasMembers && !hasMarks) {
                        delete userData.groups[group];
                        if (data.groups?.[group]) {
                            delete data.groups[group];
                        }
                        groupCount++;
                    }
                }
                
                for (const group in userData.marks) {
                    if (!userData.members?.[group]) {
                        delete userData.marks[group];
                        markCount++;
                        continue;
                    }
                    
                    for (const studentId in userData.marks[group]) {
                        const studentExists = userData.members[group].some(s => s.id == studentId);
                        if (!studentExists) {
                            delete userData.marks[group][studentId];
                            markCount++;
                        }
                    }
                    
                    if (Object.keys(userData.marks[group]).length === 0) {
                        delete userData.marks[group];
                    }
                }
                
                const oldCutoff = new Date();
                oldCutoff.setDate(oldCutoff.getDate() - 60);
                
                for (const date in userData.activities) {
                    if (new Date(date) < oldCutoff) {
                        activityCount += userData.activities[date].length;
                        delete userData.activities[date];
                    }
                }
                
                deleted = groupCount + markCount + activityCount;
                message = `Удалено: групп ${groupCount}, отметок ${markCount}, мероприятий ${activityCount}`;
                break;
        }
        
        await saveData(data);
        res.json({ success: true, deleted, message });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка очистки' });
    }
});

const publicDir = path.join(__dirname, 'public');
fs.mkdir(publicDir, { recursive: true }).catch(() => {});

app.use(express.static(publicDir));

app.get('/', (req, res) => {
    res.sendFile(path.join(publicDir, 'index.html'));
});

app.get('/mobile', (req, res) => {
    res.sendFile(path.join(publicDir, 'mobile.html'));
});

app.get('/m', (req, res) => {
    res.sendFile(path.join(publicDir, 'mobile.html'));
});

async function startServer() {
    try {
        await initializeData();
        const ips = getAllLocalIPs();
        
        app.listen(PORT, HOST, () => {
            console.log('\n' + '='.repeat(60));
            console.log('\x1b[32m✅ СЕРВЕР ЗАПУЩЕН\x1b[0m');
            console.log('='.repeat(60));
            console.log(`\n📌 Локально: http://localhost:${PORT}`);
            ips.forEach(ip => {
                console.log(`📌 В сети:   http://${ip}:${PORT}`);
            });
            console.log('\n📱 Для подключения с телефона:');
            ips.forEach(ip => {
                console.log(`   👉 http://${ip}:${PORT}/mobile`);
                console.log(`   👉 http://${ip}:${PORT}/m`);
            });
            console.log(`\n🔑 Администратор: Егор / 382154`);
            console.log('\n');
        });
    } catch (error) {
        console.error('Ошибка при запуске сервера:', error);
    }
}

startServer();