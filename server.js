const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const os = require('os');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'counselor-journal-secret-key-2026';

// Создаем папки если их нет
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const USER_DATA_DIR = path.join(DATA_DIR, 'user_data');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(USER_DATA_DIR)) fs.mkdirSync(USER_DATA_DIR);

// ========== ПОЛУЧЕНИЕ IP АДРЕСА ==========
function getLocalIp() {
    try {
        const interfaces = os.networkInterfaces();
        console.log('\n🔍 Доступные сетевые интерфейсы:');
        
        for (const name of Object.keys(interfaces)) {
            for (const iface of interfaces[name]) {
                if (iface.family === 'IPv4' && !iface.internal) {
                    console.log(`   ✅ ${name}: ${iface.address}`);
                    return iface.address;
                }
            }
        }
        
        console.log('   ⚠️ Не удалось определить IP автоматически');
        return null;
    } catch (e) {
        console.log('   ❌ Ошибка определения IP:', e.message);
        return null;
    }
}

const LOCAL_IP = getLocalIp();

// ========== ФУНКЦИИ ДЛЯ РАБОТЫ С ПОЛЬЗОВАТЕЛЯМИ ==========
function getUsers() {
    try {
        if (fs.existsSync(USERS_FILE)) {
            return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        }
    } catch (e) {
        console.log('Ошибка чтения users.json:', e.message);
    }
    return [];
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function getUserDataPath(userId) {
    return path.join(USER_DATA_DIR, `user_${userId}.json`);
}

function loadUserData(userId) {
    const filePath = getUserDataPath(userId);
    if (fs.existsSync(filePath)) {
        try {
            return JSON.parse(fs.readFileSync(filePath, 'utf8'));
        } catch (e) {
            console.log(`Ошибка чтения данных пользователя ${userId}:`, e.message);
        }
    }
    return { groups: {}, members: {}, marks: {}, activities: {}, counselors: {}, helpers: {}, books: { list: [] } };
}

function saveUserData(userId, data) {
    fs.writeFileSync(getUserDataPath(userId), JSON.stringify(data, null, 2));
}

// ========== ИНИЦИАЛИЗАЦИЯ ПОЛЬЗОВАТЕЛЕЙ ==========
async function initializeUsers() {
    console.log('\n🔧 ПРОВЕРКА ПОЛЬЗОВАТЕЛЕЙ...');
    
    const existingUsers = getUsers();
    console.log(`   Существующих пользователей: ${existingUsers.length}`);
    
    if (existingUsers.length >= 3) {
        console.log('   ✅ Все пользователи уже есть:');
        existingUsers.forEach(u => console.log(`      - ${u.username} (${u.role})`));
        return existingUsers;
    }
    
    // Создаем хеши паролей
    console.log('   Создание новых пользователей...');
    
    const hash1 = await bcrypt.hash('382154', 10);
    const hash2 = await bcrypt.hash('302007', 10);
    const hash3 = await bcrypt.hash('282011', 10);
    
    const newUsers = [
        {
            id: 1,
            username: "Егор",
            password: hash1,
            role: "admin",
            createdAt: new Date().toISOString(),
            lastLogin: null,
            isActive: true
        },
        {
            id: 2,
            username: "Вика",
            password: hash2,
            role: "counselor",
            createdAt: new Date().toISOString(),
            lastLogin: null,
            isActive: true
        },
        {
            id: 3,
            username: "Миша",
            password: hash3,
            role: "helper",
            createdAt: new Date().toISOString(),
            lastLogin: null,
            isActive: true
        }
    ];
    
    // Сохраняем пользователей
    saveUsers(newUsers);
    console.log('   ✅ Пользователи созданы:');
    newUsers.forEach(u => console.log(`      - ${u.username} (${u.role})`));
    
    // Создаем данные для пользователей
    const user1Data = {
        groups: {
            "Магнитик": {
                createdAt: new Date().toISOString(),
                createdBy: 1,
                createdByUsername: "Егор"
            }
        },
        members: {
            "Магнитик": [
                {
                    id: Date.now(),
                    name: "Олеся",
                    birthday: "2011-08-20",
                    phone: "+7 914 715 77 53",
                    parentPhone: "8 914 661 57 73",
                    addedAt: new Date().toISOString()
                }
            ]
        },
        marks: {},
        activities: {},
        counselors: {},
        helpers: {},
        books: { list: [] }
    };
    
    const emptyData = {
        groups: {},
        members: {},
        marks: {},
        activities: {},
        counselors: {},
        helpers: {},
        books: { list: [] }
    };
    
    saveUserData(1, user1Data);
    saveUserData(2, emptyData);
    saveUserData(3, emptyData);
    
    console.log('   ✅ Данные пользователей созданы');
    
    return newUsers;
}

// Ждем инициализации
let users = [];
(async () => {
    users = await initializeUsers();
    console.log('\n🚀 ЗАПУСК СЕРВЕРА...\n');
})();

app.use(express.json({ limit: '50mb' }));

// ========== CORS ==========
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ========== СТАТИЧЕСКИЕ ФАЙЛЫ ==========
app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, 'public', 'index.html');
    const mobilePath = path.join(__dirname, 'public', 'mobile.html');
    
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else if (fs.existsSync(mobilePath)) {
        res.sendFile(mobilePath);
    } else {
        res.status(404).send(`
            <html>
                <body style="background: #0a0c14; color: #eaeef2; font-family: Arial; padding: 50px;">
                    <h1>❌ Файлы не найдены</h1>
                    <p>Создайте файлы index.html или mobile.html в папке public</p>
                </body>
            </html>
        `);
    }
});

// ========== API ==========

// Получить IP
app.get('/api/ip', (req, res) => {
    res.json({ 
        ip: LOCAL_IP,
        hostname: os.hostname(),
        message: 'IP адрес компьютера для подключения с телефона'
    });
});

// Проверка здоровья
app.get('/api/health', (req, res) => {
    res.status(200).json({ 
        status: 'ok', 
        time: new Date().toISOString(),
        users: users.length,
        ip: LOCAL_IP
    });
});

// Регистрация
app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;
    
    if (!username || !password || !role) {
        return res.status(400).json({ error: 'Все поля обязательны' });
    }

    const currentUsers = getUsers();
    
    if (currentUsers.find(u => u.username === username)) {
        return res.status(400).json({ error: 'Пользователь уже существует' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: Date.now(),
        username,
        password: hashedPassword,
        role,
        createdAt: new Date().toISOString(),
        lastLogin: null,
        isActive: true
    };

    currentUsers.push(newUser);
    saveUsers(currentUsers);
    
    const emptyData = { groups: {}, members: {}, marks: {}, activities: {}, counselors: {}, helpers: {}, books: { list: [] } };
    saveUserData(newUser.id, emptyData);

    res.status(201).json({ message: 'Пользователь создан' });
});

// Вход
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    console.log('\n' + '='.repeat(50));
    console.log(`🔑 ПОПЫТКА ВХОДА: ${username}`);
    console.log('='.repeat(50));
    
    if (!username || !password) {
        console.log('❌ Ошибка: Не указан логин или пароль');
        return res.status(400).json({ error: 'Все поля обязательны' });
    }

    try {
        const currentUsers = getUsers();
        console.log(`📊 Всего пользователей в базе: ${currentUsers.length}`);
        
        if (currentUsers.length > 0) {
            console.log('📋 Список пользователей:');
            currentUsers.forEach(u => {
                console.log(`   - ${u.username} (${u.role}) - активен: ${u.isActive}`);
            });
        }

        const user = currentUsers.find(u => u.username === username);

        if (!user) {
            console.log(`❌ Пользователь "${username}" не найден`);
            return res.status(400).json({ error: 'Пользователь не найден' });
        }

        console.log(`✅ Пользователь найден: ${user.username} (${user.role})`);
        console.log(`🔐 Хеш пароля: ${user.password.substring(0, 30)}...`);

        if (!user.isActive) {
            console.log('❌ Аккаунт заблокирован');
            return res.status(403).json({ error: 'Аккаунт заблокирован' });
        }

        console.log(`🔍 Сравниваем с введенным паролем: "${password}"`);
        
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            console.log('❌ Пароль не совпадает');
            return res.status(400).json({ error: 'Неверный пароль' });
        }

        console.log('✅ Пароль верный');

        user.lastLogin = new Date().toISOString();
        saveUsers(currentUsers);

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            SECRET_KEY,
            { expiresIn: '30d' }
        );

        console.log('✅ Токен создан');
        console.log('='.repeat(50) + '\n');

        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role
            }
        });
        
    } catch (error) {
        console.log('❌ Ошибка сервера:', error.message);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Получить данные пользователя
app.get('/api/data', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }

    try {
        const user = jwt.verify(token, SECRET_KEY);
        console.log(`📊 Запрос данных для пользователя: ${user.username} (${user.role})`);
        
        const userData = loadUserData(user.id);
        
        if (user.role === 'admin') {
            const allUsers = getUsers();
            const allUsersData = {};
            
            allUsers.forEach(u => {
                if (u.id !== user.id) {
                    allUsersData[u.id] = loadUserData(u.id);
                }
            });
            
            console.log(`   Отправка данных для админа (включая ${Object.keys(allUsersData).length} других пользователей)`);
            res.json({
                myData: userData,
                allUsersData
            });
        } else {
            console.log(`   Отправка данных для обычного пользователя`);
            res.json(userData);
        }
    } catch (error) {
        console.log('❌ Ошибка верификации токена:', error.message);
        res.status(403).json({ error: 'Недействительный токен' });
    }
});

// Сохранить данные пользователя
app.post('/api/data', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }

    try {
        const user = jwt.verify(token, SECRET_KEY);
        const newData = req.body;
        
        saveUserData(user.id, newData);
        console.log(`💾 Данные сохранены для пользователя: ${user.username}`);
        
        res.json({ 
            message: 'Данные сохранены', 
            time: new Date().toISOString() 
        });
    } catch (error) {
        console.log('❌ Ошибка сохранения данных:', error.message);
        res.status(403).json({ error: 'Недействительный токен' });
    }
});

// Синхронизация
app.post('/api/sync', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }

    try {
        const user = jwt.verify(token, SECRET_KEY);
        const clientData = req.body;
        const serverData = loadUserData(user.id);
        
        const mergedData = {
            groups: { ...serverData.groups, ...clientData.groups },
            members: { ...serverData.members, ...clientData.members },
            marks: { ...serverData.marks, ...clientData.marks },
            activities: { ...serverData.activities, ...clientData.activities },
            counselors: { ...serverData.counselors, ...clientData.counselors },
            helpers: { ...serverData.helpers, ...clientData.helpers },
            books: {
                list: [...new Map([...serverData.books?.list || [], ...clientData.books?.list || []].map(item => [item.id, item])).values()]
            }
        };
        
        saveUserData(user.id, mergedData);
        console.log(`🔄 Синхронизация для пользователя: ${user.username}`);
        
        res.json({ 
            message: 'Синхронизация успешна', 
            data: mergedData,
            time: new Date().toISOString() 
        });
    } catch (error) {
        console.log('❌ Ошибка синхронизации:', error.message);
        res.status(403).json({ error: 'Недействительный токен' });
    }
});

// Получить информацию о текущем пользователе
app.get('/api/me', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }

    try {
        const user = jwt.verify(token, SECRET_KEY);
        res.json({ user });
    } catch (error) {
        res.status(403).json({ error: 'Недействительный токен' });
    }
});

// Получить всех пользователей (только для админа)
app.get('/api/users', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }

    try {
        const user = jwt.verify(token, SECRET_KEY);
        
        if (user.role !== 'admin') {
            return res.status(403).json({ error: 'Доступ запрещен' });
        }
        
        const allUsers = getUsers();
        const usersWithoutPasswords = allUsers.map(({ password, ...rest }) => rest);
        
        res.json(usersWithoutPasswords);
    } catch (error) {
        res.status(403).json({ error: 'Недействительный токен' });
    }
});

// ========== ЗАПУСК СЕРВЕРА ==========
app.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '='.repeat(60));
    console.log('✅ СЕРВЕР ЗАПУЩЕН');
    console.log('='.repeat(60));
    console.log(`🌐 Локальный адрес: http://localhost:${PORT}`);
    
    if (LOCAL_IP) {
        console.log(`📱 Доступ с телефона: http://${LOCAL_IP}:${PORT}`);
    } else {
        console.log(`\n⚠️ НЕ УДАЛОСЬ ОПРЕДЕЛИТЬ IP АВТОМАТИЧЕСКИ!`);
        console.log(`\n👉 Чтобы узнать IP компьютера:`);
        console.log(`   1. Откройте командную строку (cmd)`);
        console.log(`   2. Введите команду: ipconfig`);
        console.log(`   3. Найдите строку "IPv4-адрес" (например 192.168.0.105)`);
        console.log(`\n📱 На телефоне введите: http://[ВАШ_IP]:3000`);
    }
    
    console.log(`\n📁 Данные хранятся: ${DATA_DIR}`);
    console.log('\n🔑 ДОСТУПНЫЕ АККАУНТЫ:');
    console.log('   1. Егор (админ) - 382154');
    console.log('   2. Вика (вожатый) - 302007');
    console.log('   3. Миша (помощник) - 282011');
    
    // Показываем текущих пользователей
    const currentUsers = getUsers();
    console.log(`\n📊 Пользователей в базе: ${currentUsers.length}`);
    currentUsers.forEach(u => {
        console.log(`   - ${u.username} (${u.role}) - активен: ${u.isActive}`);
    });
    
    console.log('='.repeat(60) + '\n');
});