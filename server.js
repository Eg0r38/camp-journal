const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'counselor-journal-secret-key-2026';

// Создаем папки если их нет
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const USER_DATA_DIR = path.join(DATA_DIR, 'user_data');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(USER_DATA_DIR)) fs.mkdirSync(USER_DATA_DIR);

// Ваши данные
const YOUR_DATA = {
  users: [
    {
      id: 1,
      username: "Егор",
      password: "$2a$10$aSvSfG7XRkR38hRHHzOJJuzIwv7UaELVpA4XjaG0FdTHVtUQOlGRa",
      role: "admin",
      createdAt: "2024-09-29T00:00:00.000Z",
      lastLogin: "2026-02-19T14:56:18.271Z",
      isActive: true
    }
  ],
  userData: {
    "1": {
      groups: {
        "Магнитик": {
          createdAt: "2024-09-29T00:00:00.000Z",
          createdBy: 1,
          createdByUsername: "Егор"
        }
      },
      members: {
        "Магнитик": [
          {
            id: 1771508141843,
            name: "Олеся",
            birthday: "2011-08-20",
            phone: "+7 914 715 77 53",
            parentPhone: "8 914 661 57 73",
            addedAt: "2026-02-19T13:35:41.843Z"
          }
        ]
      },
      marks: {
        "Магнитик": {
          "1771508141843": [
            {
              id: 1771508250509,
              status: "present",
              date: "2026-02-19T13:37:30.509Z",
              author: "Егор"
            }
          ]
        }
      },
      counselors: {
        "Магнитик": [
          {
            id: 1771508236416,
            name: "Вика",
            assignedAt: "2026-02-19T13:37:16.416Z"
          }
        ]
      },
      helpers: {
        "Магнитик": [
          {
            id: 1771508209378,
            name: "Егор",
            assignedAt: "2026-02-19T13:36:49.378Z"
          }
        ]
      },
      books: {
        list: [
          {
            id: 1771510711332,
            title: "ветры подтверждения",
            lesson: "все",
            status: "completed",
            addedAt: "2026-02-19T14:18:31.332Z"
          }
        ]
      }
    }
  }
};

// Инициализация данных при первом запуске
if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(YOUR_DATA.users, null, 2));
}

// Сохраняем данные пользователя 1
const userDataPath = path.join(USER_DATA_DIR, 'user_1.json');
if (!fs.existsSync(userDataPath)) {
    fs.writeFileSync(userDataPath, JSON.stringify(YOUR_DATA.userData["1"], null, 2));
}

app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ========== ЯВНЫЙ МАРШРУТ ДЛЯ ГЛАВНОЙ СТРАНИЦЫ ==========
app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, 'public', 'index.html');
    const mobilePath = path.join(__dirname, 'public', 'mobile.html');
    
    // Проверяем существует ли index.html
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } 
    // Если нет, пробуем mobile.html
    else if (fs.existsSync(mobilePath)) {
        res.sendFile(mobilePath);
    }
    // Если ничего нет, отправляем сообщение об ошибке
    else {
        res.status(404).send(`
            <html>
                <body style="background: #0a0c14; color: #eaeef2; font-family: Arial; padding: 50px; text-align: center;">
                    <h1>❌ Файлы не найдены</h1>
                    <p>В папке public отсутствуют index.html или mobile.html</p>
                    <p>Создайте файлы в папке: ${path.join(__dirname, 'public')}</p>
                </body>
            </html>
        `);
    }
});

// ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========
function getUsers() {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}

function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function getUserDataPath(userId) {
    return path.join(USER_DATA_DIR, `user_${userId}.json`);
}

function saveUserData(userId, data) {
    fs.writeFileSync(getUserDataPath(userId), JSON.stringify(data, null, 2));
}

function loadUserData(userId) {
    const filePath = getUserDataPath(userId);
    if (fs.existsSync(filePath)) {
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    }
    return { groups: {}, members: {}, marks: {}, activities: {}, counselors: {}, helpers: {}, books: { list: [] } };
}

// ========== МИДЛВЕРЫ ==========
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Требуется авторизация' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Недействительный токен' });
        req.user = user;
        next();
    });
}

// ========== API ЭНДПОИНТЫ ==========

// Health check
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'ok', time: new Date().toISOString() });
});

// Регистрация
app.post('/api/register', async (req, res) => {
    const { username, password, role } = req.body;
    
    if (!username || !password || !role) {
        return res.status(400).json({ error: 'Все поля обязательны' });
    }

    const users = getUsers();
    
    if (users.find(u => u.username === username)) {
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

    users.push(newUser);
    saveUsers(users);
    
    // Создаем пустой файл данных для пользователя
    saveUserData(newUser.id, { groups: {}, members: {}, marks: {}, activities: {}, counselors: {}, helpers: {}, books: { list: [] } });

    res.status(201).json({ message: 'Пользователь создан' });
});

// Вход
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Все поля обязательны' });
    }

    const users = getUsers();
    const user = users.find(u => u.username === username);

    if (!user) {
        return res.status(400).json({ error: 'Пользователь не найден' });
    }

    if (!user.isActive) {
        return res.status(403).json({ error: 'Аккаунт заблокирован' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(400).json({ error: 'Неверный пароль' });
    }

    // Обновляем время последнего входа
    user.lastLogin = new Date().toISOString();
    saveUsers(users);

    const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        SECRET_KEY,
        { expiresIn: '30d' }
    );

    res.json({
        token,
        user: {
            id: user.id,
            username: user.username,
            role: user.role
        }
    });
});

// Получить данные текущего пользователя
app.get('/api/data', authenticateToken, (req, res) => {
    const userData = loadUserData(req.user.id);
    
    if (req.user.role === 'admin') {
        // Для админа собираем данные всех пользователей
        const users = getUsers();
        const allUsersData = {};
        
        users.forEach(user => {
            if (user.id !== req.user.id) {
                allUsersData[user.id] = loadUserData(user.id);
            }
        });
        
        res.json({
            myData: userData,
            allUsersData
        });
    } else {
        res.json(userData);
    }
});

// Сохранить данные пользователя
app.post('/api/data', authenticateToken, (req, res) => {
    const newData = req.body;
    saveUserData(req.user.id, newData);
    res.json({ message: 'Данные сохранены', time: new Date().toISOString() });
});

// Синхронизация (полная)
app.post('/api/sync', authenticateToken, (req, res) => {
    const clientData = req.body;
    const serverData = loadUserData(req.user.id);
    
    // Объединяем данные (клиентские приоритетнее)
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
    
    saveUserData(req.user.id, mergedData);
    
    // Добавляем запись в историю синхронизации
    const syncHistoryPath = path.join(DATA_DIR, 'sync_history.json');
    let syncHistory = [];
    if (fs.existsSync(syncHistoryPath)) {
        syncHistory = JSON.parse(fs.readFileSync(syncHistoryPath, 'utf8'));
    }
    syncHistory.push({
        timestamp: new Date().toISOString(),
        user: req.user.username,
        userId: req.user.id,
        action: 'sync'
    });
    fs.writeFileSync(syncHistoryPath, JSON.stringify(syncHistory, null, 2));
    
    res.json({ 
        message: 'Синхронизация успешна', 
        data: mergedData,
        time: new Date().toISOString() 
    });
});

// Получить историю синхронизации (только для админа)
app.get('/api/sync/history', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }
    
    const syncHistoryPath = path.join(DATA_DIR, 'sync_history.json');
    if (fs.existsSync(syncHistoryPath)) {
        const history = JSON.parse(fs.readFileSync(syncHistoryPath, 'utf8'));
        res.json(history);
    } else {
        res.json([]);
    }
});

// Получить всех пользователей (только для админа)
app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }

    const users = getUsers().map(({ password, ...user }) => user);
    res.json(users);
});

// Получить данные конкретного пользователя (только для админа)
app.get('/api/users/:userId/data', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }

    const userId = parseInt(req.params.userId);
    const userData = loadUserData(userId);
    res.json(userData);
});

// Блокировка/разблокировка пользователя
app.put('/api/users/:userId/toggle', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }

    const users = getUsers();
    const userIndex = users.findIndex(u => u.id == req.params.userId);
    
    if (userIndex === -1) {
        return res.status(404).json({ error: 'Пользователь не найден' });
    }

    users[userIndex].isActive = !users[userIndex].isActive;
    saveUsers(users);
    res.json({ message: 'Статус изменен', isActive: users[userIndex].isActive });
});

// Изменить роль пользователя
app.put('/api/users/:userId/role', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }

    const { role } = req.body;
    if (!['admin', 'counselor', 'helper'].includes(role)) {
        return res.status(400).json({ error: 'Недопустимая роль' });
    }

    const users = getUsers();
    const userIndex = users.findIndex(u => u.id == req.params.userId);
    
    if (userIndex === -1) {
        return res.status(404).json({ error: 'Пользователь не найден' });
    }

    users[userIndex].role = role;
    saveUsers(users);
    res.json({ message: 'Роль изменена' });
});

// Удалить пользователя
app.delete('/api/users/:userId', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }

    const userId = parseInt(req.params.userId);
    if (userId === 1) {
        return res.status(400).json({ error: 'Нельзя удалить главного администратора' });
    }

    let users = getUsers();
    users = users.filter(u => u.id !== userId);
    saveUsers(users);

    // Удаляем данные пользователя
    const dataPath = getUserDataPath(userId);
    if (fs.existsSync(dataPath)) {
        fs.unlinkSync(dataPath);
    }

    res.json({ message: 'Пользователь удален' });
});

// Очистка данных
app.post('/api/cleanup', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }

    const { type } = req.body;
    const users = getUsers();
    let cleaned = 0;

    users.forEach(user => {
        if (user.id === 1) return;
        
        const userData = loadUserData(user.id);
        let changed = false;
        
        switch(type) {
            case 'empty-groups':
                Object.keys(userData.groups).forEach(groupName => {
                    if (!userData.members[groupName] || userData.members[groupName].length === 0) {
                        delete userData.groups[groupName];
                        cleaned++;
                        changed = true;
                    }
                });
                break;
                
            case 'orphaned-marks':
                Object.keys(userData.marks).forEach(group => {
                    Object.keys(userData.marks[group]).forEach(studentId => {
                        const studentExists = userData.members[group]?.some(s => s.id == studentId);
                        if (!studentExists) {
                            delete userData.marks[group][studentId];
                            cleaned++;
                            changed = true;
                        }
                    });
                    if (Object.keys(userData.marks[group]).length === 0) {
                        delete userData.marks[group];
                    }
                });
                break;
                
            case 'old-activities':
                const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
                Object.keys(userData.activities).forEach(date => {
                    if (new Date(date).getTime() < thirtyDaysAgo) {
                        delete userData.activities[date];
                        cleaned++;
                        changed = true;
                    }
                });
                break;
                
            case 'all':
                Object.keys(userData.groups).forEach(groupName => {
                    if (!userData.members[groupName] || userData.members[groupName].length === 0) {
                        delete userData.groups[groupName];
                        cleaned++;
                        changed = true;
                    }
                });
                
                Object.keys(userData.marks).forEach(group => {
                    Object.keys(userData.marks[group]).forEach(studentId => {
                        const studentExists = userData.members[group]?.some(s => s.id == studentId);
                        if (!studentExists) {
                            delete userData.marks[group][studentId];
                            cleaned++;
                            changed = true;
                        }
                    });
                    if (Object.keys(userData.marks[group]).length === 0) {
                        delete userData.marks[group];
                    }
                });
                
                const ninetyDaysAgo = Date.now() - 90 * 24 * 60 * 60 * 1000;
                Object.keys(userData.activities).forEach(date => {
                    if (new Date(date).getTime() < ninetyDaysAgo) {
                        delete userData.activities[date];
                        cleaned++;
                        changed = true;
                    }
                });
                break;
        }
        
        if (changed) {
            saveUserData(user.id, userData);
        }
    });

    res.json({ message: `Очистка завершена. Удалено элементов: ${cleaned}` });
});

// Получить данные текущего пользователя (для /api/me)
app.get('/api/me', authenticateToken, (req, res) => {
    res.json({ user: req.user });
});

// ========== ЗАПУСК СЕРВЕРА ==========
app.listen(PORT, () => {
    console.log('\n' + '='.repeat(50));
    console.log('✅ СЕРВЕР ЗАПУЩЕН');
    console.log('='.repeat(50));
    console.log(`🌐 Адрес: http://localhost:${PORT}`);
    console.log(`📁 Данные: ${DATA_DIR}`);
    console.log('\n🔑 АДМИНИСТРАТОР:');
    console.log('   Логин: Егор');
    console.log('   Пароль: 382154');
    console.log('\n📊 ВАШИ ДАННЫЕ ЗАГРУЖЕНЫ:');
    console.log(`   Группа: Магнитик`);
    console.log(`   Участник: Олеся`);
    console.log(`   Вожатый: Вика`);
    console.log(`   Помощник: Егор`);
    console.log(`   Книга: ветры подтверждения (пройдена)`);
    console.log('='.repeat(50) + '\n');
});