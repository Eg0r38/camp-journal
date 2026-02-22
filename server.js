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

// ========== ТРИ АККАУНТА ==========
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
    },
    {
      id: 2,
      username: "Вика",
      password: "$2a$10$Nt2kK8xYqZ3rL5mP7nR9sT1vW4yX6zA8bC0dE2fG4hI6jK8lM0nO2pQ4rS6tU8vW",
      role: "counselor",
      createdAt: new Date().toISOString(),
      lastLogin: null,
      isActive: true
    },
    {
      id: 3,
      username: "Миша",
      password: "$2a$10$M8nR2sT5vW7yX9zA1bC3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE1f",
      role: "helper",
      createdAt: new Date().toISOString(),
      lastLogin: null,
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
    },
    "2": {
      groups: {},
      members: {},
      marks: {},
      activities: {},
      counselors: {},
      helpers: {},
      books: { list: [] }
    },
    "3": {
      groups: {},
      members: {},
      marks: {},
      activities: {},
      counselors: {},
      helpers: {},
      books: { list: [] }
    }
  }
};

// Инициализация данных при первом запуске
if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(YOUR_DATA.users, null, 2));
}

// Сохраняем данные пользователей
const user1Path = path.join(USER_DATA_DIR, 'user_1.json');
const user2Path = path.join(USER_DATA_DIR, 'user_2.json');
const user3Path = path.join(USER_DATA_DIR, 'user_3.json');

if (!fs.existsSync(user1Path)) {
    fs.writeFileSync(user1Path, JSON.stringify(YOUR_DATA.userData["1"], null, 2));
}
if (!fs.existsSync(user2Path)) {
    fs.writeFileSync(user2Path, JSON.stringify(YOUR_DATA.userData["2"], null, 2));
}
if (!fs.existsSync(user3Path)) {
    fs.writeFileSync(user3Path, JSON.stringify(YOUR_DATA.userData["3"], null, 2));
}

app.use(express.json({ limit: '50mb' }));

// CORS
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

// Главная страница
app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, 'public', 'index.html');
    const mobilePath = path.join(__dirname, 'public', 'mobile.html');
    
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else if (fs.existsSync(mobilePath)) {
        res.sendFile(mobilePath);
    } else {
        res.status(404).send('Файлы не найдены');
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

// Синхронизация
app.post('/api/sync', authenticateToken, (req, res) => {
    const clientData = req.body;
    const serverData = loadUserData(req.user.id);
    
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
    
    res.json({ 
        message: 'Синхронизация успешна', 
        data: mergedData,
        time: new Date().toISOString() 
    });
});

// Получить всех пользователей (только для админа)
app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Доступ запрещен' });
    }

    const users = getUsers().map(({ password, ...user }) => user);
    res.json(users);
});

// Получить данные текущего пользователя
app.get('/api/me', authenticateToken, (req, res) => {
    res.json({ user: req.user });
});

// ========== ЗАПУСК СЕРВЕРА ==========
app.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '='.repeat(50));
    console.log('✅ СЕРВЕР ЗАПУЩЕН');
    console.log('='.repeat(50));
    console.log(`🌐 Адрес: http://localhost:${PORT}`);
    console.log(`📁 Данные: ${DATA_DIR}`);
    console.log('\n🔑 ДОСТУПНЫЕ АККАУНТЫ:');
    console.log('   1. Егор (админ) - 382154');
    console.log('   2. Вика (вожатый) - 302007');
    console.log('   3. Миша (помощник) - 282011');
    console.log('='.repeat(50) + '\n');
});