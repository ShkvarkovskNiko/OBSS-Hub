const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();
const port = 3000;

// Подключение к базе данных
const db = new sqlite3.Database('./obss_hub.db', (err) => {
    if (err) {
        console.error('Ошибка подключения к базе данных:', err.message);
        process.exit(1);
    }
    console.log('Подключено к базе данных SQLite');
});

// Настройка Multer для загрузки изображений
const uploadDir = './static/uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'static/uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Только изображения разрешены!'), false);
    }
};
const upload = multer({ storage: storage, fileFilter: fileFilter });

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('static', { maxAge: '1d' }));
app.use(express.static(__dirname));

// Настройка сессий
app.use(session({
    store: new SQLiteStore({ db: 'obss_hub.db', dir: './' }),
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 часа
}));

// Создание таблиц
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) console.error('Ошибка создания таблицы users:', err.message);
        else console.log('Таблица users готова');
    });

    db.run(`
        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            image TEXT,
            tags TEXT,
            category TEXT, -- Поле для категории
            rating REAL DEFAULT 0, -- Средняя оценка
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `, (err) => {
        if (err) console.error('Ошибка создания таблицы articles:', err.message);
        else console.log('Таблица articles готова');
    });

    db.run(`
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            date TEXT NOT NULL,
            location TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) console.error('Ошибка создания таблицы events:', err.message);
        else console.log('Таблица events готова');
    });

    db.run(`
        CREATE TABLE IF NOT EXISTS ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            article_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(article_id, user_id), -- Один пользователь может оценить статью только раз
            FOREIGN KEY(article_id) REFERENCES articles(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `, (err) => {
        if (err) console.error('Ошибка создания таблицы ratings:', err.message);
        else console.log('Таблица ratings готова');
    });

    db.run('CREATE INDEX IF NOT EXISTS idx_articles_title ON articles(title)', (err) => {
        if (err) console.error('Ошибка создания индекса idx_articles_title:', err.message);
        else console.log('Индекс idx_articles_title создан');
    });

    db.run('CREATE INDEX IF NOT EXISTS idx_events_date ON events(date)', (err) => {
        if (err) console.error('Ошибка создания индекса idx_events_date:', err.message);
        else console.log('Индекс idx_events_date создан');
    });
});

// API для пользователей
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
        stmt.run(username, hashedPassword, function (err) {
            if (err) {
                console.error('Ошибка регистрации:', err.message);
                return res.status(400).json({ error: 'Username already exists' });
            }
            console.log('Пользователь зарегистрирован с ID:', this.lastID);
            res.json({ message: 'Регистрация успешна', id: this.lastID });
        });
        stmt.finalize();
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            console.error('Ошибка входа:', err.message);
            return res.status(500).json({ error: err.message });
        }
        if (!user) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }
        req.session.user = { id: user.id, username: user.username };
        res.json({ message: 'Вход успешен', user: { id: user.id, username: user.username } });
    });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Выход успешен' });
    });
});

app.get('/api/user', (req, res) => {
    if (req.session.user) {
        res.json(req.session.user);
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
});

// API для статей
app.get('/api/articles', (req, res) => {
    console.log('Запрос к /api/articles');
    db.all('SELECT articles.*, users.username FROM articles JOIN users ON articles.user_id = users.id ORDER BY created_at DESC', (err, rows) => {
        if (err) {
            console.error('Ошибка БД:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        console.log('Найдено статей:', rows.length);
        res.json(rows);
    });
});

app.post('/api/articles', upload.single('image'), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    const { title, content, tags, category } = req.body;
    if (!title || !content) {
        return res.status(400).json({ error: 'Title and content are required' });
    }
    const image = req.file ? req.file.filename : null;
    const userId = req.session.user.id;
    const stmt = db.prepare('INSERT INTO articles (title, content, image, tags, category, user_id) VALUES (?, ?, ?, ?, ?, ?)');
    stmt.run(title, content, image, tags, category || 'Без категории', userId, function (err) {
        if (err) {
            console.error('Ошибка добавления статьи:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        console.log('Статья добавлена с ID:', this.lastID);
        res.json({
            id: this.lastID,
            title,
            content,
            image,
            tags,
            category: category || 'Без категории',
            user_id: userId
        });
    });
    stmt.finalize();
});

app.delete('/api/articles/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    const id = req.params.id;
    const userId = req.session.user.id;
    db.get('SELECT * FROM articles WHERE id = ?', [id], (err, row) => {
        if (err) {
            console.error('Ошибка проверки статьи:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        if (!row) {
            return res.status(404).json({ error: 'Статья не найдена' });
        }
        if (row.user_id !== userId) {
            return res.status(403).json({ error: 'Вы можете удалять только свои статьи' });
        }
        const stmt = db.prepare('DELETE FROM articles WHERE id = ?');
        stmt.run(id, function (err) {
            if (err) {
                console.error('Ошибка удаления статьи:', err.message);
                res.status(500).json({ error: err.message });
                return;
            }
            console.log('Статья удалена с ID:', id);
            if (row.image) {
                const imagePath = path.join(__dirname, 'static/uploads', row.image);
                fs.unlink(imagePath, (err) => {
                    if (err) console.error('Ошибка удаления изображения:', err.message);
                    else console.log('Изображение удалено:', row.image);
                });
            }
            res.json({ message: 'Статья успешно удалена', id });
        });
        stmt.finalize();
    });
});

// API для мероприятий
app.get('/api/events', (req, res) => {
    console.log('Запрос к /api/events');
    db.all('SELECT * FROM events ORDER BY date ASC', (err, rows) => {
        if (err) {
            console.error('Ошибка загрузки мероприятий:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        console.log('Найдено мероприятий:', rows.length);
        res.json(rows);
    });
});

app.post('/api/events', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { title, description, date, location } = req.body;

    // Проверка обязательных полей
    if (!title || !description || !date) {
        return res.status(400).json({ error: 'Title, description, and date are required' });
    }

    const isValidDate = (date) => /^\d{4}-\d{2}-\d{2}$/.test(date);
    if (!isValidDate(date)) {
        return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
    }

    const stmt = db.prepare('INSERT INTO events (title, description, date, location) VALUES (?, ?, ?, ?)');
    stmt.run(title, description, date, location, function (err) {
        if (err) {
            console.error('Ошибка добавления мероприятия:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        console.log('Мероприятие добавлено с ID:', this.lastID);
        res.json({ id: this.lastID, title, description, date, location });
    });
    stmt.finalize();
});

// API для поиска
app.get('/api/search', (req, res) => {
    const query = req.query.query ? `%${req.query.query}%` : '%';
    const sql = `
        SELECT id, title, 'article' as type FROM articles WHERE title LIKE ? OR content LIKE ? OR tags LIKE ?
        UNION
        SELECT id, title, 'event' as type FROM events WHERE title LIKE ? OR description LIKE ? OR location LIKE ?
    `;
    db.all(sql, [query, query, query, query, query, query], (err, rows) => {
        if (err) {
            console.error('Ошибка поиска:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        console.log('Результаты поиска:', rows);
        res.json(rows);
    });
});

// API для получения статей пользователя
app.get('/api/my-articles', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    const userId = req.session.user.id;
    db.all('SELECT * FROM articles WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, rows) => {
        if (err) {
            console.error('Ошибка загрузки статей пользователя:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// --- МАРШРУТЫ ДЛЯ РЕДАКТИРОВАНИЯ, УДАЛЕНИЯ И ОЦЕНОК СТАТЕЙ ---

// Получение статьи по id с проверкой прав (текущий пользователь)
app.get('/api/articles/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    const articleId = req.params.id;
    const userId = req.session.user.id;

    db.get('SELECT * FROM articles WHERE id = ? AND user_id = ?', [articleId, userId], (err, row) => {
        if (err) {
            console.error('Ошибка получения статьи:', err.message);
            return res.status(500).json({ error: err.message });
        }
        if (!row) {
            return res.status(404).json({ error: 'Статья не найдена или доступ запрещён' });
        }
        res.json(row);
    });
});

// Обновление статьи с загрузкой изображения
app.put('/api/articles/:id', upload.single('image'), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    const articleId = req.params.id;
    const userId = req.session.user.id;

    const { title, content, tags, category } = req.body;
    let imageFileName = null;
    if (req.file) {
        imageFileName = req.file.filename;
    }

    db.get('SELECT * FROM articles WHERE id = ? AND user_id = ?', [articleId, userId], (err, row) => {
        if (err) {
            console.error('Ошибка проверки статьи:', err.message);
            return res.status(500).json({ error: err.message });
        }
        if (!row) {
            return res.status(404).json({ error: 'Статья не найдена или доступ запрещён' });
        }

        // Если новый файл загружен и старая картинка есть - удаляем старую
        if (imageFileName && row.image) {
            const oldImagePath = path.join(__dirname, 'static/uploads', row.image);
            fs.unlink(oldImagePath, (unlinkErr) => {
                if (unlinkErr) {
                    console.error('Ошибка удаления старого изображения:', unlinkErr.message);
                } else {
                    console.log('Удалено старое изображение:', row.image);
                }
            });
        }

        const sql = imageFileName
            ? 'UPDATE articles SET title = ?, content = ?, tags = ?, category = ?, image = ? WHERE id = ?'
            : 'UPDATE articles SET title = ?, content = ?, tags = ?, category = ? WHERE id = ?';
        const params = imageFileName
            ? [title, content, tags, category || 'Без категории', imageFileName, articleId]
            : [title, content, tags, category || 'Без категории', articleId];

        db.run(sql, params, function (err) {
            if (err) {
                console.error('Ошибка обновления статьи:', err.message);
                return res.status(500).json({ error: err.message });
            }
            res.json({ message: 'Статья успешно обновлена' });
        });
    });
});

// Удаление статьи
app.delete('/api/articles/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    const articleId = req.params.id;
    const userId = req.session.user.id;

    db.get('SELECT * FROM articles WHERE id = ? AND user_id = ?', [articleId, userId], (err, row) => {
        if (err) {
            console.error('Ошибка проверки статьи:', err.message);
            return res.status(500).json({ error: err.message });
        }
        if (!row) {
            return res.status(404).json({ error: 'Статья не найдена или доступ запрещён' });
        }

        db.run('DELETE FROM articles WHERE id = ?', [articleId], function (err) {
            if (err) {
                console.error('Ошибка удаления статьи:', err.message);
                return res.status(500).json({ error: err.message });
            }

            if (row.image) {
                const imagePath = path.join(__dirname, 'static/uploads', row.image);
                fs.unlink(imagePath, (unlinkErr) => {
                    if (unlinkErr) {
                        console.error('Ошибка удаления изображения:', unlinkErr.message);
                    } else {
                        console.log('Изображение удалено:', row.image);
                    }
                });
            }

            res.json({ message: 'Статья успешно удалена' });
        });
    });
});

// Публичный доступ к статье по ID (без проверки авторства)
app.get('/api/public/articles/:id', (req, res) => {
    const articleId = req.params.id;
    db.get('SELECT articles.*, users.username FROM articles JOIN users ON articles.user_id = users.id WHERE articles.id = ?', [articleId], (err, row) => {
        if (err) {
            console.error('Ошибка получения статьи:', err.message);
            return res.status(500).json({ error: err.message });
        }
        if (!row) {
            return res.status(404).json({ error: 'Статья не найдена' });
        }
        res.json(row);
    });
});

// Получение средней оценки статьи
app.get('/api/articles/:id/rating', (req, res) => {
    const articleId = req.params.id;
    db.get('SELECT rating FROM articles WHERE id = ?', [articleId], (err, row) => {
        if (err) {
            console.error('Ошибка получения оценки:', err.message);
            return res.status(500).json({ error: err.message });
        }
        if (!row) {
            return res.status(404).json({ error: 'Статья не найдена' });
        }
        res.json({ rating: row.rating || 0 });
    });
});

// Добавление или обновление оценки статьи пользователем
app.post('/api/articles/:id/rating', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    const articleId = req.params.id;
    const userId = req.session.user.id;
    const { rating } = req.body;

    if (!rating || rating < 1 || rating > 5) {
        return res.status(400).json({ error: 'Оценка должна быть от 1 до 5' });
    }

    db.get('SELECT id FROM articles WHERE id = ?', [articleId], (err, article) => {
        if (err) {
            console.error('Ошибка проверки статьи:', err.message);
            return res.status(500).json({ error: err.message });
        }
        if (!article) {
            return res.status(404).json({ error: 'Статья не найдена' });
        }

        db.get('SELECT rating FROM ratings WHERE article_id = ? AND user_id = ?', [articleId, userId], (err, existingRating) => {
            if (err) {
                console.error('Ошибка проверки оценки:', err.message);
                return res.status(500).json({ error: err.message });
            }

            if (existingRating) {
                db.run('UPDATE ratings SET rating = ? WHERE article_id = ? AND user_id = ?', [rating, articleId, userId], (err) => {
                    if (err) {
                        console.error('Ошибка обновления оценки:', err.message);
                        return res.status(500).json({ error: err.message });
                    }
                    updateAverageRating(articleId, res);
                });
            } else {
                db.run('INSERT INTO ratings (article_id, user_id, rating) VALUES (?, ?, ?)', [articleId, userId, rating], (err) => {
                    if (err) {
                        console.error('Ошибка добавления оценки:', err.message);
                        return res.status(500).json({ error: err.message });
                    }
                    updateAverageRating(articleId, res);
                });
            }
        });
    });
});

// Функция для пересчёта средней оценки статьи
function updateAverageRating(articleId, res) {
    db.all('SELECT rating FROM ratings WHERE article_id = ?', [articleId], (err, rows) => {
        if (err) {
            console.error('Ошибка получения оценок:', err.message);
            return res.status(500).json({ error: err.message });
        }
        const total = rows.reduce((sum, row) => sum + row.rating, 0);
        const average = rows.length ? (total / rows.length).toFixed(1) : 0;

        db.run('UPDATE articles SET rating = ? WHERE id = ?', [average, articleId], (err) => {
            if (err) {
                console.error('Ошибка обновления средней оценки:', err.message);
                return res.status(500).json({ error: err.message });
            }
            res.json({ message: 'Оценка добавлена', average });
        });
    });
}

// Закрытие базы данных при завершении
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error('Ошибка закрытия базы данных:', err.message);
        } else {
            console.log('База данных закрыта');
        }
        process.exit(0);
    });
});

app.listen(port, () => {
    console.log(`Сервер запущен на http://localhost:${port}`);
});