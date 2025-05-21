const sqlite3 = require('sqlite3').verbose();

// Открытие или создание базы данных
const db = new sqlite3.Database('./obss_hub.db', (err) => {
    if (err) {
        console.error('Ошибка при подключении к базе данных:', err.message);
    } else {
        console.log('Подключено к базе данных SQLite');
    }
});

// Экспортируем объект db для использования в других файлах
module.exports = db;