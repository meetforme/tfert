# ProfShock Mega Bot

Эффектный Telegram-бот для защиты курсовой/практики по ИБ.

## Что умеет
- ИБ-демонстрации и симуляции атак
- IDS-статистика, dashboard, incident reports
- 2-step admin login по PIN
- honeypot-команды
- генератор паролей, SHA-256, калькулятор
- заметки, todo, напоминания
- мини-викторина, шутки, цитаты, dice/coin
- PDF-отчёт по безопасности
- подсказки команд и кнопочное меню

## Запуск
```bash
python -m pip install -r requirements.txt
python bot.py
```

## Команды
- /start
- /help
- /menu
- /info
- /security
- /profile
- /check текст
- /verify код
- /password 20
- /calc 2*(5+7)
- /hash текст
- /note текст
- /notes
- /todo add текст
- /todo list
- /todo done 1
- /remind 10m текст
- /quiz
- /fun
- /risk
- /ids
- /simulate sql
- /dashboard
- /admin
- /admin_login 123456
- /logs
- /incident latest
- /report

## Важно
Токен уже встроен в архив, потому что он был предоставлен в чате. После демонстрации лучше перевыпустить токен через BotFather.
