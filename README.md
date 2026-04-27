# cert_bot_max

Бот для контроля сроков ЭЦП и отправки уведомлений в MAX.

## Что умеет

- Рекурсивно сканирует каталоги с сертификатами.
- Поддерживает файлы `.cer`, `.crt`, `.pem`, `.der`.
- Отправляет уведомления по порогам из `config.py`.
- Хранит кэш отправок, чтобы не спамить одинаковыми сообщениями.
- Обрабатывает команды из чата:
  - `/cert` — полный список ЭЦП по возрастанию срока.
  - `/cert N` — список ЭЦП, у которых осталось `N` дней и меньше.

Формат строки в ответе:

`Наименование/ФИО - YYYY-MM-DD - осталось N дней`

Между записями добавляется разделитель:

`------------------------------`

## Структура проекта

- `check_certs.py` — основной скрипт.
- `config.py` — настройки.
- `requirements.txt` — зависимости Python.
- `sent_cache.json` — кэш отправок (создается автоматически).

## Установка

```bash
git clone https://github.com/den063rus-design/cert_bot_max.git
cd cert_bot_max
pip install -r requirements.txt
```

## Настройка (`config.py`)

Обязательные параметры:

- `MAX_ACCESS_TOKEN` — токен бота MAX.
- `CHAT_ID` — ID чата.
- `CERT_ROOTS` — список папок с сертификатами.

Полезные параметры:

- `ALERT_THRESHOLDS` — пороги уведомлений.
- `WORK_HOUR_START`, `WORK_HOUR_END` — рабочее окно отправки.
- `FORCE_SEND_EVERY_RUN` — тестовый режим.
- `RUN_AS_DAEMON` — постоянная работа в цикле.
- `DAEMON_LOOP_INTERVAL` — интервал полного цикла (секунды).
- `COMMAND_LOOP_INTERVAL` — интервал опроса команд (секунды).
- `COMMAND_POLL_COUNT` — сколько сообщений читать за один опрос.

## Запуск

Один проход:

```bash
python3 check_certs.py
```

Постоянный режим:

```bash
python3 check_certs.py --daemon
```

## Рекомендуемый запуск через systemd

Для пути проекта `/home/user/bot_cert`:

1. Создайте сервис:

```bash
sudo nano /etc/systemd/system/bot-cert.service
```

2. Вставьте:

```ini
[Unit]
Description=MAX Certificate Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=user
WorkingDirectory=/home/user/bot_cert
ExecStart=/usr/bin/python3 /home/user/bot_cert/check_certs.py --daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

3. Активируйте:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bot-cert
sudo systemctl status bot-cert --no-pager
```

Логи:

```bash
journalctl -u bot-cert -f
```

