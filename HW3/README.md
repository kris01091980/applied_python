# Link Shortener API

**Описание:**  
API-сервис для сокращения длинных URL, реализованный на Flask. 

Включает JWT-аутентификацию, административную панель (
Flask-Admin), in-memory кэширование (Flask-Caching), автоматическое удаление просроченных ссылок (APScheduler) и
Swagger-документацию.

## Возможности

- **API:**
    - `POST /auth/register` — регистрация пользователя.
    - `POST /auth/login` — авторизация и получение JWT-токена.
    - `POST /links/shorten` — создание короткой ссылки с опциональными параметрами:
        - `custom_alias` — пользовательский alias.
        - `expires_at` — время жизни ссылки (формат: `YYYY-MM-DD HH:MM`).
    - `GET /links/<short_code>/stats` — получение статистики по ссылке.
    - `PUT /links/<short_code>` — обновление оригинального URL (требуется JWT).
    - `DELETE /links/<short_code>` — удаление ссылки (требуется JWT).
    - `GET /links/search?original_url=...` — поиск ссылки по оригинальному URL.
    - `GET /<short_code>` — редирект на оригинальный URL.

- **Админ-панель:**  
  Доступна по адресу `/admin`. Защищена сессионной авторизацией (только суперпользователи с `is_admin=True`).

- **Автоматическое удаление:**  
  APScheduler каждые 60 секунд удаляет ссылки с истекшим сроком действия.

- **Кэширование:**  
  In-memory кэширование (Flask-Caching) для ускорения получения статистики.

- **Swagger-документация:**  
  Доступна по адресу `/apidocs`.

- **CLI-команда:**  
  `flask create_superuser` — создание суперпользователя для админ-панели.

## Требования

- Python 3.10-slim (для Docker)
- Flask, Flask-SQLAlchemy, Flasgger, Gunicorn, Click - основные библиотеки

## Установка

1. **Клонируйте репозиторий** и перейдите в директорию проекта.

2. **Установите зависимости:**

   ```bash
   pip install -r requirements.txt
    ```
3. Создайте суперпользователя:

  ```bash
  flask create_superuser
  ```

4. Запустите проект:

  ```bash
  flask run
  ```
  
  Либо:
  
  ```bash
  gunicorn -b 0.0.0.0:5000 app:create_app()
  ```

## Развертывание

Для развертывания приложения необходимо собрать и запустить Dockerfile:

1. `docker build -t link-shortener .`
2. `docker run -d -p 5000:5000 link-shortener`

Таким образом, образ будет собран и контейнер запущен.