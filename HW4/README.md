# Link Shortener API

**Описание:**  
API-сервис для сокращения длинных URL, реализованный на FastAPI. 

Включает JWT-аутентификацию, in-memory кэширование, автоматическое удаление просроченных ссылок (APScheduler) и
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

- **Автоматическое удаление:**  
  APScheduler каждые 60 секунд удаляет ссылки с истекшим сроком действия.

- **Кэширование:**  
  In-memory кэширование для ускорения получения статистики.

- **Swagger-документация:**  
  Доступна по адресу `/docs`.


## Требования

- Python 3.10-slim (для Docker)
- FastAPI, Pytest, Locust - основные библиотеки

## Установка

1. **Клонируйте репозиторий** и перейдите в директорию проекта.

2. **Установите зависимости:**

   ```bash
   pip install -r requirements.txt
    ```

3. Запустите проект:

  ```bash
  python app.py
  ```
  
  Либо:
  
  ```bash
  gunicorn -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000 main:app()
  ```

## Развертывание

Для развертывания приложения необходимо собрать и запустить Dockerfile:

1. `docker build -t link-shortener .`
2. `docker run -d -p 5000:5000 link-shortener`

Таким образом, образ будет собран и контейнер запущен.