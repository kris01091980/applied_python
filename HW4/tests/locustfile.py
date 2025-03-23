import uuid

from locust import HttpUser, TaskSet, task, between
import random
import string


class UserBehavior(TaskSet):
    def on_start(self):
        # Генерируем уникальное имя пользователя и пароль для регистрации
        self.username = "user" + "".join(random.choices(string.digits, k=5))
        self.password = "pass" + "".join(random.choices(string.ascii_letters, k=5))

        # Регистрируем пользователя (если уже зарегистрирован, ошибки игнорируются)
        self.client.post("/auth/register", json={"username": self.username, "password": self.password})

        # Логинимся, чтобы получить токен для авторизованных операций
        login_response = self.client.post("/auth/login", json={"username": self.username, "password": self.password})
        if login_response.status_code == 200:
            self.token = login_response.json().get("access_token")
        else:
            self.token = None

    @task(2)
    def test_create_link_without_auth_and_redirect(self):
        """
        Тест создания ссылки без авторизации и проверка редиректа
        """
        original_url = "https://ya.ru"
        response = self.client.post("/links/shorten", json={"original_url": original_url})
        if response.status_code == 201:
            data = response.json()
            short_code = data["short_code"]
            # Выполняем редирект с отключенным follow, чтобы проверить статус и заголовок location
            redirect_response = self.client.request("GET", f"/{short_code}", allow_redirects=False)
            if redirect_response.status_code not in (302, 307):
                print(f"[Non-Auth] Неожиданный статус редиректа для {short_code}: {redirect_response.status_code}")
            elif redirect_response.headers.get("location") != original_url:
                print(f"[Non-Auth] Неверный location для {short_code}: {redirect_response.headers.get('location')}")
        else:
            print(f"[Non-Auth] Ошибка создания ссылки: {response.status_code}")

    @task(3)
    def test_create_update_delete_with_auth(self):
        """
        Тест создания ссылки с авторизацией, обновление оригинального URL,
        проверка статистики и последующее удаление ссылки
        """
        if not self.token:
            return  # Пропускаем, если токен не получен

        original_url = "https://ya.ru"
        # Создание ссылки с авторизацией (передача токена через query-параметр)
        create_response = self.client.post(f"/links/shorten?token={self.token}", json={"original_url": original_url})
        if create_response.status_code != 201:
            print(f"[Auth] Ошибка создания ссылки: {create_response.status_code}")
            return
        data = create_response.json()
        short_code = data["short_code"]

        # Обновление ссылки: меняем оригинальный URL
        new_url = "https://ya.ru"
        update_response = self.client.put(
            f"/links/{short_code}",
            json={"original_url": new_url},
            headers={"Authorization": f"Bearer {self.token}"}
        )
        if update_response.status_code != 200:
            print(f"[Auth] Ошибка обновления ссылки {short_code}: {update_response.status_code}")

        # Проверка статистики: оригинальный URL должен быть обновлён
        stats_response = self.client.get(f"/links/{short_code}/stats")
        if stats_response.status_code != 200:
            print(f"[Auth] Ошибка получения статистики для {short_code}: {stats_response.status_code}")
        else:
            stats = stats_response.json()
            if stats.get("original_url") != new_url:
                print(f"[Auth] Неверный URL в статистике для {short_code}: {stats.get('original_url')} != {new_url}")

        # Удаление ссылки
        delete_response = self.client.delete(
            f"/links/{short_code}",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        if delete_response.status_code != 200:
            print(f"[Auth] Ошибка удаления ссылки {short_code}: {delete_response.status_code}")

        # Проверка, что ссылка удалена (статистика должна вернуть 404)
        stats_after_delete = self.client.get(f"/links/{short_code}/stats")
        if stats_after_delete.status_code != 404:
            print(
                f"[Auth] Ссылка {short_code} не была удалена должным образом. Статус: {stats_after_delete.status_code}")

    @task(1)
    def test_search_link(self):
        """
        Тест создания ссылки с кастомным alias и последующий поиск по оригинальному URL
        """
        search_url = "https://ya.ru" + str(uuid.uuid4())[:5]
        custom_alias = "search" + "https://ya.ru" + str(uuid.uuid4())[:5]
        create_response = self.client.post("/links/shorten",
                                           json={"original_url": search_url, "custom_alias": custom_alias})
        if create_response.status_code != 201:
            print(f"[Search] Ошибка создания ссылки для поиска: {create_response.status_code}")
            return
        search_response = self.client.get("/links/search", params={"original_url": search_url})
        if search_response.status_code != 200:
            print(f"[Search] Ошибка поиска ссылки: {search_response.status_code}")


class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    host = "http://localhost:8000"
    wait_time = between(1, 3)
