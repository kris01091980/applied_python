import os
import tempfile
import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import app, Base, get_db


@pytest.fixture(scope="session")
def temp_db():
    """
    Фикстура для создания временной базы данных с использованием временного файла
    """
    temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    temp_file.close()
    db_url = f"sqlite:///{temp_file.name}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    # Создаем таблицы
    Base.metadata.create_all(bind=engine)
    yield {"engine": engine, "session_local": TestingSessionLocal, "db_file": temp_file.name}
    # Очистка: сбрасываем соединения и удаляем файл
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    os.remove(temp_file.name)


@pytest.fixture()
def db_session(temp_db):
    """
    Фикстура для переопределения зависимости get_db
    """
    db = temp_db["session_local"]()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def client(db_session):
    """
    Фикстура для TestClient с переопределенной зависимостью get_db
    """

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


# ============
# Функциональные тесты
# ============
def test_register_and_login(client):
    # Тест регистрации
    user_data = {"username": "func_user", "password": "func_pass"}
    response = client.post("/auth/register", json=user_data)
    # Если пользователь уже зарегистрирован, можно получить 400
    assert response.status_code in (201, 400)

    # Тест логина
    response = client.post("/auth/login", json=user_data)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data


def test_create_link_without_auth(client):
    # Создание ссылки без токена
    original_url = "https://ya.ru"
    link_data = {"original_url": original_url}
    response = client.post("/links/shorten", json=link_data)
    assert response.status_code == 201
    data = response.json()
    short_code = data["short_code"]

    # Проверка редиректа с отключением автоматического следования за редиректом
    redirect_response = client.request("GET", f"/{short_code}", follow_redirects=False)
    # Если редирект срабатывает, ожидаем статус 302 или 307
    assert redirect_response.status_code in (302, 307)
    assert redirect_response.headers.get("location") == original_url


def test_create_link_with_custom_alias_and_expires_at(client):
    original_url = "https://customexpire.com"
    custom_alias = "customalias"
    # Формируем время в формате "YYYY-MM-DD HH:MM"
    future_time = (datetime.utcnow() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M")
    link_data = {
        "original_url": original_url,
        "custom_alias": custom_alias,
        "expires_at": future_time
    }
    response = client.post("/links/shorten", json=link_data)
    assert response.status_code == 201
    data = response.json()
    assert data["short_code"] == custom_alias

    # Получаем статистику и проверяем expires_at
    stats_response = client.get(f"/links/{custom_alias}/stats")
    assert stats_response.status_code == 200
    stats = stats_response.json()
    # Преобразуем future_time в ожидаемый формат ISO:
    expected_iso = future_time.replace(" ", "T") + ":00"
    # Проверяем, что строка начинается с ожидаемой подстроки (в случае наличия долей секунд)
    assert stats["expires_at"].startswith(expected_iso)


def test_create_link_invalid_expires_at(client):
    # Передаем невалидное значение expires_at
    original_url = "https://invaliddate.com"
    link_data = {"original_url": original_url, "expires_at": "invalid-date-format"}
    response = client.post("/links/shorten", json=link_data)
    assert response.status_code == 400


def test_search_link(client):
    original_url = "https://searchexample.com"
    custom_alias = "searchalias"
    link_data = {"original_url": original_url, "custom_alias": custom_alias}
    # Создаем ссылку
    response = client.post("/links/shorten", json=link_data)
    assert response.status_code == 201

    # Ищем ссылку по оригинальному URL
    search_response = client.get("/links/search", params={"original_url": original_url})
    assert search_response.status_code == 200
    data = search_response.json()
    assert data["short_code"] == custom_alias
    assert data["original_url"] == original_url


def test_update_and_delete_link(client):
    # Регистрируем пользователя для обновления и удаления
    user_data = {"username": "cruduser", "password": "crudpass"}
    reg_response = client.post("/auth/register", json=user_data)
    assert reg_response.status_code in (201, 400)
    login_response = client.post("/auth/login", json=user_data)
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    # Создаем ссылку с использованием токена (передаем через query-параметр)
    original_url = "https://crudcreate.com"
    custom_alias = "crudalias"
    link_data = {"original_url": original_url, "custom_alias": custom_alias}
    create_response = client.post(f"/links/shorten?token={token}", json=link_data)
    assert create_response.status_code == 201

    # Обновляем ссылку
    new_url = "https://crudupdated.com"
    update_data = {"original_url": new_url}
    update_response = client.put(
        f"/links/{custom_alias}",
        json=update_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    assert update_response.status_code == 200

    # Проверяем, что ссылка обновилась
    stats_response = client.get(f"/links/{custom_alias}/stats")
    assert stats_response.status_code == 200
    stats = stats_response.json()
    assert stats["original_url"] == new_url

    # Удаляем ссылку
    delete_response = client.delete(
        f"/links/{custom_alias}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert delete_response.status_code == 200

    # Проверяем, что ссылка удалена
    stats_after_delete = client.get(f"/links/{custom_alias}/stats")
    assert stats_after_delete.status_code == 404


def test_redirect_invalid_link(client):
    # Запрашиваем редирект по несуществующему коду
    response = client.get("/nonexistent")
    assert response.status_code == 404
