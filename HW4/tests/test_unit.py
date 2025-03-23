import time
from datetime import datetime, timedelta
import jwt
import pytest

from app import (
    generate_short_code,
    set_cache,
    get_cache,
    delete_cache,
    create_access_token,
    SECRET_KEY,
    ALGORITHM,
    cache_data,
)


def test_generate_short_code():
    """Проверяем, что функция генерирует строку длиной 6 символов и содержит только буквы и цифры"""
    code = generate_short_code()
    assert isinstance(code, str)
    assert len(code) == 6
    assert code.isalnum()


def test_cache_set_get_and_expire():
    """Проверяем корректную работу кэширования:
    - set_cache записывает значение с TTL,
    - get_cache возвращает значение до истечения TTL,
    - после истечения TTL значение удаляется
    """
    key = "test_key"
    value = {"data": "test"}
    ttl = 1  # 1 секунда
    set_cache(key, value, ttl)
    # Проверяем, что значение сразу доступно
    cached = get_cache(key)
    assert cached == value

    # Ждем истечения TTL
    time.sleep(ttl + 0.5)
    assert get_cache(key) is None


def test_cache_delete():
    """Проверяем, что функция delete_cache корректно удаляет запись из кэша"""
    key = "delete_key"
    value = "delete_me"
    set_cache(key, value, ttl=10)
    # Убеждаемся, что значение установлено
    assert get_cache(key) == value

    delete_cache(key)
    assert get_cache(key) is None


def test_create_access_token():
    """Проверяем создание JWT-токена:
    - токен содержит нужные данные (sub),
    - срок действия (exp) установлен корректно
    """
    data = {"sub": "123"}
    expire_minutes = 5
    token = create_access_token(data, expires_delta=timedelta(minutes=expire_minutes))
    decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

    # Проверяем наличие обязательных полей
    assert decoded.get("sub") == "123"
    exp = decoded.get("exp")
    assert exp is not None

    # Проверяем, что время истечения соответствует заданному интервалу (с погрешностью в несколько секунд)
    exp_datetime = datetime.utcfromtimestamp(exp)
    expected_exp = datetime.utcnow() + timedelta(minutes=expire_minutes)
    diff = abs((exp_datetime - expected_exp).total_seconds())
    assert diff < 10  # до 10 секунд разницы


@pytest.fixture(autouse=True)
def clear_cache():
    """Фикстура для очистки кэша перед каждым тестом"""
    cache_data.clear()
    yield
    cache_data.clear()
