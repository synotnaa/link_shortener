import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient


TEST_DB_PATH = Path('test_app.sqlite3').resolve()

# отдельная база для тестов
os.environ['DATABASE_URL'] = f'sqlite:///{TEST_DB_PATH}'
os.environ['REDIS_URL'] = 'redis://127.0.0.1:6390/0'
os.environ['SECRET_KEY'] = 'test-secret-key'
os.environ['APP_BASE_URL'] = 'http://testserver'

from app import main

ORIGINAL_GET_REDIS = main.get_redis


@pytest.fixture(autouse=True)
def reset_state(monkeypatch: pytest.MonkeyPatch):
    # redis в тестах не используем
    main.redis_client = None
    monkeypatch.setattr(main, 'get_redis', lambda: None)

    # чистим бд перед каждым тестом
    main.Base.metadata.create_all(bind=main.engine, checkfirst=True)

    with main.SessionLocal() as session:
        session.query(main.Link).delete()
        session.query(main.User).delete()
        session.commit()

    yield


@pytest.fixture
def client():
    # клиент для запросов к фастапи
    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture
def db_session():
    # если в тесте надо залезть в базу напрямую
    with main.SessionLocal() as session:
        yield session


@pytest.fixture
def user_payload() -> dict[str, str]:
    # обычный тестовый пользователь
    return {
        'username': 'student',
        'email': 'student@example.com',
        'password': 'strongpass'
    }


@pytest.fixture
def auth_headers(client: TestClient, user_payload: dict[str, str]) -> dict[str, str]:
    register_response = client.post('/auth/register', json=user_payload) # получаем токен для защищённых ручек
    assert register_response.status_code == 201

    response = client.post(
        '/auth/login',
        data={'username': user_payload['username'], 'password': user_payload['password']}
    )
    assert response.status_code == 200
    token = response.json()['access_token']
    return {'Authorization': f'Bearer {token}'}
