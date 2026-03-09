import os
from pathlib import Path

from fastapi.testclient import TestClient

# Для теста используем отдельную SQLite-базу, чтобы не трогать рабочие данные.
db_path = Path('test_app.sqlite3').resolve()
if db_path.exists():
    db_path.unlink()

os.environ['DATABASE_URL'] = f'sqlite:///{db_path}'
os.environ['REDIS_URL'] = 'redis://127.0.0.1:6390/0'
os.environ['SECRET_KEY'] = 'test-secret-key'

from app.main import app


def test_root_and_basic_link_flow() -> None:
    # Это smoke test: он не покрывает всё, но быстро показывает, что проект живой.
    with TestClient(app) as client:
        root_response = client.get('/')
        assert root_response.status_code == 200

        register_response = client.post(
            '/auth/register',
            json={
                'username': 'student',
                'email': 'student@example.com',
                'password': 'strongpass',
            },
        )
        assert register_response.status_code == 201

        login_response = client.post(
            '/auth/login',
            data={'username': 'student', 'password': 'strongpass'},
        )
        assert login_response.status_code == 200
        token = login_response.json()['access_token']

        create_response = client.post(
            '/links/shorten',
            json={'original_url': 'https://example.com/article'},
            headers={'Authorization': f'Bearer {token}'},
        )
        assert create_response.status_code == 201
        short_code = create_response.json()['short_code']

        stats_response = client.get(f'/links/{short_code}/stats')
        assert stats_response.status_code == 200
        assert stats_response.json()['original_url'] == 'https://example.com/article'
