from datetime import UTC, datetime, timedelta
from app import main


def test_root_works(client):
    response = client.get('/')
    assert response.status_code == 200
    assert response.json()['docs'] == '/docs'


def test_full_link_flow_for_authorized_user(client, auth_headers):
    create_response = client.post('/links/shorten', json={'original_url': 'https://example.com/article', 'custom_alias': 'manual1'}, headers=auth_headers)
    assert create_response.status_code == 201
    short_code = create_response.json()['short_code']


    stats_response = client.get(f'/links/{short_code}/stats')
    assert stats_response.status_code == 200
    assert stats_response.json()['click_count'] == 0

    # идём по короткой ссылке
    redirect_response = client.get(f'/links/{short_code}', follow_redirects=False)
    assert redirect_response.status_code == 307
    assert redirect_response.headers['location'] == 'https://example.com/article'

    # увиличение счётчика кликов
    stats_after_redirect = client.get(f'/links/{short_code}/stats')
    assert stats_after_redirect.status_code == 200
    assert stats_after_redirect.json()['click_count'] == 1

    # обновление исходной ссылки
    update_response = client.put(f'/links/{short_code}', json={'original_url': 'https://example.com/updated'}, headers=auth_headers)
    assert update_response.status_code == 200
    assert update_response.json()['original_url'] == 'https://example.com/updated'

    # удаляем ссылку
    delete_response = client.delete(f'/links/{short_code}', headers=auth_headers)
    assert delete_response.status_code == 204

    stats_after_delete = client.get(f'/links/{short_code}/stats')
    assert stats_after_delete.status_code == 404




def test_anonymous_user_can_create_link(client):
    response = client.post('/links/shorten', json={'original_url': 'https://example.com/public'})
    assert response.status_code == 201
    assert response.json()['owner_id'] is None


def test_create_link_rejects_taken_alias(client, auth_headers):
    # первый alias занимает имя
    first_response = client.post('/links/shorten', json={'original_url': 'https://example.com/first', 'custom_alias': 'samealias'}, headers=auth_headers)
    assert first_response.status_code == 201

    # второй такой же alias уже нельзя
    second_response = client.post('/links/shorten', json={'original_url': 'https://example.com/second', 'custom_alias': 'samealias'}, headers=auth_headers)
    assert second_response.status_code == 409


def test_create_link_rejects_past_expiration_date(client, auth_headers):
    # дата истечения в прошлом недопустима
    response = client.post('/links/shorten', 
        json={
            'original_url': 'https://example.com/expired',
            'expires_at': '2000-01-01T00:00:00+00:00',
        },
        headers=auth_headers
    )
    assert response.status_code == 400


# невалидный url должен дать 422
def test_create_link_validates_input(client):
    response = client.post('/links/shorten', json={'original_url': 'bad-url', 'custom_alias': 'ab'}
    )
    assert response.status_code == 422



# создаём две ссылки на один и тот же url
def test_search_returns_only_active_links(client, auth_headers, db_session):
    first_response = client.post('/links/shorten', json={'original_url': 'https://example.com/shared'}, headers=auth_headers)
    second_response = client.post('/links/shorten', json={'original_url': 'https://example.com/shared', 'custom_alias': 'gone123'}, headers=auth_headers)

    assert first_response.status_code == 201
    assert second_response.status_code == 201

    # одну ссылку делаем неактивной вручную
    hidden_link = db_session.query(main.Link).filter_by(short_code=second_response.json()['short_code']).one()
    hidden_link.is_active = False
    db_session.commit()

    search_response = client.get('/links/search', params={'original_url': 'https://example.com/shared'})

    assert search_response.status_code == 200
    assert len(search_response.json()['results']) == 1
    assert search_response.json()['results'][0]['short_code'] == first_response.json()['short_code']


def test_anonymous_link_cannot_be_updated(client, auth_headers):
    create_response = client.post('/links/shorten', json={'original_url': 'https://example.com/anonymous'})
    short_code = create_response.json()['short_code']

    update_response = client.put(f'/links/{short_code}', json={'original_url': 'https://example.com/blocked'}, headers=auth_headers)
    assert update_response.status_code == 403


def test_user_cannot_edit_someone_elses_link(client, auth_headers):
    # первый пользователь создаёт ссылку
    create_response = client.post('/links/shorten', json={'original_url': 'https://example.com/private'}, headers=auth_headers)
    short_code = create_response.json()['short_code']

    # второй пользователь получает свой токен
    second_user = {
        'username': 'mentor',
        'email': 'mentor@example.com',
        'password': 'strongpass',
    }
    assert client.post('/auth/register', json=second_user).status_code == 201

    login_response = client.post('/auth/login', data={'username': second_user['username'], 'password': second_user['password']})
    second_token = login_response.json()['access_token']
    second_headers = {'Authorization': f'Bearer {second_token}'}

    # запрет на редактирование чужой ссылки
    update_response = client.put(f'/links/{short_code}', json={'original_url': 'https://example.com/forbidden'}, headers=second_headers)
    assert update_response.status_code == 403


def test_delete_requires_authentication(client, auth_headers):
    # без токена удалить ссылку нельзя
    create_response = client.post('/links/shorten', json={'original_url': 'https://example.com/private'}, headers=auth_headers)
    short_code = create_response.json()['short_code']

    delete_response = client.delete(f'/links/{short_code}')
    assert delete_response.status_code == 401


def test_expired_link_returns_410_and_appears_in_history(client, auth_headers):
    # создаём ссылку с будущей датой истечения
    create_response = client.post(
        '/links/shorten',
        json={
            'original_url': 'https://example.com/will-expire',
            'custom_alias': 'expiring',
            'expires_at': (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        },
        headers=auth_headers
    )

    assert create_response.status_code == 201
    short_code = create_response.json()['short_code']

    # потом делаем её уже истёкшей
    with main.SessionLocal() as session:
        link = session.query(main.Link).filter_by(short_code=short_code).one()
        link.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        session.commit()

    redirect_response = client.get(f'/links/{short_code}', follow_redirects=False)
    assert redirect_response.status_code == 410

    stats_response = client.get(f'/links/{short_code}/stats')
    assert stats_response.status_code == 200

    history_response = client.get('/links/expired-history')
    assert history_response.status_code == 200
    assert history_response.json()[0]['short_code'] == short_code


def test_cleanup_endpoint_marks_expired_and_inactive_links(client, db_session):
    # готовим одну expired и одну inactive ссылку
    expired_link = main.Link(short_code='oldexp', original_url='https://example.com/expired', expires_at=datetime.now(UTC) - timedelta(days=1))
    inactive_link = main.Link(short_code='oldidle', original_url='https://example.com/inactive', last_accessed_at=datetime.now(UTC) - timedelta(days=main.INACTIVE_LINK_DAYS + 1))
    db_session.add_all([expired_link, inactive_link])
    db_session.commit()

    # очистка
    response = client.post('/maintenance/cleanup')
    assert response.status_code == 200
    assert response.json() == {'expired_links_marked': 1, 'inactive_links_marked': 1}

    expired_link = db_session.query(main.Link).filter_by(short_code='oldexp').one()
    inactive_link = db_session.query(main.Link).filter_by(short_code='oldidle').one()
    assert expired_link.deactivated_reason == 'expired'
    assert inactive_link.deactivated_reason == 'inactive'
