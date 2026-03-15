def test_basic_smoke_flow(client, user_payload):
    root_response = client.get('/')

    assert root_response.status_code == 200

    register_response = client.post('/auth/register', json=user_payload) # регистрация

    assert register_response.status_code == 201

    # токен
    login_response = client.post('/auth/login', data={'username': user_payload['username'], 'password': user_payload['password']})

    assert login_response.status_code == 200

    token = login_response.json()['access_token']

    # создание короткой ссылки
    create_response = client.post('/links/shorten', json={'original_url': 'https://example.com/article'}, headers={'Authorization': f'Bearer {token}'})
    
    assert create_response.status_code == 201

    short_code = create_response.json()['short_code']

    stats_response = client.get(f'/links/{short_code}/stats') # смотрим статистику

    assert stats_response.status_code == 200
    assert stats_response.json()['original_url'] == 'https://example.com/article'
