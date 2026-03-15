def test_register_login_and_get_current_user(client, user_payload):
    register_response = client.post('/auth/register', json=user_payload)
    assert register_response.status_code == 201
    assert register_response.json()['username'] == user_payload['username']


    login_response = client.post('/auth/login', data={'username': user_payload['username'], 'password': user_payload['password']})
    assert login_response.status_code == 200
    token = login_response.json()['access_token']

    # проверяем защищённую ручку
    me_response = client.get('/auth/me', headers={'Authorization': f'Bearer {token}'})


    assert me_response.status_code == 200
    assert me_response.json()['email'] == user_payload['email']


def test_register_rejects_duplicate_username_and_email(client, user_payload):
    assert client.post('/auth/register', json=user_payload).status_code == 201

    # повтор username
    duplicate_username = client.post('/auth/register', json={**user_payload, 'email': 'another@example.com'})
    assert duplicate_username.status_code == 409

    # повтор email
    duplicate_email = client.post('/auth/register', json={**user_payload, 'username': 'othername'})
    assert duplicate_email.status_code == 409



# пароль не совпадает
def test_login_rejects_invalid_credentials(client, user_payload):
    assert client.post('/auth/register', json=user_payload).status_code == 201
    response = client.post('/auth/login', data={'username': user_payload['username'], 'password': 'wrongpass'})

    assert response.status_code == 401


# без токена доступ закрыт
def test_get_me_requires_authentication(client):
    response = client.get('/auth/me')
    assert response.status_code == 401


# фастапи должен отклонять плохие данные
def test_register_validates_payload(client):
    response = client.post('/auth/register', json={'username': 'abc', 'email': 'not-an-email', 'password': '123'})
    assert response.status_code == 422
