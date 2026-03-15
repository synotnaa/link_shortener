import os
from uuid import uuid4
from locust import HttpUser, between, task


class LinkShortenerUser(HttpUser):
    wait_time = between(1, 3)

    # готовим пользователя для нагрузочного теста
    def on_start(self):
        suffix = uuid4().hex[:8]
        self.username = f'loaduser_{suffix}'
        self.password = 'strongpass'
        self.headers = {}
        self.short_code = None

        register_response = self.client.post('/auth/register',
            json={
                'username': self.username,
                'email': f'{self.username}@example.com',
                'password': self.password,
            },
            name='/auth/register'
        )

        if register_response.status_code not in (201, 409):
            register_response.failure(f'unexpected register status: {register_response.status_code}')

        login_response = self.client.post('/auth/login', data={'username': self.username, 'password': self.password}, name='/auth/login')
        if login_response.status_code == 200:
            token = login_response.json()['access_token']
            self.headers = {'Authorization': f'Bearer {token}'}
        else:
            login_response.failure(f'unexpected login status: {login_response.status_code}')

    @task(3)
    def create_short_link(self):
        alias = uuid4().hex[:10]
        response = self.client.post('/links/shorten',
            json={
                'original_url': f'https://example.com/load/{uuid4().hex}',
                'custom_alias': alias,
            },
            headers=self.headers,
            name='/links/shorten'
        )

        if response.status_code == 201:
            self.short_code = response.json()['short_code']
        else:
            response.failure(f'unexpected create status: {response.status_code}')

    @task(2)
    def get_stats(self):
        if not self.short_code:
            return

        response = self.client.get(f'/links/{self.short_code}/stats', name='/links/:short_code/stats')

        if response.status_code != 200:
            response.failure(f'unexpected stats status: {response.status_code}')

    @task(2)
    def redirect(self):
        if not self.short_code:
            return

        response = self.client.get(f'/links/{self.short_code}', allow_redirects=False, name='/links/:short_code')

        if response.status_code != 307:
            response.failure(f'unexpected redirect status: {response.status_code}')


if os.getenv('LOCUST_EXPLAIN'):
    print('Run with: locust -f locustfile.py --host http://127.0.0.1:8000')
