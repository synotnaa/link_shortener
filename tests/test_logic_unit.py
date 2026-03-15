from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import Mock
import pytest
from fastapi import HTTPException
from jose import JWTError
from redis.exceptions import RedisError
from app import main
from tests.conftest import ORIGINAL_GET_REDIS


# фейк редис для тестирования без подключения
class FakeRedis:
    def __init__(self, value=None, should_fail=False):
        self.value = value
        self.should_fail = should_fail
        self.set_calls = []
        self.delete_calls = []

    def get(self, key):
        if self.should_fail:
            raise RedisError('boom')
        return self.value

    def set(self, key, value, ex=None):
        if self.should_fail:
            raise RedisError('boom')
        self.set_calls.append((key, value, ex))

    def delete(self, *keys):
        if self.should_fail:
            raise RedisError('boom')
        self.delete_calls.append(keys)


# заготовка ссылки для тестов
def make_link(**overrides):
    now = datetime.now(UTC)
    payload = {
        'short_code': 'abc123',
        'original_url': 'https://example.com',
        'custom_alias': None,
        'created_at': now,
        'updated_at': now,
        'expires_at': None,
        'click_count': 0,
        'last_accessed_at': None,
        'is_active': True,
        'deactivated_reason': None,
        'deactivated_at': None,
        'owner_id': None,
    }
    payload.update(overrides)
    return main.Link(**payload)


# заготовка пользователя для тестов
def make_user(**overrides):
    payload = {
        'username': 'student',
        'email': 'student@example.com',
        'hashed_password': main.get_password_hash('strongpass'),
    }
    payload.update(overrides)
    return main.User(**payload)


def test_get_env_int_returns_default_for_invalid_value(monkeypatch):
    monkeypatch.setenv('BROKEN_INT', 'abc')
    assert main.get_env_int('BROKEN_INT', 7) == 7


def test_password_hash_and_token_helpers_roundtrip():
    hashed = main.get_password_hash('strongpass')
    assert hashed != 'strongpass'
    assert main.verify_password('strongpass', hashed) is True
    assert main.verify_password('wrongpass', hashed) is False

    token = main.create_access_token(42)
    payload = main.decode_access_token(token)
    assert payload['sub'] == '42'


def test_get_optional_current_user_handles_missing_invalid_and_deleted_user(db_session, monkeypatch):
    # без токена пользователя нет
    assert main.get_optional_current_user(db_session, None) is None

    # плохой токен даёт 401
    with pytest.raises(HTTPException) as invalid_token_exc:
        main.get_optional_current_user(db_session, 'bad-token')
    assert invalid_token_exc.value.status_code == 401

    # токен без sub тоже даёт 401
    monkeypatch.setattr(main, 'decode_access_token', lambda token: {})
    with pytest.raises(HTTPException) as missing_sub_exc:
        main.get_optional_current_user(db_session, 'token')
    assert missing_sub_exc.value.status_code == 401

    # если пользователя нет в бд, тоже 401
    monkeypatch.setattr(main, 'decode_access_token', lambda token: {'sub': '999'})
    with pytest.raises(HTTPException) as missing_user_exc:
        main.get_optional_current_user(db_session, 'token')
    assert missing_user_exc.value.status_code == 401


def test_get_current_user_requires_existing_user():
    with pytest.raises(HTTPException) as exc:
        main.get_current_user(None)
    assert exc.value.status_code == 401


def test_normalize_datetime_and_url_builders():
    naive = datetime(2024, 1, 1, 12, 0, 0)
    aware = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone(timedelta(hours=3)))

    assert main.normalize_datetime(None) is None
    assert main.normalize_datetime(naive).tzinfo == UTC
    assert main.normalize_datetime(aware).tzinfo == UTC
    assert main.build_short_url('code1') == 'http://testserver/links/code1'
    assert main.redirect_cache_key('x') == 'link:redirect:x'
    assert main.stats_cache_key('x') == 'link:stats:x'


def test_link_serializers_produce_public_models():
    link = make_link(owner_id=3, custom_alias='alias1')
    link_read = main.link_to_read(link)
    link_stats = main.link_to_stats(link)

    assert link_read.short_code == 'abc123'
    assert link_read.owner_id == 3
    assert link_stats.short_url.endswith('/abc123')


def test_generate_short_code_returns_first_free_candidate(db_session, monkeypatch):
    existing = make_link(short_code='aaaaaa')
    db_session.add(existing)
    db_session.commit()

    choices = iter(list('aaaaaabbbbbb'))
    monkeypatch.setattr(main.secrets, 'choice', lambda alphabet: next(choices))

    assert main.generate_short_code(db_session) == 'bbbbbb'


def test_generate_short_code_raises_after_too_many_collisions(db_session, monkeypatch):
    db_session.add(make_link(short_code='aaaaaa'))
    db_session.commit()
    monkeypatch.setattr(main.secrets, 'choice', lambda alphabet: 'a')

    with pytest.raises(HTTPException) as exc:
        main.generate_short_code(db_session)
    assert exc.value.status_code == 500


# проверяем защиту от конфликтов и missing deleted ссылок
def test_short_code_and_link_lookup_guards(db_session):
    db_session.add(make_link(short_code='taken1'))
    db_session.add(make_link(short_code='gone01', deactivated_reason='deleted'))
    db_session.commit()

    with pytest.raises(HTTPException) as conflict_exc:
        main.ensure_short_code_is_free(db_session, 'taken1')
    assert conflict_exc.value.status_code == 409

    assert main.get_link_or_404(db_session, 'taken1').short_code == 'taken1'

    with pytest.raises(HTTPException) as missing_exc:
        main.get_link_or_404(db_session, 'unknown')
    assert missing_exc.value.status_code == 404

    with pytest.raises(HTTPException) as deleted_exc:
        main.get_link_or_404(db_session, 'gone01')
    assert deleted_exc.value.status_code == 404


def test_ensure_link_is_accessible_handles_expired_and_inactive(db_session, monkeypatch):
    # истёкшая ссылка должна деактивироваться
    delete_cache = Mock()
    monkeypatch.setattr(main, 'cache_delete', delete_cache)

    expired = make_link(short_code='exp123', expires_at=datetime.now(UTC) - timedelta(minutes=1))
    db_session.add(expired)
    db_session.commit()

    with pytest.raises(HTTPException) as expired_exc:
        main.ensure_link_is_accessible(db_session, expired, allow_expired=False)
    assert expired_exc.value.status_code == 410

    db_session.refresh(expired)
    assert expired.deactivated_reason == 'expired'

    accessible_expired = make_link(short_code='exp124', expires_at=datetime.now(UTC) - timedelta(minutes=1))
    db_session.add(accessible_expired)
    db_session.commit()
    assert main.ensure_link_is_accessible(db_session, accessible_expired, allow_expired=True).short_code == 'exp124'

    inactive = make_link(short_code='idle01', is_active=False, deactivated_reason='inactive')
    with pytest.raises(HTTPException) as inactive_exc:
        main.ensure_link_is_accessible(db_session, inactive, allow_expired=False)
    assert inactive_exc.value.status_code == 404

    delete_cache.assert_called()


def test_ensure_link_belongs_to_user_checks_owner():
    # проверяем владельца ссылки
    owner = make_user(id=1)
    stranger = make_user(id=2, username='mentor', email='mentor@example.com')

    with pytest.raises(HTTPException) as anonymous_exc:
        main.ensure_link_belongs_to_user(make_link(owner_id=None), owner)
    assert anonymous_exc.value.status_code == 403

    with pytest.raises(HTTPException) as forbidden_exc:
        main.ensure_link_belongs_to_user(make_link(owner_id=1), stranger)
    assert forbidden_exc.value.status_code == 403

    assert main.ensure_link_belongs_to_user(make_link(owner_id=1), owner) is None


def test_register_click_and_cleanup_links_update_state(db_session, monkeypatch):
    delete_cache = Mock()
    monkeypatch.setattr(main, 'cache_delete', delete_cache)

    clicked = make_link(short_code='click1')
    expired = make_link(short_code='exp001', expires_at=datetime.now(UTC) - timedelta(days=1))
    inactive = make_link(
        short_code='idle02',
        last_accessed_at=datetime.now(UTC) - timedelta(days=main.INACTIVE_LINK_DAYS + 1),
    )
    db_session.add_all([clicked, expired, inactive])
    db_session.commit()

    main.register_click(db_session, clicked)
    db_session.refresh(clicked)
    assert clicked.click_count == 1
    assert clicked.last_accessed_at is not None

    result = main.cleanup_links(db_session)
    db_session.refresh(expired)
    db_session.refresh(inactive)
    assert result.expired_links_marked == 1
    assert result.inactive_links_marked == 1
    assert expired.deactivated_reason == 'expired'
    assert inactive.deactivated_reason == 'inactive'


def test_cache_helpers_work_with_fake_redis(monkeypatch):
    fake = FakeRedis(value='{"answer": 42}')
    monkeypatch.setattr(main, 'get_redis', lambda: fake)

    assert main.cache_get_json('demo') == {'answer': 42}
    main.cache_set_json('demo', {'answer': 42}, ttl_seconds=60)
    main.cache_delete('demo', 'other')

    assert fake.set_calls == [('demo', '{"answer": 42}', 60)]
    assert fake.delete_calls == [('demo', 'other')]


def test_cache_helpers_swallow_redis_errors(monkeypatch):
    fake = FakeRedis(should_fail=True)
    monkeypatch.setattr(main, 'get_redis', lambda: fake)

    assert main.cache_get_json('demo') is None
    assert main.cache_set_json('demo', {'answer': 42}) is None
    assert main.cache_delete('demo') is None


def test_get_redis_uses_cached_client_and_handles_connection_error(monkeypatch):
    # сначала используем кешированный клиент
    monkeypatch.setattr(main, 'get_redis', ORIGINAL_GET_REDIS)
    sentinel = object()
    main.redis_client = sentinel
    assert main.get_redis() is sentinel

    # потом проверяем ошибку подключения
    main.redis_client = None

    class DummyRedis:
        def ping(self):
            raise RedisError('offline')

    monkeypatch.setattr(main.Redis, 'from_url', lambda *args, **kwargs: DummyRedis())
    assert main.get_redis() is None


def test_decode_access_token_raises_for_invalid_token():
    with pytest.raises(JWTError):
        main.decode_access_token('not-a-real-token')


# простая проверка root-ручки
def test_read_root():
    payload = main.read_root()
    assert payload['docs'] == '/docs'
