import json
import os
import secrets
import string
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, EmailStr, Field, HttpUrl
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker


def get_env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


APP_NAME = os.getenv('APP_NAME', 'Applied Python. Link Shortener')
APP_BASE_URL = os.getenv('APP_BASE_URL', 'http://127.0.0.1:8000')
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///./study_shortener.sqlite3')
REDIS_URL = os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/0')
SECRET_KEY = os.getenv('SECRET_KEY', 'zaglushka')
ACCESS_TOKEN_EXPIRE_MINUTES = get_env_int('ACCESS_TOKEN_EXPIRE_MINUTES', 60)
DEFAULT_SHORT_CODE_LENGTH = get_env_int('DEFAULT_SHORT_CODE_LENGTH', 6)
INACTIVE_LINK_DAYS = get_env_int('INACTIVE_LINK_DAYS', 30)



class Base(DeclarativeBase):
    pass


connect_args = {'check_same_thread': False}
engine = create_engine(DATABASE_URL, future=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, class_=Session)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


DbSession = Annotated[Session, Depends(get_db)]


class User(Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=lambda: datetime.now(UTC))
    links = relationship('Link', back_populates='owner')


class Link(Base):
    __tablename__ = 'links'

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    short_code: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    original_url: Mapped[str] = mapped_column(Text())
    custom_alias: Mapped[str | None] = mapped_column(String(50), unique=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC),onupdate=lambda: datetime.now(UTC))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    click_count: Mapped[int] = mapped_column(Integer, default=0)
    last_accessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    deactivated_reason: Mapped[str | None] = mapped_column(String(30), nullable=True)
    deactivated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey('users.id'), nullable=True)
    owner = relationship('User', back_populates='links')



# схемы для валидации данных
class UserCreate(BaseModel):

    username: str = Field(min_length=5, max_length=50)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)


class UserRead(BaseModel):
    id: int
    username: str
    email: EmailStr
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = 'bearer'


class LinkCreate(BaseModel):
    original_url: HttpUrl
    custom_alias: str | None = Field(default=None, min_length=3, max_length=50)
    expires_at: datetime | None = None


class LinkUpdate(BaseModel):
    original_url: HttpUrl


class LinkRead(BaseModel):
    short_code: str
    short_url: str
    original_url: str
    custom_alias: str | None
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None
    click_count: int
    last_accessed_at: datetime | None
    is_active: bool
    owner_id: int | None


class LinkStats(BaseModel):
    short_code: str
    short_url: str
    original_url: str
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None
    click_count: int
    last_accessed_at: datetime | None
    owner_id: int | None


class LinkSearchResponse(BaseModel):
    original_url: str
    results: list[LinkRead]


class CleanupResult(BaseModel):
    expired_links_marked: int
    inactive_links_marked: int


# хеширование для безоппасности паролей
pwd_context = CryptContext(schemes=['pbkdf2_sha256'], deprecated='auto')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/login', auto_error=False)
JWT_ALGORITHM = 'HS256'


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# jwt токен 
def create_access_token(user_id: int) -> str:
    expire_at = datetime.now(UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {'sub': str(user_id), 'exp': expire_at}
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)



def decode_access_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])


def get_optional_current_user(db: DbSession, token: Annotated[str | None, Depends(oauth2_scheme)]) -> User | None:
    if not token:
        return None

    try:
        payload = decode_access_token(token)
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Неверный токен авторизации') from exc

    user_id = payload.get('sub')
    if user_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='В токене нет id пользователя')

    user = db.get(User, int(user_id))
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Пользователь из токена не найден')
    return user


def get_current_user(user: Annotated[User | None, Depends(get_optional_current_user)]) -> User:
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Для этого действия нужна авторизация')
    return user





# кэширование через рэдис
redis_client: Redis | None = None


def get_redis() -> Redis | None:
    global redis_client

    if redis_client is not None:
        return redis_client

    try:
        redis_client = Redis.from_url(REDIS_URL, decode_responses=True)
        redis_client.ping()
    except RedisError:
        redis_client = None

    return redis_client


def cache_get_json(key: str) -> dict[str, Any] | None:
    client = get_redis()
    if client is None:
        return None
    try:
        value = client.get(key)
    except RedisError:
        return None
    if value is None:
        return None
    return json.loads(value)


def cache_set_json(key: str, value: dict[str, Any], ttl_seconds: int = 300) -> None:
    client = get_redis()
    if client is None:
        return
    try:
        client.set(key, json.dumps(value, default=str), ex=ttl_seconds)
    except RedisError:
        return


def cache_delete(*keys: str) -> None:
    client = get_redis()
    if client is None or not keys:
        return
    try:
        client.delete(*keys)
    except RedisError:
        return


def redirect_cache_key(short_code: str) -> str:
    return f'link:redirect:{short_code}'


def stats_cache_key(short_code: str) -> str:
    return f'link:stats:{short_code}'


# нормализация дат
def normalize_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def build_short_url(short_code: str) -> str:
    return f'{APP_BASE_URL}/links/{short_code}'


# из алхимии в апи
def link_to_read(link: Link) -> LinkRead:
    return LinkRead(
        short_code=link.short_code,
        short_url=build_short_url(link.short_code),
        original_url=link.original_url,
        custom_alias=link.custom_alias,
        created_at=link.created_at,
        updated_at=link.updated_at,
        expires_at=link.expires_at,
        click_count=link.click_count,
        last_accessed_at=link.last_accessed_at,
        is_active=link.is_active,
        owner_id=link.owner_id)


def link_to_stats(link: Link) -> LinkStats:
    return LinkStats(
        short_code=link.short_code,
        short_url=build_short_url(link.short_code),
        original_url=link.original_url,
        created_at=link.created_at,
        updated_at=link.updated_at,
        expires_at=link.expires_at,
        click_count=link.click_count,
        last_accessed_at=link.last_accessed_at,
        owner_id=link.owner_id)



# если юзер не указал свой алиас
def generate_short_code(db: Session) -> str:
    alphabet = string.ascii_letters + string.digits

    for _ in range(20):
        candidate = ''.join(secrets.choice(alphabet) for _ in range(DEFAULT_SHORT_CODE_LENGTH))

        existing_link = db.scalar(select(Link).where(Link.short_code == candidate))

        if existing_link is None:
            return candidate

    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Не удалось сгенерировать уникальный короткий код')


def ensure_short_code_is_free(db: Session, short_code: str) -> None:
    existing_link = db.scalar(select(Link).where(Link.short_code == short_code))
    if existing_link is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Данная ссылка уже занята, попрбуйте другую')


def get_link_or_404(db: Session, short_code: str) -> Link:
    link = db.scalar(select(Link).where(Link.short_code == short_code))
    if link is None or link.deactivated_reason == 'deleted':
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Короткая ссылка не найдена')
    return link


def ensure_link_is_accessible(db: Session, link: Link, allow_expired: bool) -> Link:
    now = datetime.now(UTC)
    expires_at = normalize_datetime(link.expires_at)

    if expires_at and expires_at <= now:
        link.is_active = False
        link.deactivated_reason = 'expired'
        link.deactivated_at = now
        link.expires_at = expires_at
        db.commit()
        cache_delete(redirect_cache_key(link.short_code), stats_cache_key(link.short_code))

        if not allow_expired:
            raise HTTPException(status_code=status.HTTP_410_GONE, detail='Срок жизни ссылки истёк')

    if not link.is_active and link.deactivated_reason == 'inactive':
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Ссылка отключена из-за неиспользования')

    if not link.is_active and link.deactivated_reason == 'expired' and not allow_expired:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail='Срок жизни ссылки истёк')

    return link



def ensure_link_belongs_to_user(link: Link, current_user: User) -> None:
    if link.owner_id is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Эта ссылка создана анонимно и не может изменяться')

    if link.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Можно управлять только своими ссылками')


def register_click(db: Session, link: Link) -> None:
    link.click_count += 1
    link.last_accessed_at = datetime.now(UTC)
    db.commit()
    db.refresh(link)
    cache_delete(stats_cache_key(link.short_code))


def cleanup_links(db: Session) -> CleanupResult:

    now = datetime.now(UTC)
    inactivity_border = now - timedelta(days=INACTIVE_LINK_DAYS)

    expired_links = db.scalars(
        select(Link).where(
            Link.is_active.is_(True),
            Link.expires_at.is_not(None),
            Link.expires_at <= now,
                        )).all()

    for link in expired_links:
        link.is_active = False
        link.deactivated_reason = 'expired'
        link.deactivated_at = now

        cache_delete(redirect_cache_key(link.short_code), stats_cache_key(link.short_code))

    inactive_links = db.scalars(
        select(Link).where(
            Link.is_active.is_(True),
            Link.expires_at.is_(None),
            Link.last_accessed_at.is_not(None),
            Link.last_accessed_at <= inactivity_border,
        )).all()

    for link in inactive_links:
        link.is_active = False
        link.deactivated_reason = 'inactive'
        link.deactivated_at = now
        cache_delete(redirect_cache_key(link.short_code), stats_cache_key(link.short_code))

    db.commit()

    return CleanupResult(expired_links_marked=len(expired_links), inactive_links_marked=len(inactive_links))



@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        cleanup_links(db)
    yield


app = FastAPI(
    title=APP_NAME,
    description='Прикладной python. Проект по сокращению ссылок с авторизацией и статистикой',
    version='1.0.0',
    lifespan=lifespan
    )

@app.post('/auth/register', response_model=UserRead, status_code=status.HTTP_201_CREATED, tags=['auth'], summary='Регистрация нового пользователя', description='Создание нового пользователя с переданными именем, email и паролем')
def register_user(payload: UserCreate, db: DbSession) -> User:
    existing_user = db.scalar(select(User).where(User.username == payload.username))

    if existing_user is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Имя пользователя занято')

    existing_email = db.scalar(select(User).where(User.email == payload.email))

    if existing_email is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='email уже зарегистрирован')

    user = User(username=payload.username, email=payload.email, hashed_password=get_password_hash(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post('/auth/login', response_model=TokenResponse, tags=['auth'], summary='Авторизация пользователя', description='Получение JWT токена для авторизации в системе по логину и паролю')
def login_user(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: DbSession) -> TokenResponse:
    user = db.scalar(select(User).where(User.username == form_data.username))

    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Неверное имя пользователя или пароль')

    token = create_access_token(user.id)
    return TokenResponse(access_token=token)


@app.get('/auth/me', response_model=UserRead, tags=['auth'], summary='Получение информации о текущем пользователе', description='Возврат информации о залогиненном пользователе')
def get_me(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    return current_user



@app.post('/links/shorten', response_model=LinkRead, status_code=status.HTTP_201_CREATED,
           tags=['links'],
           summary='Создать короткую ссылку', 
           description='Создаёт короткую ссылку для переданного URL. Если указать custom_alias и он будет свободен, то он будет использоваться в качестве короткого урла. Указание expires_at задаст срок жизни ссылки')
def create_short_link( payload: LinkCreate, db: DbSession, current_user: Annotated[User | None, Depends(get_optional_current_user)]) -> LinkRead:
    expires_at = normalize_datetime(payload.expires_at)

    if expires_at and expires_at <= datetime.now(UTC):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='дата истечения работы ссылки')

    short_code = payload.custom_alias or generate_short_code(db)
    ensure_short_code_is_free(db, short_code)

    link = Link(
        short_code=short_code,
        original_url=str(payload.original_url),
        custom_alias=payload.custom_alias,
        expires_at=expires_at,
        owner_id=current_user.id if current_user else None
        )


    db.add(link)
    db.commit()
    db.refresh(link)

    return link_to_read(link)


@app.get('/links/search', response_model=LinkSearchResponse, tags=['links'], summary='Поиск ссылок по оригинальному URL', description='Поиск всех активных ссылок для переданного оригинального URL')
def search_links(original_url: Annotated[str, Query(..., min_length=5)], db: DbSession) -> LinkSearchResponse:
    links = db.scalars(select(Link).where(Link.original_url == original_url, Link.is_active.is_(True))).all()

    return LinkSearchResponse(original_url=original_url, results=[link_to_read(link) for link in links])


@app.get('/links/expired-history', response_model=list[LinkRead], tags=['links'], summary='История истекших ссылок', description='Получение списка всех истекших ссылок')
def expired_history(db: DbSession) -> list[LinkRead]:
    links = db.scalars(select(Link).where(Link.deactivated_reason == 'expired').order_by(Link.deactivated_at.desc())).all()

    return [link_to_read(link) for link in links]


@app.get('/links/{short_code}/stats', response_model=LinkStats, tags=['links'], summary='Статистика по ссылке', description='Количество кликов, дата последнего доступа, срок жизни и тд')
def get_link_stats(short_code: str, db: DbSession) -> LinkStats:
    cached_stats = cache_get_json(stats_cache_key(short_code))

    if cached_stats is not None:
        return LinkStats(**cached_stats)

    link = get_link_or_404(db, short_code)
    link = ensure_link_is_accessible(db, link, allow_expired=True)
    stats = link_to_stats(link)

    cache_set_json(stats_cache_key(short_code), stats.model_dump(mode='json'))
    return stats


@app.get('/links/{short_code}', tags=['links'], summary='Переход по короткой ссылке', description='Редирект на оригинальный URL или на страницу ошибки (если ссылка истекла)')
def redirect_short_link(short_code: str, db: DbSession) -> RedirectResponse:
    cached_redirect = cache_get_json(redirect_cache_key(short_code))
    if cached_redirect is not None:
        expires_at = cached_redirect.get('expires_at')
        if expires_at is None or datetime.fromisoformat(expires_at) > datetime.now(UTC):
            link = get_link_or_404(db, short_code)
            link = ensure_link_is_accessible(db, link, allow_expired=False)
            register_click(db, link)
            return RedirectResponse(url=cached_redirect['original_url'], status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    link = get_link_or_404(db, short_code)
    link = ensure_link_is_accessible(db, link, allow_expired=False)

    cache_set_json(
        redirect_cache_key(short_code),
        {
            'original_url': link.original_url,
            'expires_at': link.expires_at.isoformat() if link.expires_at else None,
        },
    )

    register_click(db, link)
    return RedirectResponse(url=link.original_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@app.put('/links/{short_code}', response_model=LinkRead, tags=['links'], summary='Обновление оригинальной ссылки по короткой ссылке', description='Позволяет переименовать оригинальную ссылку для существующей короткой ссылки')
def update_link(
    short_code: str,
    payload: LinkUpdate,
    db: DbSession,
    current_user: Annotated[User, Depends(get_current_user)],
) -> LinkRead:
    link = get_link_or_404(db, short_code)
    ensure_link_belongs_to_user(link, current_user)

    link.original_url = str(payload.original_url)
    link.updated_at = datetime.now(UTC)
    db.commit()
    db.refresh(link)

    cache_delete(redirect_cache_key(short_code), stats_cache_key(short_code))
    return link_to_read(link)


@app.delete('/links/{short_code}', status_code=status.HTTP_204_NO_CONTENT, tags=['links'], summary='Удаление ссылки', description='Удаляет указанную короткую ссылку')
def delete_link(
    short_code: str,
    db: DbSession,
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    link = get_link_or_404(db, short_code)
    ensure_link_belongs_to_user(link, current_user)

    link.is_active = False
    link.deactivated_reason = 'deleted'
    link.deactivated_at = datetime.now(UTC)
    db.commit()

    cache_delete(redirect_cache_key(short_code), stats_cache_key(short_code))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ручная очистка 
@app.post('/maintenance/cleanup', response_model=CleanupResult, tags=['maintenance'], summary='Очистка устаревших ссылок', description='Удаляет все истекшие ссылки')
def run_cleanup(db: DbSession) -> CleanupResult:
    return cleanup_links(db)


@app.get('/', tags=['root'], summary='Проверка работоспособности сервиса')
def read_root() -> dict[str, str]:
    return {
        'message': 'Сервис сокращения ссылок работает!',
        'docs': '/docs',
    }
