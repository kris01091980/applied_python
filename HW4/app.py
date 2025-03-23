import os
import logging
import random
import string
import time
from datetime import datetime, timedelta
from threading import Lock
from typing import Optional

import jwt
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey, func
from sqlalchemy.orm import sessionmaker, relationship, declarative_base, Session
from apscheduler.schedulers.background import BackgroundScheduler

# =========================
# Логирование и настройки
# =========================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =========================
# Конфигурация БД (SQLite для простоты)
# =========================
DATABASE_URL = os.getenv("DATABASE_URI", "sqlite:///./links.db")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# =========================
# Кэширование в RAM (простой in-memory cache)
# =========================
cache_data = {}
cache_lock = Lock()


def set_cache(key: str, value, ttl: int):
    expire_at = time.time() + ttl
    with cache_lock:
        cache_data[key] = (value, expire_at)


def get_cache(key: str):
    with cache_lock:
        entry = cache_data.get(key)
        if entry:
            value, expire_at = entry
            if time.time() < expire_at:
                return value
            else:
                del cache_data[key]
        return None


def delete_cache(key: str):
    with cache_lock:
        if key in cache_data:
            del cache_data[key]


# =========================
# Модели SQLAlchemy
# =========================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    password_hash = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    def set_password(self, password: str):
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.password_hash = pwd_context.hash(password)

    def check_password(self, password: str) -> bool:
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        return pwd_context.verify(password, self.password_hash)


class Link(Base):
    __tablename__ = "links"
    id = Column(Integer, primary_key=True, index=True)
    original_url = Column(Text, nullable=False)
    short_code = Column(String(20), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Если None — аноним
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    visit_count = Column(Integer, default=0)
    project = Column(String(100), nullable=True)  # Дополнительное поле для группировки

    user = relationship("User", backref="links")

    @property
    def creator(self):
        return self.user.username if self.user else "Anonymous"


# =========================
# Pydantic модели
# =========================
class UserCreate(BaseModel):
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class LinkCreate(BaseModel):
    original_url: str
    custom_alias: Optional[str] = None  # Если задан, проверяется уникальность
    expires_at: Optional[str] = None  # Формат "YYYY-MM-DD HH:MM"
    project: Optional[str] = None  # Для группировки ссылок


class LinkUpdate(BaseModel):
    original_url: str


class LinkStats(BaseModel):
    original_url: str
    created_at: str
    expires_at: Optional[str]
    last_used_at: Optional[str]
    visit_count: int
    created_by: str


# =========================
# JWT-конфигурация
# =========================
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# =========================
# Зависимости: получение сессии и текущего пользователя
# =========================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401, detail="Could not validate credentials"
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = db.query(User).get(int(user_id))
    if user is None:
        raise credentials_exception
    return user


# =========================
# Инициализация FastAPI
# =========================
app = FastAPI(
    title="Link Shortener API",
    description=(
        "API-сервис для сокращения ссылок. "
        "POST и GET эндпоинты доступны всем, а PUT и DELETE – только для зарегистрированных пользователей, "
        "создавших ссылку."
    ),
    version="1.0.0"
)


# =========================
# Эндпоинты аутентификации
# =========================
@app.post("/auth/register", status_code=201, summary="Регистрация пользователя")
def register(user_create: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user_create.username).first():
        raise HTTPException(status_code=400, detail="User already exists")
    user = User(username=user_create.username)
    user.set_password(user_create.password)
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info(f"User registered: {user.username}")
    return {"message": "User registered successfully"}


@app.post("/auth/login", summary="Логин пользователя")
def login(user_login: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_login.username).first()
    if not user or not user.check_password(user_login.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    logger.info(f"User logged in: {user.username}")
    return {"access_token": access_token}


# =========================
# Эндпоинты работы со ссылками (обязательные функции)
# =========================
def generate_short_code(length: int = 6) -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


# Создание ссылки (доступно всем)
@app.post("/links/shorten", status_code=201, summary="Создание короткой ссылки")
def shorten_link(link_create: LinkCreate, db: Session = Depends(get_db), token: Optional[str] = None):
    user_id = None
    # Если токен передан, пробуем получить пользователя
    if token:
        try:
            user = get_current_user(token, db)
            user_id = user.id
        except Exception:
            logger.warning("Invalid or missing token; proceeding as anonymous.")
    # Проверяем кастомный alias, если он задан
    if link_create.custom_alias:
        if db.query(Link).filter(Link.short_code == link_create.custom_alias).first():
            raise HTTPException(status_code=400, detail="Custom alias already exists")
        short_code = link_create.custom_alias
    else:
        short_code = generate_short_code()
        while db.query(Link).filter(Link.short_code == short_code).first() is not None:
            short_code = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    expires_at = None
    if link_create.expires_at:
        try:
            expires_at = datetime.strptime(link_create.expires_at, "%Y-%m-%d %H:%M")
        except ValueError:
            raise HTTPException(status_code=400, detail="expires_at must be in format YYYY-MM-DD HH:MM")
    link = Link(
        original_url=link_create.original_url,
        short_code=short_code,
        user_id=user_id,
        expires_at=expires_at,
        project=link_create.project
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    logger.info(f"Link created: {short_code} -> {link_create.original_url}")
    return {
        "short_code": link.short_code,
        "original_url": link.original_url,
        "created_by": link.creator
    }


# Редирект по короткому коду (доступно всем)
@app.get("/{short_code}", summary="Редирект по короткому коду")
def redirect_link(short_code: str, db: Session = Depends(get_db)):
    link = db.query(Link).filter(Link.short_code == short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    if link.expires_at and link.expires_at < datetime.utcnow():
        raise HTTPException(status_code=410, detail="Link has expired")
    link.visit_count += 1
    link.last_used_at = datetime.utcnow()
    db.commit()
    return RedirectResponse(url=link.original_url)


# Обновление ссылки (PUT) – только для создателя
@app.put("/links/{short_code}", summary="Обновление ссылки")
def update_link(short_code: str, link_update: LinkUpdate, db: Session = Depends(get_db),
                current_user: User = Depends(get_current_user)):
    link = db.query(Link).filter(Link.short_code == short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    if link.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this link")
    link.original_url = link_update.original_url
    db.commit()
    logger.info(f"Link updated: {short_code} by user {current_user.username}")
    return {"message": "Link updated successfully"}


# Удаление ссылки (DELETE) – только для создателя
@app.delete("/links/{short_code}", summary="Удаление ссылки")
def delete_link(short_code: str, db: Session = Depends(get_db),
                current_user: User = Depends(get_current_user)):
    link = db.query(Link).filter(Link.short_code == short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    if link.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this link")
    db.delete(link)
    db.commit()
    # Очищаем кэш статистики, если он есть
    delete_cache(f"link_stats:{short_code}")
    logger.info(f"Link deleted: {short_code} by user {current_user.username}")
    return {"message": "Link deleted successfully"}


# Получение статистики по ссылке (GET) – доступно всем (с кэшированием)
@app.get("/links/{short_code}/stats", response_model=LinkStats, summary="Получение статистики ссылки")
def get_link_stats(short_code: str, db: Session = Depends(get_db)):
    cache_key = f"link_stats:{short_code}"
    cached = get_cache(cache_key)
    if cached is not None:
        return cached
    link = db.query(Link).filter(Link.short_code == short_code).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    stats = {
        "original_url": link.original_url,
        "created_at": link.created_at.isoformat(),
        "expires_at": link.expires_at.isoformat() if link.expires_at else None,
        "last_used_at": link.last_used_at.isoformat() if link.last_used_at else None,
        "visit_count": link.visit_count,
        "created_by": link.creator
    }
    set_cache(cache_key, stats, 60)
    return stats


# Поиск ссылки по оригинальному URL (GET) – доступно всем
@app.get("/links/search", summary="Поиск ссылки по оригинальному URL")
def search_link(original_url: str = Query(..., description="Оригинальный URL для поиска"),
                db: Session = Depends(get_db)):
    link = db.query(Link).filter(Link.original_url == original_url).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    return {"short_code": link.short_code, "original_url": link.original_url}


# =========================
# Дополнительные функции
# =========================
# 1. Эндпоинт для получения истории истёкших ссылок (только для зарегистрированных пользователей)
@app.get("/links/expired", summary="Получение истории истёкших ссылок")
def get_expired_links(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    expired_links = db.query(Link).filter(Link.expires_at != None, Link.expires_at < datetime.utcnow()).all()
    return [
        {
            "short_code": link.short_code,
            "original_url": link.original_url,
            "expires_at": link.expires_at.isoformat() if link.expires_at else None,
            "created_at": link.created_at.isoformat(),
            "visit_count": link.visit_count,
            "created_by": link.creator
        }
        for link in expired_links
    ]


# 2. Эндпоинт для группировки ссылок по проектам (доступно всем)
@app.get("/links/grouped", summary="Группировка ссылок по проектам")
def group_links_by_project(db: Session = Depends(get_db)):
    groups = db.query(Link.project, func.count(Link.id)).group_by(Link.project).all()
    # Если поле project не заполнено, группируем под "No Project"
    return {group[0] if group[0] else "No Project": group[1] for group in groups}


# Фоновая задача: удаление истёкших ссылок и ссылок, не использованных более UNUSED_LINKS_DAYS
UNUSED_LINKS_DAYS = int(os.getenv("UNUSED_LINKS_DAYS", 30))


def delete_expired_and_unused_links():
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        expired = db.query(Link).filter(Link.expires_at != None, Link.expires_at < now).all()
        threshold = now - timedelta(days=UNUSED_LINKS_DAYS)
        unused = db.query(Link).filter(
            ((Link.last_used_at == None) & (Link.created_at < threshold)) |
            ((Link.last_used_at != None) & (Link.last_used_at < threshold))
        ).all()
        to_delete = set(expired + unused)
        count = len(to_delete)
        for link in to_delete:
            db.delete(link)
            delete_cache(f"link_stats:{link.short_code}")
        db.commit()
        logger.info(f"Deleted {count} expired/unused links.")
    except Exception as e:
        logger.error(f"Error during deletion: {e}")
    finally:
        db.close()


scheduler = BackgroundScheduler()
scheduler.add_job(delete_expired_and_unused_links, 'interval', seconds=60)
scheduler.start()


# =========================
# Событие запуска: создание таблиц в БД
# =========================
@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created.")


# =========================
# Запуск приложения
# =========================
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
