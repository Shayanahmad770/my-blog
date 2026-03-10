import sqlite3
import os
import re
import uuid
import secrets
import logging
import smtplib
from supabase import create_client
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, g, abort, flash, jsonify)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import requests
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from PIL import Image, UnidentifiedImageError
from flask_caching import Cache
from flask_wtf.csrf import CSRFProtect 
# Add these imports
import sys
from pathlib import Path

# ─── Bootstrap ────────────────────────────────────────────────────
load_dotenv()

app = Flask(__name__)

# CSRF — every POST form in templates must include {{ csrf_token() }}
csrf = CSRFProtect(app)

# ─── Cache ────────────────────────────────────────────────────────
# NOTE: 'simple' is single-process only. For multiple workers / horizontal
# scaling switch to Redis: CACHE_TYPE='redis', CACHE_REDIS_URL=...
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

# ─── Rate Limiter ─────────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# ─── Secret Key ───────────────────────────────────────────────────
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    if os.environ.get('FLASK_ENV') == 'production':
        raise RuntimeError(
            "SECRET_KEY must be set in production via environment variable.\n"
            "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
        )
    app.secret_key = os.urandom(24).hex()
    logging.warning("SECRET_KEY not set — random key used (sessions lost on restart)")
    
    # Also warn in production-like environments
    if os.environ.get('RENDER') or os.environ.get('HEROKU'):
        logging.warning("Running on cloud platform without SECRET_KEY - set it for session persistence!")

# ─── Paths ────────────────────────────────────────────────────────
basedir = os.path.abspath(os.path.dirname(__file__))

# IMPORTANT: On ephemeral filesystems (Heroku/Render free tier) images are lost
# on restart. Mount a persistent disk or use cloud storage (e.g. AWS S3).
app.config['UPLOAD_FOLDER'] = os.environ.get(
    'UPLOAD_FOLDER', os.path.join(basedir, 'static', 'images')
)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB; also enforce at Nginx level

# ─── Session / Cookie Security ────────────────────────────────────
app.config['SESSION_COOKIE_SECURE']      = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY']    = True
app.config['SESSION_COOKIE_SAMESITE']   = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Warn if in production and secure cookie not enabled
if os.environ.get('FLASK_ENV') == 'production' and not app.config['SESSION_COOKIE_SECURE']:
    logging.warning("SESSION_COOKIE_SECURE is False in production. Set it to True to enforce HTTPS.")

# ─── Image Processing Config ──────────────────────────────────────
IMAGE_MAX_WIDTH  = int(os.environ.get('IMAGE_MAX_WIDTH',  1200))
IMAGE_MAX_HEIGHT = int(os.environ.get('IMAGE_MAX_HEIGHT', 1200))
IMAGE_QUALITY    = int(os.environ.get('IMAGE_QUALITY',    85))   # JPEG/WebP quality 1-95

# ─── Logging ──────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

# ─── Upload Allow-Lists ───────────────────────────────────────────
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
# SVG deliberately excluded — requires separate sanitisation to prevent XSS.
ALLOWED_MIME_TYPES = {'image/png', 'image/jpeg', 'image/gif', 'image/webp'}

# ─── Database Configuration ───────────────────────────────────────
# Make database_path available globally
database_path = None  # Initialize variable

if os.environ.get('DATABASE_URL'):
    DATABASE_URL = os.environ['DATABASE_URL']
    if DATABASE_URL.startswith('postgres://'):
        DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

    # Ensure SSL mode is set for Supabase
    if 'supabase.co' in DATABASE_URL and 'sslmode' not in DATABASE_URL:
        if '?' in DATABASE_URL:
            DATABASE_URL += '&sslmode=require'
        else:
            DATABASE_URL += '?sslmode=require'

    import psycopg2
    from psycopg2 import pool
    from urllib.parse import urlparse

    _db_url     = urlparse(DATABASE_URL)
    PG_USER     = _db_url.username
    PG_PASSWORD = _db_url.password
    PG_HOST     = _db_url.hostname
    PG_PORT     = _db_url.port or 5432
    PG_DATABASE = _db_url.path[1:]

    def get_pg_connection():
        return psycopg2.connect(
            user=PG_USER, 
            password=PG_PASSWORD, 
            host=PG_HOST,
            port=PG_PORT, 
            database=PG_DATABASE,
            sslmode='require'
        )

    # Create connection pool
    app.config['POSTGRESQL_POOL'] = psycopg2.pool.SimpleConnectionPool(
        1, 5,  # min connections, max connections
        user=PG_USER, 
        password=PG_PASSWORD, 
        host=PG_HOST,
        port=PG_PORT, 
        database=PG_DATABASE,
        sslmode='require'
    )
    app.config['USING_POSTGRESQL'] = True
    logger.info("Using PostgreSQL via psycopg2")
# ... rest of your code (SQLite section) remains the same

# ─── Create Missing Directories and Template Files ─────────────────
def create_missing_directories():
    """Create necessary directories and template files if they don't exist."""
    # Create directories
    dirs_to_create = [
        os.path.join(basedir, 'templates', 'errors'),
        os.path.join(basedir, 'database', 'backups'),
        os.path.join(basedir, 'logs'),
    ]
    
    for dir_path in dirs_to_create:
        os.makedirs(dir_path, exist_ok=True)
        logger.debug(f"Ensured directory exists: {dir_path}")
    
    # Create error templates if they don't exist
    error_templates = {
        '404.html': '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <div class="error-container">
        <h1>404</h1>
        <h2>Page Not Found</h2>
        <p>The page you're looking for doesn't exist or has been moved.</p>
        <a href="{{ url_for('index') }}" class="btn">Go Home</a>
    </div>
</body>
</html>''',
        '500.html': '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>500 - Server Error</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <div class="error-container">
        <h1>500</h1>
        <h2>Internal Server Error</h2>
        <p>Something went wrong on our end. Please try again later.</p>
        <a href="{{ url_for('index') }}" class="btn">Go Home</a>
    </div>
</body>
</html>''',
        'forgot_password.html': '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <div class="auth-container">
        <h1>Forgot Password</h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" required>
            </div>
            <button type="submit" class="btn">Send Reset Link</button>
        </form>
        <p><a href="{{ url_for('login') }}">Back to Login</a></p>
    </div>
</body>
</html>''',
        'reset_password.html': '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <div class="auth-container">
        <h1>Reset Password</h1>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="form-group">
                <label for="new_password">New Password</label>
                <input type="password" id="new_password" name="new_password" required>
                <small>Minimum 8 characters with uppercase, lowercase, number, and special character</small>
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
            </div>
            <button type="submit" class="btn">Reset Password</button>
        </form>
    </div>
</body>
</html>'''
    }
    
    errors_dir = os.path.join(basedir, 'templates', 'errors')
    for filename, content in error_templates.items():
        if filename in ['404.html', '500.html']:
            filepath = os.path.join(errors_dir, filename)
        else:
            filepath = os.path.join(basedir, 'templates', filename)
        
        if not os.path.exists(filepath):
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                logger.info(f"Created placeholder template: {filename}")
            except Exception as e:
                logger.error(f"Failed to create template {filename}: {e}")

# Run directory creation
create_missing_directories()

# ═══════════════════════════════════════════════════════════════════
# CSP NONCE  (replaces 'unsafe-inline')
# ═══════════════════════════════════════════════════════════════════

@app.before_request
def generate_csp_nonce():
    """
    Generate a cryptographically secure nonce per request.
    Use it in templates to allow specific inline scripts/styles:
        <script nonce="{{ csp_nonce }}">...</script>
        <style  nonce="{{ csp_nonce }}">...</style>
    Only server-rendered tags carry the nonce; injected XSS payloads cannot
    know it, so the browser will block them.
    """
    g.csp_nonce = secrets.token_hex(16)


@app.context_processor
def inject_csp_nonce():
    """Expose csp_nonce to all Jinja2 templates as {{ csp_nonce }}."""
    return {'csp_nonce': getattr(g, 'csp_nonce', '')}


@app.context_processor
def inject_common_data():
    """Inject common data into all templates."""
    return {
        'now': datetime.utcnow(),
        'site_name': os.environ.get('SITE_NAME', 'My Blog'),
        'debug': app.debug,
        'static_version': int(datetime.utcnow().timestamp()) if app.debug else '1.0'  # For cache busting in dev
    }


# ─── Security Headers ─────────────────────────────────────────────

@app.after_request
def add_security_headers(response):
    nonce = getattr(g, 'csp_nonce', '')
    response.headers['X-Content-Type-Options']  = 'nosniff'
    response.headers['X-Frame-Options']         = 'SAMEORIGIN'
    response.headers['X-XSS-Protection']        = '1; mode=block'
    response.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
    # Nonce-based CSP — no more 'unsafe-inline'
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://code.jquery.com; "
        f"style-src  'self' 'nonce-{nonce}'; "
        f"img-src    'self' data:; "
        f"font-src   'self'; "
        f"object-src 'none';"
    )
    return response


# ═══════════════════════════════════════════════════════════════════
# GLOBAL ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found_error(_e):
    """Handle 404 errors with a custom template."""
    try:
        return render_template('errors/404.html'), 404
    except Exception as e:
        logger.error(f"Error rendering 404 template: {e}")
        # Fallback if template doesn't exist
        return "<h1>404 - Page Not Found</h1><p>The page you're looking for doesn't exist.</p>", 404


@app.errorhandler(500)
def internal_error(error):
    """Log exception server-side; show a safe page — no traceback leaks."""
    logger.exception("Unhandled 500 error: %s", error)
    db = getattr(g, '_database', None)
    if db is not None:
        try:
            db.rollback()
        except Exception:
            pass
    
    try:
        return render_template('errors/500.html'), 500
    except Exception as e:
        logger.error(f"Error rendering 500 template: {e}")
        # Fallback if template doesn't exist
        return "<h1>500 - Internal Server Error</h1><p>Something went wrong. Please try again later.</p>", 500


@app.errorhandler(413)
def request_entity_too_large(_e):
    flash('File too large. Maximum upload size is 16 MB.', 'error')
    return redirect(request.referrer or url_for('index')), 413


# ═══════════════════════════════════════════════════════════════════
# UTILITY HELPERS
# ═══════════════════════════════════════════════════════════════════

def get_client_ip():
    xff = request.headers.get('X-Forwarded-For')
    return xff.split(',')[0].strip() if xff else request.remote_addr


def get_count(result):
    """Extract integer COUNT from a SQLite Row (dict-like) or pg8000 tuple."""
    if result is None:
        return 0
    if isinstance(result, dict):
        return result.get('count', 0)
    return result[0] if result else 0


def allowed_file(filename: str, file_data=None) -> bool:
    """
    Three-layer upload validation:
      1. Extension allow-list.
      2. Declared MIME type — fast early rejection before stream is read.
      3. PIL deep verification — rejects corrupt or disguised non-images.
    """
    if '.' not in filename or filename.rsplit('.', 1)[1].lower() not in ALLOWED_EXTENSIONS:
        logger.warning("Upload rejected — bad extension: %s", filename)
        return False

    if file_data is None:
        return True

    content_type = getattr(file_data, 'content_type', None)
    if content_type and content_type not in ALLOWED_MIME_TYPES:
        logger.warning("Upload rejected — disallowed MIME %s: %s", content_type, filename)
        return False

    if not hasattr(file_data, 'stream'):
        logger.warning("Upload rejected — no stream on file_data: %s", filename)
        return False

    try:
        img = Image.open(file_data.stream)
        img.verify()
        file_data.stream.seek(0)
        return True
    except (UnidentifiedImageError, Exception) as exc:
        logger.warning("Upload rejected — PIL failed for %s: %s", filename, exc)
        return False


def process_and_save_image(file_data, dest_path: str) -> None:
    """
    Resize and optimise an image before writing to disk.

    • Resizes to fit within IMAGE_MAX_WIDTH x IMAGE_MAX_HEIGHT (aspect-ratio preserved).
    • Flattens RGBA/P transparency to white background for JPEG compatibility.
    • Saves at IMAGE_QUALITY to reduce file size without visible degradation.
    • GIFs are checked for dimensions and saved as-is if within limits, otherwise rejected.
    Raises ValueError if GIF dimensions exceed max, or OSError/PIL exceptions on failure.
    """
    file_data.stream.seek(0)
    ext = os.path.splitext(dest_path)[1].lower()

    # Open image to check dimensions (for both GIF and non-GIF)
    img = Image.open(file_data.stream)
    if img.width > IMAGE_MAX_WIDTH or img.height > IMAGE_MAX_HEIGHT:
        raise ValueError(f"Image dimensions {img.width}x{img.height} exceed limit {IMAGE_MAX_WIDTH}x{IMAGE_MAX_HEIGHT}")
    file_data.stream.seek(0)

    if ext == '.gif':
        # Write as-is after dimension check
        with open(dest_path, 'wb') as fh:
            fh.write(file_data.stream.read())
        return

    # Non-GIF: resize and optimise
    img.thumbnail((IMAGE_MAX_WIDTH, IMAGE_MAX_HEIGHT), Image.LANCZOS)

    if img.mode in ('RGBA', 'LA', 'P'):
        bg = Image.new('RGB', img.size, (255, 255, 255))
        if img.mode == 'P':
            img = img.convert('RGBA')
        mask = img.split()[-1] if img.mode in ('RGBA', 'LA') else None
        bg.paste(img, mask=mask)
        img = bg

    fmt         = 'JPEG' if ext in ('.jpg', '.jpeg') else 'PNG'
    save_kwargs = {}
    if fmt in ('JPEG', 'WEBP'):
        save_kwargs = {'quality': IMAGE_QUALITY, 'optimize': True, 'progressive': True}

    img.save(dest_path, format=fmt, **save_kwargs)
    logger.info("Image saved and optimised → %s", dest_path)


# ═══════════════════════════════════════════════════════════════════
# DATABASE COMPATIBILITY
# ═══════════════════════════════════════════════════════════════════

def format_query(query: str) -> str:
    """Convert %s placeholders to ? for SQLite."""
    if not app.config['USING_POSTGRESQL']:
        return query.replace('%s', '?')
    return query


def get_id_field() -> str:
    return "SERIAL PRIMARY KEY" if app.config['USING_POSTGRESQL'] else "INTEGER PRIMARY KEY AUTOINCREMENT"


def execute_query(query, params=None, fetchone=False, fetchall=False, commit=False):
    """
    Unified DB execution for SQLite and PostgreSQL.

    Callers must pass at least one of fetchone, fetchall, or commit=True.
    Omitting all three emits a WARNING and defaults to fetchall so nothing
    silently breaks — but fix the call site when you see that warning.
    """
    db = get_db()

    if not fetchone and not fetchall and not commit:
        logger.warning(
            "execute_query called without fetchone/fetchall/commit — defaulting to fetchall. "
            "Query prefix: %.120s", query.strip()
        )
        fetchall = True

    try:
        fq = format_query(query)

        if app.config['USING_POSTGRESQL']:
            cur = db.cursor()
            try:
                cur.execute(fq, params) if params else cur.execute(fq)
                if commit:
                    db.commit()
                    return None
                if fetchone:
                    result = cur.fetchone()
                else:
                    result = cur.fetchall()
                return result
            finally:
                cur.close()
        else:
            cur = db.execute(fq, params) if params else db.execute(fq)
            if commit:
                db.commit()
                return None
            return cur.fetchone() if fetchone else cur.fetchall()

    except Exception as exc:
        logger.error("DB error [%.120s]: %s", query.strip(), exc)
        if commit:
            try:
                db.rollback()
            except Exception:
                pass
        raise


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        if app.config['USING_POSTGRESQL']:
            # Get connection from pool (psycopg2 uses getconn(), not get())
            db = g._database = app.config['POSTGRESQL_POOL'].getconn()
        else:
            # Use the global database_path variable
            global database_path
            if database_path is None:
                # Fallback if database_path not set
                database_path = os.path.join(basedir, 'database', 'blog.db')
                os.makedirs(os.path.dirname(database_path), exist_ok=True)
                logger.warning(f"database_path was None, using fallback: {database_path}")
            db = g._database = sqlite3.connect(database_path)
            db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(_exc):
    db = getattr(g, '_database', None)
    if db is not None:
        if app.config['USING_POSTGRESQL']:
            # Return connection to pool (psycopg2 uses putconn(), not put())
            app.config['POSTGRESQL_POOL'].putconn(db)
        else:
            db.close()


# ═══════════════════════════════════════════════════════════════════
# DATABASE INITIALISATION
# ═══════════════════════════════════════════════════════════════════

def ensure_full_text_search():
    """Create full-text search indexes for better performance."""
    if app.config['USING_POSTGRESQL']:
        try:
            # Create tsvector columns for full-text search
            execute_query('''
                CREATE INDEX IF NOT EXISTS idx_posts_fts ON posts 
                USING GIN (to_tsvector('english', title || ' ' || coalesce(excerpt, '') || ' ' || content))
            ''', commit=True)
            logger.info("PostgreSQL full-text search index created/verified")
        except Exception as exc:
            logger.warning("Could not create full-text search index: %s", exc)
    else:
        # For SQLite, consider implementing FTS5 tables if needed
        logger.info("SQLite in use; full-text search not automatically created. Consider using FTS5 for large datasets.")


def init_db():
    """Create all tables, indexes, and the default admin account if absent."""
    with app.app_context():
        id_field   = get_id_field()
        bool_false = "BOOLEAN DEFAULT FALSE" if app.config['USING_POSTGRESQL'] else "INTEGER DEFAULT 0"

        execute_query(f'''
            CREATE TABLE IF NOT EXISTS posts (
                id             {id_field},
                title          TEXT NOT NULL,
                slug           TEXT UNIQUE,
                content        TEXT NOT NULL,
                excerpt        TEXT,
                category       TEXT NOT NULL,
                image_filename TEXT,
                date           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                views          INTEGER DEFAULT 0
            )
        ''', commit=True)

        execute_query(f'''
            CREATE TABLE IF NOT EXISTS users (
                id                    {id_field},
                username              TEXT UNIQUE NOT NULL,
                password_hash         TEXT NOT NULL,
                email                 TEXT,
                force_password_change INTEGER DEFAULT 0,
                last_login            TIMESTAMP,
                last_login_ip         TEXT,
                failed_attempts       INTEGER DEFAULT 0,
                locked_until          TIMESTAMP,
                created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''', commit=True)

        execute_query(f'''
            CREATE TABLE IF NOT EXISTS admin_activity (
                id         {id_field},
                user_id    INTEGER,
                action     TEXT NOT NULL,
                details    TEXT,
                ip_address TEXT,
                timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''', commit=True)

        execute_query(f'''
            CREATE TABLE IF NOT EXISTS contact_messages (
                id         {id_field},
                name       TEXT NOT NULL,
                email      TEXT NOT NULL,
                message    TEXT NOT NULL,
                date       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read    {bool_false},
                ip_address TEXT,
                user_agent TEXT,
                city TEXT, region TEXT, country TEXT, isp TEXT,
                lat  REAL,  lon REAL
            )
        ''', commit=True)

        execute_query(f'''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id         {id_field},
                user_id    INTEGER NOT NULL,
                token      TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used       {bool_false},
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''', commit=True)

        for sql in [
            'CREATE INDEX IF NOT EXISTS idx_posts_date     ON posts(date)',
            'CREATE INDEX IF NOT EXISTS idx_posts_category ON posts(category)',
            'CREATE INDEX IF NOT EXISTS idx_posts_slug     ON posts(slug)',
            'CREATE INDEX IF NOT EXISTS idx_posts_views    ON posts(views)',  # for popular-posts queries
            'CREATE INDEX IF NOT EXISTS idx_messages_read  ON contact_messages(is_read)',
            'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)',
        ]:
            execute_query(sql, commit=True)
        
        # Add full-text search support
        ensure_full_text_search()
        
        logger.info("Database schema and indexes ensured.")

        existing = execute_query("SELECT id FROM users WHERE username = 'admin'", fetchone=True)
        if existing is None:
            _create_default_admin()


def _create_default_admin():
    """
    Create the default admin account.

    In production, DEFAULT_ADMIN_PASSWORD *must* come from the environment.
    The account is created with force_password_change=1 so the login flow
    redirects to change-password automatically — no hardcoded string comparison
    needed inside the login route.
    """
    is_prod          = os.environ.get('FLASK_ENV') == 'production'
    default_password = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'Admin@123')

    if is_prod and default_password == 'Admin@123':
        raise RuntimeError(
            "DEFAULT_ADMIN_PASSWORD must be a strong custom value in production. "
            "Set it via environment variable."
        )

    admin_email = os.environ.get('DEFAULT_ADMIN_EMAIL', 'admin@example.com')
    execute_query('''
        INSERT INTO users (username, password_hash, email, force_password_change, created_at)
        VALUES (%s, %s, %s, 1, %s)
    ''', ('admin', generate_password_hash(default_password), admin_email, datetime.utcnow()),
        commit=True)

    logger.info("=" * 52)
    logger.info("  DEFAULT ADMIN ACCOUNT CREATED")
    logger.info("  Username : admin")
    if not is_prod:
        logger.info("  Password : %s", default_password)
    else:
        logger.info("  Password : <see DEFAULT_ADMIN_PASSWORD env var>")
    logger.info("  Email    : %s", admin_email)
    logger.info("  !! Change password on first login !!")
    logger.info("=" * 52)


@app.cli.command("init-db")
def init_db_command():
    """flask init-db — initialise schema and seed default admin."""
    init_db()
    print("Database initialised.")


# ═══════════════════════════════════════════════════════════════════
# CACHE HELPERS
# ═══════════════════════════════════════════════════════════════════

def clear_post_caches():
    """
    Invalidate post-related cache entries after any write.

    Uses cache.clear() because flask-caching's 'simple' backend has no
    key-listing API. When you upgrade to Redis, replace this body with
    cache.delete_many() on specific key prefixes or use cache tags.
    """
    cache.clear()
    logger.debug("Post caches cleared")


# ═══════════════════════════════════════════════════════════════════
# DOMAIN HELPERS
# ═══════════════════════════════════════════════════════════════════

def generate_slug(title: str) -> str:
    slug = re.sub(r'[^\w\s-]', '', title.lower())
    slug = re.sub(r'[\s_-]+', '-', slug)
    slug = re.sub(r'^-+|-+$', '', slug)
    return slug[:80]


def generate_unique_slug(title: str) -> str:
    base = generate_slug(title)
    if execute_query('SELECT id FROM posts WHERE slug = %s', (base,), fetchone=True):
        ts   = int(datetime.utcnow().timestamp())
        slug = f"{base}-{ts}"
        if len(slug) > 120:
            slug = f"{base[:80 - len(str(ts)) - 1]}-{ts}"
        return slug
    return base


def get_ip_location(ip: str) -> dict:
    _empty = dict(city='Unknown', region='Unknown', country='Unknown',
                  isp='Unknown', lat=0, lon=0)
    try:
        if ip in ('127.0.0.1', '::1', 'localhost'):
            return dict(city='Local', region='Local', country='Local',
                        isp='Local', lat=0, lon=0)
        # FIX: Use HTTPS endpoint
        r    = requests.get(f'https://ip-api.com/json/{ip}', timeout=2)
        data = r.json()
        if data.get('status') == 'success':
            return dict(
                city=data.get('city', 'Unknown'),    region=data.get('regionName', 'Unknown'),
                country=data.get('country', 'Unknown'), isp=data.get('isp', 'Unknown'),
                lat=data.get('lat', 0),              lon=data.get('lon', 0),
            )
        return _empty
    except Exception as exc:
        logger.error("IP location lookup failed for %s: %s", ip, exc)
        return _empty


def is_password_strong(pw: str):
    for ok, msg in [
        (len(pw) >= 8,                               "At least 8 characters required"),
        (re.search(r'[A-Z]', pw),                    "At least one uppercase letter required"),
        (re.search(r'[a-z]', pw),                    "At least one lowercase letter required"),
        (re.search(r'\d', pw),                       "At least one digit required"),
        (re.search(r'[!@#$%^&*(),.?\":{}|<>]', pw), "At least one special character required"),
    ]:
        if not ok:
            return False, msg
    return True, "Password is strong"


def is_valid_email(email: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email))


# ─── Email Sending Helper for Password Reset ──────────────────────

def send_reset_email(recipient_email, reset_link):
    """
    Send password reset email using SMTP settings from environment.
    If SMTP not configured, log the link (development only) and flash warning.
    """
    smtp_server = os.environ.get('SMTP_SERVER')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_password = os.environ.get('SMTP_PASSWORD')
    from_email = os.environ.get('MAIL_FROM', 'noreply@example.com')

    if not all([smtp_server, smtp_user, smtp_password]):
        logger.warning("SMTP not configured. Password reset link: %s", reset_link)
        flash('Password reset link generated. Check server logs (if in dev) or contact admin.', 'warning')
        return

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = recipient_email
    msg['Subject'] = 'Password Reset Request'
    body = f'Click the following link to reset your password: {reset_link}\n\nThis link expires in 1 hour.'
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(msg)
        server.quit()
        logger.info("Password reset email sent to %s", recipient_email)
    except Exception as exc:
        logger.error("Failed to send password reset email: %s", exc)
        flash('Failed to send email. Please try again later.', 'error')


# ═══════════════════════════════════════════════════════════════════
# ADMIN ACTIVITY LOGGING
# ═══════════════════════════════════════════════════════════════════

def log_admin_activity(action: str, details: str = ""):
    if 'user_id' not in session:
        return
    try:
        execute_query('''
            INSERT INTO admin_activity (user_id, action, details, ip_address, timestamp)
            VALUES (%s, %s, %s, %s, %s)
        ''', (session['user_id'], action, details, get_client_ip(), datetime.utcnow()),
            commit=True)
    except Exception as exc:
        logger.error("Failed to log admin activity [%s]: %s", action, exc)


# ═══════════════════════════════════════════════════════════════════
# AUTH DECORATOR
# ═══════════════════════════════════════════════════════════════════

def login_required(view):
    @wraps(view)
    def wrapped(**kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        if 'last_activity' in session:
            try:
                last = datetime.fromisoformat(session['last_activity'])
                if datetime.utcnow() - last > app.config['PERMANENT_SESSION_LIFETIME']:
                    session.clear()
                    flash('Your session expired. Please log in again.', 'warning')
                    return redirect(url_for('login'))
            except (ValueError, TypeError):
                pass
        session['last_activity'] = datetime.utcnow().isoformat()
        return view(**kwargs)
    return wrapped


# ─── Pagination Helper ────────────────────────────────────────────

def handle_pagination(page, total_pages):
    if total_pages > 0 and page > total_pages:
        return redirect(url_for(request.endpoint, page=total_pages, **request.view_args))
    return None


# ═══════════════════════════════════════════════════════════════════
# PUBLIC ROUTES
# ═══════════════════════════════════════════════════════════════════

@app.route('/')
@app.route('/page/<int:page>')
@cache.cached(timeout=300, query_string=True)
def index(page=1):
    per_page    = 10
    offset      = (page - 1) * per_page
    total       = get_count(execute_query('SELECT COUNT(*) as count FROM posts', fetchone=True))
    total_pages = (total + per_page - 1) // per_page

    redir = handle_pagination(page, total_pages)
    if redir:
        return redir

    posts = execute_query(
        'SELECT * FROM posts ORDER BY date DESC LIMIT %s OFFSET %s',
        (per_page, offset), fetchall=True
    )
    return render_template('blog.html', posts=posts, page=page, total_pages=total_pages)


@app.route('/post/<string:slug>')
def post_detail(slug):
    post = execute_query('SELECT * FROM posts WHERE slug = %s', (slug,), fetchone=True)
    if post is None:
        abort(404)
    execute_query('UPDATE posts SET views = views + 1 WHERE id = %s', (post['id'],), commit=True)
    related = execute_query('''
        SELECT * FROM posts WHERE category = %s AND id != %s ORDER BY date DESC LIMIT 3
    ''', (post['category'], post['id']), fetchall=True)
    return render_template('post.html', post=post, related_posts=related)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def contact():
    if request.method == 'POST':
        name    = request.form.get('name', '').strip()
        email   = request.form.get('email', '').strip()
        message = request.form.get('message', '').strip()

        if not (name and email and message):
            flash('All fields are required.', 'error')
            return render_template('contact.html', success=False)
        if not is_valid_email(email):
            flash('Please enter a valid email address.', 'error')
            return render_template('contact.html', success=False)

        ip       = get_client_ip()
        ua       = request.user_agent.string if request.user_agent else ''
        location = get_ip_location(ip)
        try:
            execute_query('''
                INSERT INTO contact_messages
                    (name, email, message, ip_address, user_agent,
                     city, region, country, isp, lat, lon, date)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ''', (name, email, message, ip, ua,
                  location['city'], location['region'], location['country'],
                  location['isp'], location['lat'], location['lon'],
                  datetime.utcnow()),
                commit=True)
        except Exception as exc:
            logger.error("Failed to save contact message from %s: %s", ip, exc)
            flash('An error occurred. Please try again later.', 'error')
            return render_template('contact.html', success=False)

        flash("Thank you! We'll be in touch soon.", 'success')
        return render_template('contact.html', success=True)

    return render_template('contact.html', success=False)


@app.route('/categories')
@cache.cached(timeout=300)
def categories():
    cats = execute_query(
        'SELECT category, COUNT(*) as post_count FROM posts GROUP BY category ORDER BY category',
        fetchall=True
    )
    return render_template('categories.html', categories=cats)


@app.route('/category/<category_name>')
@app.route('/category/<category_name>/page/<int:page>')
@cache.cached(timeout=300, query_string=True)
def category_posts(category_name, page=1):
    per_page    = 10
    offset      = (page - 1) * per_page
    total       = get_count(execute_query(
        'SELECT COUNT(*) as count FROM posts WHERE category = %s', (category_name,), fetchone=True
    ))
    total_pages = (total + per_page - 1) // per_page

    redir = handle_pagination(page, total_pages)
    if redir:
        return redir

    posts = execute_query('''
        SELECT * FROM posts WHERE category = %s ORDER BY date DESC LIMIT %s OFFSET %s
    ''', (category_name, per_page, offset), fetchall=True)
    return render_template('category_posts.html', category=category_name,
                           posts=posts, page=page, total_pages=total_pages)


# ─── SEO ──────────────────────────────────────────────────────────

@app.route('/sitemap.xml')
def sitemap():
    posts = execute_query('SELECT slug, date FROM posts ORDER BY date DESC', fetchall=True)
    return app.response_class(
        response=render_template('sitemap.xml', posts=posts),
        status=200, mimetype='application/xml'
    )


@app.route('/robots.txt')
def robots():
    return render_template('robots.txt'), 200, {'Content-Type': 'text/plain'}


# ─── Search ───────────────────────────────────────────────────────

@app.route('/search')
def search():
    """
    Enhanced search with PostgreSQL full-text search when available,
    falling back to LIKE/ILIKE.
    For SQLite, LIKE is case-insensitive for ASCII but not full Unicode;
    consider using FTS5 if needed.
    """
    query    = request.args.get('q', '').strip()
    page     = request.args.get('page', 1, type=int)
    per_page = 10
    offset   = (page - 1) * per_page

    if not query:
        return render_template('search.html', posts=[], query='', page=1, total_pages=1)

    # Use PostgreSQL full-text search if available
    if app.config['USING_POSTGRESQL'] and len(query) > 3:  # Only for meaningful queries
        try:
            posts = execute_query('''
                SELECT *,
                       ts_rank(to_tsvector('english', title || ' ' || coalesce(excerpt, '') || ' ' || content), 
                               plainto_tsquery('english', %s)) as rank
                FROM posts
                WHERE to_tsvector('english', title || ' ' || coalesce(excerpt, '') || ' ' || content) 
                      @@ plainto_tsquery('english', %s)
                ORDER BY rank DESC, date DESC
                LIMIT %s OFFSET %s
            ''', (query, query, per_page, offset), fetchall=True)

            total = get_count(execute_query('''
                SELECT COUNT(*) as count FROM posts
                WHERE to_tsvector('english', title || ' ' || coalesce(excerpt, '') || ' ' || content) 
                      @@ plainto_tsquery('english', %s)
            ''', (query,), fetchone=True))
        except Exception as exc:
            logger.warning("Full-text search failed, falling back to LIKE: %s", exc)
            # Fall back to LIKE/ILIKE
            op      = 'ILIKE'
            pattern = f'%{query}%'
            posts = execute_query(f'''
                SELECT * FROM posts
                WHERE title {op} %s OR content {op} %s OR excerpt {op} %s
                ORDER BY date DESC LIMIT %s OFFSET %s
            ''', (pattern, pattern, pattern, per_page, offset), fetchall=True)
            total = get_count(execute_query(f'''
                SELECT COUNT(*) as count FROM posts
                WHERE title {op} %s OR content {op} %s OR excerpt {op} %s
            ''', (pattern, pattern, pattern), fetchone=True))
    else:
        # Use standard LIKE/ILIKE for SQLite or short queries
        op      = 'ILIKE' if app.config['USING_POSTGRESQL'] else 'LIKE'
        pattern = f'%{query}%'
        posts = execute_query(f'''
            SELECT * FROM posts
            WHERE title {op} %s OR content {op} %s OR excerpt {op} %s
            ORDER BY date DESC LIMIT %s OFFSET %s
        ''', (pattern, pattern, pattern, per_page, offset), fetchall=True)
        total = get_count(execute_query(f'''
            SELECT COUNT(*) as count FROM posts
            WHERE title {op} %s OR content {op} %s OR excerpt {op} %s
        ''', (pattern, pattern, pattern), fetchone=True))

    total_pages = (total + per_page - 1) // per_page
    if total_pages > 0 and page > total_pages:
        return redirect(url_for('search', q=query, page=total_pages))

    return render_template('search.html', posts=posts, query=query,
                           page=page, total_pages=total_pages)


# ═══════════════════════════════════════════════════════════════════
# PASSWORD RESET ROUTES
# ═══════════════════════════════════════════════════════════════════

# ─── Password Reset Templates Check ───────────────────────────────
# Ensure password reset templates exist (created in create_missing_directories function)
# This is a safety check to verify they're available
def ensure_password_reset_templates():
    """Verify that password reset templates exist, log warning if missing."""
    templates_to_check = ['forgot_password.html', 'reset_password.html']
    missing_templates = []
    
    for template in templates_to_check:
        template_path = os.path.join(basedir, 'templates', template)
        if not os.path.exists(template_path):
            missing_templates.append(template)
            logger.warning(f"Password reset template missing: {template}")
    
    if missing_templates:
        logger.info("Password reset templates will be created on next startup if missing")
        # They'll be created by create_missing_directories() on next restart

# Run the check
ensure_password_reset_templates()


@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def forgot_password():
    """Request a password reset token."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email or not is_valid_email(email):
            flash('Please enter a valid email address.', 'error')
            return render_template('forgot_password.html')

        user = execute_query('SELECT id, email FROM users WHERE email = %s', (email,), fetchone=True)
        if not user:
            # Don't reveal that email doesn't exist (anti-enumeration)
            flash('If that email exists, a reset link has been sent.', 'info')
            return render_template('forgot_password.html')

        # Generate token (valid for 1 hour)
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=1)
        execute_query(
            'INSERT INTO password_reset_tokens (user_id, token, expires_at, used) VALUES (%s, %s, %s, 0)',
            (user['id'], token, expires_at), commit=True
        )

        # Construct reset link
        reset_link = url_for('reset_password', token=token, _external=True)
        send_reset_email(email, reset_link)

        flash('If that email exists, a reset link has been sent.', 'info')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def reset_password(token):
    """Reset password using a valid token."""
    # Find token
    token_record = execute_query(
        'SELECT * FROM password_reset_tokens WHERE token = %s AND used = 0 AND expires_at > %s',
        (token, datetime.utcnow()), fetchone=True
    )
    if not token_record:
        flash('Invalid or expired password reset token.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_pw = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        ok, msg = is_password_strong(new_pw)
        if not ok:
            flash(msg, 'error')
            return render_template('reset_password.html', token=token)

        if new_pw != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)

        # Update user password
        execute_query(
            'UPDATE users SET password_hash = %s, force_password_change = 0 WHERE id = %s',
            (generate_password_hash(new_pw), token_record['user_id']), commit=True
        )

        # Mark token as used
        execute_query(
            'UPDATE password_reset_tokens SET used = 1 WHERE id = %s',
            (token_record['id'],), commit=True
        )

        flash('Password reset successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


# ═══════════════════════════════════════════════════════════════════
# ADMIN — AUTH
# ═══════════════════════════════════════════════════════════════════

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """
    Login with lockout and anti-enumeration messaging.

    Anti-enumeration: we show the same generic 'Invalid credentials.' message
    whether the username does not exist OR the password is wrong. This prevents
    attackers from probing valid usernames via differing error responses.

    Default-password detection: the users.force_password_change column is set
    to 1 on account creation. The login route checks that flag and redirects
    to change-password — we never compare against a hardcoded password string here.
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ip       = get_client_ip()

        user = execute_query('SELECT * FROM users WHERE username = %s', (username,), fetchone=True)

        # Lockout check
        if user and user['locked_until']:
            try:
                locked_until = datetime.fromisoformat(str(user['locked_until']))
                if datetime.utcnow() < locked_until:
                    mins = int((locked_until - datetime.utcnow()).total_seconds() / 60)
                    flash(f'Account locked. Try again in {mins} minute(s).', 'error')
                    return render_template('admin/login.html')
            except (ValueError, TypeError):
                execute_query('UPDATE users SET locked_until = NULL WHERE id = %s',
                              (user['id'],), commit=True)

        if user and check_password_hash(user['password_hash'], password):
            execute_query('''
                UPDATE users
                SET failed_attempts = 0, locked_until = NULL,
                    last_login = %s, last_login_ip = %s
                WHERE id = %s
            ''', (datetime.utcnow(), ip, user['id']), commit=True)

            session.clear()
            session['user_id']       = user['id']
            session['username']      = user['username']
            session['last_activity'] = datetime.utcnow().isoformat()
            session.permanent        = True

            log_admin_activity('LOGIN', f'Login from {ip}')
            flash('Login successful!', 'success')

            # DB flag set at account creation — no hardcoded string comparison needed
            if user['force_password_change']:
                flash('Please set a new password before continuing.', 'warning')
                return redirect(url_for('change_password'))

            return redirect(url_for('admin_dashboard'))

        else:
            if user:
                failed = (user['failed_attempts'] or 0) + 1
                if failed >= 5:
                    lock_until = datetime.utcnow() + timedelta(minutes=15)
                    execute_query(
                        'UPDATE users SET failed_attempts=%s, locked_until=%s WHERE id=%s',
                        (failed, lock_until.isoformat(), user['id']), commit=True
                    )
                    flash('Too many failed attempts. Account locked for 15 minutes.', 'error')
                    return render_template('admin/login.html')
                else:
                    execute_query('UPDATE users SET failed_attempts=%s WHERE id=%s',
                                  (failed, user['id']), commit=True)

            # Anti-enumeration: same message regardless of whether user existed
            flash('Invalid credentials.', 'error')
            logger.warning("Failed login for '%s' from %s", username, ip)
            log_admin_activity('LOGIN_FAILED', f'Failed login for {username} from {ip}')

    return render_template('admin/login.html')


@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_admin_activity('LOGOUT', 'Logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))
# ─── SEO ──────────────────────────────────────────────────────────

@app.route('/sitemap.xml')
def sitemap():
    posts = execute_query('SELECT slug, date FROM posts ORDER BY date DESC', fetchall=True)
    return app.response_class(
        response=render_template('sitemap.xml', posts=posts),
        status=200, mimetype='application/xml'
    )


@app.route('/robots.txt')
def robots():
    return render_template('robots.txt'), 200, {'Content-Type': 'text/plain'}


# ─── Search ───────────────────────────────────────────────────────

@app.route('/search')
def search():
    """
    Enhanced search with PostgreSQL full-text search when available,
    falling back to LIKE/ILIKE.
    For SQLite, LIKE is case-insensitive for ASCII but not full Unicode;
    consider using FTS5 if needed.
    """
    query    = request.args.get('q', '').strip()
    page     = request.args.get('page', 1, type=int)
    per_page = 10
    offset   = (page - 1) * per_page

    if not query:
        return render_template('search.html', posts=[], query='', page=1, total_pages=1)

    # Use PostgreSQL full-text search if available
    if app.config['USING_POSTGRESQL'] and len(query) > 3:  # Only for meaningful queries
        try:
            posts = execute_query('''
                SELECT *,
                       ts_rank(to_tsvector('english', title || ' ' || coalesce(excerpt, '') || ' ' || content), 
                               plainto_tsquery('english', %s)) as rank
                FROM posts
                WHERE to_tsvector('english', title || ' ' || coalesce(excerpt, '') || ' ' || content) 
                      @@ plainto_tsquery('english', %s)
                ORDER BY rank DESC, date DESC
                LIMIT %s OFFSET %s
            ''', (query, query, per_page, offset), fetchall=True)

            total = get_count(execute_query('''
                SELECT COUNT(*) as count FROM posts
                WHERE to_tsvector('english', title || ' ' || coalesce(excerpt, '') || ' ' || content) 
                      @@ plainto_tsquery('english', %s)
            ''', (query,), fetchone=True))
        except Exception as exc:
            logger.warning("Full-text search failed, falling back to LIKE: %s", exc)
            # Fall back to LIKE/ILIKE
            op      = 'ILIKE'
            pattern = f'%{query}%'
            posts = execute_query(f'''
                SELECT * FROM posts
                WHERE title {op} %s OR content {op} %s OR excerpt {op} %s
                ORDER BY date DESC LIMIT %s OFFSET %s
            ''', (pattern, pattern, pattern, per_page, offset), fetchall=True)
            total = get_count(execute_query(f'''
                SELECT COUNT(*) as count FROM posts
                WHERE title {op} %s OR content {op} %s OR excerpt {op} %s
            ''', (pattern, pattern, pattern), fetchone=True))
    else:
        # Use standard LIKE/ILIKE for SQLite or short queries
        op      = 'ILIKE' if app.config['USING_POSTGRESQL'] else 'LIKE'
        pattern = f'%{query}%'
        posts = execute_query(f'''
            SELECT * FROM posts
            WHERE title {op} %s OR content {op} %s OR excerpt {op} %s
            ORDER BY date DESC LIMIT %s OFFSET %s
        ''', (pattern, pattern, pattern, per_page, offset), fetchall=True)
        total = get_count(execute_query(f'''
            SELECT COUNT(*) as count FROM posts
            WHERE title {op} %s OR content {op} %s OR excerpt {op} %s
        ''', (pattern, pattern, pattern), fetchone=True))

    total_pages = (total + per_page - 1) // per_page
    if total_pages > 0 and page > total_pages:
        return redirect(url_for('search', q=query, page=total_pages))

    return render_template('search.html', posts=posts, query=query,
                           page=page, total_pages=total_pages)


# ═══════════════════════════════════════════════════════════════════
# PASSWORD RESET ROUTES (NEW)
# ═══════════════════════════════════════════════════════════════════

@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def forgot_password():
    """Request a password reset token."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email or not is_valid_email(email):
            flash('Please enter a valid email address.', 'error')
            return render_template('forgot_password.html')

        user = execute_query('SELECT id, email FROM users WHERE email = %s', (email,), fetchone=True)
        if not user:
            # Don't reveal that email doesn't exist (anti-enumeration)
            flash('If that email exists, a reset link has been sent.', 'info')
            return render_template('forgot_password.html')

        # Generate token (valid for 1 hour)
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=1)
        execute_query(
            'INSERT INTO password_reset_tokens (user_id, token, expires_at, used) VALUES (%s, %s, %s, 0)',
            (user['id'], token, expires_at), commit=True
        )

        # Construct reset link
        reset_link = url_for('reset_password', token=token, _external=True)
        send_reset_email(email, reset_link)

        flash('If that email exists, a reset link has been sent.', 'info')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def reset_password(token):
    """Reset password using a valid token."""
    # Find token
    token_record = execute_query(
        'SELECT * FROM password_reset_tokens WHERE token = %s AND used = 0 AND expires_at > %s',
        (token, datetime.utcnow()), fetchone=True
    )
    if not token_record:
        flash('Invalid or expired password reset token.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_pw = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        ok, msg = is_password_strong(new_pw)
        if not ok:
            flash(msg, 'error')
            return render_template('reset_password.html', token=token)

        if new_pw != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)

        # Update user password
        execute_query(
            'UPDATE users SET password_hash = %s, force_password_change = 0 WHERE id = %s',
            (generate_password_hash(new_pw), token_record['user_id']), commit=True
        )

        # Mark token as used
        execute_query(
            'UPDATE password_reset_tokens SET used = 1 WHERE id = %s',
            (token_record['id'],), commit=True
        )

        flash('Password reset successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


# ═══════════════════════════════════════════════════════════════════
# ADMIN — AUTH
# ═══════════════════════════════════════════════════════════════════

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """
    Login with lockout and anti-enumeration messaging.

    Anti-enumeration: we show the same generic 'Invalid credentials.' message
    whether the username does not exist OR the password is wrong. This prevents
    attackers from probing valid usernames via differing error responses.

    Default-password detection: the users.force_password_change column is set
    to 1 on account creation. The login route checks that flag and redirects
    to change-password — we never compare against a hardcoded password string here.
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ip       = get_client_ip()

        user = execute_query('SELECT * FROM users WHERE username = %s', (username,), fetchone=True)

        # Lockout check
        if user and user['locked_until']:
            try:
                locked_until = datetime.fromisoformat(str(user['locked_until']))
                if datetime.utcnow() < locked_until:
                    mins = int((locked_until - datetime.utcnow()).total_seconds() / 60)
                    flash(f'Account locked. Try again in {mins} minute(s).', 'error')
                    return render_template('admin/login.html')
            except (ValueError, TypeError):
                execute_query('UPDATE users SET locked_until = NULL WHERE id = %s',
                              (user['id'],), commit=True)

        if user and check_password_hash(user['password_hash'], password):
            execute_query('''
                UPDATE users
                SET failed_attempts = 0, locked_until = NULL,
                    last_login = %s, last_login_ip = %s
                WHERE id = %s
            ''', (datetime.utcnow(), ip, user['id']), commit=True)

            session.clear()
            session['user_id']       = user['id']
            session['username']      = user['username']
            session['last_activity'] = datetime.utcnow().isoformat()
            session.permanent        = True

            log_admin_activity('LOGIN', f'Login from {ip}')
            flash('Login successful!', 'success')

            # DB flag set at account creation — no hardcoded string comparison needed
            if user['force_password_change']:
                flash('Please set a new password before continuing.', 'warning')
                return redirect(url_for('change_password'))

            return redirect(url_for('admin_dashboard'))

        else:
            if user:
                failed = (user['failed_attempts'] or 0) + 1
                if failed >= 5:
                    lock_until = datetime.utcnow() + timedelta(minutes=15)
                    execute_query(
                        'UPDATE users SET failed_attempts=%s, locked_until=%s WHERE id=%s',
                        (failed, lock_until.isoformat(), user['id']), commit=True
                    )
                    flash('Too many failed attempts. Account locked for 15 minutes.', 'error')
                    return render_template('admin/login.html')
                else:
                    execute_query('UPDATE users SET failed_attempts=%s WHERE id=%s',
                                  (failed, user['id']), commit=True)

            # Anti-enumeration: same message regardless of whether user existed
            flash('Invalid credentials.', 'error')
            logger.warning("Failed login for '%s' from %s", username, ip)
            log_admin_activity('LOGIN_FAILED', f'Failed login for {username} from {ip}')

    return render_template('admin/login.html')


@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_admin_activity('LOGOUT', 'Logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new_pw  = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        user = execute_query('SELECT * FROM users WHERE id = %s',
                             (session['user_id'],), fetchone=True)
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('logout'))

        if not check_password_hash(user['password_hash'], current):
            flash('Current password is incorrect.', 'error')
            return render_template('admin/change_password.html')

        ok, msg = is_password_strong(new_pw)
        if not ok:
            flash(msg, 'error')
            return render_template('admin/change_password.html')

        if new_pw != confirm:
            flash('New passwords do not match.', 'error')
            return render_template('admin/change_password.html')

        execute_query(
            'UPDATE users SET password_hash=%s, force_password_change=0 WHERE id=%s',
            (generate_password_hash(new_pw), session['user_id']), commit=True
        )
        log_admin_activity('PASSWORD_CHANGE', 'Password changed')
        flash('Password changed successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/change_password.html')


# ═══════════════════════════════════════════════════════════════════
# ADMIN — DASHBOARD & POST CRUD
# ═══════════════════════════════════════════════════════════════════

@app.route('/admin/activity')
@login_required
def admin_activity():
    activities = execute_query('''
        SELECT a.*, u.username FROM admin_activity a
        JOIN users u ON a.user_id = u.id
        ORDER BY a.timestamp DESC LIMIT 100
    ''', fetchall=True)
    return render_template('admin/activity.html', activities=activities)


@app.route('/admin')
@login_required
def admin_dashboard():
    page     = request.args.get('page', 1, type=int)
    per_page = 20
    offset   = (page - 1) * per_page
    total    = get_count(execute_query('SELECT COUNT(*) as count FROM posts', fetchone=True))
    total_pages = (total + per_page - 1) // per_page

    if total_pages > 0 and page > total_pages:
        return redirect(url_for('admin_dashboard', page=total_pages))

    posts = execute_query(
        'SELECT * FROM posts ORDER BY date DESC LIMIT %s OFFSET %s',
        (per_page, offset), fetchall=True
    )
    unread = get_count(execute_query(
        'SELECT COUNT(*) as count FROM contact_messages WHERE is_read = 0', fetchone=True
    ))
    user = execute_query('SELECT * FROM users WHERE id = %s',
                         (session['user_id'],), fetchone=True)
    return render_template('admin/dashboard.html', posts=posts, unread_count=unread,
                           user=user, page=page, total_pages=total_pages)


def _handle_image_upload(image, existing_filename=None):
    """
    Validate, optimise, and persist an uploaded image file.

    Returns the new filename string on success.
    Returns existing_filename unchanged if no new file was provided.
    Returns empty string if validation fails (and flashes a warning) to avoid NULL in DB.
    Deletes the old file automatically when replacing.
    """
    if not (image and image.filename):
        return existing_filename

    if not allowed_file(image.filename, image):
        logger.warning("Image upload rejected: '%s'", image.filename)
        flash('Invalid image file — upload skipped.', 'warning')
        # FIX: Return empty string instead of None to avoid NULL in DB
        return '' if existing_filename is None else existing_filename

    if existing_filename:
        old_path = os.path.join(app.config['UPLOAD_FOLDER'], existing_filename)
        try:
            if os.path.exists(old_path):
                os.remove(old_path)
        except OSError as exc:
            logger.warning("Could not remove old image %s: %s", existing_filename, exc)

    safe_name   = secure_filename(image.filename)
    unique_name = f"{uuid.uuid4()}_{safe_name}"
    dest_path   = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)

    try:
        process_and_save_image(image, dest_path)
        return unique_name
    except ValueError as ve:
        # Dimension limit exceeded
        logger.warning("Image dimension error: %s", ve)
        flash(str(ve), 'warning')
        return '' if existing_filename is None else existing_filename
    except Exception as exc:
        logger.error("Failed to process/save image %s: %s", unique_name, exc)
        flash('Image processing failed — post saved without new image.', 'warning')
        # FIX: Return empty string on failure to avoid NULL
        return '' if existing_filename is None else existing_filename


@app.route('/admin/create', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
def create_post():
    if request.method == 'POST':
        title    = request.form.get('title', '').strip()
        content  = request.form.get('content', '').strip()
        excerpt  = request.form.get('excerpt', '').strip()
        category = request.form.get('category', '').strip()

        if not excerpt:
            excerpt = re.sub('<[^<]+?>', '', content)
            excerpt = (excerpt[:150] + '...') if len(excerpt) > 150 else excerpt

        slug     = generate_unique_slug(title)
        filename = _handle_image_upload(request.files.get('image'))
        
        # Ensure filename is never None (use empty string as default)
        if filename is None:
            filename = ''

        try:
            execute_query('''
                INSERT INTO posts (title, slug, content, excerpt, category, image_filename, date)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (title, slug, content, excerpt, category, filename, datetime.utcnow()),
                commit=True)
        except Exception as exc:
            logger.error("Failed to create post '%s': %s", title, exc)
            flash('Failed to create post. Please try again.', 'error')
            return render_template('admin/edit_post.html', post=None)

        clear_post_caches()
        log_admin_activity('CREATE_POST', f'Created: {title}')
        flash('Post created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/edit_post.html', post=None)


@app.route('/admin/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
@limiter.limit("10 per minute")
def edit_post(post_id):
    post = execute_query('SELECT * FROM posts WHERE id = %s', (post_id,), fetchone=True)
    if post is None:
        abort(404)

    if request.method == 'POST':
        title    = request.form.get('title', '').strip()
        content  = request.form.get('content', '').strip()
        excerpt  = request.form.get('excerpt', '').strip()
        category = request.form.get('category', '').strip()

        if not excerpt:
            excerpt = re.sub('<[^<]+?>', '', content)
            excerpt = (excerpt[:150] + '...') if len(excerpt) > 150 else excerpt

        # FIX: Always use generate_unique_slug when title changes
        if title != post['title']:
            # Title changed - generate new unique slug
            slug = generate_unique_slug(title)
        else:
            # Title unchanged - keep existing slug
            slug = post['slug']

        uploaded = request.files.get('image')
        if uploaded and uploaded.filename:
            filename = _handle_image_upload(uploaded, existing_filename=post['image_filename'])
        else:
            filename = post['image_filename']  # preserve existing when no new file submitted

        try:
            execute_query('''
                UPDATE posts
                SET title=%s, slug=%s, content=%s, excerpt=%s,
                    category=%s, image_filename=%s
                WHERE id=%s
            ''', (title, slug, content, excerpt, category, filename, post_id), commit=True)
        except Exception as exc:
            logger.error("Failed to update post %s: %s", post_id, exc)
            flash('Failed to update post. Please try again.', 'error')
            return render_template('admin/edit_post.html', post=post)

        clear_post_caches()
        log_admin_activity('EDIT_POST', f'Edited: {title}')
        flash('Post updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/edit_post.html', post=post)


@app.route('/admin/delete/<int:post_id>', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def delete_post(post_id):
    post = execute_query('SELECT title, image_filename FROM posts WHERE id = %s',
                         (post_id,), fetchone=True)
    if not post:
        flash('Post not found.', 'error')
        return redirect(url_for('admin_dashboard'))

    if post['image_filename']:
        try:
            p = os.path.join(app.config['UPLOAD_FOLDER'], post['image_filename'])
            if os.path.exists(p):
                os.remove(p)
        except OSError as exc:
            logger.warning("Could not delete image for post %s: %s", post_id, exc)

    try:
        execute_query('DELETE FROM posts WHERE id = %s', (post_id,), commit=True)
    except Exception as exc:
        logger.error("Failed to delete post %s: %s", post_id, exc)
        flash('Failed to delete post. Please try again.', 'error')
        return redirect(url_for('admin_dashboard'))

    clear_post_caches()
    log_admin_activity('DELETE_POST', f'Deleted: {post["title"]}')
    flash('Post deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


# ═══════════════════════════════════════════════════════════════════
# ADMIN — MESSAGES
# ═══════════════════════════════════════════════════════════════════

@app.route('/admin/messages')
@login_required
def admin_messages():
    page     = request.args.get('page', 1, type=int)
    per_page = 20
    offset   = (page - 1) * per_page
    total    = get_count(execute_query(
        'SELECT COUNT(*) as count FROM contact_messages', fetchone=True
    ))
    total_pages = (total + per_page - 1) // per_page

    if total_pages > 0 and page > total_pages:
        return redirect(url_for('admin_messages', page=total_pages))

    messages = execute_query('''
        SELECT * FROM contact_messages ORDER BY is_read ASC, date DESC LIMIT %s OFFSET %s
    ''', (per_page, offset), fetchall=True)

    unread = get_count(execute_query(
        'SELECT COUNT(*) as count FROM contact_messages WHERE is_read = 0', fetchone=True
    ))
    return render_template('admin/messages.html', messages=messages, unread_count=unread,
                           total_messages=total, page=page, total_pages=total_pages)


@app.route('/admin/message/<int:message_id>')
@login_required
def view_message(message_id):
    execute_query('UPDATE contact_messages SET is_read = 1 WHERE id = %s',
                  (message_id,), commit=True)
    msg = execute_query('SELECT * FROM contact_messages WHERE id = %s',
                        (message_id,), fetchone=True)
    if msg is None:
        abort(404)
    return render_template('admin/view_message.html', message=msg)


@app.route('/admin/message/delete/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    execute_query('DELETE FROM contact_messages WHERE id = %s', (message_id,), commit=True)
    log_admin_activity('DELETE_MESSAGE', f'Deleted message {message_id}')
    flash('Message deleted.', 'success')
    return redirect(url_for('admin_messages'))


@app.route('/admin/messages/mark-all-read', methods=['POST'])
@login_required
def mark_all_read():
    execute_query('UPDATE contact_messages SET is_read = 1 WHERE is_read = 0', commit=True)
    log_admin_activity('MARK_ALL_READ', 'All messages marked read')
    flash('All messages marked as read.', 'success')
    return redirect(url_for('admin_messages'))


# ═══════════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════════

def clean_expired_tokens():
    execute_query(
        'DELETE FROM password_reset_tokens WHERE expires_at < %s',
        (datetime.utcnow(),), commit=True
    )


@app.route('/health')
def health_check():
    try:
        clean_expired_tokens()
    except Exception:
        pass
    return jsonify({"status": "healthy"}), 200


# ═══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    # Upload folder and DB directory are both created at module level (top of file).
    # Run `flask init-db` to create the schema before first use.
    port  = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug)