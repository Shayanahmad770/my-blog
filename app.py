import sqlite3
import os
import re
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, g, abort, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import requests

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24).hex()  # 🔐 Generate strong random secret key
app.config['UPLOAD_FOLDER'] = 'static/images'        # Where uploaded images will be stored
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Allowed image file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ─── Helper Functions ──────────────────────────────────────────────
def generate_slug(title):
    """Convert title to URL-friendly slug."""
    slug = title.lower()
    # Replace spaces and special characters
    slug = re.sub(r'[^\w\s-]', '', slug)
    slug = re.sub(r'[\s_-]+', '-', slug)
    slug = re.sub(r'^-+|-+$', '', slug)
    return slug

def get_ip_location(ip_address):
    """Get location info from IP address using free API."""
    try:
        # Skip localhost IPs
        if ip_address in ['127.0.0.1', '::1', 'localhost']:
            return {
                'city': 'Local Development',
                'region': 'Local',
                'country': 'Local',
                'isp': 'Local',
                'lat': 0,
                'lon': 0
            }
        
        # Using free ip-api.com
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=2)
        data = response.json()
        
        if data['status'] == 'success':
            return {
                'city': data.get('city', 'Unknown'),
                'region': data.get('regionName', 'Unknown'),
                'country': data.get('country', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'lat': data.get('lat', 0),
                'lon': data.get('lon', 0)
            }
        else:
            return {
                'city': 'Unknown',
                'region': 'Unknown', 
                'country': 'Unknown',
                'isp': 'Unknown',
                'lat': 0,
                'lon': 0
            }
    except Exception as e:
        print(f"Error getting location: {e}")
        return {
            'city': 'Error',
            'region': 'Error',
            'country': 'Error',
            'isp': 'Error',
            'lat': 0,
            'lon': 0
        }

def is_password_strong(password):
    """Check if password meets strength requirements."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, "Password is strong"

# ─── Database Helpers ──────────────────────────────────────────────
def get_db():
    """Open a new database connection per request."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('database/blog.db')
        db.row_factory = sqlite3.Row   # allows accessing columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Close the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Create tables and default admin user if they don't exist."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        # Create posts table with views column and excerpt column
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                excerpt TEXT,
                category TEXT NOT NULL,
                image_filename TEXT,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                views INTEGER DEFAULT 0
            )
        ''')

        # Create users table with more fields
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                last_login TIMESTAMP,
                last_login_ip TEXT,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create admin activity log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create contact_messages table with location fields
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contact_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                message TEXT NOT NULL,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read INTEGER DEFAULT 0,
                ip_address TEXT,
                user_agent TEXT,
                city TEXT,
                region TEXT,
                country TEXT,
                isp TEXT,
                lat REAL,
                lon REAL
            )
        ''')

        # Create password reset tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        db.commit()

        # Create a default admin user if none exists (username: admin, password: Admin@123)
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        if cursor.fetchone() is None:
            default_password = "Admin@123"  # Strong default password
            password_hash = generate_password_hash(default_password)
            cursor.execute('''
                INSERT INTO users (username, password_hash, email, created_at)
                VALUES (?, ?, ?, ?)
            ''', ('admin', password_hash, 'admin@nexttechdaily.com', datetime.now()))
            db.commit()
            print("="*50)
            print("DEFAULT ADMIN CREDENTIALS:")
            print(f"Username: admin")
            print(f"Password: {default_password}")
            print("="*50)
            print("IMPORTANT: Change this password immediately after first login!")

# Run the database initialization
init_db()

# ─── Log Admin Activity ────────────────────────────────────────────
def log_admin_activity(action, details=""):
    """Log admin actions to database."""
    if 'user_id' in session:
        db = get_db()
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        db.execute('''
            INSERT INTO admin_activity (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
        ''', (session['user_id'], action, details, ip_address))
        db.commit()

# ─── Enhanced Login Required Decorator ─────────────────────────────
def login_required(view):
    """Decorator to restrict access to logged-in users with session validation."""
    @wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        # Check if session is expired
        if 'last_activity' in session:
            if datetime.now() - datetime.fromisoformat(session['last_activity']) > app.config['PERMANENT_SESSION_LIFETIME']:
                session.clear()
                flash('Your session has expired. Please log in again.', 'warning')
                return redirect(url_for('login'))
        
        # Update last activity
        session['last_activity'] = datetime.now().isoformat()
        
        return view(**kwargs)
    return wrapped_view

# ─── Public Routes ─────────────────────────────────────────────────
@app.route('/')
def index():
    """Homepage: display all blog posts."""
    db = get_db()
    posts = db.execute('SELECT * FROM posts ORDER BY date DESC').fetchall()
    return render_template('blog.html', posts=posts)

@app.route('/post/<int:post_id>')
@app.route('/post/<int:post_id>/<slug>')
def post_detail(post_id, slug=None):
    """Full article page for a single post with SEO-friendly URL."""
    db = get_db()
    post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    if post is None:
        abort(404)
    
    # Increment view count
    db.execute('UPDATE posts SET views = views + 1 WHERE id = ?', (post_id,))
    db.commit()
    
    # Get related posts (same category)
    related_posts = db.execute('''
        SELECT * FROM posts 
        WHERE category = ? AND id != ? 
        ORDER BY date DESC 
        LIMIT 3
    ''', (post['category'], post_id)).fetchall()
    
    return render_template('post.html', post=post, related_posts=related_posts)

@app.route('/about')
def about():
    """About page."""
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """Contact page with form handling."""
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        
        # Basic validation
        if not name or not email or not message:
            flash('All fields are required.', 'error')
            return render_template('contact.html', success=False)
        
        # Get real IP
        if request.headers.get('X-Forwarded-For'):
            ip_address = request.headers.get('X-Forwarded-For').split(',')[0]
        else:
            ip_address = request.remote_addr
            
        user_agent = request.user_agent.string
        
        # Get location from IP
        location = get_ip_location(ip_address)
        
        # Save to database
        db = get_db()
        db.execute('''
            INSERT INTO contact_messages 
            (name, email, message, ip_address, user_agent, city, region, country, isp, lat, lon) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (name, email, message, ip_address, user_agent, 
              location['city'], location['region'], location['country'], 
              location['isp'], location['lat'], location['lon']))
        db.commit()
        
        flash('Thank you for your message! We\'ll get back to you soon.', 'success')
        return render_template('contact.html', success=True)
    
    return render_template('contact.html', success=False)

@app.route('/categories')
def categories():
    """Show all categories and post counts."""
    db = get_db()
    categories = db.execute('''
        SELECT category, COUNT(*) as post_count 
        FROM posts 
        GROUP BY category 
        ORDER BY category
    ''').fetchall()
    return render_template('categories.html', categories=categories)

@app.route('/category/<category_name>')
def category_posts(category_name):
    """Show all posts in a specific category."""
    db = get_db()
    posts = db.execute('''
        SELECT * FROM posts 
        WHERE category = ? 
        ORDER BY date DESC
    ''', (category_name,)).fetchall()
    return render_template('category_posts.html', category=category_name, posts=posts)

# ─── SEO Routes ────────────────────────────────────────────────────
@app.route('/sitemap.xml')
def sitemap():
    """Generate sitemap.xml for search engines."""
    db = get_db()
    posts = db.execute('SELECT * FROM posts ORDER BY date DESC').fetchall()
    
    sitemap_xml = render_template('sitemap.xml', posts=posts)
    return app.response_class(response=sitemap_xml, status=200, mimetype='application/xml')

@app.route('/robots.txt')
def robots():
    """Generate robots.txt for search engines."""
    return render_template('robots.txt'), 200, {'Content-Type': 'text/plain'}

# ─── Enhanced Admin Routes ─────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Enhanced admin login page with security features."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        
        db = get_db()
        
        # Check if user is locked out
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and user['locked_until']:
            locked_until = datetime.fromisoformat(user['locked_until'])
            if datetime.now() < locked_until:
                minutes_left = int((locked_until - datetime.now()).total_seconds() / 60)
                flash(f'Account locked. Try again in {minutes_left} minutes.', 'error')
                return render_template('admin/login.html')
        
        # Verify credentials
        if user and check_password_hash(user['password_hash'], password):
            # Reset failed attempts on successful login
            db.execute('UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ?, last_login_ip = ? WHERE id = ?',
                      (datetime.now(), ip_address, user['id']))
            db.commit()
            
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['last_activity'] = datetime.now().isoformat()
            session.permanent = True
            
            log_admin_activity('LOGIN', f'Successful login from {ip_address}')
            flash('Login successful!', 'success')
            
            # Force password change for default password
            if password == "Admin@123" and user['username'] == 'admin':
                flash('Please change your default password immediately.', 'warning')
                return redirect(url_for('change_password'))
            
            return redirect(url_for('admin_dashboard'))
        else:
            # Increment failed attempts
            if user:
                failed = user['failed_attempts'] + 1
                if failed >= 5:  # Lock after 5 failed attempts
                    lock_time = datetime.now() + timedelta(minutes=15)
                    db.execute('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
                              (failed, lock_time, user['id']))
                    flash('Too many failed attempts. Account locked for 15 minutes.', 'error')
                else:
                    db.execute('UPDATE users SET failed_attempts = ? WHERE id = ?',
                              (failed, user['id']))
                    flash(f'Invalid credentials. {5-failed} attempts remaining.', 'error')
                db.commit()
                
            log_admin_activity('LOGIN_FAILED', f'Failed login attempt for {username} from {ip_address}')
            return render_template('admin/login.html', error='Invalid credentials')
    
    return render_template('admin/login.html')

@app.route('/logout')
def logout():
    """Enhanced logout with logging."""
    if 'user_id' in session:
        log_admin_activity('LOGOUT', 'User logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Allow admin to change password."""
    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        # Verify current password
        if not check_password_hash(user['password_hash'], current):
            flash('Current password is incorrect.', 'error')
            return render_template('admin/change_password.html')
        
        # Check new password strength
        is_strong, message = is_password_strong(new)
        if not is_strong:
            flash(message, 'error')
            return render_template('admin/change_password.html')
        
        # Check confirmation
        if new != confirm:
            flash('New passwords do not match.', 'error')
            return render_template('admin/change_password.html')
        
        # Update password
        new_hash = generate_password_hash(new)
        db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, session['user_id']))
        db.commit()
        
        log_admin_activity('PASSWORD_CHANGE', 'Password changed successfully')
        flash('Password changed successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/change_password.html')

@app.route('/admin/activity')
@login_required
def admin_activity():
    """View admin activity log."""
    db = get_db()
    activities = db.execute('''
        SELECT a.*, u.username 
        FROM admin_activity a
        JOIN users u ON a.user_id = u.id
        ORDER BY a.timestamp DESC
        LIMIT 100
    ''').fetchall()
    return render_template('admin/activity.html', activities=activities)

@app.route('/admin')
@login_required
def admin_dashboard():
    """Admin dashboard: list all posts with edit/delete options."""
    db = get_db()
    posts = db.execute('SELECT * FROM posts ORDER BY date DESC').fetchall()
    
    # Get unread messages count for notification
    unread_count = db.execute('SELECT COUNT(*) FROM contact_messages WHERE is_read = 0').fetchone()[0]
    
    # Get user info for security card
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    return render_template('admin/dashboard.html', posts=posts, unread_count=unread_count, user=user)

# ===== UPDATED: create_post with excerpt =====
@app.route('/admin/create', methods=['GET', 'POST'])
@login_required
def create_post():
    """Create a new blog post with excerpt."""
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        excerpt = request.form.get('excerpt', '')  # NEW: Get excerpt from form
        category = request.form['category']
        image = request.files['image']

        # If no excerpt provided, generate one from content
        if not excerpt.strip():
            # Remove HTML tags and truncate
            excerpt = re.sub('<[^<]+?>', '', content)  # Remove HTML tags
            excerpt = excerpt[:150] + '...' if len(excerpt) > 150 else excerpt

        filename = None
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        db = get_db()
        # UPDATED: Include excerpt in INSERT
        db.execute('''
            INSERT INTO posts (title, content, excerpt, category, image_filename)
            VALUES (?, ?, ?, ?, ?)
        ''', (title, content, excerpt, category, filename))
        db.commit()
        
        log_admin_activity('CREATE_POST', f'Created post: {title}')
        flash('Post created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/edit_post.html', post=None)

# ===== UPDATED: edit_post with excerpt =====
@app.route('/admin/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    """Edit an existing blog post with excerpt."""
    db = get_db()
    post = db.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    if post is None:
        abort(404)

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        excerpt = request.form.get('excerpt', '')  # NEW: Get excerpt from form
        category = request.form['category']
        image = request.files['image']

        # If no excerpt provided, generate one from content
        if not excerpt.strip():
            excerpt = re.sub('<[^<]+?>', '', content)
            excerpt = excerpt[:150] + '...' if len(excerpt) > 150 else excerpt

        # Keep old filename unless a new image is uploaded
        filename = post['image_filename']
        if image and allowed_file(image.filename):
            # Delete old image if it exists
            if filename:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                except OSError:
                    pass
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        db = get_db()
        # UPDATED: Include excerpt in UPDATE
        db.execute('''
            UPDATE posts
            SET title = ?, content = ?, excerpt = ?, category = ?, image_filename = ?
            WHERE id = ?
        ''', (title, content, excerpt, category, filename, post_id))
        db.commit()
        
        log_admin_activity('EDIT_POST', f'Edited post: {title}')
        flash('Post updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/edit_post.html', post=post)

@app.route('/admin/delete/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    """Delete a blog post."""
    db = get_db()
    # Get post title for logging
    post = db.execute('SELECT title, image_filename FROM posts WHERE id = ?', (post_id,)).fetchone()
    if post:
        # Delete image if exists
        if post['image_filename']:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], post['image_filename']))
            except OSError:
                pass
        
        db.execute('DELETE FROM posts WHERE id = ?', (post_id,))
        db.commit()
        
        log_admin_activity('DELETE_POST', f'Deleted post: {post["title"]}')
        flash('Post deleted successfully!', 'success')
    
    return redirect(url_for('admin_dashboard'))

# ─── Admin Contact Messages Routes ─────────────────────────────────
@app.route('/admin/messages')
@login_required
def admin_messages():
    """Show all contact messages."""
    db = get_db()
    messages = db.execute('''
        SELECT * FROM contact_messages 
        ORDER BY is_read ASC, date DESC
    ''').fetchall()
    
    # Get counts
    unread_count = db.execute('SELECT COUNT(*) FROM contact_messages WHERE is_read = 0').fetchone()[0]
    total_count = db.execute('SELECT COUNT(*) FROM contact_messages').fetchone()[0]
    
    return render_template('admin/messages.html', 
                          messages=messages, 
                          unread_count=unread_count,
                          total_count=total_count)

@app.route('/admin/message/<int:message_id>')
@login_required
def view_message(message_id):
    """View a single message and mark as read."""
    db = get_db()
    
    # Mark as read
    db.execute('UPDATE contact_messages SET is_read = 1 WHERE id = ?', (message_id,))
    db.commit()
    
    # Get message
    message = db.execute('SELECT * FROM contact_messages WHERE id = ?', (message_id,)).fetchone()
    
    if message is None:
        abort(404)
    
    return render_template('admin/view_message.html', message=message)

@app.route('/admin/message/delete/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    """Delete a message."""
    db = get_db()
    db.execute('DELETE FROM contact_messages WHERE id = ?', (message_id,))
    db.commit()
    
    log_admin_activity('DELETE_MESSAGE', f'Deleted message ID: {message_id}')
    flash('Message deleted successfully!', 'success')
    return redirect(url_for('admin_messages'))

@app.route('/admin/messages/mark-all-read', methods=['POST'])
@login_required
def mark_all_read():
    """Mark all messages as read."""
    db = get_db()
    db.execute('UPDATE contact_messages SET is_read = 1 WHERE is_read = 0')
    db.commit()
    
    log_admin_activity('MARK_ALL_READ', 'Marked all messages as read')
    flash('All messages marked as read!', 'success')
    return redirect(url_for('admin_messages'))

# ─── Run the App ───────────────────────────────────────────────────
if __name__ == '__main__':
    # Create the upload folder if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Setup logging for production
    if not app.debug:
        import logging
        from logging.handlers import RotatingFileHandler
        
        file_handler = RotatingFileHandler('blog.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Blog startup')
    
    # Run the app
    # For development:
    app.run(debug=True)
    # For production, use:
    # app.run(host='0.0.0.0', port=5000)