import os
import re
import json
import math
import sqlite3
import time
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = 'super_secret_key_change_this_in_production'
APP_START_TIME = time.time()

# কনফিগারেশন
UPLOAD_FOLDER = 'static/uploads'
PROFILE_UPLOAD_FOLDER = 'static/profile_uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROFILE_UPLOAD_FOLDER'] = PROFILE_UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROFILE_UPLOAD_FOLDER, exist_ok=True)

# লগইন ম্যানেজার
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- ডাটাবেস ফাংশন ---

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()

    # ১. ইউজার টেবিল
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            name TEXT,
            email TEXT,
            bio TEXT,
            hobby TEXT,
            categories TEXT,
            social_links TEXT,
            facebook_link TEXT,
            x_link TEXT,
            instagram_link TEXT,
            website_link TEXT,
            youtube_link TEXT,
            profile_pic TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # ২. পোস্ট টেবিল (আপডেটেড: user_id, status যুক্ত)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            intro TEXT NOT NULL,
            content TEXT NOT NULL,
            category TEXT NOT NULL,
            views INTEGER DEFAULT 0,
            status TEXT DEFAULT 'draft', -- draft, pending, approved, rejected
            is_active INTEGER DEFAULT 1, -- ইউজার চাইলে তার approved পোস্ট লুকাতে পারে
            thumbnail TEXT,
            trending_thumbnail TEXT,
            slug TEXT,
            toc_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # ৩. রিপোর্ট টেবিল (নতুন)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_id INTEGER,
            post_id INTEGER,
            comment_id INTEGER,
            reason TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(reporter_id) REFERENCES users(id)
        )
    ''')

    # ৪. লাইক, কমেন্ট ও বুকমার্ক টেবিল
    conn.execute('CREATE TABLE IF NOT EXISTS post_likes (user_id INTEGER, post_id INTEGER, PRIMARY KEY (user_id, post_id))')
    conn.execute('CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER, user_id INTEGER, content TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))')
    conn.execute('CREATE TABLE IF NOT EXISTS comment_likes (user_id INTEGER, comment_id INTEGER, PRIMARY KEY (user_id, comment_id))')
    conn.execute('CREATE TABLE IF NOT EXISTS bookmarks (user_id INTEGER, post_id INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (user_id, post_id))')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS error_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    ensure_user_columns(conn)
    ensure_post_columns(conn)
    conn.commit()
    conn.close()

def ensure_user_columns(conn):
    existing_columns = {
        row['name'] for row in conn.execute("PRAGMA table_info(users)").fetchall()
    }
    columns_to_add = {
        'name': 'TEXT',
        'email': 'TEXT',
        'bio': 'TEXT',
        'hobby': 'TEXT',
        'categories': 'TEXT',
        'social_links': 'TEXT',
        'facebook_link': 'TEXT',
        'x_link': 'TEXT',
        'instagram_link': 'TEXT',
        'website_link': 'TEXT',
        'youtube_link': 'TEXT',
        'profile_pic': 'TEXT',
        'created_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP'
    }
    for column, column_type in columns_to_add.items():
        if column not in existing_columns:
            conn.execute(f"ALTER TABLE users ADD COLUMN {column} {column_type}")

def ensure_post_columns(conn):
    existing_columns = {
        row['name'] for row in conn.execute("PRAGMA table_info(posts)").fetchall()
    }
    columns_to_add = {
        'slug': 'TEXT'
    }
    for column, column_type in columns_to_add.items():
        if column not in existing_columns:
            conn.execute(f"ALTER TABLE posts ADD COLUMN {column} {column_type}")

# --- ইউজার মডেল ---
class User(UserMixin):
    def __init__(self, id, username, is_admin, name=None, email=None, profile_pic=None):
        self.id = id
        self.username = username
        self.is_admin = is_admin
        self.name = name
        self.email = email
        self.profile_pic = profile_pic

    @property
    def display_name(self):
        return self.name or self.username

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user['id'], user['username'], user['is_admin'], user['name'], user['email'], user['profile_pic'])
    return None

# --- হেল্পার ফাংশন ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def slugify_text(text):
    cleaned = re.sub(r'[^\w\s-]', '', (text or '').strip().lower())
    cleaned = re.sub(r'[\s_-]+', '-', cleaned)
    return cleaned.strip('-') or 'post'

def calculate_read_time(content):
    plain_text = re.sub(r'<[^>]+>', ' ', content or '')
    words = re.findall(r'\w+', plain_text)
    minutes = max(1, math.ceil(len(words) / 200))
    return f"{minutes} মিনিট"

def calculate_read_time_minutes(content):
    plain_text = re.sub(r'<[^>]+>', ' ', content or '')
    words = re.findall(r'\w+', plain_text)
    return max(1, math.ceil(len(words) / 200))

def parse_json_list(value):
    if not value:
        return []
    if isinstance(value, list):
        return value
    try:
        data = json.loads(value)
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass
    return [item.strip() for item in str(value).split(',') if item.strip()]

CATEGORY_OPTIONS = [
    'পাইথন', 'ওয়েব ডেভেলপমেন্ট', 'ডেটা সায়েন্স', 'এআই', 'মোবাইল',
    'ডিজাইন', 'টেক নিউজ', 'সাইবার সিকিউরিটি', 'ডেভঅপস', 'ক্যারিয়ার'
]

HOBBY_OPTIONS = [
    'ভ্রমণ', 'গান শোনা', 'বই পড়া', 'খেলাধুলা', 'ফটোগ্রাফি',
    'রান্না', 'গেমিং', 'লেখালেখি', 'মুভি', 'ড্রইং'
]

def build_post_payload(rows):
    posts = []
    for row in rows:
        post = dict(row)
        author_name = row['author_name'] or row['username']
        post['author_display_name'] = author_name
        post['author_profile_pic'] = row['author_profile_pic']
        post['read_time'] = calculate_read_time(post.get('content', ''))
        post = format_post_meta(post)
        post['slug'] = post.get('slug') or slugify_text(post.get('title'))
        posts.append(post)
    return posts

def format_post_meta(post):
    minutes = calculate_read_time_minutes(post.get('content', ''))
    post['read_time_en'] = f"{minutes} min"
    created_at = post.get('created_at')
    short_date = created_at
    if created_at:
        try:
            parsed = datetime.fromisoformat(created_at)
        except ValueError:
            try:
                parsed = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                parsed = None
        if parsed:
            short_date = f"{parsed.strftime('%b')} {parsed.day}"
    post['short_date'] = short_date
    return post

def build_writer_payload(rows):
    writers = []
    for row in rows:
        writer = dict(row)
        writer['display_name'] = row['name'] or row['username']
        writers.append(writer)
    return writers

def get_post_slug(conn, post_id):
    row = conn.execute('SELECT slug, title FROM posts WHERE id = ?', (post_id,)).fetchone()
    if not row:
        return None
    return row['slug'] or slugify_text(row['title'])

def is_json_request():
    return request.headers.get('X-Requested-With') == 'fetch' or request.accept_mimetypes['application/json']

# গ্লোবাল ডাটা (বুকমার্ক) সব টেমপ্লেটে পাঠানোর জন্য
@app.context_processor
def inject_global_data():
    bookmarks = []
    if current_user.is_authenticated:
        conn = get_db_connection()
        bookmarks = conn.execute('''
            SELECT posts.id, posts.title, posts.thumbnail, posts.slug
            FROM bookmarks 
            JOIN posts ON bookmarks.post_id = posts.id 
            WHERE bookmarks.user_id = ? 
            ORDER BY bookmarks.created_at DESC
        ''', (current_user.id,)).fetchall()
        conn.close()
        bookmarks = [
            dict(row, slug=row['slug'] or slugify_text(row['title'])) for row in bookmarks
        ]
    return dict(my_bookmarks=bookmarks)

# --- অথেন্টিকেশন রাউটস ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        name = request.form.get('name') or None
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')
        terms = request.form.get('terms')

        if not terms:
            flash('Terms & Privacy গ্রহণ করতে হবে।')
            return redirect(url_for('signup'))
        if confirm_password is not None and password != confirm_password:
            flash('কনফার্ম পাসওয়ার্ড মিলছে না।')
            return redirect(url_for('signup'))

        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        conn = get_db_connection()
        try:
            # প্রথম ইউজার অটোমেটিক অ্যাডমিন হবে
            user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
            is_admin = 1 if user_count == 0 else 0

            existing = conn.execute('SELECT 1 FROM users WHERE email = ?', (email,)).fetchone()
            if existing:
                flash('এই ইমেইলটি ইতিমধ্যে ব্যবহৃত হয়েছে।')
                return redirect(url_for('signup'))

            conn.execute(
                'INSERT INTO users (username, password, is_admin, name, email) VALUES (?, ?, ?, ?, ?)',
                (email, hashed_pw, is_admin, name, email)
            )
            conn.commit()
            flash('অ্যাকাউন্ট তৈরি সফল! এখন লগইন করুন।')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('এই ইমেইলটি ইতিমধ্যে ব্যবহৃত হয়েছে।')
        finally:
            conn.close()
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            login_user(User(user['id'], user['username'], user['is_admin'], user['name'], user['email'], user['profile_pic']))
            return redirect(url_for('index'))
        else:
            flash('ভুল ইমেইল বা পাসওয়ার্ড।')
    return render_template('login.html')

@app.errorhandler(500)
def handle_internal_error(error):
    conn = get_db_connection()
    conn.execute("INSERT INTO error_logs (message) VALUES (?)", (str(error),))
    conn.commit()
    conn.close()
    return "Internal Server Error", 500

@app.errorhandler(404)
def handle_not_found(error):
    conn = get_db_connection()
    conn.execute("INSERT INTO error_logs (message) VALUES (?)", (str(error),))
    conn.commit()
    conn.close()
    return "Not Found", 404

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- পাবলিক ভিউ (শুধুমাত্র Approved & Active পোস্ট) ---

@app.route('/')
def index():
    conn = get_db_connection()
    # ফিল্টার: status='approved' AND is_active=1

    # ১. ট্রেন্ডিং (Views অনুযায়ী Top 5)
    trending_posts = conn.execute("""
        SELECT posts.*, users.username, users.name as author_name, users.profile_pic as author_profile_pic
        FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE posts.status='approved' AND posts.is_active=1
        ORDER BY posts.views DESC
        LIMIT 5
    """).fetchall()
    trending_posts = build_post_payload(trending_posts)

    # ২. লেটেস্ট (Top 10)
    latest_posts = conn.execute("""
        SELECT posts.*, users.username, users.name as author_name, users.profile_pic as author_profile_pic
        FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE posts.status='approved' AND posts.is_active=1
        ORDER BY posts.id DESC
        LIMIT 10
    """).fetchall()
    latest_posts = build_post_payload(latest_posts)

    # ৩. ক্যাটাগরি সেকশন
    categories = conn.execute("SELECT DISTINCT category FROM posts WHERE status='approved' AND is_active=1 LIMIT 2").fetchall()
    category_sections = []
    for cat in categories:
        cat_name = cat['category']
        posts = conn.execute("""
            SELECT posts.*, users.username, users.name as author_name, users.profile_pic as author_profile_pic
            FROM posts
            JOIN users ON posts.user_id = users.id
            WHERE posts.category = ? AND posts.status='approved' AND posts.is_active=1
            ORDER BY posts.id DESC
            LIMIT 3
        """, (cat_name,)).fetchall()
        posts = build_post_payload(posts)
        if posts:
            category_sections.append({'name': cat_name, 'posts': posts})

    all_categories = conn.execute("SELECT DISTINCT category FROM posts WHERE status='approved' AND is_active=1").fetchall()

    top_writers = conn.execute("""
        SELECT users.id, users.username, users.name, users.profile_pic,
               COUNT(posts.id) as post_count,
               COALESCE(SUM(posts.views), 0) as total_views
        FROM users
        JOIN posts ON posts.user_id = users.id
        WHERE posts.status='approved' AND posts.is_active=1
        GROUP BY users.id
        ORDER BY total_views DESC
        LIMIT 5
    """).fetchall()
    top_writers = build_writer_payload(top_writers)
    conn.close()

    return render_template('index.html', 
                           trending_posts=trending_posts, 
                           latest_posts=latest_posts, 
                           category_sections=category_sections, 
                           all_categories=all_categories,
                           top_writers=top_writers)

@app.route('/list')
def post_list():
    filter_type = request.args.get('type')
    cat_name = request.args.get('category')
    conn = get_db_connection()
    page_title = "All Posts"
    posts = []

    if filter_type == 'latest':
        page_title = "Latest Posts"
        posts = conn.execute("""
            SELECT posts.*, users.username, users.name as author_name, users.profile_pic as author_profile_pic
            FROM posts
            JOIN users ON posts.user_id = users.id
            WHERE posts.status='approved' AND posts.is_active=1
            ORDER BY posts.id DESC
        """).fetchall()
    elif filter_type == 'category' and cat_name:
        page_title = f"Category: {cat_name}"
        posts = conn.execute("""
            SELECT posts.*, users.username, users.name as author_name, users.profile_pic as author_profile_pic
            FROM posts
            JOIN users ON posts.user_id = users.id
            WHERE posts.category = ? AND posts.status='approved' AND posts.is_active=1
            ORDER BY posts.id DESC
        """, (cat_name,)).fetchall()
    posts = build_post_payload(posts)

    all_categories = conn.execute("SELECT DISTINCT category FROM posts WHERE status='approved' AND is_active=1").fetchall()
    conn.close()

    return render_template('list.html', posts=posts, title=page_title, all_categories=all_categories)

@app.route('/search')
def search():
    query = request.args.get('q')
    conn = get_db_connection()
    posts = []
    title = "সার্চ রেজাল্ট"
    if query:
        search_term = f"%{query}%"
        posts = conn.execute('''
            SELECT posts.*, users.username, users.name as author_name, users.profile_pic as author_profile_pic
            FROM posts
            JOIN users ON posts.user_id = users.id
            WHERE (title LIKE ? OR content LIKE ? OR category LIKE ?) 
            AND posts.status='approved' AND posts.is_active=1 
            ORDER BY posts.id DESC
        ''', (search_term, search_term, search_term)).fetchall()
        title = f"'{query}' এর জন্য সার্চ রেজাল্ট"
        posts = build_post_payload(posts)

    all_categories = conn.execute("SELECT DISTINCT category FROM posts WHERE status='approved' AND is_active=1").fetchall()
    conn.close()
    return render_template('list.html', posts=posts, title=title, all_categories=all_categories)

@app.route('/writers')
def writers_list():
    conn = get_db_connection()
    writers = conn.execute("""
        SELECT users.id, users.username, users.name, users.profile_pic,
               COUNT(posts.id) as post_count,
               COALESCE(SUM(posts.views), 0) as total_views
        FROM users
        JOIN posts ON posts.user_id = users.id
        WHERE posts.status='approved' AND posts.is_active=1
        GROUP BY users.id
        ORDER BY total_views DESC
    """).fetchall()
    writers = build_writer_payload(writers)
    all_categories = conn.execute("SELECT DISTINCT category FROM posts WHERE status='approved' AND is_active=1").fetchall()
    conn.close()
    return render_template('writers.html', writers=writers, all_categories=all_categories)

@app.route('/writer/<int:user_id>')
def public_profile(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        return "Not Found", 404
    selected_categories = parse_json_list(user['categories'])
    selected_hobbies = parse_json_list(user['hobby'])
    posts = conn.execute("""
        SELECT posts.*, users.username, users.name as author_name, users.profile_pic as author_profile_pic
        FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE posts.user_id = ? AND posts.status='approved' AND posts.is_active=1
        ORDER BY posts.id DESC
    """, (user_id,)).fetchall()
    posts = build_post_payload(posts)
    all_categories = conn.execute("SELECT DISTINCT category FROM posts WHERE status='approved' AND is_active=1").fetchall()
    conn.close()
    return render_template(
        'public_profile.html',
        user=user,
        posts=posts,
        all_categories=all_categories,
        selected_categories=selected_categories,
        selected_hobbies=selected_hobbies
    )

# --- ইউজার এরিয়া (পোস্ট তৈরি ও ম্যানেজ) ---

@app.route('/my_posts')
@login_required
def my_posts():
    # অ্যাডমিনের নিজস্ব পোস্ট পেইজ নেই, সে ড্যাশবোর্ডে যাবে
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts WHERE user_id = ? ORDER BY id DESC', (current_user.id,)).fetchall()
    total_posts = conn.execute('SELECT COUNT(*) FROM posts WHERE user_id = ?', (current_user.id,)).fetchone()[0]
    total_views = conn.execute('SELECT COALESCE(SUM(views), 0) FROM posts WHERE user_id = ?', (current_user.id,)).fetchone()[0]
    total_likes = conn.execute('''
        SELECT COUNT(*) FROM post_likes
        JOIN posts ON post_likes.post_id = posts.id
        WHERE posts.user_id = ?
    ''', (current_user.id,)).fetchone()[0]
    total_comments = conn.execute('''
        SELECT COUNT(*) FROM comments
        JOIN posts ON comments.post_id = posts.id
        WHERE posts.user_id = ?
    ''', (current_user.id,)).fetchone()[0]
    posts_last_30 = conn.execute(
        "SELECT COUNT(*) FROM posts WHERE user_id = ? AND created_at >= datetime('now', '-30 days')",
        (current_user.id,)
    ).fetchone()[0]
    conn.close()
    return render_template(
        'my_posts.html',
        posts=posts,
        total_posts=total_posts,
        total_views=total_views,
        total_likes=total_likes,
        total_comments=total_comments,
        posts_last_30=posts_last_30
    )

@app.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    # অ্যাডমিন পোস্ট করতে পারবে না
    if current_user.is_admin:
        return "অ্যাডমিন হিসেবে আপনি পোস্ট করতে পারবেন না।", 403

    if request.method == 'POST':
        title = request.form['title']
        intro = request.form['intro']
        raw_content = request.form['content']
        category = request.form['category']
        action = request.form.get('action') # 'draft' or 'submit'

        status = 'draft'
        if action == 'submit':
            status = 'pending'

        file = request.files['thumbnail']
        file_trending = request.files.get('trending_thumbnail')

        if title and raw_content:
            filename = None
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            trending_filename = filename
            if file_trending and allowed_file(file_trending.filename):
                trending_filename = secure_filename("trend_" + file_trending.filename)
                file_trending.save(os.path.join(app.config['UPLOAD_FOLDER'], trending_filename))

            # TOC Logic
            toc_list = []
            def replace_and_build_toc(match):
                toc_title = match.group(1)
                unique_id = f"toc-{len(toc_list)}"
                toc_list.append({'id': unique_id, 'title': toc_title})
                return f'<span id="{unique_id}" class="toc-marker" data-title="{toc_title}"></span>'
            processed_content = re.sub(r'\[toc:(.*?)\]', replace_and_build_toc, raw_content)
            toc_json = json.dumps(toc_list)
            slug = slugify_text(title)

            conn = get_db_connection()
            conn.execute('''
                INSERT INTO posts (user_id, title, intro, content, category, status, thumbnail, trending_thumbnail, toc_data, slug) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (current_user.id, title, intro, processed_content, category, status, filename, trending_filename, toc_json, slug))
            conn.commit()
            conn.close()

            if status == 'pending':
                flash('পোস্টটি এপ্রুভালের জন্য এডমিনের কাছে পাঠানো হয়েছে!')
            else:
                flash('পোস্টটি ড্রাফট হিসেবে সেভ করা হয়েছে।')

            return redirect(url_for('my_posts'))

    return render_template('create.html')

@app.route('/edit_post/<int:post_id>', methods=('GET', 'POST'))
@login_required
def edit_post(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()

    # চেক: পোস্টটি কি বর্তমান ইউজারের?
    if not post or post['user_id'] != current_user.id:
        conn.close()
        return "Access Denied", 403

    if request.method == 'POST':
        title = request.form['title']
        intro = request.form['intro']
        raw_content = request.form['content']
        category = request.form['category']
        action = request.form.get('action') # draft, submit (resubmit)

        status = post['status']
        # ইউজার যদি এডিট করে আবার সাবমিট করে, সেটা আবার পেন্ডিং হতে পারে, বা ড্রাফট করতে পারে
        if action == 'submit': status = 'pending'
        if action == 'draft': status = 'draft'

        toc_list = []
        def replace_and_build_toc(match):
            toc_title = match.group(1)
            unique_id = f"toc-{len(toc_list)}"
            toc_list.append({'id': unique_id, 'title': toc_title})
            return f'<span id="{unique_id}" class="toc-marker" data-title="{toc_title}"></span>'
        processed_content = re.sub(r'\[toc:(.*?)\]', replace_and_build_toc, raw_content)
        toc_json = json.dumps(toc_list)
        slug = slugify_text(title)

        # ফাইল আপলোড লজিক (সংক্ষিপ্ত রাখার জন্য এখানে পুরোটা রিপিট করা হলো না, create এর মতোই হবে)
        # ডাটাবেস আপডেট:
        conn.execute('UPDATE posts SET title=?, intro=?, content=?, category=?, status=?, toc_data=?, slug=? WHERE id=?', 
                     (title, intro, processed_content, category, status, toc_json, slug, post_id))
        conn.commit()
        conn.close()
        flash('পোস্ট আপডেট করা হয়েছে!')
        return redirect(url_for('my_posts'))

    conn.close()
    return render_template('edit.html', post=post)

@app.route('/delete_user_post/<int:post_id>')
@login_required
def delete_user_post(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    if post and post['user_id'] == current_user.id:
        conn.execute('DELETE FROM posts WHERE id = ?', (post_id,))
        conn.execute('DELETE FROM reports WHERE post_id = ?', (post_id,)) # রিপোর্টও ডিলিট
        conn.commit()
        flash('পোস্ট ডিলিট করা হয়েছে।', 'delete')
    conn.close()
    return redirect(url_for('my_posts'))

@app.route('/toggle_active_user/<int:post_id>')
@login_required
def toggle_active_user(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    if post and post['user_id'] == current_user.id:
        conn.execute('UPDATE posts SET is_active = NOT is_active WHERE id = ?', (post_id,))
        conn.commit()
    conn.close()
    return redirect(url_for('my_posts'))

# --- অ্যাডমিন এরিয়া (ড্যাশবোর্ড, অ্যাকশন, রিপোর্ট ম্যানেজমেন্ট) ---

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin: return "Access Denied", 403

    conn = get_db_connection()

    pending_count = conn.execute("SELECT COUNT(*) FROM posts WHERE status = 'pending'").fetchone()[0]
    post_report_count = conn.execute("SELECT COUNT(*) FROM reports WHERE post_id IS NOT NULL").fetchone()[0]
    comment_report_count = conn.execute("SELECT COUNT(*) FROM reports WHERE comment_id IS NOT NULL").fetchone()[0]
    total_posts = conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    conn.close()
    return render_template('admin_dashboard.html',
                           pending_count=pending_count,
                           post_report_count=post_report_count,
                           comment_report_count=comment_report_count,
                           total_posts=total_posts,
                           total_users=total_users)

@app.route('/admin/status')
@login_required
def admin_status():
    if not current_user.is_admin:
        return "Access Denied", 403
    conn = get_db_connection()
    total_views = conn.execute("SELECT COALESCE(SUM(views), 0) FROM posts").fetchone()[0]
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_posts = conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0]
    new_users_today = conn.execute(
        "SELECT COUNT(*) FROM users WHERE DATE(created_at) = DATE('now')"
    ).fetchone()[0]
    new_posts_today = conn.execute(
        "SELECT COUNT(*) FROM posts WHERE DATE(created_at) = DATE('now')"
    ).fetchone()[0]
    errors_today = conn.execute(
        "SELECT COUNT(*) FROM error_logs WHERE DATE(created_at) = DATE('now')"
    ).fetchone()[0]
    avg_read_time_minutes = conn.execute(
        "SELECT AVG(LENGTH(content)) FROM posts WHERE status='approved' AND is_active=1"
    ).fetchone()[0]
    avg_read_time_minutes = 0 if avg_read_time_minutes is None else avg_read_time_minutes
    avg_read_time_minutes = max(1, math.ceil((avg_read_time_minutes / 5) / 200))
    uptime_seconds = int(time.time() - APP_START_TIME)
    uptime_hours = uptime_seconds // 3600
    uptime_minutes = (uptime_seconds % 3600) // 60
    conn.close()
    return render_template(
        'admin_status.html',
        total_views=total_views,
        total_users=total_users,
        total_posts=total_posts,
        new_users_today=new_users_today,
        new_posts_today=new_posts_today,
        errors_today=errors_today,
        uptime_hours=uptime_hours,
        uptime_minutes=uptime_minutes,
        avg_read_time_minutes=avg_read_time_minutes
    )

@app.route('/admin/pending')
@login_required
def admin_pending_posts():
    if not current_user.is_admin:
        return "Access Denied", 403
    conn = get_db_connection()
    pending_posts = conn.execute('''
        SELECT posts.*, users.username, users.name as author_name, users.profile_pic as author_profile_pic
        FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE posts.status = 'pending'
        ORDER BY posts.created_at DESC
    ''').fetchall()
    conn.close()
    pending_posts = build_post_payload(pending_posts)
    return render_template('admin_pending.html', pending_posts=pending_posts)

@app.route('/admin/reports')
@login_required
def admin_reports():
    if not current_user.is_admin:
        return "Access Denied", 403
    conn = get_db_connection()
    post_reports = conn.execute('''
        SELECT reports.*, posts.title, posts.slug as post_slug, posts.thumbnail,
               users.username as reporter_name
        FROM reports
        JOIN posts ON reports.post_id = posts.id
        JOIN users ON reports.reporter_id = users.id
        WHERE reports.post_id IS NOT NULL
        ORDER BY reports.created_at DESC
    ''').fetchall()
    post_reports = [
        dict(row, post_slug=row['post_slug'] or slugify_text(row['title']))
        for row in post_reports
    ]

    comment_reports = conn.execute('''
        SELECT reports.*, comments.content as comment_content, posts.title as post_title,
               posts.slug as post_slug, posts.id as post_id, users.username as reporter_name
        FROM reports
        JOIN comments ON reports.comment_id = comments.id
        JOIN posts ON comments.post_id = posts.id
        JOIN users ON reports.reporter_id = users.id
        WHERE reports.comment_id IS NOT NULL
        ORDER BY reports.created_at DESC
    ''').fetchall()
    comment_reports = [
        dict(row, post_slug=row['post_slug'] or slugify_text(row['post_title']))
        for row in comment_reports
    ]
    conn.close()
    return render_template('admin_reports.html', post_reports=post_reports, comment_reports=comment_reports)

@app.route('/manage_posts')
@login_required
def manage_posts():
    if not current_user.is_admin:
        return "Access Denied", 403

    search_query = request.args.get('q', '').strip()
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
    page = max(1, page)
    per_page = 10
    offset = (page - 1) * per_page

    conn = get_db_connection()
    query_filters = ""
    params = []
    if search_query:
        query_filters = "WHERE title LIKE ?"
        params.append(f"%{search_query}%")

    total_posts = conn.execute(
        f"SELECT COUNT(*) FROM posts {query_filters}",
        params
    ).fetchone()[0]

    posts = conn.execute(
        f"SELECT * FROM posts {query_filters} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()
    conn.close()

    posts = [
        dict(row, slug=row['slug'] or slugify_text(row['title']))
        for row in posts
    ]
    total_pages = max(1, math.ceil(total_posts / per_page))

    return render_template(
        'manage.html',
        posts=posts,
        page=page,
        total_pages=total_pages,
        search_query=search_query
    )

@app.route('/preview/<int:post_id>')
@login_required
def admin_preview(post_id):
    if not current_user.is_admin:
        return "Access Denied", 403
    conn = get_db_connection()
    post = conn.execute('''
        SELECT posts.*, users.username, users.name as author_name, users.profile_pic as author_profile_pic
        FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE posts.id = ?
    ''', (post_id,)).fetchone()
    conn.close()
    if not post:
        return "Not Found", 404
    post = dict(post)
    post['author_display_name'] = post['author_name'] or post['username']
    post['read_time'] = calculate_read_time(post.get('content', ''))
    post['slug'] = post.get('slug') or slugify_text(post.get('title'))
    toc_items = json.loads(post['toc_data']) if post['toc_data'] else []
    return render_template('preview.html', post=post, content=post['content'], toc_items=toc_items)

@app.route('/admin_action_post/<int:post_id>/<action>')
@login_required
def admin_action_post(post_id, action):
    if not current_user.is_admin: return "Access Denied", 403
    conn = get_db_connection()

    if action == 'approve':
        conn.execute("UPDATE posts SET status = 'approved' WHERE id = ?", (post_id,))
        flash('পোস্ট এপ্রুভ করা হয়েছে!')
    elif action == 'reject':
        conn.execute("UPDATE posts SET status = 'rejected' WHERE id = ?", (post_id,))
        flash('পোস্ট রিজেক্ট করা হয়েছে।')
    elif action == 'delete':
        conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
        conn.execute("DELETE FROM reports WHERE post_id = ?", (post_id,))
        flash('পোস্ট পার্মানেন্টলি ডিলিট করা হয়েছে।', 'delete')

    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_action_report/<int:report_id>/<action>')
@login_required
def admin_action_report(report_id, action):
    if not current_user.is_admin: return "Access Denied", 403
    conn = get_db_connection()

    if action == 'dismiss':
        conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))
        flash('রিপোর্ট বাতিল করা হয়েছে।')
    elif action == 'delete_content':
        report = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        if report['post_id']:
            conn.execute("DELETE FROM posts WHERE id = ?", (report['post_id'],))
            flash('রিপোর্ট করা পোস্ট ডিলিট করা হয়েছে।', 'delete')
        elif report['comment_id']:
            conn.execute("DELETE FROM comments WHERE id = ?", (report['comment_id'],))
            flash('রিপোর্ট করা কমেন্ট ডিলিট করা হয়েছে।', 'delete')
        conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))

    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/toggle_status/<int:post_id>')
@login_required
def toggle_status(post_id):
    if not current_user.is_admin:
        return "Access Denied", 403
    conn = get_db_connection()
    conn.execute("UPDATE posts SET is_active = NOT is_active WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()
    flash('পোস্ট স্ট্যাটাস আপডেট করা হয়েছে।')
    return redirect(request.referrer or url_for('manage_posts'))

@app.route('/delete_post/<int:post_id>')
@login_required
def delete_post(post_id):
    if not current_user.is_admin:
        return "Access Denied", 403
    conn = get_db_connection()
    conn.execute("DELETE FROM post_likes WHERE post_id = ?", (post_id,))
    conn.execute("DELETE FROM bookmarks WHERE post_id = ?", (post_id,))
    comments = conn.execute("SELECT id FROM comments WHERE post_id = ?", (post_id,)).fetchall()
    for comment in comments:
        conn.execute("DELETE FROM comment_likes WHERE comment_id = ?", (comment['id'],))
    conn.execute("DELETE FROM comments WHERE post_id = ?", (post_id,))
    conn.execute("DELETE FROM reports WHERE post_id = ?", (post_id,))
    conn.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()
    flash('পোস্ট ডিলিট করা হয়েছে।', 'delete')
    return redirect(request.referrer or url_for('manage_posts'))

# --- রিপোর্ট সাবমিশন (ইউজার সাইড) ---
@app.route('/report_content', methods=['POST'])
@login_required
def report_content():
    reason = request.form.get('reason')
    post_id = request.form.get('post_id')
    comment_id = request.form.get('comment_id')

    if reason:
        conn = get_db_connection()
        conn.execute("INSERT INTO reports (reporter_id, post_id, comment_id, reason) VALUES (?, ?, ?, ?)",
                     (current_user.id, post_id, comment_id, reason))
        conn.commit()
        conn.close()
        if not is_json_request():
            flash('আপনার রিপোর্ট এডমিনের কাছে পাঠানো হয়েছে।')

    if is_json_request():
        return jsonify({"success": True})
    return redirect(request.referrer or url_for('index'))

# --- ডিটেইলস পেজ ---
@app.route('/post/<int:post_id>')
def post_redirect(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT id, title, slug FROM posts WHERE id = ?', (post_id,)).fetchone()
    conn.close()
    if not post:
        return "Not Found", 404
    slug = post['slug'] or slugify_text(post['title'])
    return redirect(url_for('post_detail', post_id=post_id, slug=slug))

@app.route('/post/<int:post_id>/<slug>')
def post_detail(post_id, slug):
    conn = get_db_connection()
    post = conn.execute('''
        SELECT posts.*, users.username, users.name as author_name, users.profile_pic as author_profile_pic
        FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE posts.id = ?
    ''', (post_id,)).fetchone()

    if not post: 
        conn.close()
        return "Not Found", 404
    post = dict(post)
    post['author_display_name'] = post['author_name'] or post['username']
    post['read_time'] = calculate_read_time(post.get('content', ''))
    post['slug'] = post.get('slug') or slugify_text(post.get('title'))
    post = format_post_meta(post)

    # অ্যাক্সেস লজিক:
    is_author = current_user.is_authenticated and post['user_id'] == current_user.id
    is_admin = current_user.is_authenticated and current_user.is_admin
    is_published = (post['status'] == 'approved' and post['is_active'] == 1)

    # যদি প্রকাশিত না হয়, এবং ইউজার লেখক বা অ্যাডমিন না হয় -> এক্সেস নেই
    if not is_published and not is_author and not is_admin:
        conn.close()
        return "এই পোস্টটি দেখার অনুমতি নেই বা এটি প্রকাশিত হয়নি।", 403

    # ভিউ কাউন্ট (শুধুমাত্র পাবলিক ভিউতে বাড়বে)
    if is_published and not is_admin:
        conn.execute('UPDATE posts SET views = views + 1 WHERE id = ?', (post_id,))
        conn.commit()

    # রিলেটেড পোস্ট (শুধু এপ্রুভড)
    related_posts = conn.execute("""
        SELECT posts.*, users.username, users.name as author_name, users.profile_pic as author_profile_pic
        FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE posts.category = ? AND posts.id != ? AND posts.status='approved' AND posts.is_active=1
        ORDER BY posts.id DESC LIMIT 3
    """, (post['category'], post_id)).fetchall()
    related_posts = build_post_payload(related_posts)

    # কমেন্ট এবং লাইক ডাটা
    comments_data = conn.execute('SELECT comments.*, users.username, (SELECT COUNT(*) FROM comment_likes WHERE comment_id = comments.id) as like_count FROM comments JOIN users ON comments.user_id = users.id WHERE post_id = ? ORDER BY id DESC', (post_id,)).fetchall()
    post_like_count = conn.execute('SELECT COUNT(*) FROM post_likes WHERE post_id = ?', (post_id,)).fetchone()[0]

    user_liked_post = False
    is_bookmarked = False
    liked_comments = []

    if current_user.is_authenticated:
        user_liked_post = conn.execute('SELECT 1 FROM post_likes WHERE user_id = ? AND post_id = ?', (current_user.id, post_id)).fetchone() is not None
        is_bookmarked = conn.execute('SELECT 1 FROM bookmarks WHERE user_id = ? AND post_id = ?', (current_user.id, post_id)).fetchone() is not None
        liked_comments_data = conn.execute('SELECT comment_id FROM comment_likes WHERE user_id = ?', (current_user.id,)).fetchall()
        liked_comments = [row[0] for row in liked_comments_data]

    toc_items = json.loads(post['toc_data']) if post['toc_data'] else []

    conn.close()
    return render_template(
        'detail.html',
        post=post,
        content=post['content'],
        toc_items=toc_items,
        related_posts=related_posts,
        comments=comments_data,
        post_like_count=post_like_count,
        user_liked_post=user_liked_post,
        liked_comments=liked_comments,
        is_bookmarked=is_bookmarked
    )

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def manage_profile():
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()
    if not user:
        conn.close()
        return "Not Found", 404
    if request.method == 'POST':
        name = request.form.get('name') or None
        email = request.form.get('email') or None
        bio = request.form.get('bio') or None
        selected_hobbies = request.form.getlist('hobby')
        selected_categories = request.form.getlist('categories')
        facebook_link = request.form.get('facebook_link') or None
        x_link = request.form.get('x_link') or None
        instagram_link = request.form.get('instagram_link') or None
        website_link = request.form.get('website_link') or None
        youtube_link = request.form.get('youtube_link') or None
        profile_pic = user['profile_pic']

        if len(selected_hobbies) > 3:
            conn.close()
            flash('সর্বোচ্চ ৩টি হবি সিলেক্ট করতে পারবেন।')
            return redirect(url_for('manage_profile'))
        if len(selected_categories) > 3:
            conn.close()
            flash('সর্বোচ্চ ৩টি ক্যাটাগরি সিলেক্ট করতে পারবেন।')
            return redirect(url_for('manage_profile'))

        file = request.files.get('profile_pic')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['PROFILE_UPLOAD_FOLDER'], filename))
            profile_pic = filename

        new_password = request.form.get('new_password')
        current_password = request.form.get('current_password')
        confirm_password = request.form.get('confirm_password')
        if new_password:
            if not current_password or not check_password_hash(user['password'], current_password):
                conn.close()
                flash('বর্তমান পাসওয়ার্ড সঠিক নয়।')
                return redirect(url_for('manage_profile'))
            if new_password != confirm_password:
                conn.close()
                flash('নতুন পাসওয়ার্ড মিলছে না।')
                return redirect(url_for('manage_profile'))
            hashed_pw = generate_password_hash(new_password, method='pbkdf2:sha256')
            conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_pw, current_user.id))

        conn.execute('''
            UPDATE users
            SET name = ?, email = ?, bio = ?, hobby = ?, categories = ?, facebook_link = ?, x_link = ?, instagram_link = ?, website_link = ?, youtube_link = ?, profile_pic = ?
            WHERE id = ?
        ''', (
            name,
            email,
            bio,
            json.dumps(selected_hobbies),
            json.dumps(selected_categories),
            facebook_link,
            x_link,
            instagram_link,
            website_link,
            youtube_link,
            profile_pic,
            current_user.id
        ))
        conn.commit()
        conn.close()
        flash('প্রোফাইল আপডেট করা হয়েছে।')
        return redirect(url_for('manage_profile'))

    conn.close()
    return render_template(
        'profile.html',
        user=user,
        category_options=CATEGORY_OPTIONS,
        hobby_options=HOBBY_OPTIONS,
        selected_categories=parse_json_list(user['categories']),
        selected_hobbies=parse_json_list(user['hobby'])
    )

# --- ইন্টারঅ্যাকশন রাউটস (লাইক, কমেন্ট, বুকমার্ক) ---
@app.route('/like_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def like_post(post_id):
    conn = get_db_connection()
    existing = conn.execute('SELECT * FROM post_likes WHERE user_id = ? AND post_id = ?', (current_user.id, post_id)).fetchone()
    if existing: conn.execute('DELETE FROM post_likes WHERE user_id = ? AND post_id = ?', (current_user.id, post_id))
    else: conn.execute('INSERT INTO post_likes (user_id, post_id) VALUES (?, ?)', (current_user.id, post_id))
    conn.commit()
    count = conn.execute('SELECT COUNT(*) FROM post_likes WHERE post_id = ?', (post_id,)).fetchone()[0]
    slug = get_post_slug(conn, post_id)
    conn.close()
    if is_json_request():
        return jsonify({"liked": not existing, "count": count})
    if not slug:
        return redirect(url_for('index'))
    return redirect(url_for('post_detail', post_id=post_id, slug=slug))

@app.route('/add_comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    content = request.form.get('content') or (request.json or {}).get('content')
    conn = get_db_connection()
    slug = get_post_slug(conn, post_id)
    if content:
        cursor = conn.execute(
            'INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
            (post_id, current_user.id, content)
        )
        conn.commit()
        comment_id = cursor.lastrowid
        comment = conn.execute(
            'SELECT comments.id, comments.content, comments.created_at, users.username '
            'FROM comments JOIN users ON comments.user_id = users.id WHERE comments.id = ?',
            (comment_id,)
        ).fetchone()
        conn.close()
        if is_json_request():
            return jsonify({
                "id": comment['id'],
                "content": comment['content'],
                "created_at": comment['created_at'],
                "username": comment['username']
            })
    else:
        conn.close()
    if is_json_request():
        return jsonify({"error": "Missing content"}), 400
    if not slug:
        return redirect(url_for('index'))
    return redirect(url_for('post_detail', post_id=post_id, slug=slug))

@app.route('/like_comment/<int:comment_id>/<int:post_id>', methods=['GET', 'POST'])
@login_required
def like_comment(comment_id, post_id):
    conn = get_db_connection()
    existing = conn.execute('SELECT * FROM comment_likes WHERE user_id = ? AND comment_id = ?', (current_user.id, comment_id)).fetchone()
    if existing: conn.execute('DELETE FROM comment_likes WHERE user_id = ? AND comment_id = ?', (current_user.id, comment_id))
    else: conn.execute('INSERT INTO comment_likes (user_id, comment_id) VALUES (?, ?)', (current_user.id, comment_id))
    conn.commit()
    count = conn.execute('SELECT COUNT(*) FROM comment_likes WHERE comment_id = ?', (comment_id,)).fetchone()[0]
    slug = get_post_slug(conn, post_id)
    conn.close()
    if is_json_request():
        return jsonify({"liked": not existing, "count": count, "comment_id": comment_id})
    if not slug:
        return redirect(url_for('index'))
    return redirect(url_for('post_detail', post_id=post_id, slug=slug))

@app.route('/toggle_bookmark/<int:post_id>', methods=['GET', 'POST'])
@login_required
def toggle_bookmark(post_id):
    conn = get_db_connection()
    existing = conn.execute('SELECT * FROM bookmarks WHERE user_id = ? AND post_id = ?', (current_user.id, post_id)).fetchone()
    if existing:
        conn.execute('DELETE FROM bookmarks WHERE user_id = ? AND post_id = ?', (current_user.id, post_id))
    else:
        conn.execute('INSERT INTO bookmarks (user_id, post_id) VALUES (?, ?)', (current_user.id, post_id))
    conn.commit()
    conn.close()
    if is_json_request():
        return jsonify({"bookmarked": not existing})
    flash('বুকমার্ক রিমুভ করা হয়েছে।' if existing else 'বুকমার্ক যুক্ত করা হয়েছে!')
    return redirect(request.referrer or url_for('index'))

if __name__ == '__main__':
    init_db()
    print("Server is running on http://0.0.0.0:8080")
    app.run(host='0.0.0.0', port=8080, debug=True)
