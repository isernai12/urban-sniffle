import os
import re
import json
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = 'super_secret_key_change_this_in_production'

# কনফিগারেশন
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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
            is_admin INTEGER DEFAULT 0
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

    conn.commit()
    conn.close()

# --- ইউজার মডেল ---
class User(UserMixin):
    def __init__(self, id, username, is_admin):
        self.id = id
        self.username = username
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user: return User(user['id'], user['username'], user['is_admin'])
    return None

# --- হেল্পার ফাংশন ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# গ্লোবাল ডাটা (বুকমার্ক) সব টেমপ্লেটে পাঠানোর জন্য
@app.context_processor
def inject_global_data():
    bookmarks = []
    if current_user.is_authenticated:
        conn = get_db_connection()
        bookmarks = conn.execute('''
            SELECT posts.id, posts.title, posts.thumbnail 
            FROM bookmarks 
            JOIN posts ON bookmarks.post_id = posts.id 
            WHERE bookmarks.user_id = ? 
            ORDER BY bookmarks.created_at DESC
        ''', (current_user.id,)).fetchall()
        conn.close()
    return dict(my_bookmarks=bookmarks)

# --- অথেন্টিকেশন রাউটস ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        conn = get_db_connection()
        try:
            # প্রথম ইউজার অটোমেটিক অ্যাডমিন হবে
            user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
            is_admin = 1 if user_count == 0 else 0

            conn.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)', 
                         (username, hashed_pw, is_admin))
            conn.commit()
            flash('অ্যাকাউন্ট তৈরি সফল! এখন লগইন করুন।')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('এই ইউজারনেমটি ইতিমধ্যে ব্যবহৃত হয়েছে।')
        finally:
            conn.close()
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            login_user(User(user['id'], user['username'], user['is_admin']))
            return redirect(url_for('index'))
        else:
            flash('ভুল ইউজারনেম বা পাসওয়ার্ড।')
    return render_template('login.html')

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
    trending_posts = conn.execute("SELECT * FROM posts WHERE status='approved' AND is_active=1 ORDER BY views DESC LIMIT 5").fetchall()

    # ২. লেটেস্ট (Top 10)
    latest_posts = conn.execute("SELECT * FROM posts WHERE status='approved' AND is_active=1 ORDER BY id DESC LIMIT 10").fetchall()

    # ৩. ক্যাটাগরি সেকশন
    categories = conn.execute("SELECT DISTINCT category FROM posts WHERE status='approved' AND is_active=1 LIMIT 2").fetchall()
    category_sections = []
    for cat in categories:
        cat_name = cat['category']
        posts = conn.execute("SELECT * FROM posts WHERE category = ? AND status='approved' AND is_active=1 ORDER BY id DESC LIMIT 3", (cat_name,)).fetchall()
        if posts:
            category_sections.append({'name': cat_name, 'posts': posts})

    all_categories = conn.execute("SELECT DISTINCT category FROM posts WHERE status='approved' AND is_active=1").fetchall()
    conn.close()

    return render_template('index.html', 
                           trending_posts=trending_posts, 
                           latest_posts=latest_posts, 
                           category_sections=category_sections, 
                           all_categories=all_categories)

@app.route('/list')
def post_list():
    filter_type = request.args.get('type')
    cat_name = request.args.get('category')
    conn = get_db_connection()
    page_title = "সকল পোস্ট"
    posts = []

    if filter_type == 'latest':
        page_title = "সর্বশেষ সকল পোস্ট"
        posts = conn.execute("SELECT * FROM posts WHERE status='approved' AND is_active=1 ORDER BY id DESC").fetchall()
    elif filter_type == 'category' and cat_name:
        page_title = f"ক্যাটাগরি: {cat_name}"
        posts = conn.execute("SELECT * FROM posts WHERE category = ? AND status='approved' AND is_active=1 ORDER BY id DESC", (cat_name,)).fetchall()

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
            SELECT * FROM posts 
            WHERE (title LIKE ? OR content LIKE ? OR category LIKE ?) 
            AND status='approved' AND is_active=1 
            ORDER BY id DESC
        ''', (search_term, search_term, search_term)).fetchall()
        title = f"'{query}' এর জন্য সার্চ রেজাল্ট"

    all_categories = conn.execute("SELECT DISTINCT category FROM posts WHERE status='approved' AND is_active=1").fetchall()
    conn.close()
    return render_template('list.html', posts=posts, title=title, all_categories=all_categories)

# --- ইউজার এরিয়া (পোস্ট তৈরি ও ম্যানেজ) ---

@app.route('/my_posts')
@login_required
def my_posts():
    # অ্যাডমিনের নিজস্ব পোস্ট পেইজ নেই, সে ড্যাশবোর্ডে যাবে
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts WHERE user_id = ? ORDER BY id DESC', (current_user.id,)).fetchall()
    conn.close()
    return render_template('my_posts.html', posts=posts)

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

            conn = get_db_connection()
            conn.execute('''
                INSERT INTO posts (user_id, title, intro, content, category, status, thumbnail, trending_thumbnail, toc_data) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (current_user.id, title, intro, processed_content, category, status, filename, trending_filename, toc_json))
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

        # ফাইল আপলোড লজিক (সংক্ষিপ্ত রাখার জন্য এখানে পুরোটা রিপিট করা হলো না, create এর মতোই হবে)
        # ডাটাবেস আপডেট:
        conn.execute('UPDATE posts SET title=?, intro=?, content=?, category=?, status=? WHERE id=?', 
                     (title, intro, raw_content, category, status, post_id))
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
        flash('পোস্ট ডিলিট করা হয়েছে।')
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

    # ১. পেন্ডিং পোস্ট (রিভিউয়ের জন্য)
    pending_posts = conn.execute('''
        SELECT posts.*, users.username 
        FROM posts JOIN users ON posts.user_id = users.id 
        WHERE status = 'pending'
    ''').fetchall()

    # ২. পোস্ট রিপোর্টস
    post_reports = conn.execute('''
        SELECT reports.*, posts.title, users.username as reporter_name
        FROM reports 
        JOIN posts ON reports.post_id = posts.id
        JOIN users ON reports.reporter_id = users.id
        WHERE reports.post_id IS NOT NULL
    ''').fetchall()

    # ৩. কমেন্ট রিপোর্টস
    comment_reports = conn.execute('''
        SELECT reports.*, comments.content as comment_content, users.username as reporter_name
        FROM reports 
        JOIN comments ON reports.comment_id = comments.id
        JOIN users ON reports.reporter_id = users.id
        WHERE reports.comment_id IS NOT NULL
    ''').fetchall()

    conn.close()
    return render_template('admin_dashboard.html', 
                           pending_posts=pending_posts, 
                           post_reports=post_reports, 
                           comment_reports=comment_reports)

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
        flash('পোস্ট পার্মানেন্টলি ডিলিট করা হয়েছে।')

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
            flash('রিপোর্ট করা পোস্ট ডিলিট করা হয়েছে।')
        elif report['comment_id']:
            conn.execute("DELETE FROM comments WHERE id = ?", (report['comment_id'],))
            flash('রিপোর্ট করা কমেন্ট ডিলিট করা হয়েছে।')
        conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))

    conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))

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
        flash('আপনার রিপোর্ট এডমিনের কাছে পাঠানো হয়েছে।')

    return redirect(request.referrer or url_for('index'))

# --- ডিটেইলস পেজ ---
@app.route('/post/<int:post_id>')
def post_detail(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()

    if not post: 
        conn.close()
        return "Not Found", 404

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
    related_posts = conn.execute("SELECT * FROM posts WHERE category = ? AND id != ? AND status='approved' AND is_active=1 ORDER BY id DESC LIMIT 3", (post['category'], post_id)).fetchall()

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
    return render_template('detail.html', post=post, content=post['content'], toc_items=toc_items, related_posts=related_posts, comments=comments_data, post_like_count=post_like_count, user_liked_post=user_liked_post, liked_comments=liked_comments, is_bookmarked=is_bookmarked)

# --- ইন্টারঅ্যাকশন রাউটস (লাইক, কমেন্ট, বুকমার্ক) ---
@app.route('/like_post/<int:post_id>')
@login_required
def like_post(post_id):
    conn = get_db_connection()
    existing = conn.execute('SELECT * FROM post_likes WHERE user_id = ? AND post_id = ?', (current_user.id, post_id)).fetchone()
    if existing: conn.execute('DELETE FROM post_likes WHERE user_id = ? AND post_id = ?', (current_user.id, post_id))
    else: conn.execute('INSERT INTO post_likes (user_id, post_id) VALUES (?, ?)', (current_user.id, post_id))
    conn.commit()
    conn.close()
    return redirect(url_for('post_detail', post_id=post_id))

@app.route('/add_comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    content = request.form['content']
    if content:
        conn = get_db_connection()
        conn.execute('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)', (post_id, current_user.id, content))
        conn.commit()
        conn.close()
    return redirect(url_for('post_detail', post_id=post_id))

@app.route('/like_comment/<int:comment_id>/<int:post_id>')
@login_required
def like_comment(comment_id, post_id):
    conn = get_db_connection()
    existing = conn.execute('SELECT * FROM comment_likes WHERE user_id = ? AND comment_id = ?', (current_user.id, comment_id)).fetchone()
    if existing: conn.execute('DELETE FROM comment_likes WHERE user_id = ? AND comment_id = ?', (current_user.id, comment_id))
    else: conn.execute('INSERT INTO comment_likes (user_id, comment_id) VALUES (?, ?)', (current_user.id, comment_id))
    conn.commit()
    conn.close()
    return redirect(url_for('post_detail', post_id=post_id))

@app.route('/toggle_bookmark/<int:post_id>')
@login_required
def toggle_bookmark(post_id):
    conn = get_db_connection()
    existing = conn.execute('SELECT * FROM bookmarks WHERE user_id = ? AND post_id = ?', (current_user.id, post_id)).fetchone()
    if existing:
        conn.execute('DELETE FROM bookmarks WHERE user_id = ? AND post_id = ?', (current_user.id, post_id))
        flash('বুকমার্ক রিমুভ করা হয়েছে।')
    else:
        conn.execute('INSERT INTO bookmarks (user_id, post_id) VALUES (?, ?)', (current_user.id, post_id))
        flash('বুকমার্ক যুক্ত করা হয়েছে!')
    conn.commit()
    conn.close()
    return redirect(request.referrer or url_for('index'))

if __name__ == '__main__':
    init_db()
    print("Server is running on http://0.0.0.0:8080")
    app.run(host='0.0.0.0', port=8080, debug=True)