from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import uuid
# SocketIO 관련 설정 개선
from engineio.async_drivers import gevent  # gevent 드라이버 명시적 로드
from flask_socketio import SocketIO, join_room, leave_room, send, emit
from flask_wtf.csrf import CSRFProtect
import pytz
from functools import wraps
from flask_migrate import Migrate

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-make-it-complex'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['SESSION_COOKIE_SECURE'] = False  # 개발 환경에서는 False로 설정
app.config['SESSION_COOKIE_HTTPONLY'] = True  # JavaScript에서 쿠키 접근 불가
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)  # 세션 만료 시간 설정
app.config['MAX_REPORT_COUNT'] = 3  # 최대 신고 횟수

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database and other extensions
db = SQLAlchemy(app)
# SocketIO 설정 수정 - gevent 사용
socketio = SocketIO(app, async_mode='gevent', cors_allowed_origins='*')
csrf = CSRFProtect(app)
migrate = Migrate(app, db)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = '이 페이지에 접근하려면 로그인이 필요합니다.'
login_manager.login_message_category = 'warning'

# 커스텀 관리자 필요 데코레이터
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('관리자 권한이 필요합니다.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Define database models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    products = db.relationship('Product', backref='author', lazy=True)
    status = db.Column(db.String(20), default='active')  # active, suspended
    report_count = db.Column(db.Integer, default=0)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    profile_image = db.Column(db.String(200), default='default_profile.png')
    login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @property
    def is_suspended(self):
        return self.status == 'suspended'

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='active')  # active, blocked
    report_count = db.Column(db.Integer, default=0)
    view_count = db.Column(db.Integer, default=0)
    
    @property
    def is_blocked(self):
        return self.status == 'blocked'

class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.String(100), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('Message', backref='chat', lazy=True)
    
    product = db.relationship('Product', backref='chats')
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_chats')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_chats')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    chat_id = db.Column(db.Integer, db.ForeignKey('chat.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    user = db.relationship('User', backref='messages')

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_type = db.Column(db.String(20), nullable=False)  # 'product', 'user' 등
    target_id = db.Column(db.Integer, nullable=False)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, reviewed, resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    reporter = db.relationship('User', backref='reports')

# 전체 채팅을 위한 모델
class PublicMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    user = db.relationship('User', backref='public_messages')

# 접속 로그 기록
class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    ip_address = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)
    
    user = db.relationship('User', backref='access_logs')

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user and user.is_suspended:
        return None
    return user

# 보안 강화: 의심스러운 활동 기록
def log_activity(user_id, action, details=None, ip=None):
    ip_address = ip or request.remote_addr
    log_entry = AccessLog(
        user_id=user_id,
        ip_address=ip_address,
        action=action,
        details=details
    )  # 괄호 누락 수정
    db.session.add(log_entry)
    db.session.commit()

# 비밀번호 강도 검증
def validate_password(password):
    """비밀번호 강도 검증"""
    # 글자 수 제한 해제 (테스트 목적)
    return True, ""

# 메시지 전송 속도 제한 확인
def check_message_rate(user_id):
    """사용자의 메시지 전송 속도 제한 확인"""
    now = datetime.utcnow()
    one_minute_ago = now - timedelta(minutes=1)
    
    # 최근 1분간 전송한 메시지 수 확인
    recent_messages = Message.query.filter(
        Message.user_id == user_id,
        Message.timestamp >= one_minute_ago
    ).count()
    
    return recent_messages < 10  # 1분에 최대 10개 메시지 허용

# 보안 헤더 추가
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://kit.fontawesome.com https://cdn.socket.io; style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data:; connect-src 'self' wss: ws:;"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Routes
@app.route('/')
def index():
    try:
        products = Product.query.filter_by(status='active').order_by(Product.created_at.desc()).all()
        return render_template('index.html', products=products)
    except Exception as e:
        # 데이터베이스 오류 처리 - 개발 환경에서만 오류 메시지 표시
        if app.debug:
            flash(f'오류가 발생했습니다: {str(e)}', 'danger')
        else:
            flash('오류가 발생했습니다. 나중에 다시 시도해주세요.', 'danger')
        return render_template('index.html', products=[])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # 유효성 검사 - 글자 수 제한 해제 (테스트 목적)
        if not username or not email or not password or not confirm_password:
            flash('모든 필드를 입력해주세요.', 'danger')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('비밀번호가 일치하지 않습니다.', 'danger')
            return render_template('register.html')
        
        try:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('이미 존재하는 사용자명입니다.', 'danger')
                return render_template('register.html')
                
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash('이미 사용 중인 이메일입니다.', 'danger')
                return render_template('register.html')
            
            # 새 사용자 생성
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            
            log_activity(new_user.id, "회원가입", f"유저명: {username}, 이메일: {email}")
            
            flash('회원가입이 완료되었습니다. 로그인해주세요.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'회원가입 중 오류가 발생했습니다: {str(e)}', 'danger')
            return render_template('register.html')
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        # 유효성 검사
        if not username or not password:
            flash('사용자명과 비밀번호를 모두 입력해주세요.', 'danger')
            return render_template('login.html')
        
        # 사용자 검색
        user = User.query.filter_by(username=username).first()
        
        # 로그인 시도 기록
        if user:
            user.last_login_attempt = datetime.utcnow()
            
            # 로그인 시도 제한 확인
            if user.login_attempts >= 5:
                time_diff = (datetime.utcnow() - user.last_login_attempt).total_seconds() if user.last_login_attempt else 301
                if time_diff < 300:  # 5분 이내
                    log_activity(user.id, "로그인 시도 제한", f"사용자: {username}, 시도 횟수: {user.login_attempts}")
                    flash('로그인 시도 횟수를 초과했습니다. 5분 후에 다시 시도해주세요.', 'danger')
                    db.session.commit()
                    return render_template('login.html')
                else:
                    # 5분 지났으면 시도 횟수 초기화
                    user.login_attempts = 0
        
        # 계정 상태 확인
        if user and user.is_suspended:
            flash('이 계정은 현재 정지 상태입니다. 관리자에게 문의하세요.', 'danger')
            log_activity(user.id, "로그인 시도 (계정 정지)", f"사용자: {username}")
            return render_template('login.html')
            
        # 비밀번호 확인
        if not user or not user.check_password(password):
            if user:
                user.login_attempts += 1
                db.session.commit()
                
            flash('사용자명 또는 비밀번호가 올바르지 않습니다.', 'danger')
            log_activity(user.id if user else None, "로그인 실패", f"사용자명: {username}")
            return render_template('login.html')
            
        # 로그인 성공: 시도 횟수 초기화
        user.login_attempts = 0
        
        # 로그인 처리
        login_user(user, remember=remember)
        
        # 마지막 로그인 시간 업데이트
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        log_activity(user.id, "로그인 성공", f"사용자: {username}")
        
        flash('로그인되었습니다!', 'success')
        
        # 리디렉션
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect(url_for('index'))
        
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, "로그아웃", f"사용자: {current_user.username}")
    logout_user()
    flash('로그아웃되었습니다.', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    user_products = Product.query.filter_by(user_id=current_user.id).order_by(Product.created_at.desc()).all()
    return render_template('profile.html', products=user_products)

@app.route('/profile/<int:user_id>')  # URL 패턴 수정
def view_profile(user_id):
    user = User.query.get_or_404(user_id)
    user_products = Product.query.filter_by(user_id=user.id, status='active').order_by(Product.created_at.desc()).all()
    return render_template('view_profile.html', user=user, products=user_products)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if current_user.is_suspended:
        flash('계정이 정지 상태입니다. 상품을 등록할 수 없습니다.', 'danger')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        price = request.form.get('price')
        
        # 가격 필터링 및 검증
        try:
            price = float(price.replace(',', '').strip())
            if price <= 0:
                flash('가격은 0보다 커야 합니다.', 'danger')
                return redirect(url_for('add_product'))
        except ValueError:
            flash('가격 형식이 올바르지 않습니다.', 'danger')
            return redirect(url_for('add_product'))
        
        image = None
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                # 파일 형식 검증
                if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                    flash('지원되는 이미지 형식은 PNG, JPG, JPEG, GIF입니다.', 'danger')
                    return redirect(url_for('add_product'))
                
                filename = secure_filename(file.filename)
                # 파일명 충돌 방지를 위한 고유 식별자 추가
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                image = unique_filename
        
        new_product = Product(
            title=title,
            description=description,
            price=price,
            image=image,
            user_id=current_user.id
        )
        
        db.session.add(new_product)
        db.session.commit()
        
        log_activity(current_user.id, "상품 등록", f"상품: {title}, 가격: {price}")
        
        flash('상품이 추가되었습니다!', 'success')
        return redirect(url_for('index'))
    
    return render_template('add_product.html')

@app.route('/product/<int:product_id>')  # URL 패턴 수정
def view_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # 상품이 차단된 경우 확인
    if product.is_blocked and (not current_user.is_authenticated or (not current_user.is_admin and current_user.id != product.user_id)):
        flash('이 상품은 현재 이용할 수 없습니다.', 'warning')
        return redirect(url_for('index'))
    
    # 조회수 증가
    product.view_count += 1
    db.session.commit()
    
    return render_template('view_product.html', product=product)

@app.route('/product/<int:product_id>/edit', methods=['GET', 'POST'])  # URL 패턴 수정
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # 현재 사용자가 상품 작성자인지 확인
    if product.user_id != current_user.id:
        flash('상품을 수정할 권한이 없습니다.', 'danger')
        return redirect(url_for('view_product', product_id=product_id))
    
    if current_user.is_suspended:
        flash('계정이 정지 상태입니다. 상품을 수정할 수 없습니다.', 'danger')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        price = request.form.get('price')
        
        product.title = title
        product.description = description
        
        # 가격 필터링 및 검증
        try:
            price = float(price.replace(',', '').strip())
            if price <= 0:
                flash('가격은 0보다 커야 합니다.', 'danger')
                return redirect(url_for('edit_product', product_id=product_id))
            product.price = price
        except ValueError:
            flash('가격 형식이 올바르지 않습니다.', 'danger')
            return redirect(url_for('edit_product', product_id=product_id))
        
        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '':
                # 파일 형식 검증
                if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                    flash('지원되는 이미지 형식은 PNG, JPG, JPEG, GIF입니다.', 'danger')
                    return redirect(url_for('edit_product', product_id=product_id))
                
                # 기존 이미지 삭제
                if product.image:
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image))
                    except:
                        pass
                        
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                product.image = unique_filename
        
        db.session.commit()
        
        log_activity(current_user.id, "상품 수정", f"상품 ID: {product_id}, 제목: {title}")
        
        flash('상품이 수정되었습니다!', 'success')
        return redirect(url_for('view_product', product_id=product_id))
    
    return render_template('edit_product.html', product=product)

@app.route('/admin/products/<int:product_id>/delete', methods=['POST'])  # URL 패턴 수정
@admin_required
def admin_delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # 관련 데이터 삭제
    chats = Chat.query.filter_by(product_id=product_id).all()
    for chat in chats:
        Message.query.filter_by(chat_id=chat.id).delete()
        db.session.delete(chat)
        
    Report.query.filter_by(target_type='product', target_id=product_id).delete()
    
    # 이미지 삭제
    if product.image:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image))
        except Exception as e:
            app.logger.error(f"Error deleting image: {str(e)}")
    
    db.session.delete(product)
    db.session.commit()
    
    flash('상품이 삭제되었습니다!', 'success')
    return redirect(url_for('admin_products'))

@app.route('/product/<int:product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # 현재 사용자가 상품 작성자이거나 관리자인지 확인
    if product.user_id != current_user.id and not current_user.is_admin:
        flash('상품을 삭제할 권한이 없습니다.', 'danger')
        return redirect(url_for('view_product', product_id=product_id))
    
    # 관련 채팅 및 메시지 삭제
    chats = Chat.query.filter_by(product_id=product_id).all()
    for chat in chats:
        Message.query.filter_by(chat_id=chat.id).delete()
        db.session.delete(chat)
    
    # 이 상품과 관련된 신고 삭제
    Report.query.filter_by(target_type='product', target_id=product_id).delete()
    
    # 상품 이미지 삭제
    if product.image:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image))
        except:
            pass
    
    db.session.delete(product)
    db.session.commit()
    
    flash('상품이 삭제되었습니다!', 'success')
    return redirect(url_for('index'))

@app.route('/chat/<int:product_id>/<int:seller_id>', methods=['GET', 'POST'])  # URL 패턴 수정
@login_required
def chat(product_id, seller_id):
    if current_user.is_suspended:
        flash('계정이 정지 상태입니다. 채팅 기능을 사용할 수 없습니다.', 'danger')
        return redirect(url_for('index'))
        
    product = Product.query.get_or_404(product_id)
    seller = User.query.get_or_404(seller_id)
    
    # 판매자가 실제로 상품 소유자인지 확인
    if product.user_id != seller_id:
        flash('이 상품에 대한 유효하지 않은 판매자입니다.', 'danger')
        return redirect(url_for('view_product', product_id=product_id))
    
    # 자신과 채팅할 수 없음
    if current_user.id == seller_id:
        flash('자신과 채팅할 수 없습니다.', 'danger')
        return redirect(url_for('view_product', product_id=product_id))
    
    # 판매자가 정지 상태인지 확인
    if seller.is_suspended:
        flash('이 판매자는 현재 이용할 수 없습니다.', 'warning')
        return redirect(url_for('view_product', product_id=product_id))
    
    # 상품이 차단되었는지 확인
    if product.is_blocked:
        flash('이 상품은 현재 이용할 수 없습니다.', 'warning')
        return redirect(url_for('index'))
    
    # 이 상품에 대해 이미 채팅이 존재하는지 확인
    chat_exists = Chat.query.filter_by(
        product_id=product_id,
        sender_id=current_user.id, 
        receiver_id=seller_id
    ).first() or Chat.query.filter_by(
        product_id=product_id,
        sender_id=seller_id, 
        receiver_id=current_user.id
    ).first()
    
    if chat_exists:
        # 채팅이 이미 존재하면 해당 채팅으로 리디렉션
        log_activity(current_user.id, "채팅방 입장", f"채팅 ID: {chat_exists.id}, 상품: {product.title}")
        return redirect(url_for('view_chat', chat_id=chat_exists.id))
    
    # 새 채팅 생성
    room_id = str(uuid.uuid4())
    new_chat = Chat(
        room_id=room_id,
        product_id=product_id,
        sender_id=current_user.id,
        receiver_id=seller_id
    )
    
    db.session.add(new_chat)
    db.session.commit()
    
    log_activity(current_user.id, "새 채팅방 생성", f"채팅 ID: {new_chat.id}, 상품: {product.title}")
    
    return redirect(url_for('view_chat', chat_id=new_chat.id))

@app.route('/chats')
@login_required
def chats():
    if current_user.is_suspended:
        flash('계정이 정지 상태입니다. 채팅 기능을 사용할 수 없습니다.', 'danger')
        return redirect(url_for('index'))
        
    # 현재 사용자가 발신자이거나 수신자인 모든 채팅 가져오기
    user_chats = Chat.query.filter(
        (Chat.sender_id == current_user.id) | (Chat.receiver_id == current_user.id)
    ).order_by(Chat.created_at.desc()).all()
    
    # 차단된 상품 관련 채팅 필터링
    active_chats = []
    for chat in user_chats:
        if not chat.product.is_blocked:
            active_chats.append(chat)
    
    return render_template('chats.html', chats=active_chats)

@app.route('/chat/view/<int:chat_id>')  # URL 패턴 수정
@login_required
def view_chat(chat_id):
    if current_user.is_suspended:
        flash('계정이 정지 상태입니다. 채팅 기능을 사용할 수 없습니다.', 'danger')
        return redirect(url_for('index'))
        
    chat = Chat.query.get_or_404(chat_id)
    
    # 현재 사용자가 이 채팅의 일부인지 확인
    if chat.sender_id != current_user.id and chat.receiver_id != current_user.id:
        flash('이 채팅에 접근할 수 없습니다.', 'danger')
        return redirect(url_for('chats'))
    
    # 상품이 차단되었는지 확인
    if chat.product.is_blocked:
        flash('이 상품은 현재 이용할 수 없습니다.', 'warning')
        return redirect(url_for('chats'))
    
    # 채팅의 다른 참여자
    other_user = chat.receiver if chat.sender_id == current_user.id else chat.sender
    
    # 다른 참여자가 정지 상태인지 확인
    if other_user.is_suspended:
        flash('상대방이 현재 이용할 수 없는 상태입니다.', 'warning')
        return redirect(url_for('chats'))
    
    # 이 채팅의 모든 메시지 가져오기
    messages = Message.query.filter_by(chat_id=chat.id).order_by(Message.timestamp).all()
    
    return render_template('view_chat.html', chat=chat, messages=messages, other_user=other_user)

@socketio.on('join')
def on_join(data):
    if not current_user.is_authenticated:
        return
        
    chat_id = data['chat_id']
    chat = Chat.query.get_or_404(chat_id)
    
    # 사용자가 이 채팅의 일부인지 확인
    if chat.sender_id != current_user.id and chat.receiver_id != current_user.id:
        return
    
    room = chat.room_id
    join_room(room)

@socketio.on('leave')
def on_leave(data):
    if not current_user.is_authenticated:
        return
        
    chat_id = data['chat_id']
    chat = Chat.query.get_or_404(chat_id)
    room = chat.room_id
    leave_room(room)

@socketio.on('send_message')
def handle_message(data):
    if not current_user.is_authenticated:
        return
        
    try:
        chat_id = int(data['chat_id'])
        chat = Chat.query.get_or_404(chat_id)
        
        # 채팅방 접근 권한 확인
        if chat.sender_id != current_user.id and chat.receiver_id != current_user.id:
            return
            
        message_content = data['message'].strip()
        if not message_content:
            return
            
        # 새 메시지 저장
        new_message = Message(
            content=message_content,
            chat_id=chat_id,
            user_id=current_user.id
        )
        db.session.add(new_message)
        db.session.commit()
        
        # 메시지 브로드캐스트 - 중요: room 값은 chat.room_id여야 함
        emit('receive_message', {
            'message': message_content,
            'user_id': current_user.id,
            'username': current_user.username,
            'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        }, room=chat.room_id)
        
    except Exception as e:
        app.logger.error(f"메시지 전송 오류: {str(e)}")

@app.route('/report/<string:target_type>/<int:target_id>', methods=['GET', 'POST'])  # URL 패턴 수정
@login_required
def report(target_type, target_id):
    if current_user.is_suspended:
        flash('계정이 정지 상태입니다. 신고 기능을 사용할 수 없습니다.', 'danger')
        return redirect(url_for('index'))
        
    # 대상 유형 검증
    valid_target_types = ['product', 'user']
    if target_type not in valid_target_types:
        flash('유효하지 않은 신고 대상입니다.', 'danger')
        return redirect(url_for('index'))
    
    # 대상이 존재하는지 확인
    if target_type == 'product':
        target = Product.query.get_or_404(target_id)
        
        # 자신의 상품을 신고할 수 없음
        if target.user_id == current_user.id:
            flash('자신의 상품은 신고할 수 없습니다.', 'danger')
            return redirect(url_for('view_product', product_id=target_id))
            
    elif target_type == 'user':
        target = User.query.get_or_404(target_id)
        
        # 자신을 신고할 수 없음
        if target.id == current_user.id:
            flash('자신을 신고할 수 없습니다.', 'danger')
            return redirect(url_for('view_profile', user_id=target_id))
            
        # 관리자를 신고할 수 없음
        if target.is_admin:
            flash('관리자는 신고할 수 없습니다.', 'danger')
            return redirect(url_for('view_profile', user_id=target_id))
    
    if request.method == 'POST':
        reason = request.form.get('reason')
        
        if not reason:
            flash('신고 이유를 입력해주세요.', 'danger')
            return redirect(url_for('report', target_type=target_type, target_id=target_id))
        
        # 사용자가 이미 대상을 신고했는지 확인
        existing_report = Report.query.filter_by(
            target_type=target_type,
            target_id=target_id,
            reporter_id=current_user.id,
            status='pending'
        ).first()
        
        if existing_report:
            flash('이미 신고하셨습니다. 처리 중입니다.', 'warning')
            if target_type == 'product':
                return redirect(url_for('view_product', product_id=target_id))
            else:
                return redirect(url_for('view_profile', user_id=target_id))
        
        # 새 신고 생성
        new_report = Report(
            target_type=target_type,
            target_id=target_id,
            reporter_id=current_user.id,
            reason=reason
        )
        
        db.session.add(new_report)
        
        # 신고 횟수 증가 및 상태 확인
        if target_type == 'product':
            product = Product.query.get(target_id)
            product.report_count += 1
            
            # 신고 횟수가 기준을 초과하면 차단
            if product.report_count >= app.config['MAX_REPORT_COUNT']:
                product.status = 'blocked'
                flash('신고가 접수되었습니다. 신고 횟수 초과로 해당 상품이 차단되었습니다.', 'warning')
            else:
                flash('신고가 접수되었습니다.', 'success')
                
        elif target_type == 'user':
            user = User.query.get(target_id)
            user.report_count += 1
            
            # 신고 횟수가 기준을 초과하면 휴면계정 처리
            if user.report_count >= app.config['MAX_REPORT_COUNT']:
                user.status = 'suspended'
                flash('신고가 접수되었습니다. 신고 횟수 초과로 해당 사용자 계정이 정지되었습니다.', 'warning')
            else:
                flash('신고가 접수되었습니다.', 'success')
        
        db.session.commit()
        
        log_activity(current_user.id, f"{target_type} 신고", f"대상 ID: {target_id}, 이유: {reason[:30]}...")
        
        if target_type == 'product':
            return redirect(url_for('view_product', product_id=target_id))
        else:
            return redirect(url_for('view_profile', user_id=target_id))
    
    return render_template('report.html', target_type=target_type, target_id=target_id)

# 전체 채팅 기능 - URL 경로 수정 ('public_chat' -> 'community_chat')
@app.route('/community_chat')
@login_required
def community_chat():
    if current_user.is_suspended:
        flash('계정이 정지 상태입니다. 채팅 기능을 사용할 수 없습니다.', 'danger')
        return redirect(url_for('index'))
        
    # 전체 채팅 메시지 가져오기 (최신 100개만)
    messages = PublicMessage.query.order_by(PublicMessage.timestamp.desc()).limit(100).all()
    messages.reverse()  # 시간순으로 정렬
    
    log_activity(current_user.id, "전체 채팅방 입장", "")
    
    return render_template('community_chat.html', messages=messages)

@socketio.on('public_join')
def on_public_join():
    if not current_user.is_authenticated or current_user.is_suspended:
        return
        
    join_room('public')
    emit('public_status', {'msg': f'{current_user.username}님이 입장했습니다.'}, to='public')

@socketio.on('public_leave')
def on_public_leave():
    if not current_user.is_authenticated:
        return
        
    leave_room('public')
    emit('public_status', {'msg': f'{current_user.username}님이 퇴장했습니다.'}, to='public')

@socketio.on('public_message')
def on_public_message(data):
    if not current_user.is_authenticated or current_user.is_suspended:
        return
        
    message_content = data['message']
    
    if not message_content.strip():
        return
    
    # 새 메시지 생성
    new_message = PublicMessage(
        content=message_content,
        user_id=current_user.id
    )
    
    db.session.add(new_message)
    db.session.commit()
    
    # 모든 사용자에게 메시지 전송
    emit('public_receive', {
        'message': message_content,
        'user_id': current_user.id,
        'username': current_user.username,
        'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        'is_admin': current_user.is_admin
    }, to='public')

@app.route('/admin')
@admin_required
def admin_dashboard():
    pending_reports = Report.query.filter_by(status='pending').order_by(Report.created_at.desc()).all()
    all_users = User.query.order_by(User.username).all()
    blocked_products = Product.query.filter_by(status='blocked').count()
    suspended_users = User.query.filter_by(status='suspended').count()
    total_reports = Report.query.count()
    
    # 최근 로그 가져오기
    recent_logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(20).all()
    
    return render_template('admin.html', 
                           reports=pending_reports, 
                           users=all_users,
                           blocked_products=blocked_products,
                           suspended_users=suspended_users,
                           total_reports=total_reports,
                           recent_logs=recent_logs)

@app.route('/admin/reports')
@admin_required
def admin_reports():
    status = request.args.get('status', 'all')
    target_type = request.args.get('target_type', 'all')
    
    query = Report.query
    
    if status != 'all':
        query = query.filter_by(status=status)
        
    if target_type != 'all':
        query = query.filter_by(target_type=target_type)
    
    reports = query.order_by(Report.created_at.desc()).all()
    
    return render_template('admin_reports.html', reports=reports, status=status, target_type=target_type)

@app.route('/admin/reports/<int:report_id>/review', methods=['POST'])  # URL 패턴 수정
@admin_required
def review_report(report_id):
    report = Report.query.get_or_404(report_id)
    status = request.form.get('status')
    
    if status not in ['reviewed', 'resolved']:
        flash('유효하지 않은 상태입니다.', 'danger')
        return redirect(url_for('admin_reports'))
    
    report.status = status
    db.session.commit()
    
    log_activity(current_user.id, "신고 상태 변경", f"신고 ID: {report_id}, 상태: {status}")
    
    flash('신고 상태가 업데이트되었습니다.', 'success')
    return redirect(url_for('admin_reports'))

@app.route('/admin/products')
@admin_required
def admin_products():
    status = request.args.get('status', 'all')
    
    query = Product.query
    
    if status != 'all':
        query = query.filter_by(status=status)
    
    products = query.order_by(Product.created_at.desc()).all()
    
    return render_template('admin_products.html', products=products, status=status)

@app.route('/admin/products/<int:product_id>/toggle-status', methods=['POST'])  # URL 패턴 수정
@admin_required
def toggle_product_status(product_id):
    product = Product.query.get_or_404(product_id)
    
    if product.status == 'active':
        product.status = 'blocked'
        status_msg = '차단됨'
    else:
        product.status = 'active'
        product.report_count = 0  # 신고 횟수 초기화
        status_msg = '활성화됨'
    
    db.session.commit()
    
    log_activity(current_user.id, "상품 상태 변경", f"상품 ID: {product_id}, 상태: {product.status}")
    
    flash(f'상품 상태가 {status_msg}으로 변경되었습니다.', 'success')
    return redirect(url_for('admin_products'))

@app.route('/admin/users')
@admin_required
def admin_users():
    status = request.args.get('status', 'all')
    role = request.args.get('role', 'all')
    
    query = User.query
    
    if status != 'all':
        query = query.filter_by(status=status)
        
    if role != 'all':
        is_admin = (role == 'admin')
        query = query.filter_by(is_admin=is_admin)
    
    users = query.order_by(User.username).all()
    
    return render_template('admin_users.html', users=users, status=status, role=role)

@app.route('/admin/users/<int:user_id>/toggle-status', methods=['POST'])  # URL 패턴 수정
@admin_required
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    
    # 자신의 상태 변경 방지
    if user.id == current_user.id:
        flash('자신의 계정 상태를 변경할 수 없습니다.', 'danger')
        return redirect(url_for('admin_users'))
    
    if user.status == 'active':
        user.status = 'suspended'
        status_msg = '정지됨'
    else:
        user.status = 'active'
        user.report_count = 0  # 신고 횟수 초기화
        status_msg = '활성화됨'
    
    db.session.commit()
    
    log_activity(current_user.id, "사용자 상태 변경", f"사용자 ID: {user_id}, 상태: {user.status}")
    
    flash(f'사용자 상태가 {status_msg}으로 변경되었습니다.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/toggle_admin', methods=['POST'])  # URL 패턴 수정
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    
    # 자신의 관리자 상태 변경 방지
    if user.id == current_user.id:
        flash('자신의 관리자 상태를 변경할 수 없습니다.', 'danger')
        return redirect(url_for('admin_users'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    log_activity(current_user.id, "관리자 권한 변경", f"사용자 ID: {user_id}, 관리자 권한: {user.is_admin}")
    
    flash(f"{user.username}의 관리자 상태가 {'부여되었습니다' if user.is_admin else '해제되었습니다'}.", 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])  # URL 패턴 수정
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # 자신의 계정 삭제 방지
    if user.id == current_user.id:
        flash('자신의 계정을 삭제할 수 없습니다.', 'danger')
        return redirect(url_for('admin_users'))
    
    # 사용자의 모든 상품 삭제 (및 관련 채팅, 메시지, 신고)
    products = Product.query.filter_by(user_id=user.id).all()
    for product in products:
        # 상품 이미지 삭제
        if product.image:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image))
            except:
                pass
        
        # 이 상품과 관련된 모든 채팅 가져오기
        chats = Chat.query.filter_by(product_id=product.id).all()
        for chat in chats:
            # 이 채팅의 모든 메시지 삭제
            Message.query.filter_by(chat_id=chat.id).delete()
            db.session.delete(chat)
        
        # 이 상품에 대한 모든 신고 삭제
        Report.query.filter_by(target_type='product', target_id=product.id).delete()
        
        # 상품 삭제
        db.session.delete(product)
    
    # 사용자가 발신자이거나 수신자인 모든 채팅 삭제
    chats = Chat.query.filter((Chat.sender_id == user.id) | (Chat.receiver_id == user.id)).all()
    for chat in chats:
        # 이 채팅의 모든 메시지 삭제
        Message.query.filter_by(chat_id=chat.id).delete()
        db.session.delete(chat)
    
    # 이 사용자가 작성한 모든 신고 삭제
    Report.query.filter_by(reporter_id=user.id).delete()
    
    # 이 사용자에 대한 모든 신고 삭제
    Report.query.filter_by(target_type='user', target_id=user.id).delete()
    
    # 이 사용자가 보낸 모든 메시지 삭제
    Message.query.filter_by(user_id=user.id).delete()
    
    # 이 사용자의 전체 채팅 메시지 삭제
    PublicMessage.query.filter_by(user_id=user.id).delete()
    
    # 사용자 삭제
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    log_activity(current_user.id, "사용자 삭제", f"사용자명: {username}")
    
    flash(f"사용자 {username}이(가) 삭제되었습니다.", 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/logs')
@admin_required
def admin_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).paginate(page=page, per_page=per_page)
    
    return render_template('admin_logs.html', logs=logs)

@app.route('/search')
def search():
    query = request.args.get('query', '')
    if not query:
        return redirect(url_for('index'))
    
    # 활성 상태인 상품만 검색
    products = Product.query.filter(
        (Product.title.contains(query) | Product.description.contains(query)) &
        (Product.status == 'active')
    ).all()
    
    return render_template('search_results.html', products=products, query=query)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

# 데이터베이스 생성
with app.app_context():
    try:
        # 기존 테이블 삭제
        db.drop_all()
        
        # 새 테이블 생성
        db.create_all()
        
        # 초기 관리자 생성
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("관리자 계정이 생성되었습니다.")
    except Exception as e:
        print(f"데이터베이스 초기화 중 오류 발생: {e}")

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)

