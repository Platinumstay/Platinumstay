from flask import Flask, render_template, request, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import csv, io, os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rental.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='tenant')  # landlord or tenant
    tenant = db.relationship('Tenant', backref='user', uselist=False)

class Tenant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    flat = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    rent_amount = db.Column(db.Float, nullable=False, default=0.0)
    payments = db.relationship('Payment', backref='tenant', lazy=True, cascade='all, delete-orphan')
    complaints = db.relationship('Complaint', backref='tenant', lazy=True, cascade='all, delete-orphan')

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    due_date = db.Column(db.Date, nullable=True)
    paid_date = db.Column(db.Date, nullable=True)
    note = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='Open')  # Open, In Progress, Resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid email or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'landlord':
        tenants = Tenant.query.all()
        recent_payments = Payment.query.order_by(Payment.created_at.desc()).limit(10).all()
        recent_complaints = Complaint.query.order_by(Complaint.created_at.desc()).limit(10).all()
        return render_template('dashboard_landlord.html', tenants=tenants, payments=recent_payments, complaints=recent_complaints)
    else:
        tenant = current_user.tenant
        payments = Payment.query.filter_by(tenant_id=tenant.id).order_by(Payment.created_at.desc()).all()
        complaints = Complaint.query.filter_by(tenant_id=tenant.id).order_by(Complaint.created_at.desc()).all()
        return render_template('dashboard_tenant.html', tenant=tenant, payments=payments, complaints=complaints)

# Landlord: tenants CRUD
@app.route('/tenants')
@login_required
def tenants():
    if current_user.role != 'landlord':
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))
    tenants = Tenant.query.all()
    return render_template('tenants.html', tenants=tenants)

@app.route('/tenants/add', methods=['POST'])
@login_required
def add_tenant():
    if current_user.role != 'landlord':
        flash('Unauthorized', 'danger')
        return redirect(url_for('dashboard'))
    name = request.form.get('name').strip()
    flat = request.form.get('flat').strip()
    email = request.form.get('email').strip().lower()
    password = request.form.get('password') or 'tenant123'
    rent_amount = float(request.form.get('rent_amount') or 0)
    if User.query.filter_by(email=email).first():
        flash('Email already exists', 'danger')
        return redirect(url_for('tenants'))
    user = User(email=email, password=generate_password_hash(password), role='tenant')
    db.session.add(user)
    db.session.flush()
    tenant = Tenant(name=name, flat=flat, user_id=user.id, rent_amount=rent_amount)
    db.session.add(tenant)
    db.session.commit()
    flash('Tenant created', 'success')
    return redirect(url_for('tenants'))

@app.route('/tenants/<int:tenant_id>/edit', methods=['GET','POST'])
@login_required
def edit_tenant(tenant_id):
    if current_user.role != 'landlord':
        flash('Unauthorized', 'danger'); return redirect(url_for('dashboard'))
    tenant = Tenant.query.get_or_404(tenant_id)
    if request.method == 'POST':
        tenant.name = request.form.get('name').strip()
        tenant.flat = request.form.get('flat').strip()
        tenant.rent_amount = float(request.form.get('rent_amount') or 0)
        db.session.commit()
        flash('Tenant updated', 'success')
        return redirect(url_for('tenants'))
    return render_template('tenant_edit.html', tenant=tenant)

@app.route('/tenants/<int:tenant_id>/delete', methods=['POST'])
@login_required
def delete_tenant(tenant_id):
    if current_user.role != 'landlord':
        flash('Unauthorized', 'danger'); return redirect(url_for('dashboard'))
    tenant = Tenant.query.get_or_404(tenant_id)
    # delete associated user too
    user = tenant.user
    db.session.delete(tenant)
    if user:
        db.session.delete(user)
    db.session.commit()
    flash('Tenant deleted', 'success')
    return redirect(url_for('tenants'))

# Payments CRUD (landlord)
@app.route('/payments')
@login_required
def all_payments():
    if current_user.role != 'landlord':
        flash('Unauthorized', 'danger'); return redirect(url_for('dashboard'))
    payments = Payment.query.order_by(Payment.created_at.desc()).all()
    return render_template('payments.html', payments=payments)

@app.route('/payments/add', methods=['POST'])
@login_required
def add_payment():
    if current_user.role != 'landlord':
        flash('Unauthorized', 'danger'); return redirect(url_for('dashboard'))
    tenant_id = int(request.form.get('tenant_id'))
    amount = float(request.form.get('amount'))
    due_date = request.form.get('due_date') or None
    due_date_obj = date.fromisoformat(due_date) if due_date else None
    note = request.form.get('note')
    payment = Payment(tenant_id=tenant_id, amount=amount, due_date=due_date_obj, paid_date=date.today())
    db.session.add(payment); db.session.commit()
    flash('Payment recorded', 'success')
    return redirect(url_for('all_payments'))

@app.route('/payments/<int:payment_id>/edit', methods=['GET','POST'])
@login_required
def edit_payment(payment_id):
    if current_user.role != 'landlord':
        flash('Unauthorized', 'danger'); return redirect(url_for('dashboard'))
    payment = Payment.query.get_or_404(payment_id)
    if request.method == 'POST':
        payment.amount = float(request.form.get('amount'))
        due_date = request.form.get('due_date') or None
        payment.due_date = date.fromisoformat(due_date) if due_date else None
        payment.paid_date = date.fromisoformat(request.form.get('paid_date')) if request.form.get('paid_date') else None
        payment.note = request.form.get('note')
        db.session.commit()
        flash('Payment updated', 'success')
        return redirect(url_for('all_payments'))
    return render_template('payment_edit.html', payment=payment)

@app.route('/payments/<int:payment_id>/delete', methods=['POST'])
@login_required
def delete_payment(payment_id):
    if current_user.role != 'landlord':
        flash('Unauthorized', 'danger'); return redirect(url_for('dashboard'))
    payment = Payment.query.get_or_404(payment_id)
    db.session.delete(payment); db.session.commit()
    flash('Payment deleted', 'success')
    return redirect(url_for('all_payments'))

# Tenant actions: view/add their payments and complaints
@app.route('/my/payments')
@login_required
def my_payments():
    if current_user.role != 'tenant':
        flash('Unauthorized', 'danger'); return redirect(url_for('dashboard'))
    tenant = current_user.tenant
    payments = Payment.query.filter_by(tenant_id=tenant.id).order_by(Payment.created_at.desc()).all()
    return render_template('payments_tenant.html', payments=payments, tenant=tenant)

@app.route('/my/payments/add', methods=['POST'])
@login_required
def tenant_add_payment():
    if current_user.role != 'tenant':
        flash('Unauthorized', 'danger'); return redirect(url_for('dashboard'))
    tenant = current_user.tenant
    amount = float(request.form.get('amount'))
    due_date = request.form.get('due_date') or None
    due_date_obj = date.fromisoformat(due_date) if due_date else None
    payment = Payment(tenant_id=tenant.id, amount=amount, due_date=due_date_obj, paid_date=date.today())
    db.session.add(payment); db.session.commit()
    flash('Payment submitted', 'success')
    return redirect(url_for('my_payments'))

@app.route('/my/payments/<int:payment_id>/edit', methods=['GET','POST'])
@login_required
def tenant_edit_payment(payment_id):
    if current_user.role != 'tenant':
        flash('Unauthorized', 'danger'); return redirect(url_for('dashboard'))
    payment = Payment.query.get_or_404(payment_id)
    if payment.tenant.user_id != current_user.id:
        flash('Unauthorized', 'danger'); return redirect(url_for('my_payments'))
    if request.method == 'POST':
        payment.amount = float(request.form.get('amount'))
        payment.paid_date = date.fromisoformat(request.form.get('paid_date')) if request.form.get('paid_date') else None
        payment.note = request.form.get('note')
        db.session.commit()
        flash('Payment updated', 'success')
        return redirect(url_for('my_payments'))
    return render_template('payment_edit_tenant.html', payment=payment)

# Complaints: tenant can add, landlord can manage
@app.route('/my/complaints')
@login_required
def my_complaints():
    if current_user.role != 'tenant':
        flash('Unauthorized', 'danger'); return redirect(url_for('dashboard'))
    tenant = current_user.tenant
    complaints = Complaint.query.filter_by(tenant_id=tenant.id).order_by(Complaint.created_at.desc()).all()
    return render_template('complaints_tenant.html', complaints=complaints)

@app.route('/my/complaints/add', methods=['GET','POST'])
@login_required
def tenant_add_complaint():
    if current_user.role != 'tenant':
        flash('Unauthorized', 'danger'); return redirect(url_for('dashboard'))
    if request.method == 'POST':
        title = request.form.get('title').strip()
        description = request.form.get('description').strip()
        complaint = Complaint(tenant_id=current_user.tenant.id, title=title, description=description)
        db.session.add(complaint); db.session.commit()
        flash('Complaint submitted', 'success')
        return redirect(url_for('my_complaints'))
    return render_template('complaint_form.html')

@app.route('/complaints')
@login_required
def manage_complaints():
    if current_user.role != 'landlord':
        flash('Unauthorized', 'danger'); return redirect(url_for('dashboard'))
    complaints = Complaint.query.order_by(Complaint.created_at.desc()).all()
    return render_template('complaints_manage.html', complaints=complaints)

@app.route('/complaints/<int:complaint_id>/status', methods=['POST'])
@login_required
def complaint_update_status(complaint_id):
    if current_user.role != 'landlord':
        flash('Unauthorized', 'danger'); return redirect(url_for('dashboard'))
    complaint = Complaint.query.get_or_404(complaint_id)
    complaint.status = request.form.get('status')
    db.session.commit()
    flash('Complaint status updated', 'success')
    return redirect(url_for('manage_complaints'))

# Export payments CSV (landlord)
@app.route('/export/payments.csv')
@login_required
def export_payments():
    if current_user.role != 'landlord':
        flash('Unauthorized', 'danger'); return redirect(url_for('dashboard'))
    payments = Payment.query.order_by(Payment.created_at.desc()).all()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID','Tenant','Flat','Amount','Due Date','Paid Date','Note','Created At'])
    for p in payments:
        cw.writerow([p.id, p.tenant.name, p.tenant.flat, p.amount, p.due_date, p.paid_date, p.note, p.created_at])
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=payments.csv"
    output.headers["Content-type"] = "text/csv"
    return output

# DB init + seed
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email='landlord@example.com').first():
        landlord = User(email='landlord@example.com', password=generate_password_hash('password123'), role='landlord')
        db.session.add(landlord); db.session.commit()
    if not User.query.filter_by(email='tenant1@example.com').first():
        u = User(email='tenant1@example.com', password=generate_password_hash('tenant123'), role='tenant')
        db.session.add(u); db.session.flush()
        t = Tenant(name='Rahul', flat='A-101', user_id=u.id, rent_amount=15000.0)
        db.session.add(t); db.session.commit()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
