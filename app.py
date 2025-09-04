
import os
from datetime import datetime, date
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTS = {"pdf","jpg","jpeg","png"}

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "super-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "rental.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25MB

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ---------------- Models ----------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="tenant")  # tenant/admin/superadmin

    # A tenant's own login record (1–to–1)
    tenant_profile = db.relationship(
        "Tenant",
        uselist=False,
        back_populates="user",
        foreign_keys="[Tenant.user_id]"
    )

    # All tenants owned/managed by this admin user (superadmin/admin)
    owned_tenants = db.relationship(
        "Tenant",
        back_populates="owner",
        foreign_keys="[Tenant.owner_user_id]"
    )


class Tenant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_code = db.Column(db.String(50), unique=True)  # optional code
    name = db.Column(db.String(100), nullable=False)
    flat = db.Column(db.String(50), nullable=False)

    # FK to the tenant's own login user (the person who signs in as a tenant)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)

    # FK to the owner/admin responsible for this tenant (who sees them in "My Tenants")
    owner_user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    # Disambiguated relationships back to User
    user = db.relationship(
        "User",
        foreign_keys=[user_id],
        back_populates="tenant_profile"
    )
    owner = db.relationship(
        "User",
        foreign_keys=[owner_user_id],
        back_populates="owned_tenants"
    )

    rent_amount = db.Column(db.Float, nullable=False, default=0.0)
    active = db.Column(db.Boolean, default=True)
    joined_on = db.Column(db.Date, default=date.today)

    payments = db.relationship("Payment", backref="tenant", lazy=True, cascade="all, delete-orphan")
    complaints = db.relationship("Complaint", backref="tenant", lazy=True, cascade="all, delete-orphan")
    docs = db.relationship("Document", backref="tenant", lazy=True, cascade="all, delete-orphan")


class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    period = db.Column(db.String(20)) # e.g., "2025-09"
    paid_on = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default="pending")  # pending/paid/failed
    note = db.Column(db.String(255))
    gateway = db.Column(db.String(20))  # razorpay/manual
    gateway_order_id = db.Column(db.String(120))
    gateway_payment_id = db.Column(db.String(120))
    gateway_signature = db.Column(db.String(255))


class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False)
    category = db.Column(db.String(50), default="other") # electrical/plumbing/paint/other
    subject = db.Column(db.String(200), nullable=False)
    detail = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(30), nullable=False, default="open")  # open/in_progress/closed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tenant_id = db.Column(db.Integer, db.ForeignKey("tenant.id"), nullable=False)
    doc_type = db.Column(db.String(50)) # aadhaar/pan/other
    filename = db.Column(db.String(255), nullable=False)
    stored_path = db.Column(db.String(500), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- Helpers ----------------
def is_superadmin():
    return current_user.is_authenticated and current_user.role == "superadmin"

def is_admin():
    return current_user.is_authenticated and current_user.role in {"admin","superadmin"}

def require_admin():
    if not is_admin():
        flash("Admin access required", "danger")
        return False
    return True

def allowed_file(filename):
    return "." in filename and filename.rsplit(".",1)[1].lower() in {"pdf","jpg","jpeg","png"}

# ---------------- Auth ----------------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/admin/signup", methods=["GET","POST"])
@login_required
def admin_signup():
    if not is_superadmin():
        abort(403)
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","").strip()
        confirm = request.form.get("confirm","").strip()
        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for("admin_signup"))
        if User.query.filter_by(email=email).first():
            flash("Email already exists", "danger")
            return redirect(url_for("admin_signup"))
        u = User(email=email, password=generate_password_hash(password), role="admin")
        db.session.add(u); db.session.commit()
        flash("Admin account created.", "success")
        return redirect(url_for("super_admins"))
    return render_template("admin_signup.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "success")
    return redirect(url_for("login"))

# ---------------- Core Pages ----------------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    if is_admin():
        # Admin & Superadmin dashboard
        if is_superadmin():
            open_complaints = Complaint.query.filter(Complaint.status!="closed").count()
            paid_this_month = Payment.query.filter_by(status="paid", period=datetime.utcnow().strftime("%Y-%m")).count()
            occupied = Tenant.query.filter_by(active=True).count()
            total_flats = occupied  # could be a setting
        else:
            tenant_ids = [t.id for t in Tenant.query.filter_by(owner_user_id=current_user.id).all()]
            open_complaints = Complaint.query.filter(Complaint.tenant_id.in_(tenant_ids), Complaint.status!="closed").count()
            paid_this_month = Payment.query.filter(Payment.tenant_id.in_(tenant_ids), Payment.status=="paid", Payment.period==datetime.utcnow().strftime("%Y-%m")).count()
            occupied = Tenant.query.filter_by(owner_user_id=current_user.id, active=True).count()
            total_flats = occupied

        categories = ["electrical","plumbing","paint","other"]
        if is_superadmin():
            comp_counts = [Complaint.query.filter_by(category=c).count() for c in categories]
            paid = Payment.query.filter_by(status="paid").count()
            pending = Payment.query.filter_by(status="pending").count()
            failed = Payment.query.filter_by(status="failed").count()
        else:
            comp_counts = [Complaint.query.join(Tenant).filter(Tenant.owner_user_id==current_user.id, Complaint.category==c).count() for c in categories]
            paid = Payment.query.join(Tenant).filter(Tenant.owner_user_id==current_user.id, Payment.status=="paid").count()
            pending = Payment.query.join(Tenant).filter(Tenant.owner_user_id==current_user.id, Payment.status=="pending").count()
            failed = Payment.query.join(Tenant).filter(Tenant.owner_user_id==current_user.id, Payment.status=="failed").count()

        return render_template("dashboard_admin.html",
                               total_flats=total_flats, occupied=occupied,
                               open_complaints=open_complaints, paid_this_month=paid_this_month,
                               categories=categories, comp_counts=comp_counts,
                               paid=paid, pending=pending, failed=failed)
    else:
        tenant = current_user.tenant_profile
        payments = Payment.query.filter_by(tenant_id=tenant.id).order_by(Payment.id.desc()).all()
        complaints = Complaint.query.filter_by(tenant_id=tenant.id).order_by(Complaint.created_at.desc()).all()
        docs = Document.query.filter_by(tenant_id=tenant.id).order_by(Document.uploaded_at.desc()).all()
        return render_template("dashboard_tenant.html", tenant=tenant, payments=payments, complaints=complaints, docs=docs)

# ---------------- Super Admin: Manage Admins ----------------
@app.route("/super/admins")
@login_required
def super_admins():
    if not is_superadmin(): abort(403)
    admins = User.query.filter(User.role=="admin").order_by(User.email.asc()).all()
    return render_template("super_admins.html", admins=admins)

@app.route("/super/admins/<int:admin_id>/delete", methods=["POST"])
@login_required
def super_admin_delete(admin_id):
    if not is_superadmin(): abort(403)
    admin = User.query.get_or_404(admin_id)
    if admin.role != "admin":
        flash("Only admin accounts can be deleted here.", "danger")
        return redirect(url_for("super_admins"))
    assigned = Tenant.query.filter_by(owner_user_id=admin.id).count()
    if assigned:
        flash("Cannot delete: tenants are assigned to this admin.", "danger")
        return redirect(url_for("super_admins"))
    db.session.delete(admin); db.session.commit()
    flash("Admin deleted.", "success")
    return redirect(url_for("super_admins"))

# ---------------- Admin: Tenants CRUD & Details ----------------
@app.route("/admin/tenants")
@login_required
def admin_tenants():
    if not require_admin(): return redirect(url_for("dashboard"))
    q = request.args.get("q","").strip()
    owner_filter = request.args.get("owner","").strip()
    qry = Tenant.query
    if not is_superadmin():
        qry = qry.filter_by(owner_user_id=current_user.id)
    if q:
        qry = qry.filter((Tenant.name.ilike(f"%{q}%")) | (Tenant.flat.ilike(f"%{q}%")) | (Tenant.tenant_code.ilike(f"%{q}%")))
    if owner_filter and is_superadmin():
        try:
            owner_id = int(owner_filter)
            qry = qry.filter_by(owner_user_id=owner_id)
        except Exception:
            pass
    tenants = qry.order_by(Tenant.id.desc()).all()
    owners = User.query.filter(User.role=="admin").all()
    return render_template("admin_tenants.html", tenants=tenants, q=q, owners=owners, owner_filter=owner_filter, is_super=is_superadmin())

@app.route("/admin/tenants/new", methods=["GET","POST"])
@login_required
def admin_tenant_new():
    if not require_admin(): return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = request.form["name"].strip()
        flat = request.form["flat"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"].strip()
        tenant_code = request.form.get("tenant_code","").strip() or None
        rent_amount = float(request.form.get("rent_amount") or 0)
        if User.query.filter_by(email=email).first():
            flash("Email already exists", "danger"); return redirect(url_for("admin_tenant_new"))
        user = User(email=email, password=generate_password_hash(password), role="tenant")
        db.session.add(user); db.session.flush()
        owner_user_id = current_user.id if not is_superadmin() else int(request.form.get("owner_user_id") or current_user.id)
        tenant = Tenant(name=name, flat=flat, user_id=user.id, tenant_code=tenant_code, rent_amount=rent_amount, owner_user_id=owner_user_id)
        db.session.add(tenant); db.session.commit()
        flash(f"Tenant created — email: {email} password: {password}", "success")
        return redirect(url_for("admin_tenants"))
    owners = User.query.filter(User.role=="admin").order_by(User.email.asc()).all()
    return render_template("admin_tenant_form.html", tenant=None, owners=owners, is_super=is_superadmin())

@app.route("/admin/tenants/<int:tenant_id>/edit", methods=["GET","POST"])
@login_required
def admin_tenant_edit(tenant_id):
    if not require_admin(): return redirect(url_for("dashboard"))
    tenant = Tenant.query.get_or_404(tenant_id)
    if not is_superadmin() and tenant.owner_user_id != current_user.id:
        abort(403)
    if request.method == "POST":
        tenant.name = request.form["name"].strip()
        tenant.flat = request.form["flat"].strip()
        tenant.rent_amount = float(request.form.get("rent_amount") or 0)
        tenant.active = True if request.form.get("active")=="on" else False
        tenant.tenant_code = request.form.get("tenant_code","").strip() or None
        if is_superadmin():
            try:
                tenant.owner_user_id = int(request.form.get("owner_user_id") or tenant.owner_user_id)
            except Exception:
                pass
        db.session.commit(); flash("Tenant updated", "success")
        return redirect(url_for("admin_tenants"))
    owners = User.query.filter(User.role=="admin").order_by(User.email.asc()).all()
    return render_template("admin_tenant_form.html", tenant=tenant, owners=owners, is_super=is_superadmin())

@app.route("/admin/tenants/<int:tenant_id>/delete", methods=["POST"])
@login_required
def admin_tenant_delete(tenant_id):
    if not require_admin(): return redirect(url_for("dashboard"))
    t = Tenant.query.get_or_404(tenant_id)
    if not is_superadmin() and t.owner_user_id != current_user.id:
        abort(403)
    user = t.user
    db.session.delete(t)
    if user and user.role == "tenant":
        db.session.delete(user)
    db.session.commit()
    flash("Tenant deleted", "success")
    return redirect(url_for("admin_tenants"))

@app.route("/admin/tenants/<int:tenant_id>")
@login_required
def admin_tenant_detail(tenant_id):
    if not require_admin(): return redirect(url_for("dashboard"))
    t = Tenant.query.get_or_404(tenant_id)
    if not is_superadmin() and t.owner_user_id != current_user.id:
        abort(403)
    payments = Payment.query.filter_by(tenant_id=t.id).order_by(Payment.id.desc()).all()
    complaints = Complaint.query.filter_by(tenant_id=t.id).order_by(Complaint.created_at.desc()).all()
    docs = Document.query.filter_by(tenant_id=t.id).order_by(Document.uploaded_at.desc()).all()
    return render_template("admin_tenant_detail.html", tenant=t, payments=payments, complaints=complaints, docs=docs)

# ---------------- Admin: Complaints Board ----------------
@app.route("/admin/complaints")
@login_required
def admin_complaints():
    if not require_admin(): return redirect(url_for("dashboard"))
    status = request.args.get("status","").strip()
    qry = Complaint.query.join(Tenant)
    if not is_superadmin():
        qry = qry.filter(Tenant.owner_user_id==current_user.id)
    if status:
        qry = qry.filter(Complaint.status==status)
    complaints = qry.order_by(Complaint.created_at.desc()).all()
    return render_template("admin_complaints.html", complaints=complaints, status=status)

@app.route("/admin/complaints/<int:cid>/status", methods=["POST"])
@login_required
def admin_complaint_status(cid):
    if not require_admin(): return redirect(url_for("dashboard"))
    c = Complaint.query.get_or_404(cid)
    if not is_superadmin():
        if not c.tenant or c.tenant.owner_user_id != current_user.id:
            abort(403)
    new_status = request.form.get("status","").strip()
    if new_status not in {"open","in_progress","closed"}:
        flash("Invalid status", "danger"); return redirect(url_for("admin_complaints"))
    c.status = new_status; db.session.commit()
    flash("Complaint updated", "success")
    return redirect(request.referrer or url_for("admin_complaints"))

# ---------------- Tenant: Complaints CRUD ----------------
@app.route("/complaints/new", methods=["POST"])
@login_required
def complaint_new():
    if current_user.role != "tenant":
        flash("Tenant-only action", "danger"); return redirect(url_for("dashboard"))
    subject = request.form.get("subject","").strip()
    detail = request.form.get("detail","").strip()
    category = request.form.get("category","other")
    if not subject or not detail:
        flash("Subject and detail required", "danger")
        return redirect(url_for("dashboard"))
    c = Complaint(tenant_id=current_user.tenant_profile.id, subject=subject, detail=detail, category=category)
    db.session.add(c); db.session.commit()
    flash("Complaint submitted", "success")
    return redirect(url_for("dashboard"))

@app.route("/complaints/<int:cid>/edit", methods=["GET","POST"])
@login_required
def complaint_edit(cid):
    c = Complaint.query.get_or_404(cid)
    if current_user.role != "tenant" or c.tenant_id != current_user.tenant_profile.id:
        abort(403)
    if request.method == "POST":
        c.category = request.form.get("category","other")
        c.subject = request.form.get("subject","").strip()
        c.detail = request.form.get("detail","").strip()
        db.session.commit()
        flash("Complaint updated", "success")
        return redirect(url_for("dashboard"))
    return render_template("tenant_complaint_form.html", c=c)

@app.route("/complaints/<int:cid>/delete", methods=["POST"])
@login_required
def complaint_delete(cid):
    c = Complaint.query.get_or_404(cid)
    if current_user.role != "tenant" or c.tenant_id != current_user.tenant_profile.id:
        abort(403)
    db.session.delete(c); db.session.commit()
    flash("Complaint deleted", "success")
    return redirect(url_for("dashboard"))

# ---------------- Tenant: Documents ----------------
@app.route("/uploads/<int:tenant_id>/<path:filename>")
@login_required
def serve_doc(tenant_id, filename):
    if not is_admin():
        if current_user.role != "tenant" or current_user.tenant_profile.id != tenant_id:
            abort(403)
    return send_from_directory(os.path.join(app.config["UPLOAD_FOLDER"], str(tenant_id)), filename, as_attachment=True)

@app.route("/tenant/docs", methods=["POST"])
@login_required
def tenant_docs_upload():
    if current_user.role != "tenant":
        abort(403)
    t = current_user.tenant_profile
    doc_type = request.form.get("doc_type","other")
    f = request.files.get("file")
    if not f or f.filename=="":
        flash("Choose a file", "danger"); return redirect(url_for("dashboard"))
    ext = f.filename.rsplit(".",1)[-1].lower()
    if ext not in { "pdf","jpg","jpeg","png" }:
        flash("Only pdf/jpg/png allowed (max 25MB)", "danger"); return redirect(url_for("dashboard"))
    safe = secure_filename(f.filename)
    dest_dir = os.path.join(app.config["UPLOAD_FOLDER"], str(t.id))
    os.makedirs(dest_dir, exist_ok=True)
    full = os.path.join(dest_dir, safe)
    f.save(full)
    d = Document(tenant_id=t.id, doc_type=doc_type, filename=safe, stored_path=full)
    db.session.add(d); db.session.commit()
    flash("Uploaded", "success")
    return redirect(url_for("dashboard"))

# ---------------- Payments (Razorpay with per-owner accounts) ----------------
try:
    import razorpay
except Exception:
    razorpay = None

def get_razorpay_client_for_owner(owner_user_id):
    if not razorpay: 
        return None
    gw = OwnerGateway.query.filter_by(owner_user_id=owner_user_id).first()
    if not gw or not gw.razorpay_key_id or not gw.razorpay_key_secret:
        return None
    return razorpay.Client(auth=(gw.razorpay_key_id, gw.razorpay_key_secret))

class OwnerGateway(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True, nullable=False)
    razorpay_key_id = db.Column(db.String(120))
    razorpay_key_secret = db.Column(db.String(120))
    bank_name = db.Column(db.String(120))
    account_name = db.Column(db.String(120))
    account_number = db.Column(db.String(120))
    ifsc = db.Column(db.String(40))
    upi_id = db.Column(db.String(120))
    owner = db.relationship("User", foreign_keys=[owner_user_id])

@app.route("/admin/gateway", methods=["GET","POST"])
@login_required
def admin_gateway():
    if current_user.role not in {"admin","superadmin"}:
        abort(403)
    owner_id = current_user.id
    gw = OwnerGateway.query.filter_by(owner_user_id=owner_id).first()
    if request.method == "POST":
        if not gw:
            gw = OwnerGateway(owner_user_id=owner_id)
            db.session.add(gw)
        gw.razorpay_key_id = request.form.get("razorpay_key_id","").strip()
        gw.razorpay_key_secret = request.form.get("razorpay_key_secret","").strip()
        gw.bank_name = request.form.get("bank_name","").strip()
        gw.account_name = request.form.get("account_name","").strip()
        gw.account_number = request.form.get("account_number","").strip()
        gw.ifsc = request.form.get("ifsc","").strip()
        gw.upi_id = request.form.get("upi_id","").strip()
        db.session.commit()
        flash("Gateway / bank details saved.", "success")
        return redirect(url_for("admin_gateway"))
    return render_template("admin_gateway.html", gw=gw)

@app.route("/pay/create", methods=["POST"])
@login_required
def create_payment():
    if current_user.role != "tenant":
        abort(403)
    t = current_user.tenant_profile
    period = request.form.get("period", datetime.utcnow().strftime("%Y-%m"))
    amount = float(request.form.get("amount") or t.rent_amount)
    p = Payment(tenant_id=t.id, amount=amount, period=period, status="pending", gateway="manual")
    db.session.add(p); db.session.commit()

    client = None
    owner_id = t.owner_user_id or (t.owner.id if t.owner else None)
    if owner_id:
        client = get_razorpay_client_for_owner(owner_id)

    if client:
        order = client.order.create(dict(amount=int(amount*100), currency="INR", payment_capture=1, notes={"tenant_id": str(t.id), "period": period}))
        p.gateway = "razorpay"
        p.gateway_order_id = order["id"]
        db.session.commit()
        key_id = OwnerGateway.query.filter_by(owner_user_id=owner_id).first().razorpay_key_id
        return jsonify({"ok": True, "order_id": p.gateway_order_id, "key_id": key_id, "amount": int(amount*100), "tenant": t.name, "email": t.user.email})
    else:
        p.status = "paid"; p.paid_on = datetime.utcnow(); db.session.commit()
        flash("Payment recorded (manual mode). Configure Razorpay for live payments.", "success")
        return redirect(url_for("dashboard"))

@app.route("/pay/confirm", methods=["POST"])
def pay_confirm():
    if not razorpay:
        return "Gateway not available on server", 400
    payment_id = request.form.get("razorpay_payment_id")
    order_id = request.form.get("razorpay_order_id")
    signature = request.form.get("razorpay_signature")
    p = Payment.query.filter_by(gateway_order_id=order_id).first()
    if not p:
        return "Order not found", 404
    tenant = Tenant.query.get(p.tenant_id)
    client = get_razorpay_client_for_owner(tenant.owner_user_id)
    if not client:
        return "Owner gateway not configured", 400
    ok = client.utility.verify_payment_signature({
        "razorpay_order_id": order_id,
        "razorpay_payment_id": payment_id,
        "razorpay_signature": signature
    })
    if ok is None:
        p.status = "paid"; p.paid_on = datetime.utcnow()
        p.gateway_payment_id = payment_id; p.gateway_signature = signature
        db.session.commit()
        flash("Payment successful", "success")
        return redirect(url_for("dashboard"))
    else:
        p.status = "failed"; db.session.commit()
        flash("Payment verification failed", "danger")
        return redirect(url_for("dashboard"))

# ---------------- Seed / Bootstrap ----------------
with app.app_context():
    db.create_all()
    # Seed super admin silently
    if not User.query.filter_by(email="petsbuzz@gmail.com").first():
        su = User(email="petsbuzz@gmail.com", password=generate_password_hash("admin123"), role="superadmin")
        db.session.add(su); db.session.commit()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
