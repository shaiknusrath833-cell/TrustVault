import os
import uuid
import sqlite3

from flask import (
    Flask, render_template, request, redirect,
    session, send_from_directory, abort
)

from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
app = Flask(__name__)
csrf = CSRFProtect(app)
app.secret_key = os.environ["TRUSTVAULT_SECRET_KEY"]
app.config["UPLOAD_FOLDER"] = os.path.join(
    app.root_path, "uploads"
)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "txt", "png", "jpg", "jpeg"
}

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )
def get_db():
    conn = sqlite3.connect("trustvault.db")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn



def log_activity(conn, user_id, document_id, action, details=None):
    conn.execute(
        """
        INSERT INTO audit_logs
        (user_id, document_id, action, details, ip_address)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            user_id,
            document_id,
            action,
            details,
            request.remote_addr
        )
    )
def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    # Add role column to existing users table if missing
    columns = [
        row[1] for row in conn.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    if "role" not in columns:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN role TEXT NOT NULL DEFAULT 'owner'
            CHECK (role IN ('admin', 'owner', 'viewer'))
        """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS document_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            permission TEXT NOT NULL
                CHECK (permission IN ('read', 'edit')),
            granted_by INTEGER NOT NULL,
            granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            revoked_at TIMESTAMP DEFAULT NULL,

            FOREIGN KEY (document_id) REFERENCES documents(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (granted_by) REFERENCES users(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            document_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (document_id) REFERENCES documents(id)
        )
    """)
    conn.commit()
    conn.close()

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        from werkzeug.security import generate_password_hash

        if len(password) < 8:
            return "Password must have at least 8 characters."

        hashed = generate_password_hash(password)

        try:

            conn = get_db()
            conn.execute(
                "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                (name, email, hashed)
            )
            conn.commit()
            conn.close()
            return redirect("/")

        except sqlite3.IntegrityError:
            conn.close()
            return "Email already registered. Please try another."

    return render_template("register.html")

@app.route("/login", methods=["POST"])
def login():
    email = request.form["email"]
    password = request.form["password"]

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()
    conn.close()

    if user and check_password_hash(user[3], password):
        session["user_id"] = user[0]
        session["user_name"] = user[1]
        session["user_role"] = user[4]

        return redirect("/dashboard")


    return "Invalid email or password. <a href='/'>Try again</a>"
@app.route("/upload", methods=["POST"])
def upload():
    if "user_id" not in session:
        return redirect("/")

    if "file" not in request.files:
        return "No file selected."

    file = request.files["file"]

    if file.filename == "":
        return "Please select a file."

    original_name = secure_filename(file.filename)

    if not original_name or not allowed_file(original_name):
        return "File type not allowed."

    extension = original_name.rsplit(".", 1)[1].lower()
    stored_name = str(uuid.uuid4()) + "." + extension

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"], stored_name
    )

    file.save(file_path)
    conn = None
        
    try:
        conn = get_db()

        cursor = conn.execute(
            """INSERT INTO documents
            (owner_id, original_name, stored_name)
            VALUES (?, ?, ?)""",
            (session["user_id"], original_name, stored_name)
        )

        document_id = cursor.lastrowid

        log_activity(
            conn,
            session["user_id"],
            document_id,
            "UPLOAD",
            "Document uploaded: " + original_name
        )

        conn.commit()
        conn.close()

    except Exception as e:
        if conn:
            conn.close()

        if os.path.exists(file_path):
            os.remove(file_path)

        print("Upload error:",e)

        return "Upload failed. Please try again."
     
    return redirect("/dashboard")
@app.route("/view/<int:document_id>")
def view_document(document_id):

    if "user_id" not in session:
        return redirect("/")

    conn = get_db()

    try:
        # Get current user's role
        user = conn.execute(
            "SELECT role FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

        # Find the requested document
        document = conn.execute(
            """
            SELECT id, owner_id, original_name, stored_name
            FROM documents
            WHERE id = ?
            """,
            (document_id,)
        ).fetchone()

        if not user or not document:
            abort(404)

        is_admin = user[0] == "admin"
        is_owner = document[1] == session["user_id"]

        # Check whether the user has permission
        permission = conn.execute(
            """
            SELECT permission
FROM document_permissions
WHERE document_id = ?
AND user_id = ?
AND revoked_at IS NULL
ORDER BY granted_at DESC, id DESC
LIMIT 1
            """,
            (document_id, session["user_id"])
        ).fetchone()

        has_permission = (
            permission is not None
            and permission[0] in ("read", "edit")
        )

        # Block unauthorized users
        if not (is_admin or is_owner or has_permission):
            abort(403)

        # Record successful document viewing
        log_activity(
            conn,
            session["user_id"],
            document_id,
            "VIEW",
            "Document viewed: " + document[2]
        )

        conn.commit()

        stored_name = document[3]
        original_name = document[2]

    finally:
        conn.close()

    # Send the authorized document
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        stored_name,
        as_attachment=False,
        download_name=original_name
    )
    
@app.route("/edit/<int:document_id>", methods=["POST"])
def edit_document(document_id):

    if "user_id" not in session:
        return redirect("/")

    if "file" not in request.files:
        return "Please select a revised document."

    file = request.files["file"]

    if file.filename == "":
        return "No file selected."

    original_name = secure_filename(file.filename)

    if not original_name or not allowed_file(original_name):
        return "File type not allowed."

    conn = get_db()
    new_file_path = None

    try:
        document = conn.execute(
            """
            SELECT owner_id, stored_name
            FROM documents
            WHERE id = ?
            """,
            (document_id,)
        ).fetchone()

        if not document:
            abort(404)

        user = conn.execute(
            "SELECT role FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

        permission = conn.execute(
            """
            SELECT permission
            FROM document_permissions
            WHERE document_id = ?
            AND user_id = ?
            AND revoked_at IS NULL
            ORDER BY granted_at DESC, id DESC
            LIMIT 1
            """,
            (document_id, session["user_id"])
        ).fetchone()

        allowed_to_edit = (
            user and (
                user[0] == "admin"
                or document[0] == session["user_id"]
                or (permission and permission[0] == "edit")
            )
        )

        if not allowed_to_edit:
            abort(403)

        extension = original_name.rsplit(".", 1)[1].lower()
        stored_name = str(uuid.uuid4()) + "." + extension

        new_file_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            stored_name
        )

        file.save(new_file_path)

        conn.execute(
            """
            UPDATE documents
            SET original_name = ?, stored_name = ?
            WHERE id = ?
            """,
            (original_name, stored_name, document_id)
        )

        log_activity(
            conn,
            session["user_id"],
            document_id,
            "EDIT",
            "Document replaced with revised version: " + original_name
        )

        conn.commit()

        old_file_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            document[1]
        )

        if os.path.exists(old_file_path):
            os.remove(old_file_path)

        return redirect("/dashboard")

    except Exception as e:
        conn.rollback()

        if new_file_path and os.path.exists(new_file_path):
            os.remove(new_file_path)

        print("Edit error:", e)
        return "Document editing failed."

    finally:
        conn.close()


@app.route("/share", methods=["POST"])
def share_document():

    if "user_id" not in session:
        return redirect("/")

    document_id = request.form.get("document_id")
    recipient_email = request.form.get("email", "").strip().lower()
    permission = request.form.get("permission")

    if permission not in ("read", "edit"):
        return "Invalid permission."

    if not document_id or not document_id.isdigit():
        return "Invalid document ID."

    conn = get_db()

    try:
        # Check document ownership
        document = conn.execute(
            """
            SELECT id, original_name
            FROM documents
            WHERE id = ? AND owner_id = ?
            """,
            (document_id, session["user_id"])
        ).fetchone()

        if not document:
            return "Only the document owner can share this document."

        # Find the recipient account
        recipient = conn.execute(
            "SELECT id FROM users WHERE email = ?",
            (recipient_email,)
        ).fetchone()

        if not recipient:
            return "Recipient account not found."

        recipient_id = recipient[0]

        if recipient_id == session["user_id"]:
            return "You cannot share a document with yourself."

        # Revoke any previous active permission
        conn.execute(
            """
            UPDATE document_permissions
            SET revoked_at = CURRENT_TIMESTAMP
            WHERE document_id = ?
            AND user_id = ?
            AND revoked_at IS NULL
            """,
            (document_id, recipient_id)
        )

        # Grant the new permission
        conn.execute(
            """
            INSERT INTO document_permissions
            (document_id, user_id, permission, granted_by, granted_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (
                document_id,
                recipient_id,
                permission,
                session["user_id"]
            )
        )

        # Record the sharing activity
        log_activity(
            conn,
            session["user_id"],
            document_id,
            "SHARE",
            "Document shared with user ID "
            + str(recipient_id)
            + " with "
            + permission
            + " permission."
        )

        conn.commit()

        return redirect("/dashboard")

    except Exception as e:
        conn.rollback()
        print("Sharing error:", e)
        return "Document sharing failed."

    finally:
        conn.close()
        
@app.route("/revoke", methods=["POST"])
def revoke_access():

    if "user_id" not in session:
        return redirect("/")

    document_id = request.form.get("document_id")
    recipient_email = request.form.get("email", "").strip().lower()

    if not document_id or not document_id.isdigit():
        return "Invalid document ID."

    conn = get_db()

    try:
        # Check document ownership
        document = conn.execute(
            """
            SELECT id
            FROM documents
            WHERE id = ? AND owner_id = ?
            """,
            (document_id, session["user_id"])
        ).fetchone()

        if not document:
            return "Only the document owner can revoke access."

        # Find recipient
        recipient = conn.execute(
            "SELECT id FROM users WHERE email = ?",
            (recipient_email,)
        ).fetchone()

        if not recipient:
            return "Recipient account not found."

        recipient_id = recipient[0]

        # Revoke active permission
        cursor = conn.execute(
            """
            UPDATE document_permissions
            SET revoked_at = CURRENT_TIMESTAMP
            WHERE document_id = ?
            AND user_id = ?
            AND revoked_at IS NULL
            """,
            (document_id, recipient_id)
        )

        if cursor.rowcount == 0:
            return "No active access found for this user."

        # Record revocation activity
        log_activity(
            conn,
            session["user_id"],
            document_id,
            "REVOKE",
            "Document access revoked for user ID " + str(recipient_id)
        )

        conn.commit()

        return redirect("/dashboard")

    except Exception as e:
        conn.rollback()
        print("Revocation error:", e)
        return "Failed to revoke access."

    finally:
        conn.close()


@app.route("/dashboard")


def dashboard():
    if "user_id" not in session:
        return redirect("/")

    conn = get_db()

    documents = conn.execute(
        """
        SELECT id, original_name, uploaded_at
        FROM documents
        WHERE owner_id = ?
        ORDER BY uploaded_at DESC
        """,
        (session["user_id"],)
    ).fetchall()
    
    shared_documents = conn.execute(
        """
        SELECT
            d.id,
            d.original_name,
            d.uploaded_at,
            u.name AS owner_name,
            dp.permission
        FROM document_permissions dp
        JOIN documents d ON dp.document_id = d.id
        JOIN users u ON d.owner_id = u.id
        WHERE dp.user_id = ?
        AND dp.revoked_at IS NULL
        ORDER BY dp.granted_at DESC
        """,
        (session["user_id"],)
    ).fetchall()


    conn.close()

    return render_template(
        "dashboard.html",
        name=session["user_name"],
        role=session["user_role"],
        documents=documents,
        shared_documents=shared_documents
    )
@app.route("/admin")
def admin_dashboard():
    if "user_id" not in session:
        return redirect("/")

    conn = get_db()

    user = conn.execute(
        "SELECT role FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if not user or user[0] != "admin":
        conn.close()
        abort(403)

    users = conn.execute(
        "SELECT id, name, email, role FROM users"
    ).fetchall()

    logs = conn.execute(
        "SELECT * FROM audit_logs ORDER BY created_at DESC"
    ).fetchall()

    conn.close()

    return render_template(
        "admin.html",
        users=users,
        logs=logs
    )
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    init_db()
    app.run(debug=False)
