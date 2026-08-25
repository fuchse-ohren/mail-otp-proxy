"""メール OTP プロキシの Flask アプリケーション。"""
import hashlib
import os
import re
import secrets
import sqlite3
import time
import uuid
from functools import wraps

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def make_app(test_config=None):
    """アプリケーションを作成する。"""
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32)),
        DATABASE=os.environ.get("DATABASE_PATH", os.path.join(app.instance_path, "mail_otp.db")),
    )
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.instance_path, exist_ok=True)

    gui_pass = app.config.get("GUI_PASSWD") if test_config and test_config.get("GUI_PASSWD") else os.environ.get("GUI_PASSWD")
    if not gui_pass:
        gui_pass = secrets.token_urlsafe(16)
        print("GUI_PASSWD が未設定です。今回の管理画面パスワード:", gui_pass)
    app.config["GUI_PASSWD"] = gui_pass

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(error=None):
        con = g.pop("db", None)
        if con is not None:
            con.close()

    def init_db():
        con = db()
        con.executescript("""
        CREATE TABLE IF NOT EXISTS accounts (
          id TEXT PRIMARY KEY, email TEXT NOT NULL, account TEXT NOT NULL,
          password TEXT NOT NULL, server TEXT NOT NULL, protocol INTEGER NOT NULL,
          encrypt INTEGER NOT NULL, port INTEGER NOT NULL,
          created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS rules (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT,
          fromRegex TEXT NOT NULL, subjectRegex TEXT NOT NULL, extractRegex TEXT NOT NULL,
          expiration INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT NOT NULL,
          message_id TEXT NOT NULL, sender TEXT, recipient TEXT, time INTEGER NOT NULL,
          subject TEXT, body_head TEXT, created_at INTEGER NOT NULL,
          FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
          UNIQUE(account_id, message_id)
        );
        CREATE TABLE IF NOT EXISTS otp (
          id INTEGER PRIMARY KEY AUTOINCREMENT, time INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0,
          account_id TEXT NOT NULL, rule_id INTEGER NOT NULL, otp TEXT NOT NULL,
          message_id INTEGER, created_at INTEGER NOT NULL,
          FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
          FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE,
          FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE SET NULL,
          UNIQUE(message_id, rule_id)
        );
        CREATE INDEX IF NOT EXISTS idx_otp_find ON otp(account_id, rule_id, used, time DESC);
        CREATE TABLE IF NOT EXISTS auth (
          apikey TEXT PRIMARY KEY, descriptions TEXT, permissions TEXT NOT NULL DEFAULT '',
          created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT OR IGNORE INTO settings(key, value) VALUES ('mail_check_seconds', '60');
        """)
        con.commit()

    def gui_only(view):
        @wraps(view)
        def inner(*args, **kwargs):
            if not session.get("gui_ok"):
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return inner

    def api_only(view):
        @wraps(view)
        def inner(*args, **kwargs):
            head = request.headers.get("Authorization", "")
            if not head.startswith("Bearer "):
                return jsonify(error="unauthorized"), 401
            key = head[7:].strip()
            rows = db().execute("SELECT apikey FROM auth").fetchall()
            if not any(check_password_hash(row["apikey"], key) for row in rows):
                return jsonify(error="unauthorized"), 401
            return view(*args, **kwargs)
        return inner

    def account_data(form):
        data = {name: form.get(name, "").strip() for name in ("id", "email", "account", "password", "server")}
        try:
            data["protocol"] = int(form.get("protocol", ""))
            data["encrypt"] = int(form.get("encrypt", ""))
            data["port"] = int(form.get("port", ""))
        except ValueError:
            raise ValueError("数値項目が不正です。")
        if not all(data[name] for name in ("id", "email", "account", "password", "server")) or "@" not in data["email"]:
            raise ValueError("必須項目またはメールアドレスが不正です。")
        if data["protocol"] not in (0, 1) or data["encrypt"] not in (0, 1, 2) or not 1 <= data["port"] <= 65535:
            raise ValueError("プロトコル、暗号化方式、またはポート番号が不正です。")
        return data

    def rule_data(form):
        data = {name: form.get(name, "").strip() for name in ("name", "description", "fromRegex", "subjectRegex", "extractRegex")}
        try:
            data["expiration"] = int(form.get("expiration", ""))
            for name in ("fromRegex", "subjectRegex", "extractRegex"):
                re.compile(data[name])
        except (ValueError, re.error):
            raise ValueError("有効期限または正規表現が不正です。")
        if not data["name"] or data["expiration"] < 1:
            raise ValueError("ルール名と1秒以上の有効期限は必須です。")
        return data

    @app.route("/")
    def root():
        return redirect(url_for("index"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST" and secrets.compare_digest(request.form.get("password", ""), app.config["GUI_PASSWD"]):
            session["gui_ok"] = True
            return redirect(url_for("index"))
        if request.method == "POST":
            flash("パスワードが正しくありません。")
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/index")
    @gui_only
    def index():
        con = db()
        now = int(time.time())
        return render_template("index.html", accounts=con.execute("SELECT id, email FROM accounts ORDER BY id").fetchall(), rules=con.execute("SELECT id, name, description FROM rules ORDER BY id").fetchall(), messages=con.execute("SELECT sender, recipient, time, subject, body_head FROM messages ORDER BY time DESC LIMIT 100").fetchall(), otps=con.execute("SELECT r.name, r.description, o.otp FROM otp o JOIN rules r ON r.id=o.rule_id WHERE o.used=0 AND o.time + r.expiration > ? ORDER BY o.time DESC", (now,)).fetchall())

    @app.route("/config")
    @gui_only
    def config():
        return render_template("config.html")

    @app.route("/config/mailAccounts", methods=["GET", "POST"])
    @gui_only
    def mail_accounts():
        con = db()
        if request.method == "POST":
            try:
                data = account_data(request.form); now = int(time.time())
                con.execute("INSERT INTO accounts VALUES (:id,:email,:account,:password,:server,:protocol,:encrypt,:port,:now,:now)", data | {"now": now}); con.commit(); flash("メールアカウントを登録しました。")
            except (ValueError, sqlite3.IntegrityError) as err: flash(str(err))
            return redirect(url_for("mail_accounts"))
        return render_template("accounts.html", accounts=con.execute("SELECT * FROM accounts ORDER BY id").fetchall(), seconds=con.execute("SELECT value FROM settings WHERE key='mail_check_seconds'").fetchone()["value"])

    @app.post("/config/mailAccounts/seconds")
    @gui_only
    def mail_seconds():
        try:
            seconds = int(request.form.get("seconds", "")); assert seconds >= 1
            db().execute("UPDATE settings SET value=? WHERE key='mail_check_seconds'", (str(seconds),)); db().commit(); flash("確認間隔を更新しました。")
        except (ValueError, AssertionError): flash("確認間隔は1秒以上の整数です。")
        return redirect(url_for("mail_accounts"))

    @app.post("/config/mailAccounts/<account_id>/delete")
    @gui_only
    def delete_account(account_id):
        db().execute("DELETE FROM accounts WHERE id=?", (account_id,)); db().commit(); return redirect(url_for("mail_accounts"))

    @app.route("/config/mailAccounts/<account_id>/edit", methods=["GET", "POST"])
    @gui_only
    def edit_account(account_id):
        con = db(); old = con.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        if not old: abort(404)
        if request.method == "POST":
            try:
                data = account_data(request.form)
                con.execute("UPDATE accounts SET email=:email,account=:account,password=:password,server=:server,protocol=:protocol,encrypt=:encrypt,port=:port,updated_at=:now WHERE id=:old_id", data | {"now": int(time.time()), "old_id": account_id}); con.commit()
                return redirect(url_for("mail_accounts"))
            except ValueError as err: flash(str(err))
        return render_template("account_edit.html", account=old)

    @app.route("/config/extractRules", methods=["GET", "POST"])
    @gui_only
    def extract_rules():
        con = db()
        if request.method == "POST":
            try:
                data = rule_data(request.form); now = int(time.time())
                con.execute("INSERT INTO rules(name,description,fromRegex,subjectRegex,extractRegex,expiration,created_at,updated_at) VALUES (:name,:description,:fromRegex,:subjectRegex,:extractRegex,:expiration,:now,:now)", data | {"now": now}); con.commit(); flash("抽出ルールを登録しました。")
            except ValueError as err: flash(str(err))
            return redirect(url_for("extract_rules"))
        return render_template("rules.html", rules=con.execute("SELECT * FROM rules ORDER BY id").fetchall())

    @app.post("/config/extractRules/<int:rule_id>/delete")
    @gui_only
    def delete_rule(rule_id):
        db().execute("DELETE FROM rules WHERE id=?", (rule_id,)); db().commit(); return redirect(url_for("extract_rules"))

    @app.route("/config/extractRules/<int:rule_id>/edit", methods=["GET", "POST"])
    @gui_only
    def edit_rule(rule_id):
        con = db(); old = con.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
        if not old: abort(404)
        if request.method == "POST":
            try:
                data = rule_data(request.form)
                con.execute("UPDATE rules SET name=:name,description=:description,fromRegex=:fromRegex,subjectRegex=:subjectRegex,extractRegex=:extractRegex,expiration=:expiration,updated_at=:now WHERE id=:rule_id", data | {"now": int(time.time()), "rule_id": rule_id}); con.commit()
                return redirect(url_for("extract_rules"))
            except ValueError as err: flash(str(err))
        return render_template("rule_edit.html", rule=old)

    @app.route("/config/api", methods=["GET", "POST"])
    @gui_only
    def api_config():
        con = db(); new_key = None
        if request.method == "POST":
            new_key = str(uuid.uuid4())
            con.execute("INSERT INTO auth(apikey,descriptions,permissions,created_at) VALUES (?,?,?,?)", (generate_password_hash(new_key), request.form.get("descriptions", "").strip(), "", int(time.time()))); con.commit()
        return render_template("api.html", keys=con.execute("SELECT rowid, descriptions, created_at FROM auth ORDER BY created_at DESC").fetchall(), new_key=new_key)

    @app.post("/config/api/<int:key_id>/delete")
    @gui_only
    def delete_key(key_id):
        db().execute("DELETE FROM auth WHERE rowid=?", (key_id,)); db().commit(); return redirect(url_for("api_config"))

    @app.get("/api/v1")
    @api_only
    def api_check():
        return jsonify(status="ok")

    @app.get("/api/v1/getOTP")
    @api_only
    def get_otp():
        account_id = request.args.get("accounts", ""); rule_text = request.args.get("rules", "")
        try: rule_id = int(rule_text)
        except ValueError: return jsonify(error="invalid_request"), 400
        con = db()
        if not con.execute("SELECT 1 FROM accounts WHERE id=?", (account_id,)).fetchone() or not con.execute("SELECT 1 FROM rules WHERE id=?", (rule_id,)).fetchone():
            return jsonify(error="not_found"), 404
        now = int(time.time())
        con.execute("BEGIN IMMEDIATE")
        row = con.execute("SELECT o.id, o.otp FROM otp o JOIN rules r ON r.id=o.rule_id WHERE o.account_id=? AND o.rule_id=? AND o.used=0 AND o.time+r.expiration>? ORDER BY o.time DESC LIMIT 1", (account_id, rule_id, now)).fetchone()
        if row:
            con.execute("UPDATE otp SET used=1 WHERE id=? AND used=0", (row["id"],)); con.commit()
            return jsonify(accounts=account_id, rules=rule_id, otp=row["otp"]), 200
        con.commit(); return jsonify(accounts=account_id, rules=rule_id, otp=None), 202

    with app.app_context(): init_db()
    return app


if __name__ == "__main__":
    make_app().run(host="0.0.0.0", port=5000)
