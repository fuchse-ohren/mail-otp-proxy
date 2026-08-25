"""メールを定期取得して OTP を保存するワーカー。"""
import email
import hashlib
import imaplib
import poplib
import re
import time
from email.header import decode_header
from email.utils import parseaddr

from app import make_app


def text(value):
    """メールヘッダまたは本文を UTF-8 文字列にする。"""
    if not value: return ""
    parts = decode_header(value) if isinstance(value, str) else [(value, None)]
    return "".join((part.decode(code or "utf-8", errors="replace") if isinstance(part, bytes) else part) for part, code in parts)


def body(msg):
    """text/plain 本文を取り出す。"""
    for part in msg.walk():
        if part.get_content_type() == "text/plain" and "attachment" not in part.get("Content-Disposition", ""):
            raw = part.get_payload(decode=True) or b""
            return raw.decode(part.get_content_charset() or "utf-8", errors="replace")
    return ""


def save_mail(app, account, raw):
    """一通のメールを重複排除し、最初の OTP を保存する。"""
    msg = email.message_from_bytes(raw); mail_body = body(msg); now = int(time.time())
    key = text(msg.get("Message-ID")).strip() or hashlib.sha256(mail_body.encode("utf-8")).hexdigest()
    sender = parseaddr(text(msg.get("From")))[1]; recipient = parseaddr(text(msg.get("To")))[1]; subject = text(msg.get("Subject"))
    with app.app_context():
        from flask import g
        con = g.db if "db" in g else None
        if con is None:
            import sqlite3
            con = sqlite3.connect(app.config["DATABASE"]); con.row_factory = sqlite3.Row; con.execute("PRAGMA foreign_keys = ON")
        try:
            cur = con.execute("INSERT INTO messages(account_id,message_id,sender,recipient,time,subject,body_head,created_at) VALUES (?,?,?,?,?,?,?,?)", (account["id"], key, sender, recipient, now, subject, mail_body[:15], now))
        except Exception:
            con.rollback(); con.close(); return
        mail_id = cur.lastrowid
        for rule in con.execute("SELECT * FROM rules").fetchall():
            if re.search(rule["fromRegex"], sender) and re.search(rule["subjectRegex"], subject):
                hit = re.search(rule["extractRegex"], mail_body)
                if hit:
                    code = hit.group(1) if hit.lastindex else hit.group(0)
                    con.execute("INSERT OR IGNORE INTO otp(time,used,account_id,rule_id,otp,message_id,created_at) VALUES (?,?,?,?,?,?,?)", (now, 0, account["id"], rule["id"], code, mail_id, now))
        con.commit(); con.close()


def run_once(app):
    """全アカウントを一巡する。"""
    import sqlite3
    con = sqlite3.connect(app.config["DATABASE"]); con.row_factory = sqlite3.Row
    accounts = con.execute("SELECT * FROM accounts").fetchall(); con.close()
    for account in accounts:
        try:
            if account["protocol"] == 1:
                client = imaplib.IMAP4_SSL(account["server"], account["port"]) if account["encrypt"] == 1 else imaplib.IMAP4(account["server"], account["port"])
                if account["encrypt"] == 2: client.starttls()
                client.login(account["account"], account["password"]); client.select("INBOX")
                _, data = client.search(None, "ALL")
                for num in data[0].split():
                    _, item = client.fetch(num, "(RFC822)"); save_mail(app, account, item[0][1])
                client.logout()
            else:
                client = poplib.POP3_SSL(account["server"], account["port"]) if account["encrypt"] == 1 else poplib.POP3(account["server"], account["port"])
                if account["encrypt"] == 2: client.stls()
                client.user(account["account"]); client.pass_(account["password"])
                count = len(client.list()[1])
                for num in range(1, count + 1):
                    save_mail(app, account, b"\n".join(client.retr(num)[1]))
                client.quit()
        except Exception:
            pass


if __name__ == "__main__":
    app = make_app()
    while True:
        run_once(app)
        import sqlite3
        con = sqlite3.connect(app.config["DATABASE"]); row = con.execute("SELECT value FROM settings WHERE key='mail_check_seconds'").fetchone(); con.close()
        time.sleep(max(1, int(row[0])))
