import os
import tempfile

from app import make_app


def app_client():
    db_file = tempfile.NamedTemporaryFile(delete=False)
    db_file.close()
    app = make_app({"TESTING": True, "DATABASE": db_file.name, "GUI_PASSWD": "test-pass", "SECRET_KEY": "test"})
    return app, db_file.name


def login(client):
    return client.post("/login", data={"password": "test-pass"})


def test_api_and_otp_use_once():
    app, path = app_client()
    try:
        client = app.test_client(); login(client)
        client.post("/config/mailAccounts", data={"id": "mail01", "email": "a@example.com", "account": "a", "password": "plain", "server": "mail.example.com", "protocol": "1", "encrypt": "1", "port": "993"})
        client.post("/config/extractRules", data={"name": "test", "description": "", "fromRegex": ".*", "subjectRegex": ".*", "extractRegex": "(\\d{6})", "expiration": "60"})
        key_page = client.post("/config/api", data={"descriptions": "test"}).data.decode()
        import re
        key = re.search(r"([0-9a-f]{8}-[0-9a-f-]{27})", key_page).group(1)
        with app.app_context():
            from flask import g
            con = __import__("sqlite3").connect(app.config["DATABASE"])
            con.execute("INSERT INTO otp(time,used,account_id,rule_id,otp,created_at) VALUES (?,?,?,?,?,?)", (9999999999, 0, "mail01", 1, "123456", 1)); con.commit(); con.close()
        head = {"Authorization": "Bearer " + key}
        assert client.get("/api/v1", headers=head).status_code == 200
        assert client.get("/api/v1/getOTP?accounts=mail01&rules=1", headers=head).get_json()["otp"] == "123456"
        assert client.get("/api/v1/getOTP?accounts=mail01&rules=1", headers=head).status_code == 202
        assert client.get("/api/v1/getOTP?accounts=none&rules=1", headers=head).status_code == 404
    finally:
        os.unlink(path)
