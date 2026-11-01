import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import pytest
from redoscan.vulnscan import scan_text, RULES, CATEGORY_LABELS

PY_VULN = '''
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
os.system("rm -rf " + path)
subprocess.run(cmd, shell=True)
pickle.loads(data)
yaml.load(data)
hashlib.md5(password.encode())
token = random.randint(0, 999999)  # token generation
open(request.args.get("path"))
requests.get(request.args.get("url"))

@app.route("/users/<int:id>")
def get_user(id):
    return db.get(id)
'''

PY_SAFE = '''
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
subprocess.run(["ls", "-la", path])
json.loads(data)
yaml.safe_load(data)
import secrets
token = secrets.token_urlsafe(32)
open(safe_join(BASE_DIR, filename))

@app.route("/users/<int:id>")
@login_required
def get_user(id):
    if db.get(id).owner_id != current_user.id:
        abort(403)
    return db.get(id)
'''


def test_detects_all_python_categories():
    found = scan_text(PY_VULN, "python", "demo.py")
    cats = {f.category for _, f in found}
    assert {"sqli", "cmdi", "deser", "crypto", "rand", "path", "ssrf", "idor"} <= cats


def test_every_finding_is_heuristic_confidence():
    found = scan_text(PY_VULN, "python", "demo.py")
    assert all(f.confidence == "heuristic" for _, f in found)
    assert all(f.category != "redos" for _, f in found)


def test_every_finding_has_cwe_and_evidence():
    found = scan_text(PY_VULN, "python", "demo.py")
    assert all(f.cwe.startswith("CWE-") for _, f in found)
    assert all(f.evidence for _, f in found)


def test_parameterized_query_not_flagged():
    found = scan_text(PY_SAFE, "python", "demo.py")
    assert not any(f.category == "sqli" for _, f in found)


def test_subprocess_without_shell_true_not_flagged():
    found = scan_text(PY_SAFE, "python", "demo.py")
    assert not any(f.category == "cmdi" for _, f in found)


def test_safe_load_not_flagged():
    found = scan_text(PY_SAFE, "python", "demo.py")
    assert not any(f.category == "deser" for _, f in found)


def test_secrets_module_not_flagged_as_insecure_random():
    found = scan_text(PY_SAFE, "python", "demo.py")
    assert not any(f.category == "rand" for _, f in found)


def test_random_without_security_context_not_flagged():
    text = "dice_roll = random.randint(1, 6)\nshuffle_deck = random.choice(cards)\n"
    found = scan_text(text, "python", "demo.py")
    assert not any(f.category == "rand" for _, f in found)


def test_random_with_security_context_is_flagged():
    text = "reset_token = random.randint(100000, 999999)\n"
    found = scan_text(text, "python", "demo.py")
    assert any(f.category == "rand" for _, f in found)


def test_route_with_ownership_check_not_flagged_idor():
    found = scan_text(PY_SAFE, "python", "demo.py")
    assert not any(f.category == "idor" for _, f in found)


def test_php_shell_exec_with_escapeshellarg_not_flagged():
    text = 'shell_exec("tar -czf backup.tar.gz " . escapeshellarg($dir));\n'
    found = scan_text(text, "php", "demo.php")
    assert not any(f.category == "cmdi" for _, f in found)


def test_php_shell_exec_without_escaping_is_flagged():
    text = 'shell_exec("tar -czf backup.tar.gz " . $dir);\n'
    found = scan_text(text, "php", "demo.php")
    assert any(f.category == "cmdi" for _, f in found)


def test_php_lfi_and_ssrf_from_get_param():
    text = "include($_GET['page']);\nfile_get_contents($_GET['url']);\n"
    found = scan_text(text, "php", "demo.php")
    cats = {f.category for _, f in found}
    assert "path" in cats and "ssrf" in cats


def test_category_filter_restricts_rules():
    found_all = scan_text(PY_VULN, "python", "demo.py")
    found_sqli = scan_text(PY_VULN, "python", "demo.py", categories={"sqli"})
    assert len(found_sqli) < len(found_all)
    assert all(f.category == "sqli" for _, f in found_sqli)


def test_unsupported_language_returns_nothing():
    assert scan_text("whatever", "ruby", "x.rb") == []


def test_every_rule_category_is_labeled():
    for rule in RULES:
        assert rule.category in CATEGORY_LABELS


# ------------------------------------------------------------- New languages
def test_kotlin_detects_all_categories():
    text = '''
MessageDigest.getInstance("MD5")
Runtime.getRuntime().exec("ls " + cmd)
val ois = ObjectInputStream(is_)
db.execSQL("SELECT * FROM users WHERE id = $id")
val r = Random()  // session token
'''
    found = scan_text(text, "kotlin")
    cats = {f.category for _, f in found}
    assert {"crypto", "cmdi", "deser", "sqli", "rand"} <= cats


def test_kotlin_sqli_matches_regardless_of_keyword_order():
    text = 'db.execSQL("SELECT * FROM t WHERE id = $id")\n'
    assert any(f.category == "sqli" for _, f in scan_text(text, "kotlin"))


def test_c_detects_memsafety_and_other_categories():
    text = '''
gets(buf);
strcpy(dest, src);
system("ls " + dir);
MD5(data, len, out);
int x = rand();  // password seed
'''
    found = scan_text(text, "c")
    cats = {f.category for _, f in found}
    assert {"memsafety", "cmdi", "crypto", "rand"} <= cats
    cwes = {f.cwe for _, f in found}
    assert "CWE-242" in cwes  # gets()


def test_c_fgets_not_flagged():
    text = "char buf[64]; fgets(buf, sizeof(buf), stdin);\n"
    found = scan_text(text, "c")
    assert not any(f.category == "memsafety" for _, f in found)


def test_bash_detects_cmdi_and_crypto():
    text = 'eval "run $USER_INPUT"\nmd5sum "$password"\n'
    found = scan_text(text, "bash")
    cats = {f.category for _, f in found}
    assert "cmdi" in cats and "crypto" in cats


# ---------------------------------------------------------------------- DOS
def test_zip_extractall_flagged_without_size_check():
    text = 'zipfile.ZipFile(f).extractall("/tmp/out")\n'
    assert any(f.category == "dos" for _, f in scan_text(text, "python"))


def test_zip_extractall_not_flagged_with_size_check():
    text = '''
for info in zf.infolist():
    if info.file_size > MAX_SIZE:
        raise ValueError("too big")
zf.extractall("/tmp/out")
'''
    assert not any(f.category == "dos" for _, f in scan_text(text, "python"))


def test_xxe_dos_flagged_without_disallow_doctype():
    text = "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
    assert any(f.category == "dos" for _, f in scan_text(text, "java"))


def test_xxe_dos_not_flagged_with_disallow_doctype():
    text = '''
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
'''
    assert not any(f.category == "dos" for _, f in scan_text(text, "java"))


def test_express_json_without_limit_flagged():
    assert any(f.category == "dos" for _, f in scan_text("app.use(express.json());\n", "js"))


def test_express_json_with_limit_not_flagged():
    text = "app.use(express.json({ limit: '100kb' }));\n"
    assert not any(f.category == "dos" for _, f in scan_text(text, "js"))


# --------------------------------------------------------------------- AUTH
def test_hardcoded_jwt_secret_flagged():
    text = 'jwt.encode(payload, "supersecret123")\n'
    assert any(f.category == "auth" and f.cwe == "CWE-798" for _, f in scan_text(text, "python"))


def test_jwt_env_secret_not_flagged():
    text = 'jwt.encode(payload, os.environ["JWT_SECRET"], algorithm="HS256")\n'
    assert not any(f.category == "auth" for _, f in scan_text(text, "python"))


def test_jwt_alg_none_flagged():
    text = 'algorithm = "none"\n'
    assert any(f.cwe == "CWE-347" for _, f in scan_text(text, "python"))


def test_csrf_exempt_flagged():
    assert any(f.cwe == "CWE-352" for _, f in scan_text("@csrf_exempt\ndef view(r): pass\n", "python"))


def test_flask_cookie_without_flags_flagged():
    text = 'resp.set_cookie("session", sid)\n'
    assert any(f.cwe == "CWE-614" for _, f in scan_text(text, "python"))


def test_flask_cookie_with_flags_not_flagged():
    text = 'resp.set_cookie("session", sid, secure=True, httponly=True)\n'
    assert not any(f.category == "auth" for _, f in scan_text(text, "python"))


def test_flask_cookie_with_nested_call_and_flags_not_flagged():
    # Regression: a nested call like token_urlsafe(32) before the flags
    # must not make the paren-matching stop early at the inner ')'.
    text = 'resp.set_cookie("session", secrets.token_urlsafe(32), secure=True, httponly=True)\n'
    assert not any(f.category == "auth" for _, f in scan_text(text, "python"))


def test_flask_cookie_with_only_one_flag_still_flagged():
    text = 'resp.set_cookie("session", sid, secure=True)\n'
    assert any(f.cwe == "CWE-614" for _, f in scan_text(text, "python"))


def test_express_cookie_with_nested_call_and_flags_not_flagged():
    text = ('res.cookie("session", crypto.randomBytes(32).toString("hex"), '
            '{ httpOnly: true, secure: true });\n')
    assert not any(f.category == "auth" for _, f in scan_text(text, "js"))


def test_express_cookie_without_flags_flagged():
    assert any(f.cwe == "CWE-614" for _, f in scan_text('res.cookie("session", sid);\n', "js"))


def test_hardcoded_credentials_flagged_python():
    text = 'if username == "admin" and password == "admin123":\n    login()\n'
    assert any(f.cwe == "CWE-798" and f.category == "auth" for _, f in scan_text(text, "python"))


def test_hardcoded_credentials_flagged_js():
    text = 'if (user === "admin" && pass === "admin123") { login(); }\n'
    assert any(f.category == "auth" for _, f in scan_text(text, "js"))
