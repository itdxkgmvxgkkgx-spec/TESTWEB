import subprocess
import os
import time
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
import base64
import uuid
import secrets
import re
import sys
from urllib.parse import parse_qs

CONFIG_PATH = "/usr/local/etc/xray/config.json"
XRAY_LOG_PATH = "/usr/local/etc/xray/xray_runtime.log"
DB_PATH = "panel_db.json"
DEFAULT_CLEAN_IP = "speed.cloudflare.com"

PANEL_USER = "admin"
# 🔑 رمز پنل: عددی ۱۰ رقمی کاملاً تصادفی (هر سیکل جدید جنریت میشه)
PANEL_PASS = ''.join(secrets.choice('0123456789') for _ in range(10))
SESSION_TOKEN = secrets.token_hex(16)

SYSTEM_LIVE_LOGS = []
USER_TARGET_SITES = {}
LAST_COUNTERS = {}


def sanitize_domain(raw):
    """پاک‌سازی و اعتبارسنجی دامنه — هیچ‌وقت خالی ثبت نمیشه"""
    d = (raw or "").strip()
    d = re.sub(r'^https?://', '', d, flags=re.IGNORECASE)
    d = d.split('/')[0].strip().rstrip('.').lower()
    return d


# 🌐 دامنه ثابت پنل روی کلودفلر
# اگر env خالی بود، دامنه جدید استفاده میشه
EDGE_DOMAIN = sanitize_domain(
    os.environ.get('PANEL_DOMAIN', 'killpv2.dpdns.org')
)

if not EDGE_DOMAIN or not re.match(
    r'^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$',
    EDGE_DOMAIN
):
    print(
        "🚨 FATAL ERROR: دامنه پنل خالی یا نامعتبر است! PANEL_DOMAIN رو چک کن داداش.",
        flush=True
    )
    sys.exit(1)

# هاست تانل = دامنه ثابت کلودفلر
tunnel_host = EDGE_DOMAIN


def load_database():
    """بارگذاری فوق امن و بدون نقص دیتابیس کلاینت‌ها برای جلوگیری از باگ یک‌بار در میان"""
    if os.path.exists(DB_PATH):
        try:
            with open(DB_PATH, 'r') as f:
                data = json.load(f)
                if data and len(data) > 0:
                    return data
        except Exception:
            pass

    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                xray_data = json.load(f)

            if "_killpv2_db_backup" in xray_data:
                backup_str = xray_data["_killpv2_db_backup"]
                decoded_data = json.loads(
                    base64.b64decode(
                        backup_str.encode('utf-8')
                    ).decode('utf-8')
                )

                if decoded_data and len(decoded_data) > 0:
                    return decoded_data

        except Exception:
            pass

    return {
        "Main_kill_pv2": {
            "uuid": "b6a00fb0-460e-4323-96af-3ba2f48470ee",
            "total_limit_bytes": 0,
            "used_bytes": 0,
            "clean_ip": "speed.cloudflare.com",
            "status": "OFFLINE",
            "last_active_time": 0,
            "down_speed": 0,
            "up_speed": 0,
            "created_at": int(time.time()),
            "expire_seconds": 31536000,
            "active": True
        }
    }


configs_db = load_database()


def ensure_sub_tokens():
    """به هر کاربر یک توکن ساب تصادفی و غیرقابل حدس میده تا بات‌ها نتونن لینک ساب رو پیدا کنن"""
    changed = False

    for _u_name, _u_data in configs_db.items():
        if not _u_data.get("sub_token"):
            _u_data["sub_token"] = secrets.token_urlsafe(24)
            changed = True

        if "stats_offset" not in _u_data:
            _u_data["stats_offset"] = 0
            changed = True

        if "stats_last" not in _u_data:
            _u_data["stats_last"] = 0
            changed = True

    return changed


def save_database():
    with open(DB_PATH, 'w') as f:
        json.dump(configs_db, f, indent=4)


if ensure_sub_tokens():
    save_database()


def find_user_by_token(token):
    for un, ud in configs_db.items():
        if ud.get("sub_token") == token:
            return un
    return None


def push_subs_to_github():
    """تولید اتوماتیک لینک‌های ساب و آپلود مستقیم به گیت‌هاب جهت پایداری همیشگی لینک ساب"""
    try:
        os.makedirs('sub_links', exist_ok=True)

        # حذف فایل‌های کاربران پاک شده
        for f in os.listdir('sub_links'):
            if f not in configs_db:
                try:
                    os.remove(os.path.join('sub_links', f))
                except:
                    pass

        now = int(time.time())

        for k, v in configs_db.items():
            if not v.get("active", True):
                payload_str = "// ACCOUNT EXPIRED OR DISABLED\n"
                payload = base64.b64encode(
                    payload_str.encode('utf-8')
                ).decode('utf-8')

            else:
                c_ip = v.get("clean_ip", DEFAULT_CLEAN_IP)
                total_bytes = v["total_limit_bytes"]
                rem_bytes = (
                    max(0, total_bytes - v["used_bytes"])
                    if total_bytes > 0 else 0
                )

                # محاسبه دقیق زمان باقی‌مانده
                passed_seconds = now - v.get("created_at", now)
                total_seconds = v.get("expire_seconds", 2592000)

                rem_seconds = max(
                    0,
                    total_seconds - passed_seconds
                )

                rem_d = int(rem_seconds // 86400)
                rem_h = int((rem_seconds % 86400) // 3600)

                # ۱. کانفیگ‌های اصلی اتصال کلاینت
                clean_link = (
                    f"vless://{v['uuid']}@{c_ip}:443"
                    f"?path=%2Fkillpv2"
                    f"&security=tls"
                    f"&encryption=none"
                    f"&insecure=0"
                    f"&type=ws"
                    f"&allowInsecure=0"
                    f"&host={tunnel_host}"
                    f"&sni={tunnel_host}"
                    f"#{k}_Clean"
                )

                regular_link = (
                    f"vless://{v['uuid']}@{tunnel_host}:443"
                    f"?path=%2Fkillpv2"
                    f"&security=tls"
                    f"&encryption=none"
                    f"&insecure=0"
                    f"&type=ws"
                    f"&allowInsecure=0"
                    f"#{k}_Direct"
                )

                # ۲. کانفیگ‌های کاملاً واقعی و فعال اما با تگ نام‌گذاری وضعیت
                info_used = (
                    f"vless://{v['uuid']}@{c_ip}:443"
                    f"?path=%2Fkillpv2"
                    f"&security=tls"
                    f"&encryption=none"
                    f"&insecure=0"
                    f"&type=ws"
                    f"&allowInsecure=0"
                    f"&host={tunnel_host}"
                    f"&sni={tunnel_host}"
                    f"#📊 مصرف شده: {format_bytes(v['used_bytes'])}"
                )

                info_rem = (
                    f"vless://{v['uuid']}@{c_ip}:443"
                    f"?path=%2Fkillpv2"
                    f"&security=tls"
                    f"&encryption=none"
                    f"&insecure=0"
                    f"&type=ws"
                    f"&allowInsecure=0"
                    f"&host={tunnel_host}"
                    f"&sni={tunnel_host}"
                    f"#💾 باقی‌مانده: "
                    f"{format_bytes(rem_bytes) if total_bytes > 0 else 'نامحدود'}"
                )

                info_time = (
                    f"vless://{v['uuid']}@{c_ip}:443"
                    f"?path=%2Fkillpv2"
                    f"&security=tls"
                    f"&encryption=none"
                    f"&insecure=0"
                    f"&type=ws"
                    f"&allowInsecure=0"
                    f"&host={tunnel_host}"
                    f"&sni={tunnel_host}"
                    f"#⏳ زمان: {rem_d} روز و {rem_h} ساعت"
                )

                # سرهم کردن کانفیگ‌ها در خروجی نهایی ساب
                payload_str = (
                    f"{clean_link}\n"
                    f"{regular_link}\n"
                    f"{info_used}\n"
                    f"{info_rem}\n"
                    f"{info_time}\n"
                )

                payload = base64.b64encode(
                    payload_str.encode('utf-8')
                ).decode('utf-8')

            with open(os.path.join('sub_links', k), 'w') as sf:
                sf.write(payload)

        # Git sync را فقط برای فایل‌های واقعی state انجام بده
        subprocess.run(
            "git config --local user.email 'action@github.com'",
            shell=True,
            check=False
        )

        subprocess.run(
            "git config --local user.name 'GitHub Action'",
            shell=True,
            check=False
        )

        # -A مهم است چون حذف فایل‌ها را هم stage می‌کند
        subprocess.run(
            "git add -A -- sub_links panel_db.json",
            shell=True,
            check=False
        )

        commit = subprocess.run(
            "git diff --cached --quiet || "
            "git commit -m '🔗 Update stable subscription links and db [Skip CI]'",
            shell=True,
            capture_output=True,
            text=True
        )

        if commit.returncode not in (0, 1):
            print(
                f"⚠️ Git commit failed: {commit.stderr.strip()}",
                flush=True
            )

        push = subprocess.run(
            "git push origin HEAD:main",
            shell=True,
            capture_output=True,
            text=True
        )

        if push.returncode != 0:
            print(
                f"⚠️ Git push failed (remote may have changed): "
                f"{push.stderr.strip()}",
                flush=True
            )
        else:
            print(
                "✅ [GitHub Sync] Repository state pushed successfully!",
                flush=True
            )

        # در صورت باقی‌ماندن فایل‌های runtime، آن‌ها را از وضعیت Git خارج کن
        subprocess.run(
            "git reset -- xray.zip edge_driver.deb "
            "analytics_worker.log cloudflare_edge.log 2>/dev/null || true",
            shell=True,
            check=False
        )

        print(
            "🔗 [GitHub Sync] Static info-embedded sub links successfully updated!",
            flush=True
        )

    except Exception as e:
        print(
            f"❌ Error in push_subs_to_github: {e}",
            flush=True
        )


def check_expiration_and_limits():
    now = int(time.time())
    changed = False

    for u_name, u_data in configs_db.items():
        if not u_data.get("active", True):
            continue

        total_limit = u_data.get("total_limit_bytes", 0)

        if total_limit > 0 and u_data["used_bytes"] >= total_limit:
            configs_db[u_name]["active"] = False
            configs_db[u_name]["status"] = "EXPIRED"

            SYSTEM_LIVE_LOGS.append(
                f"⛔ [{u_name}] حجم کاربر به سقف رسید و قطع شد."
            )

            changed = True

        created_time = u_data.get("created_at", now)
        expire_seconds = u_data.get("expire_seconds", 2592000)

        if now - created_time > expire_seconds:
            configs_db[u_name]["active"] = False
            configs_db[u_name]["status"] = "EXPIRED"

            SYSTEM_LIVE_LOGS.append(
                f"⛔ [{u_name}] زمان اشتراک کاربر تمام شد و قطع شد."
            )

            changed = True

    if changed:
        save_database()
        sync_xray_core()
        push_subs_to_github()


def sync_xray_core():
    """سینک هسته Xray — منطق اتصال VLESS/WS/8085/killpv2"""
    clients = [
        {
            "id": u_data["uuid"],
            "email": u_name,
            "level": 0
        }
        for u_name, u_data in configs_db.items()
        if u_data.get("active", True)
    ]

    db_backup_string = base64.b64encode(
        json.dumps(configs_db).encode('utf-8')
    ).decode('utf-8')

    xray_json_config = {
        "_killpv2_db_backup": db_backup_string,

        "log": {
            "loglevel": "info",
            "access": XRAY_LOG_PATH,
            "error": XRAY_LOG_PATH
        },

        "stats": {},

        "api": {
            "tag": "api",
            "services": ["StatsService"]
        },

        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True
            }
        },

        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["api"],
                    "outboundTag": "api"
                }
            ]
        },

        "inbounds": [
            {
                "port": 8085,
                "protocol": "vless",
                "settings": {
                    "clients": clients,
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {
                        "path": "/killpv2"
                    }
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"]
                }
            },

            {
                "listen": "127.0.0.1",
                "port": 10085,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "127.0.0.1"
                },
                "tag": "api"
            }
        ],

        "outbounds": [
            {
                "protocol": "freedom",
                "tag": "direct_out"
            }
        ]
    }

    with open(CONFIG_PATH, 'w') as f:
        json.dump(xray_json_config, f, indent=4)

    subprocess.run(
        "sudo killall xray || true",
        shell=True
    )

    subprocess.run(
        f"sudo touch {XRAY_LOG_PATH} && "
        f"sudo chmod 777 {XRAY_LOG_PATH}",
        shell=True
    )

    subprocess.run(
        f"sudo nohup /usr/local/bin/xray "
        f"-config {CONFIG_PATH} > /dev/null 2>&1 &",
        shell=True
    )


def format_bytes(b):
    if b == 0:
        return "نامحدود"

    if b >= 1024**3:
        return f"{b / (1024**3):.2f} GB"

    if b >= 1024**2:
        return f"{b / (1024**2):.2f} MB"

    if b >= 1024:
        return f"{b / 1024:.2f} KB"

    return f"{b} B"


def format_speed(bytes_per_sec):
    kb = bytes_per_sec / 1024

    if kb >= 1024:
        return f"{kb/1024:.1f} MB/s"

    return f"{kb:.1f} KB/s"


class SanaeiMobileXuiServer(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        return

    def is_authenticated(self):
        cookies = self.headers.get('Cookie', '')
        return f"session={SESSION_TOKEN}" in cookies

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = parse_qs(post_data)

        if self.path == "/login":
            username = params.get('username', [''])[0].strip()
            password = params.get('password', [''])[0].strip()

            if username == PANEL_USER and password == PANEL_PASS:
                self.send_response(303)
                self.send_header(
                    'Set-Cookie',
                    f'session={SESSION_TOKEN}; Path=/; HttpOnly'
                )
                self.send_header('Location', '/')
                self.end_headers()
            else:
                self.send_response(303)
                self.send_header(
                    'Location',
                    '/?error=true'
                )
                self.end_headers()

            return

        if not self.is_authenticated():
            self.send_response(303)
            self.send_header('Location', '/')
            self.end_headers()
            return

        action = params.get('action', [''])[0]

        if action == 'create':
            username = params.get(
                'username',
                ['']
            )[0].strip()

            is_unlimited = (
                params.get(
                    'unlimited_volume',
                    ['']
                )[0] == 'true'
            )

            volume_val = float(
                params.get(
                    'volume_value',
                    [0]
                )[0] or 0
            )

            volume_unit = params.get(
                'volume_unit',
                ['GB']
            )[0]

            initial_used_val = float(
                params.get(
                    'initial_used_value',
                    [0]
                )[0] or 0
            )

            initial_used_unit = params.get(
                'initial_used_unit',
                ['GB']
            )[0]

            expire_days = int(
                params.get(
                    'expire_days',
                    [0]
                )[0] or 0
            )

            expire_hours = int(
                params.get(
                    'expire_hours',
                    [0]
                )[0] or 0
            )

            total_seconds = (
                expire_days * 86400
            ) + (
                expire_hours * 3600
            )

            if total_seconds <= 0:
                total_seconds = 2592000

            clean_ip = params.get(
                'clean_ip',
                ['speed.cloudflare.com']
            )[0].strip()

            if not clean_ip:
                clean_ip = "speed.cloudflare.com"

            if is_unlimited:
                final_bytes = 0
            else:
                if volume_unit == 'GB':
                    final_bytes = int(
                        volume_val * 1024 * 1024 * 1024
                    )
                else:
                    final_bytes = int(
                        volume_val * 1024 * 1024
                    )

            if initial_used_unit == 'GB':
                final_initial_used_bytes = int(
                    initial_used_val * 1024 * 1024 * 1024
                )
            else:
                final_initial_used_bytes = int(
                    initial_used_val * 1024 * 1024
                )

            if username and username not in configs_db:
                configs_db[username] = {
                    "uuid": str(uuid.uuid4()),
                    "total_limit_bytes": final_bytes,
                    "used_bytes": final_initial_used_bytes,
                    "clean_ip": clean_ip,
                    "status": "OFFLINE",
                    "last_active_time": 0,
                    "down_speed": 0,
                    "up_speed": 0,
                    "created_at": int(time.time()),
                    "expire_seconds": total_seconds,
                    "active": True,
                    "sub_token": secrets.token_urlsafe(24),
                    "stats_offset": final_initial_used_bytes,
                    "stats_last": 0
                }

                USER_TARGET_SITES[username] = []

                SYSTEM_LIVE_LOGS.append(
                    f"➕ کلاینت جدید [{username}] ساخته شد."
                )

                save_database()
                sync_xray_core()
                push_subs_to_github()

        elif action == 'edit':
            username = params.get(
                'username',
                ['']
            )[0].strip()

            if username and username in configs_db:
                u = configs_db[username]
                now = int(time.time())

                # ♾️ حجم: نامحدود یا مقدار جدید
                is_unlimited = (
                    params.get(
                        'unlimited_volume',
                        ['']
                    )[0] == 'true'
                )

                if is_unlimited:
                    u["total_limit_bytes"] = 0
                else:
                    volume_val = float(
                        params.get(
                            'volume_value',
                            [0]
                        )[0] or 0
                    )

                    volume_unit = params.get(
                        'volume_unit',
                        ['GB']
                    )[0]

                    if volume_val > 0:
                        if volume_unit == 'GB':
                            u["total_limit_bytes"] = int(
                                volume_val * 1024 * 1024 * 1024
                            )
                        else:
                            u["total_limit_bytes"] = int(
                                volume_val * 1024 * 1024
                            )

                # 🔄 زمان: فقط اگر تیک اعمال زمان جدید خورده باشه
                if params.get(
                    'apply_expire',
                    ['']
                )[0] == 'true':

                    expire_days = int(
                        params.get(
                            'expire_days',
                            [0]
                        )[0] or 0
                    )

                    expire_hours = int(
                        params.get(
                            'expire_hours',
                            [0]
                        )[0] or 0
                    )

                    total_seconds = (
                        expire_days * 86400
                    ) + (
                        expire_hours * 3600
                    )

                    if total_seconds > 0:
                        u["expire_seconds"] = total_seconds
                        u["created_at"] = now

                # ♻️ صفر کردن دقیق مصرف
                if params.get(
                    'reset_used',
                    ['']
                )[0] == 'true':

                    u["stats_offset"] = -u.get(
                        "stats_last",
                        0
                    )

                    u["used_bytes"] = 0

                # ✅ فعال‌سازی مجدد اکانت
                if params.get(
                    'reactivate',
                    ['']
                )[0] == 'true':

                    u["active"] = True
                    u["status"] = "OFFLINE"
                    u["last_active_time"] = 0

                # 🔑 جنریت UUID جدید
                if params.get(
                    'regenerate_uuid',
                    ['']
                )[0] == 'true':

                    u["uuid"] = str(uuid.uuid4())

                clean_ip = params.get(
                    'clean_ip',
                    ['']
                )[0].strip()

                if clean_ip:
                    u["clean_ip"] = clean_ip

                SYSTEM_LIVE_LOGS.append(
                    f"✏️ کانفیگ [{username}] ویرایش شد (حجم/زمان/ریست)."
                )

                save_database()
                sync_xray_core()
                push_subs_to_github()

        elif action == 'toggle':
            username = params.get(
                'username',
                ['']
            )[0]

            if username in configs_db:
                configs_db[username]["active"] = not configs_db[username].get(
                    "active",
                    True
                )

                if configs_db[username]["active"]:
                    configs_db[username]["created_at"] = int(time.time())
                    configs_db[username]["status"] = "OFFLINE"

                SYSTEM_LIVE_LOGS.append(
                    f"⚙️ وضعیت [{username}] سوییچ شد."
                )

                save_database()
                sync_xray_core()
                push_subs_to_github()

        elif action == 'delete':
            username = params.get(
                'username',
                ['']
            )[0]

            if username in configs_db:
                del configs_db[username]

                if username in USER_TARGET_SITES:
                    del USER_TARGET_SITES[username]

                if username in LAST_COUNTERS:
                    del LAST_COUNTERS[username]

                SYSTEM_LIVE_LOGS.append(
                    f"🗑️ کلاینت [{username}] حذف شد."
                )

                save_database()
                sync_xray_core()
                push_subs_to_github()

        self.send_response(303)
        self.send_header('Location', '/')
        self.end_headers()

    def do_GET(self):
        url_path = self.path.strip("/")

        if url_path == "api/stats":
            if not self.is_authenticated():
                self.send_response(401)
                self.end_headers()
                return

            self.send_response(200)
            self.send_header(
                'Content-Type',
                'application/json'
            )
            self.end_headers()

            check_expiration_and_limits()

            response_data = []

            total_online = sum(
                1
                for u in configs_db.values()
                if u.get("status") == "ONLINE"
                and u.get("active", True)
            )

            now = int(time.time())

            for k, v in configs_db.items():
                total = v["total_limit_bytes"]

                rem = (
                    max(
                        0,
                        total - v["used_bytes"]
                    )
                    if total > 0 else 0
                )

                pct = (
                    min(
                        100,
                        (v["used_bytes"] / total * 100)
                    )
                    if total > 0 else 0
                )

                passed_seconds = now - v.get(
                    "created_at",
                    now
                )

                total_seconds = v.get(
                    "expire_seconds",
                    2592000
                )

                rem_seconds = max(
                    0,
                    total_seconds - passed_seconds
                )

                rem_d = int(
                    rem_seconds // 86400
                )

                rem_h = int(
                    (rem_seconds % 86400) // 3600
                )

                vless_config_str = (
                    f"vless://{v['uuid']}@"
                    f"{v.get('clean_ip', DEFAULT_CLEAN_IP)}:443"
                    f"?path=%2Fkillpv2"
                    f"&security=tls"
                    f"&encryption=none"
                    f"&insecure=0"
                    f"&type=ws"
                    f"&allowInsecure=0"
                    f"&host={tunnel_host}"
                    f"&sni={tunnel_host}"
                    f"#{k}_killpv2"
                )

                status_label = v["status"]

                if not v.get("active", True):
                    status_label = (
                        "EXPIRED"
                        if v["status"] == "EXPIRED"
                        else "DISABLED"
                    )

                response_data.append({
                    "username": k,
                    "status": status_label,
                    "used": format_bytes(v["used_bytes"]),
                    "total": (
                        format_bytes(total)
                        if total > 0
                        else "نامحدود"
                    ),
                    "remaining": (
                        format_bytes(rem)
                        if total > 0
                        else "نامحدود"
                    ),
                    "rem_days": (
                        f"{rem_d} روز و {rem_h} ساعت"
                    ),
                    "progress": pct,
                    "down_speed": format_speed(
                        v.get("down_speed", 0)
                    ),
                    "up_speed": format_speed(
                        v.get("up_speed", 0)
                    ),
                    "config_raw": vless_config_str,
                    "sub_url": (
                        f"https://{EDGE_DOMAIN}/sub/"
                        f"{v.get('sub_token', '')}"
                    ),
                    "clean_ip": v.get(
                        "clean_ip",
                        DEFAULT_CLEAN_IP
                    ),
                    "total_limit_bytes": total,
                    "expire_seconds": total_seconds,
                    "created_at": v.get(
                        "created_at",
                        now
                    ),
                    "destinations": USER_TARGET_SITES.get(
                        k,
                        []
                    )[-12:]
                })

            final_payload = {
                "total_online": total_online,
                "users": response_data,
                "sys_logs": SYSTEM_LIVE_LOGS[-30:]
            }

            self.wfile.write(
                json.dumps(final_payload).encode('utf-8')
            )

            return

        if url_path.startswith("sub/"):
            # 🔐 ساب با توکن تصادفی غیرقابل حدس
            token = url_path.replace(
                "sub/",
                "",
                1
            ).strip()

            target_user = (
                find_user_by_token(token)
                if token else None
            )

            if target_user and configs_db[target_user].get(
                "active",
                True
            ):

                u_data = configs_db[target_user]
                c_ip = u_data.get(
                    "clean_ip",
                    DEFAULT_CLEAN_IP
                )

                total_bytes = u_data[
                    "total_limit_bytes"
                ]

                rem_bytes = (
                    max(
                        0,
                        total_bytes - u_data["used_bytes"]
                    )
                    if total_bytes > 0 else 0
                )

                now = int(time.time())

                passed_seconds = now - u_data.get(
                    "created_at",
                    now
                )

                total_seconds = u_data.get(
                    "expire_seconds",
                    2592000
                )

                rem_seconds = max(
                    0,
                    total_seconds - passed_seconds
                )

                rem_d = int(
                    rem_seconds // 86400
                )

                rem_h = int(
                    (rem_seconds % 86400) // 3600
                )

                clean_link = (
                    f"vless://{u_data['uuid']}@{c_ip}:443"
                    f"?path=%2Fkillpv2"
                    f"&security=tls"
                    f"&encryption=none"
                    f"&insecure=0"
                    f"&type=ws"
                    f"&allowInsecure=0"
                    f"&host={tunnel_host}"
                    f"&sni={tunnel_host}"
                    f"#{target_user}_Clean"
                )

                regular_link = (
                    f"vless://{u_data['uuid']}@"
                    f"{tunnel_host}:443"
                    f"?path=%2Fkillpv2"
                    f"&security=tls"
                    f"&encryption=none"
                    f"&insecure=0"
                    f"&type=ws"
                    f"&allowInsecure=0"
                    f"#{target_user}_Direct"
                )

                info_used = (
                    f"vless://{u_data['uuid']}@{c_ip}:443"
                    f"?path=%2Fkillpv2"
                    f"&security=tls"
                    f"&encryption=none"
                    f"&insecure=0"
                    f"&type=ws"
                    f"&allowInsecure=0"
                    f"&host={tunnel_host}"
                    f"&sni={tunnel_host}"
                    f"#📊 مصرف شده: "
                    f"{format_bytes(u_data['used_bytes'])}"
                )

                info_rem = (
                    f"vless://{u_data['uuid']}@{c_ip}:443"
                    f"?path=%2Fkillpv2"
                    f"&security=tls"
                    f"&encryption=none"
                    f"&insecure=0"
                    f"&type=ws"
                    f"&allowInsecure=0"
                    f"&host={tunnel_host}"
                    f"&sni={tunnel_host}"
                    f"#💾 باقی‌مانده: "
                    f"{format_bytes(rem_bytes) if total_bytes > 0 else 'نامحدود'}"
                )

                info_time = (
                    f"vless://{u_data['uuid']}@{c_ip}:443"
                    f"?path=%2Fkillpv2"
                    f"&security=tls"
                    f"&encryption=none"
                    f"&insecure=0"
                    f"&type=ws"
                    f"&allowInsecure=0"
                    f"&host={tunnel_host}"
                    f"&sni={tunnel_host}"
                    f"#⏳ زمان: {rem_d} روز و {rem_h} ساعت"
                )

                payload = (
                    f"{clean_link}\n"
                    f"{regular_link}\n"
                    f"{info_used}\n"
                    f"{info_rem}\n"
                    f"{info_time}\n"
                )

                encoded_payload = base64.b64encode(
                    payload.encode('utf-8')
                ).decode('utf-8')

                self.send_response(200)
                self.send_header(
                    'Content-Type',
                    'text/plain; charset=utf-8'
                )
                self.send_header(
                    'Cache-Control',
                    'no-store'
                )
                self.end_headers()

                self.wfile.write(
                    encoded_payload.encode('utf-8')
                )

                return

            self.send_response(404)
            self.end_headers()
            return

        if not self.is_authenticated():
            self.send_response(200)
            self.send_header(
                'Content-Type',
                'text/html; charset=utf-8'
            )
            self.end_headers()

            err_msg = (
                '<div style="color:#f87171; '
                'text-align:center; margin-bottom:10px; '
                'font-size:0.85rem;">'
                '❌ رمز عبور اشتباه است داداش'
                '</div>'
                if "error=true" in self.path
                else ''
            )

            login_html = f"""
            <!DOCTYPE html>
            <html lang="fa" dir="rtl">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>ورود به سیستم امنیت پنل</title>
                <style>
                    body {{ font-family: system-ui, -apple-system, sans-serif; background-color: #0b0f19; color: #f1f5f9; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
                    .login-card {{ background: #151d30; padding: 25px; border-radius: 16px; border: 1px solid #222f4c; width: 100%; max-width: 320px; box-shadow: 0 10px 25px rgba(0,0,0,0.4); }}
                    h3 {{ margin: 0 0 20px 0; text-align: center; color: #38bdf8; }}
                    .form-control {{ width: 100%; padding: 11px; background: #0b0f19; border: 1px solid #2d3d5f; border-radius: 10px; color: #fff; margin-bottom: 15px; box-sizing: border-box; font-size: 0.95rem; outline: none; }}
                    .btn {{ width: 100%; padding: 11px; background: #2563eb; color: white; border: none; border-radius: 10px; font-weight: bold; cursor: pointer; font-size: 1rem; }}
                </style>
            </head>
            <body>
                <div class="login-card">
                    <h3>🔓 ورود به پنل kill_pv2</h3>
                    {err_msg}
                    <form method="POST" action="/login">
                        <input type="text" name="username" class="form-control" placeholder="نام کاربری" required>
                        <input type="password" name="password" class="form-control" placeholder="رمز عبور ۱۰ رقمی اکشن" required>
                        <button type="submit" class="btn">ورود ایمن</button>
                    </form>
                </div>
            </body>
            </html>
            """

            self.wfile.write(
                login_html.encode('utf-8')
            )

            return

        if url_path == "" or url_path == "index.html":
            self.send_response(200)
            self.send_header(
                'Content-Type',
                'text/html; charset=utf-8'
            )
            self.end_headers()

            html_content = f"""
            <!DOCTYPE html>
            <html lang="fa" dir="rtl">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>پنل مدیریت سنایی | kill_pv2</title>
                <style>
                    :root {{ --bg-main: #0b0f19; --bg-card: #151d30; --text-p: #94a3b8; --accent: #2563eb; }}
                    body {{ font-family: system-ui, -apple-system, sans-serif; background-color: var(--bg-main); color: #f1f5f9; margin: 0; padding: 12px; }}
                    .panel-container {{ max-width: 700px; margin: 0 auto; }}
                    .header-board {{ background: linear-gradient(135deg, #1e40af, #1d4ed8); padding: 20px; border-radius: 16px; margin-bottom: 15px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.3); }}
                    .header-board h2 {{ margin: 0; font-size: 1.4rem; color: #fff; }}
                    .status-box {{ display: inline-block; background: rgba(250,250,250,0.15); padding: 5px 12px; border-radius: 30px; font-size: 0.85rem; margin-top: 8px; }}
                    .card {{ background: var(--bg-card); border-radius: 16px; padding: 16px; margin-bottom: 15px; border: 1px solid #222f4c; }}
                    .card h4 {{ margin: 0 0 12px 0; color: #38bdf8; font-size: 1.05rem; }}
                    .form-control {{ width: 100%; padding: 10px; background: #0b0f19; border: 1px solid #2d3d5f; border-radius: 10px; color: #fff; margin-bottom: 10px; box-sizing: border-box; font-size: 0.9rem; outline: none; }}
                    .btn {{ width: 100%; padding: 11px; border: none; border-radius: 10px; font-weight: bold; cursor: pointer; font-size: 0.95rem; }}
                    .btn-add {{ background: #10b981; color: white; }}
                    .btn-scanner-toggle {{ background: #8b5cf6; color: white; margin-bottom: 15px; }}
                    .user-row {{ background: #1a243d; border-radius: 12px; padding: 12px; margin-bottom: 10px; border: 1px solid #273659; cursor: pointer; transition: 0.2s; }}
                    .user-row:hover {{ border-color: #3b82f6; }}
                    .user-flex {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
                    .u-name {{ font-weight: bold; color: #e2e8f0; font-size: 1rem; }}
                    .badge {{ padding: 3px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 600; }}
                    .bg-online {{ background: rgba(16,185,129,0.15); color: #34d399; }}
                    .bg-offline {{ background: rgba(239,68,68,0.15); color: #f87171; }}
                    .bg-disabled {{ background: #334155; color: #94a3b8; }}
                    .bg-expired {{ background: rgba(239,68,68,0.3); color: #fca5a5; border: 1px dashed #ef4444; }}
                    .data-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 6px; font-size: 0.8rem; color: var(--text-p); border-top: 1px solid #273659; padding-top: 8px; }}
                    .p-bar-bg {{ width: 100%; background: #2d3d5f; height: 6px; border-radius: 10px; margin-top: 6px; overflow: hidden; }}
                    .p-bar-fill {{ background: var(--accent); height: 100%; width: 0%; transition: width 0.4s; }}
                    .action-bar {{ display: flex; flex-wrap: wrap; gap: 5px; margin-top: 10px; }}
                    .action-bar button, .action-bar a {{ flex: 1; min-width: 65px; text-align: center; padding: 8px 4px; border-radius: 6px; font-size: 0.75rem; font-weight: bold; border: none; cursor: pointer; color: white; }}
                    .btn-sub {{ background: #3b82f6; }} .btn-conf {{ background: #8b5cf6; }} .btn-edit {{ background: #06b6d4; }} .btn-tog {{ background: #f59e0b; color: black; }} .btn-del {{ background: #ef4444; }}
                    .scanner-area {{ display: none; background: #111827; border: 1px dashed #4b5563; border-radius: 12px; padding: 12px; margin-top: 10px; }}
                    .ip-list-output {{ width: 100%; height: 120px; background: #030712; color: #10b981; font-family: monospace; font-size: 0.8rem; padding: 6px; border-radius: 8px; border: 1px solid #1f2937; margin-top: 8px; box-sizing: border-box; }}
                    .flex-input {{ display: flex; gap: 8px; margin-bottom: 10px; }}
                    .flex-input select, .flex-input input {{ background: #0b0f19; color: white; border: 1px solid #2d3d5f; border-radius: 10px; padding: 10px; outline: none; font-size:0.9rem; box-sizing: border-box; }}
                    .terminal-box {{ background: #020617; border: 1px solid #1e293b; border-radius: 12px; height: 180px; overflow-y: auto; font-family: monospace; font-size: 0.78rem; padding: 10px; color: #cbd5e1; direction: ltr; text-align: left; }}
                    .log-line {{ margin: 2px 0; border-bottom: 1px solid #0f172a; padding-bottom: 2px; }}
                    .target-active-user {{ border: 2px solid #3b82f6 !important; background: #1e294b !important; }}
                    .edit-modal-wrap {{ display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.72); z-index: 60; padding: 15px; overflow-y: auto; }}
                    .edit-modal-card {{ background: var(--bg-card); border: 1px solid #0ea5e9; border-radius: 16px; padding: 16px; max-width: 430px; margin: 25px auto; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
                    .edit-check {{ display: block; margin-bottom: 10px; font-size: 0.85rem; color: #cbd5e1; }}
                </style>

                <script>
                    let cachedConfigs = {{}};
                    let cachedStats = {{}};
                    let selectedUserFilter = null;

                    async function loadLiveStats() {{
                        try {{
                            let res = await fetch('/api/stats');
                            let data = await res.json();

                            document.getElementById('online_count').innerText = data.total_online;

                            const term = document.getElementById('sys_terminal');

                            let isScrolledDown =
                                term.scrollHeight - term.clientHeight
                                <= term.scrollTop + 20;

                            term.innerHTML = "";

                            data.sys_logs.forEach(l => {{
                                term.innerHTML +=
                                    "<div class='log-line'>" +
                                    l +
                                    "</div>";
                            }});

                            if (isScrolledDown)
                                term.scrollTop = term.scrollHeight;

                            data.users.forEach(u => {{
                                cachedStats[u.username] = u;

                                let row =
                                    document.getElementById(
                                        'u_' + u.username
                                    );

                                if(row) {{
                                    let badge =
                                        row.querySelector('.badge');

                                    if (u.status === 'ONLINE') {{
                                        badge.innerText = '🟢 آنلاین';
                                        badge.className =
                                            'badge bg-online';
                                    }}

                                    else if (u.status === 'OFFLINE') {{
                                        badge.innerText = '🔴 آفلاین';
                                        badge.className =
                                            'badge bg-offline';
                                    }}

                                    else if (u.status === 'EXPIRED') {{
                                        badge.innerText = '⏳ تمام شده';
                                        badge.className =
                                            'badge bg-expired';
                                    }}

                                    else {{
                                        badge.innerText = '⚫ غیرفعال';
                                        badge.className =
                                            'badge bg-disabled';
                                    }}

                                    row.querySelector(
                                        '.u-used'
                                    ).innerText = u.used;

                                    row.querySelector(
                                        '.u-rem'
                                    ).innerText = u.remaining;

                                    row.querySelector(
                                        '.u-days'
                                    ).innerText = u.rem_days;

                                    row.querySelector(
                                        '.u-dspeed'
                                    ).innerText = u.down_speed;

                                    row.querySelector(
                                        '.u-uspeed'
                                    ).innerText = u.up_speed;

                                    row.querySelector(
                                        '.p-bar-fill'
                                    ).style.width =
                                        u.progress + '%';

                                    cachedConfigs[u.username] =
                                        u.config_raw;

                                    if(selectedUserFilter === u.username) {{
                                        const sniperBox =
                                            document.getElementById(
                                                'user_sniper_logs'
                                            );

                                        sniperBox.innerHTML =
                                            u.destinations.length === 0
                                                ? "در حال انتظار برای دریافت پکت داده..."
                                                : "";

                                        u.destinations.forEach(dst => {{
                                            sniperBox.innerHTML +=
                                                "<div style='color:#38bdf8; margin:3px 0;'>" +
                                                "🌐 -> " +
                                                dst +
                                                "</div>";
                                        }});
                                    }}
                                }}
                            }});
                        }} catch(e) {{}}
                    }}

                    function filterUserSniper(username) {{
                        if(selectedUserFilter) {{
                            let prevRow =
                                document.getElementById(
                                    'u_' + selectedUserFilter
                                );

                            if(prevRow)
                                prevRow.classList.remove(
                                    'target-active-user'
                                );
                        }}

                        if(selectedUserFilter === username) {{
                            selectedUserFilter = null;

                            document.getElementById(
                                'sniper_title'
                            ).innerText =
                                "🔍 مانیتورینگ دامنه کلاینت (روی کلاینت کلیک کن)";

                            document.getElementById(
                                'user_sniper_logs'
                            ).innerHTML =
                                "داداش روی ردیف هر کلاینتی که می‌خواهی کلیک کنی، دامنه سایت‌هایی که میره اینجا لیست میشه.";
                        }}

                        else {{
                            selectedUserFilter = username;

                            document.getElementById(
                                'u_' + username
                            ).classList.add(
                                'target-active-user'
                            );

                            document.getElementById(
                                'sniper_title'
                            ).innerText =
                                "🛰️ دامنه‌های باز شده توسط " + username;

                            document.getElementById(
                                'user_sniper_logs'
                            ).innerHTML =
                                "در حال تحلیل ترافیک زنده کلاینت...";
                        }}
                    }}

                    function copyConfig(user) {{
                        if(cachedConfigs[user]) {{
                            navigator.clipboard.writeText(
                                cachedConfigs[user]
                            );

                            alert(
                                '📋 کانفیگ VLESS با موفقیت کپی شد داداش!'
                            );
                        }}
                    }}

                    function toggleUnlimitedVolume(checkbox) {{
                        const vInput =
                            document.getElementById(
                                'volume_value_input'
                            );

                        if (checkbox.checked) {{
                            vInput.disabled = true;
                            vInput.placeholder =
                                "حجم نامحدود فعال شد";
                            vInput.value = "";
                        }}

                        else {{
                            vInput.disabled = false;
                            vInput.placeholder =
                                "میزان حجم مجاز";
                            vInput.value = "400";
                        }}
                    }}

                    function toggleEditUnlimited(checkbox) {{
                        const vInput =
                            document.getElementById(
                                'edit_volume_value'
                            );

                        if (checkbox.checked) {{
                            vInput.disabled = true;
                            vInput.placeholder = "نامحدود";
                            vInput.value = "";
                        }}

                        else {{
                            vInput.disabled = false;
                        }}
                    }}

                    function copyFixedSubscription(user) {{
                        let st = cachedStats[user];

                        if (st && st.sub_url) {{
                            navigator.clipboard.writeText(
                                st.sub_url
                            );

                            alert(
                                "🔗 لینک ساب امن دامنه (توکن‌دار و غیرقابل حدس برای بات‌ها) کپی شد داداش!"
                            );
                        }}

                        else {{
                            alert(
                                "⏳ چند ثانیه صبر کن تا آمار لود بشه داداش."
                            );
                        }}
                    }}

                    function openEdit(user) {{
                        let st = cachedStats[user];

                        if (!st) {{
                            alert(
                                "⏳ هنوز آمار لود نشده داداش، چند ثانیه صبر کن."
                            );
                            return;
                        }}

                        document.getElementById(
                            'edit_title'
                        ).innerText = user;

                        document.getElementById(
                            'edit_username'
                        ).value = user;

                        let unlim =
                            (
                                st.total_limit_bytes === 0
                            );

                        document.getElementById(
                            'edit_unlimited'
                        ).checked = unlim;

                        let vInput =
                            document.getElementById(
                                'edit_volume_value'
                            );

                        vInput.disabled = unlim;

                        vInput.value =
                            unlim
                                ? ""
                                : (
                                    st.total_limit_bytes /
                                    (1024*1024*1024)
                                ).toFixed(2);

                        document.getElementById(
                            'edit_volume_unit'
                        ).value = 'GB';

                        let rem =
                            Math.max(
                                0,
                                st.expire_seconds -
                                (
                                    Math.floor(Date.now()/1000) -
                                    st.created_at
                                )
                            );

                        document.getElementById(
                            'edit_expire_days'
                        ).value =
                            Math.floor(rem / 86400);

                        document.getElementById(
                            'edit_expire_hours'
                        ).value =
                            Math.floor(
                                (rem % 86400) / 3600
                            );

                        document.getElementById(
                            'edit_apply_expire'
                        ).checked = false;

                        document.getElementById(
                            'edit_reset_used'
                        ).checked = false;

                        document.getElementById(
                            'edit_reactivate'
                        ).checked = false;

                        document.getElementById(
                            'edit_regen_uuid'
                        ).checked = false;

                        document.getElementById(
                            'edit_clean_ip'
                        ).value =
                            st.clean_ip || '';

                        document.getElementById(
                            'edit_modal'
                        ).style.display = 'block';
                    }}

                    function closeEdit() {{
                        document.getElementById(
                            'edit_modal'
                        ).style.display = 'none';
                    }}

                    const cleanIpsToTest = [];

                    const baseSubnets = [
                        "104.16.123.",
                        "104.17.3.",
                        "104.18.2.",
                        "172.67.143.",
                        "104.21.43.",
                        "162.159.135.",
                        "172.64.149.",
                        "104.16.50.",
                        "104.17.51.",
                        "104.19.60."
                    ];

                    baseSubnets.forEach(subnet => {{
                        for(let i = 10; i <= 55; i += 1) {{
                            cleanIpsToTest.push(
                                subnet + i
                            );
                        }}
                    }});

                    async function startWebPingTest() {{
                        const btn =
                            document.getElementById(
                                'ping_btn'
                            );

                        const output =
                            document.getElementById(
                                'good_ips_box'
                            );

                        const statusText =
                            document.getElementById(
                                'ping_status_text'
                            );

                        btn.disabled = true;
                        output.value = "";

                        let workingCount = 0;

                        statusText.innerText =
                            "⏳ شروع تست روی جادوی ۵۰۰ آی‌پی تمیز کلودفلر...";

                        for(
                            let i = 0;
                            i < cleanIpsToTest.length;
                            i += 10
                        ) {{

                            let slice =
                                cleanIpsToTest.slice(
                                    i,
                                    i + 10
                                );

                            statusText.innerText =
                                "🛰️ در حال پینگ گرفتن کلاستر آی‌پی‌ها (" +
                                i +
                                " / " +
                                cleanIpsToTest.length +
                                ")...";

                            await Promise.all(
                                slice.map(
                                    async (ip) => {{
                                        let start = Date.now();

                                        try {{
                                            let controller =
                                                new AbortController();

                                            setTimeout(
                                                () => controller.abort(),
                                                1200
                                            );

                                            await fetch(
                                                'https://' +
                                                ip +
                                                '/cdn-cgi/trace',
                                                {{
                                                    mode: 'no-cors',
                                                    signal:
                                                        controller.signal
                                                }}
                                            );

                                            let duration =
                                                Date.now() - start;

                                            workingCount++;

                                            output.value +=
                                                ip +
                                                " -> " +
                                                duration +
                                                "ms\\n";
                                        }} catch(e) {{}}
                                    }}
                                )
                            );
                        }}

                        statusText.innerText =
                            "✅ تست تمام شد! تعداد آی‌پی فعال: " +
                            workingCount;

                        btn.disabled = false;
                    }}

                    function toggleScanner() {{
                        const box =
                            document.getElementById(
                                'scanner_box'
                            );

                        box.style.display =
                            box.style.display === 'block'
                                ? 'none'
                                : 'block';
                    }}

                    setInterval(
                        loadLiveStats,
                        2000
                    );
                </script>
            </head>

            <body>

                <div class="panel-container">

                    <div class="header-board">
                        <h2>🎛️ سیستم مدیریت اتصال هوشمند kill_pv2</h2>

                        <div class="status-box">
                            کاربران متصل زنده:
                            <span
                                id="online_count"
                                style="color:#6ee7b7; font-weight:bold;"
                            >0</span>
                        </div>
                    </div>

                    <button
                        class="btn btn-scanner-toggle"
                        onclick="toggleScanner()"
                    >
                        🔍 تست شبکه زنده (۵۰۰ آی‌پی فوق تمیز)
                    </button>

                    <div
                        class="card scanner-area"
                        id="scanner_box"
                    >
                        <h4
                            style="color:#a7f3d0; margin-top:0;"
                        >
                            📡 اسکنر پینگ پرقدرت شبکه کلودفلر
                        </h4>

                        <button
                            class="btn"
                            id="ping_btn"
                            style="background:#4c1d95;"
                            onclick="startWebPingTest()"
                        >
                            ▶️ شروع پینگ سیکل ترکیبی
                        </button>

                        <div
                            id="ping_status_text"
                            style="font-size:0.8rem; color:#f59e0b; margin-top:8px; text-align:center;"
                        >
                            آماده برای استارت...
                        </div>

                        <textarea
                            id="good_ips_box"
                            class="ip-list-output"
                            readonly
                            placeholder="آی‌پی‌های تمیز متصل به شبکه کشور اینجا چیده میشن داداش..."
                        ></textarea>
                    </div>

                    <div
                        class="card"
                        style="border: 1px solid #1e3a8a; background: #0f172a;"
                    >
                        <h4
                            id="sniper_title"
                            style="color:#60a5fa; margin-top:0;"
                        >
                            🔍 مانیتورینگ دامنه کلاینت (روی کلاینت کلیک کن)
                        </h4>

                        <div
                            id="user_sniper_logs"
                            style="font-family:monospace; font-size:0.82rem; color:#94a3b8; max-height:100px; overflow-y:auto; line-height:1.4;"
                        >
                            داداش روی ردیف هر کلاینتی که می‌خواهی کلیک کنی،
                            دامنه سایت‌هایی که میره اینجا لیست میشه.
                        </div>
                    </div>

                    <div class="card">
                        <h4>➕ افزودن کلاینت VLESS جدید</h4>

                        <form method="POST" action="/">
                            <input
                                type="hidden"
                                name="action"
                                value="create"
                            >

                            <input
                                type="text"
                                name="username"
                                class="form-control"
                                placeholder="نام کاربری (انگلیسی)"
                                required
                            >

                            <div
                                style="margin-bottom:10px; font-size:0.85rem; color:#6ee7b7;"
                            >
                                <label>
                                    <input
                                        type="checkbox"
                                        name="unlimited_volume"
                                        value="true"
                                        onchange="toggleUnlimitedVolume(this)"
                                    >
                                    ♾️ فعال‌سازی حجم نامحدود برای کاربر
                                </label>
                            </div>

                            <div class="flex-input">
                                <input
                                    type="number"
                                    step="0.1"
                                    name="volume_value"
                                    id="volume_value_input"
                                    class="form-control"
                                    placeholder="میزان حجم مجاز"
                                    value="400"
                                    style="margin-bottom:0; flex:2;"
                                >

                                <select
                                    name="volume_unit"
                                    id="volume_unit_select"
                                    style="flex:1;"
                                >
                                    <option value="GB">GB</option>
                                    <option value="MB">MB</option>
                                </select>
                            </div>

                            <div class="flex-input">
                                <input
                                    type="number"
                                    step="0.1"
                                    name="initial_used_value"
                                    class="form-control"
                                    placeholder="میزان حجم مصرف شده اولیه (اختیاری)"
                                    style="margin-bottom:0; flex:2;"
                                >

                                <select
                                    name="initial_used_unit"
                                    style="flex:1;"
                                >
                                    <option value="GB">GB</option>
                                    <option value="MB">MB</option>
                                </select>
                            </div>

                            <div class="flex-input">
                                <input
                                    type="number"
                                    name="expire_days"
                                    placeholder="اعتبار (روز)"
                                    value="30"
                                    min="0"
                                    required
                                    style="flex:1;"
                                >

                                <input
                                    type="number"
                                    name="expire_hours"
                                    placeholder="اعتبار (ساعت)"
                                    value="0"
                                    min="0"
                                    max="23"
                                    required
                                    style="flex:1;"
                                >
                            </div>

                            <input
                                type="text"
                                name="clean_ip"
                                class="form-control"
                                placeholder="آی‌پی تمیز کلودفلر (پیش‌فرض: speed.cloudflare.com)"
                            >

                            <button
                                type="submit"
                                class="btn btn-add"
                            >
                                ⚡ ایجاد کانفیگ و ریلود پایدار
                            </button>
                        </form>
                    </div>

                    <div class="card">
                        <h4>👤 لیست کلاینت‌ها و ترافیک آنالیز</h4>

                        <div id="users_container">
            """

            for user_name, user_data in configs_db.items():
                is_active = user_data.get(
                    "active",
                    True
                )

                status_class = (
                    "bg-disabled"
                    if not is_active
                    else (
                        "bg-online"
                        if user_data["status"] == "ONLINE"
                        else "bg-offline"
                    )
                )

                if user_data.get("status") == "EXPIRED":
                    status_class = "bg-expired"

                status_text = (
                    "⚫ غیرفعال"
                    if not is_active
                    else (
                        "🟢 آنلاین"
                        if user_data["status"] == "ONLINE"
                        else "🔴 آفلاین"
                    )
                )

                if user_data.get("status") == "EXPIRED":
                    status_text = "⏳ تمام شده"

                html_content += f"""
                            <div
                                class="user-row"
                                id="u_{user_name}"
                                onclick="filterUserSniper('{user_name}')"
                            >
                                <div class="user-flex">
                                    <span class="u-name">
                                        {user_name}
                                    </span>

                                    <span class="badge {status_class}">
                                        {status_text}
                                    </span>
                                </div>

                                <div class="data-grid">
                                    <div>
                                        مصرف:
                                        <span class="u-used">0 B</span>
                                    </div>

                                    <div>
                                        باقی‌مانده:
                                        <span class="u-rem">0 B</span>
                                    </div>

                                    <div>
                                        زمان مانده:
                                        <span class="u-days">0 روز</span>
                                    </div>

                                    <div>
                                        ⬇️ دانلود:
                                        <span
                                            class="u-dspeed"
                                            style="color:#6ee7b7;"
                                        >0 KB/s</span>
                                    </div>

                                    <div>
                                        ⬆️ آپلود:
                                        <span
                                            class="u-uspeed"
                                            style="color:#38bdf8;"
                                        >0 KB/s</span>
                                    </div>
                                </div>

                                <div class="p-bar-bg">
                                    <div class="p-bar-fill"></div>
                                </div>

                                <div
                                    class="action-bar"
                                    onclick="event.stopPropagation();"
                                >
                                    <button
                                        class="btn-sub"
                                        onclick="copyFixedSubscription('{user_name}')"
                                    >
                                        🔗 ساب دامنه
                                    </button>

                                    <button
                                        class="btn-conf"
                                        onclick="copyConfig('{user_name}')"
                                    >
                                        📋 کانفیگ
                                    </button>

                                    <button
                                        class="btn-edit"
                                        onclick="openEdit('{user_name}')"
                                    >
                                        ✏️ ویرایش
                                    </button>

                                    <form
                                        method="POST"
                                        action="/"
                                        style="flex:1; display:flex;"
                                    >
                                        <input
                                            type="hidden"
                                            name="action"
                                            value="toggle"
                                        >

                                        <input
                                            type="hidden"
                                            name="username"
                                            value="{user_name}"
                                        >

                                        <button
                                            type="submit"
                                            class="btn-tog"
                                        >
                                            ⚙️ سوییچ
                                        </button>
                                    </form>

                                    <form
                                        method="POST"
                                        action="/"
                                        style="flex:1; display:flex;"
                                        onsubmit="return confirm('حذف بشه داداش؟');"
                                    >
                                        <input
                                            type="hidden"
                                            name="action"
                                            value="delete"
                                        >

                                        <input
                                            type="hidden"
                                            name="username"
                                            value="{user_name}"
                                        >

                                        <button
                                            type="submit"
                                            class="btn-del"
                                        >
                                            🗑️ حذف
                                        </button>
                                    </form>
                                </div>
                            </div>
                """

            html_content += f"""
                        </div>
                    </div>

                    <div class="card">
                        <h4>📟 لاگ زنده و سراسری هسته شبکه</h4>

                        <div
                            class="terminal-box"
                            id="sys_terminal"
                        >
                            در حال بارگذاری لاگ‌های سیستم...
                        </div>
                    </div>

                </div>

                <div
                    class="edit-modal-wrap"
                    id="edit_modal"
                >
                    <div class="edit-modal-card">

                        <h4>
                            ✏️ ویرایش کانفیگ:
                            <span
                                id="edit_title"
                                style="color:#6ee7b7;"
                            ></span>
                        </h4>

                        <form
                            method="POST"
                            action="/"
                        >
                            <input
                                type="hidden"
                                name="action"
                                value="edit"
                            >

                            <input
                                type="hidden"
                                name="username"
                                id="edit_username"
                            >

                            <label
                                class="edit-check"
                                style="color:#6ee7b7;"
                            >
                                <input
                                    type="checkbox"
                                    name="unlimited_volume"
                                    id="edit_unlimited"
                                    value="true"
                                    onchange="toggleEditUnlimited(this)"
                                >
                                ♾️ حجم نامحدود
                            </label>

                            <div class="flex-input">
                                <input
                                    type="number"
                                    step="0.01"
                                    name="volume_value"
                                    id="edit_volume_value"
                                    placeholder="حجم جدید"
                                    style="flex:2;"
                                >

                                <select
                                    name="volume_unit"
                                    id="edit_volume_unit"
                                    style="flex:1;"
                                >
                                    <option value="GB">GB</option>
                                    <option value="MB">MB</option>
                                </select>
                            </div>

                            <label class="edit-check">
                                <input
                                    type="checkbox"
                                    name="apply_expire"
                                    id="edit_apply_expire"
                                    value="true"
                                >
                                🔄 اعمال زمان جدید
                                (شروع مجدد دوره از همین لحظه)
                            </label>

                            <div class="flex-input">
                                <input
                                    type="number"
                                    name="expire_days"
                                    id="edit_expire_days"
                                    placeholder="روز"
                                    min="0"
                                    style="flex:1;"
                                >

                                <input
                                    type="number"
                                    name="expire_hours"
                                    id="edit_expire_hours"
                                    placeholder="ساعت"
                                    min="0"
                                    max="23"
                                    style="flex:1;"
                                >
                            </div>

                            <input
                                type="text"
                                name="clean_ip"
                                id="edit_clean_ip"
                                class="form-control"
                                placeholder="آی‌پی تمیز کلودفلر"
                            >

                            <label class="edit-check">
                                <input
                                    type="checkbox"
                                    name="reset_used"
                                    id="edit_reset_used"
                                    value="true"
                                >
                                ♻️ صفر کردن حجم مصرف‌شده
                            </label>

                            <label class="edit-check">
                                <input
                                    type="checkbox"
                                    name="reactivate"
                                    id="edit_reactivate"
                                    value="true"
                                >
                                ✅ فعال‌سازی مجدد اکانت
                                (اگر تمام‌شده/غیرفعال بود)
                            </label>

                            <label class="edit-check">
                                <input
                                    type="checkbox"
                                    name="regenerate_uuid"
                                    id="edit_regen_uuid"
                                    value="true"
                                >
                                🔑 جنریت UUID جدید
                                (لینک‌های قبلی از کار میوفتن)
                            </label>

                            <button
                                type="submit"
                                class="btn btn-add"
                            >
                                💾 ذخیره تغییرات
                            </button>

                            <button
                                type="button"
                                class="btn"
                                style="background:#334155; margin-top:8px;"
                                onclick="closeEdit()"
                            >
                                انصراف
                            </button>
                        </form>
                    </div>
                </div>

                <script>
                    loadLiveStats();
                </script>

            </body>
            </html>
            """

            self.wfile.write(
                html_content.encode('utf-8')
            )

            return

        self.send_response(404)
        self.end_headers()


def xray_live_log_sniffer():
    """اسنیفر لاگ زنده هسته — لاگ‌ها و دامنه‌های مقصد هر کلاینت"""

    global SYSTEM_LIVE_LOGS

    print(
        "\n==============================================================",
        flush=True
    )

    print(
        "🛡️ SECURITY LOGIN CREDENTIALS FOR PANEL ACCESS",
        flush=True
    )

    print(
        f"🔗 PANEL URL : https://{tunnel_host}",
        flush=True
    )

    print(
        f"👤 USERNAME  : {PANEL_USER}",
        flush=True
    )

    print(
        f"🔑 PASSWORD  : {PANEL_PASS}",
        flush=True
    )

    print(
        "==============================================================\n",
        flush=True
    )

    while not os.path.exists(XRAY_LOG_PATH):
        time.sleep(1)

    log_file = open(
        XRAY_LOG_PATH,
        "r"
    )

    log_file.seek(
        0,
        os.SEEK_END
    )

    def speed_resetter():
        while True:
            time.sleep(3)

            now = time.time()
            changed = False

            for u_name, u_data in configs_db.items():

                if now - u_data.get(
                    "last_active_time",
                    0
                ) > 8:

                    if (
                        u_data["down_speed"] > 0
                        or
                        u_data["up_speed"] > 0
                    ):
                        configs_db[u_name]["down_speed"] = 0
                        configs_db[u_name]["up_speed"] = 0
                        changed = True

                if now - u_data.get(
                    "last_active_time",
                    0
                ) > 40:

                    if (
                        u_data["status"] != "OFFLINE"
                        and
                        u_data["status"] != "EXPIRED"
                    ):
                        configs_db[u_name]["status"] = "OFFLINE"
                        changed = True

            if changed:
                save_database()

    threading.Thread(
        target=speed_resetter,
        daemon=True
    ).start()

    while True:
        line = log_file.readline()

        if not line:
            time.sleep(0.2)
            continue

        clean_line = line.strip()

        if clean_line:
            SYSTEM_LIVE_LOGS.append(clean_line)

            if len(SYSTEM_LIVE_LOGS) > 100:
                SYSTEM_LIVE_LOGS.pop(0)

        for user_name in list(configs_db.keys()):

            if (
                user_name in clean_line
                or
                configs_db[user_name]["uuid"] in clean_line
            ):

                if configs_db[user_name].get(
                    "active",
                    True
                ):

                    now = time.time()

                    if configs_db[user_name]["status"] != "ONLINE":
                        SYSTEM_LIVE_LOGS.append(
                            f"🟢 [{user_name}] آنلاین شد."
                        )

                    configs_db[user_name]["status"] = "ONLINE"
                    configs_db[user_name]["last_active_time"] = now

                    match = re.search(
                        r'tcp:([a-zA-Z0-9.-]+):\d+|accepted\s+([a-zA-Z0-9.-]+):\d+',
                        clean_line,
                        re.IGNORECASE
                    )

                    if match:
                        dst_target = (
                            match.group(1)
                            or
                            match.group(2)
                        )

                        if dst_target and not dst_target.startswith(
                            "127.0.0.1"
                        ):

                            if user_name not in USER_TARGET_SITES:
                                USER_TARGET_SITES[user_name] = []

                            if dst_target not in USER_TARGET_SITES[user_name]:
                                USER_TARGET_SITES[user_name].append(
                                    dst_target
                                )


def xray_traffic_collector():
    """📊 شمارش دقیق و واقعی حجم مصرفی هر کلاینت از Stats API خود هسته Xray"""

    time.sleep(6)

    while True:
        try:
            proc = subprocess.run(
                [
                    "/usr/local/bin/xray",
                    "api",
                    "statsquery",
                    "--server=127.0.0.1:10085",
                    "-pattern",
                    "user>>>"
                ],
                capture_output=True,
                text=True,
                timeout=10
            )

            out = proc.stdout or ""
            counters = {}

            for m in re.finditer(
                r'name:\s*"user>>>(.+?)>>>traffic>>>(uplink|downlink)"\s*\nvalue:\s*(\d+)',
                out
            ):
                uname = m.group(1)
                direction = m.group(2)
                val = int(m.group(3))

                if uname not in counters:
                    counters[uname] = {
                        "uplink": 0,
                        "downlink": 0
                    }

                counters[uname][direction] = val

            now = time.time()
            changed = False

            for uname, c in counters.items():

                if uname not in configs_db:
                    continue

                u = configs_db[uname]

                total_counter = (
                    c["uplink"]
                    +
                    c["downlink"]
                )

                offset = u.get(
                    "stats_offset",
                    0
                )

                last_counter = u.get(
                    "stats_last",
                    0
                )

                # اگر هسته ریستارت شده و شمارنده صفر شده
                if total_counter < last_counter:
                    offset += last_counter
                    u["stats_offset"] = offset

                u["stats_last"] = total_counter

                new_used = (
                    offset
                    +
                    total_counter
                )

                delta = (
                    new_used
                    -
                    u.get("used_bytes", 0)
                )

                if delta < 0:
                    delta = 0
                    new_used = u.get(
                        "used_bytes",
                        0
                    )

                # محاسبه سرعت واقعی دانلود/آپلود
                prev = LAST_COUNTERS.get(
                    uname
                )

                if prev and total_counter >= prev["total"]:

                    dt = now - prev["t"]

                    if dt > 0:
                        u["down_speed"] = max(
                            0,
                            int(
                                (
                                    c["downlink"]
                                    -
                                    prev["down"]
                                ) / dt
                            )
                        ) if c["downlink"] >= prev["down"] else 0

                        u["up_speed"] = max(
                            0,
                            int(
                                (
                                    c["uplink"]
                                    -
                                    prev["up"]
                                ) / dt
                            )
                        ) if c["uplink"] >= prev["up"] else 0

                LAST_COUNTERS[uname] = {
                    "total": total_counter,
                    "down": c["downlink"],
                    "up": c["uplink"],
                    "t": now
                }

                if delta > 0:
                    u["used_bytes"] = new_used

                    if u.get("active", True):
                        u["status"] = "ONLINE"
                        u["last_active_time"] = now

                    changed = True

                elif new_used != u.get(
                    "used_bytes",
                    0
                ):
                    u["used_bytes"] = new_used
                    changed = True

            if changed:
                save_database()

        except Exception as e:
            print(
                f"⚠️ traffic collector warn: {e}",
                flush=True
            )

        time.sleep(3)


sync_xray_core()
push_subs_to_github()

threading.Thread(
    target=lambda: HTTPServer(
        ('127.0.0.1', 8086),
        SanaeiMobileXuiServer
    ).serve_forever(),
    daemon=True
).start()

threading.Thread(
    target=xray_live_log_sniffer,
    daemon=True
).start()

threading.Thread(
    target=xray_traffic_collector,
    daemon=True
).start()

print(
    "🚀 Stable Microservice deployed inside GitHub Action Engine.",
    flush=True
)

# GitHub Actions owns the service lifetime.
last_github_update_time = time.time()

while True:
    time.sleep(10)

    check_expiration_and_limits()

    # 🔄 Keep subscription/state files synchronized approximately every minute.
    if time.time() - last_github_update_time >= 60:
        print(
            "🔄 [Periodic Sync] Running 1-minute auto-update for subscription info...",
            flush=True
        )

        push_subs_to_github()

        last_github_update_time = time.time()
