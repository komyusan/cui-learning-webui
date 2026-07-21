#!/bin/sh
# =================================================================
# Docker for Mac IPv6 ブラックホール対策 entrypoint
# =================================================================
# 問題: Docker for Mac の IPv6 TCP 接続がブラックホールになり、
#       OS の TCP タイムアウト（約 75 秒）を待ってから IPv4 にフォールバックする。
#       さらに IP 文字列を getaddrinfo(AF_UNSPEC) に渡すと
#       ::ffff:x.x.x.x (IPv4-mapped-IPv6) が生成され同じ問題が起きる。
#
# 対策: /etc/resolv.conf の既存 options 行に "no-aaaa" を統合する。
#   - "no-aaaa" は別行ではなく既存 options 行に追加することで
#     glibc が確実に読み込む（複数 options 行の解釈は実装依存のため）。
#   - Python による in-place 書き換えで bind mount 制約を回避。
#   - C ライブラリ (glibc) と OpenSSL の内部解決にも効果がある。
# =================================================================

echo "[entrypoint] IPv6 ブラックホール対策を開始します..." >&2

# --- resolv.conf に no-aaaa を統合（Python で in-place 書き換え）---
python3 - >&2 << 'PYEOF'
import re, sys

path = '/etc/resolv.conf'
try:
    with open(path, 'r') as f:
        content = f.read()

    if 'no-aaaa' in content:
        print(f'[entrypoint] no-aaaa は既に {path} に設定されています ✓')
        sys.exit(0)

    # 既存の options 行に no-aaaa を追加（最初の options 行を対象）
    new_content, n = re.subn(
        r'^(options\b[^\n]*)$',
        r'\1 no-aaaa',
        content,
        count=1,
        flags=re.MULTILINE
    )

    if n == 0:
        # options 行がない場合は追加
        new_content = content.rstrip('\n') + '\noptions no-aaaa\n'
        print(f'[entrypoint] options no-aaaa を新規追加します')
    else:
        print(f'[entrypoint] 既存の options 行に no-aaaa を追加します')

    with open(path, 'w') as f:
        f.write(new_content)
    print(f'[entrypoint] resolv.conf 更新完了 ✓')

except PermissionError as e:
    print(f'[entrypoint] WARNING: {path} の書き込み権限がありません: {e}')
    print('[entrypoint] Python レベルの getaddrinfo パッチのみで動作します')
except Exception as e:
    print(f'[entrypoint] WARNING: resolv.conf の更新中にエラー: {e}')
PYEOF

echo "[entrypoint] /etc/resolv.conf の現在の設定:" >&2
cat /etc/resolv.conf >&2
echo "---" >&2

# --- DNS 解決テスト ---
echo "[entrypoint] api.openai.com の DNS 解決テスト..." >&2
python3 - >&2 << 'PYEOF'
import socket

print("  [A のみ (AF_INET)]:", end="  ")
try:
    results = socket.getaddrinfo('api.openai.com', 443, socket.AF_INET, socket.SOCK_STREAM)
    print([r[4][0] for r in results])
except Exception as e:
    print(f"FAIL: {e}")

print("  [A+AAAA (AF_UNSPEC)]:", end="")
try:
    results = socket.getaddrinfo('api.openai.com', 443, 0, socket.SOCK_STREAM)
    for r in results[:6]:
        fam = "IPv4" if r[0] == socket.AF_INET else "IPv6"
        print(f"    {fam}: {r[4][0]}")
except Exception as e:
    print(f"FAIL: {e}")
PYEOF

# --- TCP + TLS 接続テスト ---
echo "[entrypoint] api.openai.com:443 への TCP+TLS 接続テスト..." >&2
python3 - >&2 << 'PYEOF'
import socket, ssl, time

def test(label, host, port, sni):
    start = time.time()
    try:
        # TCP 接続
        sock = socket.create_connection((host, port), timeout=20)
        tcp_s = time.time() - start
        # TLS ハンドシェイク
        ctx = ssl.create_default_context()
        sock.settimeout(20)
        tls_sock = ctx.wrap_socket(sock, server_hostname=sni)
        tls_s = time.time() - start - tcp_s
        tls_sock.close()
        print(f"  [{label}] SUCCESS: TCP={tcp_s:.2f}s TLS={tls_s:.2f}s 合計={(tcp_s+tls_s):.2f}s")
    except Exception as e:
        print(f"  [{label}] FAIL after {time.time()-start:.2f}s: {e}")

# IPv4 アドレスを取得
try:
    ipv4_addrs = [r[4][0] for r in socket.getaddrinfo('api.openai.com', 443, socket.AF_INET, socket.SOCK_STREAM)]
    ip = ipv4_addrs[0]
except Exception:
    ip = None

test("hostname", "api.openai.com", 443, "api.openai.com")
if ip:
    test(f"ip_direct({ip})", ip, 443, "api.openai.com")
PYEOF

echo "[entrypoint] 起動します: $@" >&2
exec "$@"
