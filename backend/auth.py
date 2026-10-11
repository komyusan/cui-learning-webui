"""
auth.py
LDAP 認証 + 署名付きセッションクッキー管理

環境変数:
  LDAP_SERVER_URL    : LDAP サーバ URL（例: ldap://10.x.x.x）
  SESSION_SECRET_KEY : セッション署名キー
"""

import logging
import os

from fastapi import HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, TimestampSigner
from ldap3 import ANONYMOUS, SIMPLE, Connection, Server
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# 定数
# ──────────────────────────────────────────────
LDAP_BASE_DN = "ou=ie,o=u-ryukyu,c=jp"
SESSION_COOKIE_NAME = "session"
SESSION_MAX_AGE = 8 * 60 * 60  # 8時間（秒）
LDAP_TIMEOUT = 5  # 秒


DEV_USER_UID = "dev_user"


def is_skip_auth() -> bool:
    """開発モード判定: SKIP_AUTH=true のとき認証をバイパスする（本番では使わないこと）"""
    return os.getenv("SKIP_AUTH", "false").lower() == "true"


def _get_ldap_url() -> str:
    url = os.environ.get("LDAP_SERVER_URL")
    if not url:
        raise RuntimeError("環境変数 LDAP_SERVER_URL が設定されていません。")
    return url


def _get_signer() -> TimestampSigner:
    secret = os.environ.get("SESSION_SECRET_KEY")
    if not secret:
        raise RuntimeError("環境変数 SESSION_SECRET_KEY が設定されていません。")
    return TimestampSigner(secret)


# ──────────────────────────────────────────────
# LDAP 認証
# ──────────────────────────────────────────────
def authenticate_ldap(uid: str, password: str) -> dict | None:
    """
    LDAPで認証する。
    1. 匿名バインドでou=ie,o=u-ryukyu,c=jp以下をuidで検索しDNを取得
    2. 取得したDNとパスワードでsimple bindを試みる
    3. 成功したらユーザ情報dict（uid, dn, cn, mail）を返す。失敗したらNoneを返す
    """
    # 空パスワードは LDAP の unauthenticated bind として成功扱いになるため拒否する
    if not uid or not password:
        return None

    server = Server(_get_ldap_url(), connect_timeout=LDAP_TIMEOUT)

    # ── 1. 匿名バインドで DN を検索 ──
    try:
        with Connection(
            server, authentication=ANONYMOUS, auto_bind=True,
            receive_timeout=LDAP_TIMEOUT,
        ) as search_conn:
            search_conn.search(
                search_base=LDAP_BASE_DN,
                search_filter=f"(uid={escape_filter_chars(uid)})",
                attributes=["uid", "cn", "mail"],
                size_limit=2,
            )
            # 0件・複数件ヒットは認証失敗とする
            if len(search_conn.entries) != 1:
                logger.info("[auth] ユーザ検索結果が一意でありません: uid=%s", uid)
                return None
            entry = search_conn.entries[0]
            user_dn = entry.entry_dn
            cn = str(entry.cn.value) if "cn" in entry and entry.cn.value else ""
            mail = str(entry.mail.value) if "mail" in entry and entry.mail.value else ""
    except LDAPException as e:
        logger.error("[auth] LDAP 検索エラー: %s", e)
        return None

    # ── 2. 取得した DN とパスワードで simple bind ──
    try:
        user_conn = Connection(
            server, user=user_dn, password=password,
            authentication=SIMPLE, receive_timeout=LDAP_TIMEOUT,
        )
        bound = user_conn.bind()
        user_conn.unbind()
    except LDAPException as e:
        logger.error("[auth] LDAP バインドエラー: %s", e)
        return None

    if not bound:
        logger.info("[auth] 認証失敗: uid=%s", uid)
        return None

    logger.info("[auth] 認証成功: uid=%s", uid)
    return {"uid": uid, "dn": user_dn, "cn": cn, "mail": mail}


# ──────────────────────────────────────────────
# セッションクッキー
# ──────────────────────────────────────────────
def create_session_cookie(uid: str) -> str:
    """itsdangerous で署名付きセッショントークンを生成して返す"""
    return _get_signer().sign(uid).decode("utf-8")


def verify_session_cookie(token: str) -> str | None:
    """トークンを検証し有効なら uid を返す。無効・期限切れは None"""
    if not token:
        return None
    try:
        uid = _get_signer().unsign(token, max_age=SESSION_MAX_AGE)
        return uid.decode("utf-8")
    except (BadSignature, SignatureExpired):
        return None


def get_current_user(request: Request) -> str:
    """
    FastAPIの依存性注入用。
    クッキー "session" を検証し、有効なら uid を返す。
    無効なら HTTPException 401 を raise する
    """
    if is_skip_auth():
        return DEV_USER_UID

    token = request.cookies.get(SESSION_COOKIE_NAME)
    uid = verify_session_cookie(token) if token else None
    if uid is None:
        raise HTTPException(status_code=401, detail="ログインが必要です。")
    return uid
