"""REALITY 所需的 X25519 密钥生成（纯 Python，RFC 7748）。

为什么不依赖 cryptography：
  * 新 Mac / 新 Linux 上不一定装了这个包；
  * 只需要“生成私钥 + 推导公钥”，不需要通用加密库；
  * 纯 Python 实现可以用 RFC 7748 测试向量固定住。

注意：这是密钥生成用途，不是侧信道安全的通用加密实现。私钥只在本机生成，
不会在不可信环境里做大量运算。
"""
from __future__ import annotations

import base64
import secrets
from typing import Tuple

P = 2 ** 255 - 19
A24 = 121665
BASE_POINT = (9).to_bytes(32, "little")


def _clamp_scalar(k: bytes) -> int:
    if len(k) != 32:
        raise ValueError("X25519 scalar must be 32 bytes")
    value = int.from_bytes(k, "little")
    value &= ~7
    value &= (1 << 254) - 1
    value |= 1 << 254
    return value


def _decode_u(u: bytes) -> int:
    if len(u) != 32:
        raise ValueError("X25519 u must be 32 bytes")
    return int.from_bytes(u, "little") & ((1 << 255) - 1)


def x25519(private_key: bytes, u: bytes = BASE_POINT) -> bytes:
    """RFC 7748 X25519。返回 32 字节共享值/公钥。"""
    k = _clamp_scalar(private_key)
    x1 = _decode_u(u)
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x3 = ((da + cb) ** 2) % P
        z3 = (x1 * ((da - cb) ** 2)) % P
        x2 = (aa * bb) % P
        z2 = (e * (aa + A24 * e)) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, "little")


def public_from_private(private_key: bytes) -> bytes:
    return x25519(private_key)


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def generate_keypair() -> Tuple[str, str]:
    """生成 REALITY 的 (privateKey, publicKey)，均为 base64url 无填充。"""
    raw = secrets.token_bytes(32)
    return b64u_encode(raw), b64u_encode(public_from_private(raw))


def keypair_from_private(private_b64: str) -> Tuple[str, str]:
    raw = b64u_decode(private_b64)
    if len(raw) != 32:
        raise ValueError("REALITY 私钥必须是 32 字节的 base64url")
    return b64u_encode(raw), b64u_encode(public_from_private(raw))


def random_hex(nbytes: int) -> str:
    return secrets.token_hex(nbytes)


def random_password(length: int = 32) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def random_sub_path() -> str:
    return "/" + secrets.token_hex(16)
