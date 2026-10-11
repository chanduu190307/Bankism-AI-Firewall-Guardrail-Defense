"""Unicode-aware input normalizer and obfuscation detector for Bankism AI Firewall."""

import base64
import binascii
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

# Zero-width, directional, and invisible unicode characters
ZERO_WIDTH_CHARS = {
    "\u200b",  # Zero Width Space
    "\u200c",  # Zero Width Non-Joiner
    "\u200d",  # Zero Width Joiner
    "\u200e",  # Left-to-Right Mark
    "\u200f",  # Right-to-Left Mark
    "\u2060",  # Word Joiner
    "\ufeff",  # Zero Width No-Break Space / Byte Order Mark
    "\u00ad",  # Soft Hyphen
}

# Common Cyrillic and Greek homoglyphs used to evade Latin keyword matching
HOMOGLYPH_MAP = {
    "а": "a",  # Cyrillic small a
    "е": "e",  # Cyrillic small ie
    "о": "o",  # Cyrillic small o
    "р": "p",  # Cyrillic small er
    "с": "c",  # Cyrillic small es
    "у": "y",  # Cyrillic small u
    "х": "x",  # Cyrillic small ha
    "і": "i",  # Cyrillic small i
    "ј": "j",  # Cyrillic small je
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    "І": "I",
    "Ї": "I",
}

# Regex for detecting potential Base64 blocks (min 12 chars, valid base64 chars + padding)
BASE64_PATTERN = re.compile(
    r"(?:(?<=\s)|(?<=^)|(?<=[=:\"']))[A-Za-z0-9+/]{12,}={0,2}(?=\s|$|[\"';,.])"
)
# Regex for detecting hex sequences (e.g., \x69\x67 or 49676e6f7265)
HEX_ESCAPE_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
HEX_STRING_PATTERN = re.compile(r"\b[0-9a-fA-F]{16,}\b")


@dataclass(frozen=True)
class NormalizationResult:
    """Immutable outcome of input normalization and obfuscation inspection."""

    raw_text: str
    normalized_text: str
    stripped_zero_width_count: int
    decoded_payloads: list[str] = field(default_factory=list)
    obfuscation_detected: bool = False
    obfuscation_types: list[str] = field(default_factory=list)


def normalize_input(text: str) -> NormalizationResult:
    """Safely inspects and normalizes text while preserving original raw input for inspection.

    Performs:
    1. Unicode NFKC normalization.
    2. Stripping and counting of zero-width and invisible characters.
    3. Homoglyph substitution for evasion detection.
    4. Safe detection and decoding of Base64, Hex, and URL percent-encoded payloads.
    """
    if not text:
        return NormalizationResult(
            raw_text="",
            normalized_text="",
            stripped_zero_width_count=0,
        )

    # 1. Detect zero-width characters
    zero_width_count = sum(text.count(char) for char in ZERO_WIDTH_CHARS)
    cleaned_chars = [ch for ch in text if ch not in ZERO_WIDTH_CHARS]
    zero_stripped_text = "".join(cleaned_chars)

    # 2. Unicode NFKC normalization
    nfkc_text = unicodedata.normalize("NFKC", zero_stripped_text)

    # 3. Homoglyph mapping
    mapped_chars = [HOMOGLYPH_MAP.get(ch, ch) for ch in nfkc_text]
    homoglyph_normalized = "".join(mapped_chars)

    # 4. Obfuscation detection and decoding
    obfuscation_types: list[str] = []
    decoded_payloads: list[str] = []

    if zero_width_count > 0:
        obfuscation_types.append("ZERO_WIDTH_INJECTION")

    # URL decoding check
    if "%" in text:
        try:
            unquoted = urllib.parse.unquote(text)
            if unquoted != text and len(unquoted) < len(text):
                obfuscation_types.append("URL_PERCENT_ENCODING")
                decoded_payloads.append(unquoted)
        except (ValueError, UnicodeDecodeError):
            pass

    # Hex escape check (\x69\x67...)
    hex_escapes = HEX_ESCAPE_PATTERN.findall(text)
    for hex_esc in hex_escapes:
        try:
            raw_hex = hex_esc.replace("\\x", "")
            decoded = binascii.unhexlify(raw_hex).decode("utf-8", errors="ignore")
            if decoded.strip() and all(c.isprintable() or c.isspace() for c in decoded):
                obfuscation_types.append("HEX_ESCAPE_ENCODING")
                decoded_payloads.append(decoded)
        except (ValueError, binascii.Error, UnicodeDecodeError):
            pass

    # Pure Hex string check (e.g. 49676e6f7265...)
    hex_blocks = HEX_STRING_PATTERN.findall(text)
    for hex_block in hex_blocks:
        if len(hex_block) % 2 == 0 and len(hex_block) >= 16:
            try:
                decoded = binascii.unhexlify(hex_block).decode("utf-8", errors="ignore")
                if len(decoded.strip()) >= 6 and all(
                    c.isprintable() or c.isspace() for c in decoded
                ):
                    obfuscation_types.append("HEX_STRING_ENCODING")
                    decoded_payloads.append(decoded)
            except (ValueError, binascii.Error, UnicodeDecodeError):
                pass

    # Base64 check
    b64_matches = BASE64_PATTERN.findall(text)
    for b64_cand in b64_matches:
        try:
            decoded_bytes = base64.b64decode(b64_cand, validate=True)
            decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
            if len(decoded_str.strip()) >= 6 and all(
                c.isprintable() or c.isspace() for c in decoded_str
            ):
                obfuscation_types.append("BASE64_ENCODING")
                decoded_payloads.append(decoded_str)
        except (ValueError, binascii.Error, UnicodeDecodeError):
            pass

    # Deduplicate obfuscation types and payloads
    unique_types = sorted(list(set(obfuscation_types)))
    unique_payloads = sorted(list(set(decoded_payloads)))

    return NormalizationResult(
        raw_text=text,
        normalized_text=homoglyph_normalized,
        stripped_zero_width_count=zero_width_count,
        decoded_payloads=unique_payloads,
        obfuscation_detected=len(unique_types) > 0,
        obfuscation_types=unique_types,
    )
