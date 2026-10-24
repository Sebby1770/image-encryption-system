"""The browser crypto modules against crypto.py, hashlib, and Pillow.

End-to-end mode only works if the browser and the server agree byte for byte:
the AAD the browser seals must be the one Python rebuilds, its Scrypt must be
Scrypt, and an envelope written by either side must open on the other. These
tests run the real browser modules under Node (``tests/js/harness.mjs``).
"""

from __future__ import annotations

import base64
import json
import random
import shutil
import subprocess
from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image, ImageSequence

from image_encryption_system import crypto, web
from image_encryption_system.cli import main as cli_main
from image_encryption_system.crypto import (
    AES_GCM_PASSPHRASE,
    MIN_SCRYPT_N,
    RSA_HYBRID,
    context_aad,
    decrypt_image_bytes,
    encrypt_image_bytes,
    generate_rsa_key_pair,
    pack_ies,
    public_key_fingerprint,
    unpack_ies,
)

HARNESS = Path(__file__).parent / "js" / "harness.mjs"
NODE = shutil.which("node")


def _node_major() -> int:
    if NODE is None:
        return 0
    version = subprocess.run([NODE, "--version"], capture_output=True, text=True).stdout
    return int(version.strip().lstrip("v").split(".")[0])


pytestmark = pytest.mark.skipif(_node_major() < 20, reason="needs Node.js 20+ (WebCrypto)")

# Text that breaks naive JSON canonicalisation: escapes, astral characters,
# combining marks, line separators, and control characters.
NASTY = [
    "plain.png",
    'quote " and backslash \\.png',
    "tab\tnewline\ncr\rnul\x00bell\x07del\x7f.png",
    "café ☕ \U0001f600 \U0001f9d1‍\U0001f4bb.png",
    "é combining.png",
    "line para sep.png",
    "﻿bom � replacement.png",
    "日本語のファイル名.jpg",
    "עברית rtl.gif",
    "<script>alert(1)</script>.png",
    "x" * 255,
]
GPS_MARKER = "GPS-SECRET-48.8584N-2.2945E"


def run_js(op: str, args):
    completed = subprocess.run(
        [NODE, str(HARNESS)],
        input=json.dumps({"op": op, "args": args}),
        capture_output=True,
        text=True,
        timeout=180,
        check=True,
    )
    response = json.loads(completed.stdout)
    if not response["ok"]:
        raise RuntimeError(response["error"])
    return response["result"]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text)


# ---------------------------------------------------------------------------
# Primitives


def test_scrypt_matches_hashlib_across_parameters() -> None:
    import hashlib

    rng = random.Random(7914)
    cases = []
    for _ in range(40):
        cases.append(
            {
                "password": rng.randbytes(rng.randrange(1, 70)),
                "salt": rng.randbytes(rng.randrange(0, 40)),
                "n": 2 ** rng.randrange(1, 11),
                "r": rng.randrange(1, 5),
                "p": rng.randrange(1, 4),
                "length": rng.randrange(1, 90),
            }
        )
    got = run_js(
        "scrypt",
        [{**case, "password": b64(case["password"]), "salt": b64(case["salt"])} for case in cases],
    )
    for case, derived in zip(cases, got, strict=True):
        expected = hashlib.scrypt(
            case["password"],
            salt=case["salt"],
            n=case["n"],
            r=case["r"],
            p=case["p"],
            dklen=case["length"],
        )
        assert unb64(derived) == expected, case


def test_context_aad_is_byte_identical_for_hostile_text() -> None:
    rng = random.Random(3)
    alphabet = [chr(c) for c in range(0, 0x250)] + list("  ﻿\U0001f600\U0010fffd")
    contexts = []
    for name in NASTY + [
        "".join(rng.choices(alphabet, k=rng.randrange(1, 60))) for _ in range(300)
    ]:
        contexts.append(
            {
                "asset": "0123456789abcdef0123456789abcdef",
                "algorithm": AES_GCM_PASSPHRASE,
                "wrap": "scrypt-aes-gcm",
                "owner": rng.randrange(1, 2**31),
                "filename": name,
                "mime": "image/png",
                "format": "PNG",
                "width": rng.randrange(1, 2**31),
                "height": 1,
                "source": "browser",
            }
        )
    for context, aad in zip(contexts, run_js("aad", contexts), strict=True):
        assert unb64(aad) == context_aad(context), context["filename"]


def test_canonical_json_matches_the_private_key_header_encoding() -> None:
    values = [
        {"kdf": {"type": "scrypt", "salt": "AAAA", "n": 65536, "r": 8, "p": 1}, "owner": 3},
        {"z": [1, {"b": None, "a": True}], "é": "\U0001f600"},
    ]
    for value, encoded in zip(values, run_js("canonical", values), strict=True):
        assert encoded.encode("utf-8") == crypto.canonical_json(value)


# ---------------------------------------------------------------------------
# Envelopes, both directions


def _png() -> bytes:
    output = BytesIO()
    Image.new("RGB", (5, 3), "#0f766e").save(output, format="PNG")
    return output.getvalue()


def _context(name: str = NASTY[3]) -> dict:
    return {
        "owner": 12,
        "filename": name,
        "mime": "image/png",
        "format": "PNG",
        "width": 5,
        "height": 3,
        "source": "browser",
    }


@pytest.mark.parametrize("name", NASTY)
def test_a_browser_envelope_opens_in_python(name) -> None:
    plaintext = _png()
    sealed = run_js(
        "encrypt",
        {
            "plaintext": b64(plaintext),
            "algorithm": AES_GCM_PASSPHRASE,
            "passphrase": "a browser passphrase ☕",
            "context": _context(name),
            "n": MIN_SCRYPT_N,
        },
    )
    ciphertext, metadata = unpack_ies(unb64(sealed["ies"]))
    assert metadata["context"]["filename"] == name
    assert crypto.validate_envelope(metadata) == 3
    assert (
        decrypt_image_bytes(ciphertext, metadata, passphrase="a browser passphrase ☕") == plaintext
    )


def test_a_browser_envelope_opens_in_the_cli(tmp_path) -> None:
    sealed = run_js(
        "encrypt",
        {
            "plaintext": b64(_png()),
            "algorithm": AES_GCM_PASSPHRASE,
            "passphrase": "cli passphrase",
            "context": _context(),
            "n": MIN_SCRYPT_N,
        },
    )
    source = tmp_path / "browser.ies"
    source.write_bytes(unb64(sealed["ies"]))
    out = tmp_path / "out.png"
    assert cli_main(["decrypt", str(source), "--passphrase", "cli passphrase", "-o", str(out)]) == 0
    assert out.read_bytes() == _png()


def test_a_python_envelope_opens_in_the_browser() -> None:
    result = encrypt_image_bytes(
        _png(), AES_GCM_PASSPHRASE, passphrase="server side", context=_context(NASTY[2])
    )
    blob = pack_ies(result.ciphertext, result.metadata)
    opened = run_js("decrypt", {"ies": b64(blob), "passphrase": "server side"})
    assert unb64(opened["plaintext"]) == _png()
    with pytest.raises(RuntimeError, match="Passphrase did not unlock"):
        run_js("decrypt", {"ies": b64(blob), "passphrase": "wrong"})


def test_rsa_envelopes_and_sealed_private_keys_work_in_both_directions() -> None:
    private_key, public_pem = generate_rsa_key_pair("account password one", owner=12)

    # Browser seals to the account's public key; Python opens with the sealed key.
    sealed = run_js(
        "encrypt",
        {
            "plaintext": b64(_png()),
            "algorithm": RSA_HYBRID,
            "public_key": public_pem.decode(),
            "context": {**_context(), "wrap": "rsa-oaep-sha256"},
        },
    )
    ciphertext, metadata = unpack_ies(unb64(sealed["ies"]))
    assert (
        decrypt_image_bytes(
            ciphertext,
            metadata,
            private_key_pem=private_key,
            private_key_passphrase="account password one",
        )
        == _png()
    )

    # Python seals; the browser opens the Scrypt-sealed private key itself.
    result = encrypt_image_bytes(_png(), RSA_HYBRID, public_key_pem=public_pem, context=_context())
    blob = b64(pack_ies(result.ciphertext, result.metadata))
    request = {
        "ies": blob,
        "private_key": private_key.decode(),
        "password": "account password one",
        "owner": 12,
    }
    assert unb64(run_js("decrypt", request)["plaintext"]) == _png()
    with pytest.raises(RuntimeError, match="does not belong"):
        run_js("decrypt", {**request, "owner": 13})
    with pytest.raises(RuntimeError, match="passphrase is invalid"):
        run_js("decrypt", {**request, "password": "not the password"})


def test_fingerprints_agree() -> None:
    _private, public_pem = generate_rsa_key_pair("fingerprint password", owner=1)
    assert run_js("fingerprint", {"pem": public_pem.decode()}) == public_key_fingerprint(public_pem)


# ---------------------------------------------------------------------------
# Metadata stripping


def _exif_with_gps(orientation: int = 1) -> Image.Exif:
    exif = Image.Exif()
    exif[0x010F] = "Camera Maker"
    exif[0x0110] = "Camera Model " + GPS_MARKER
    exif[0x0112] = orientation
    exif[0x9286] = GPS_MARKER
    exif.get_ifd(0x8825)[2] = (48.0, 51.0, 29.0)
    return exif


def _xmp() -> bytes:
    return (
        '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
        'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        f'<rdf:Description exif:GPSLatitude="{GPS_MARKER}" '
        'xmlns:exif="http://ns.adobe.com/exif/1.0/"/></rdf:RDF></x:xmpmeta>'
    ).encode()


def _photo(mode: str = "RGB", size=(48, 32)) -> Image.Image:
    image = Image.new(mode, size)
    image.putdata(
        [
            (x * 5 % 256, y * 7 % 256, (x + y) % 256)[: len(mode)]
            if len(mode) > 1
            else (x * y) % 256
            for y in range(size[1])
            for x in range(size[0])
        ]
    )
    return image


def _jpeg(**extra) -> bytes:
    output = BytesIO()
    _photo().save(output, format="JPEG", quality=90, **extra)
    return output.getvalue()


def _insert_after_soi(jpeg: bytes, *segments: bytes) -> bytes:
    return jpeg[:2] + b"".join(segments) + jpeg[2:]


def _segment(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + (len(payload) + 2).to_bytes(2, "big") + payload


def _png_with_metadata() -> bytes:
    from PIL.PngImagePlugin import PngInfo

    info = PngInfo()
    info.add_text("Location", GPS_MARKER)
    info.add_text("Comment", GPS_MARKER, zip=True)
    info.add_itxt("XML:com.adobe.xmp", _xmp().decode())
    output = BytesIO()
    _photo().save(output, format="PNG", pnginfo=info, exif=_exif_with_gps())
    raw = output.getvalue()
    # Add a tIME chunk and an unknown private ancillary chunk (a C2PA-style
    # manifest) before IEND.
    import zlib

    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(kind + data).to_bytes(4, "big")
        return len(data).to_bytes(4, "big") + kind + data + crc

    iend = raw.rindex(b"IEND") - 4
    extra = chunk(b"tIME", bytes([7, 234, 10, 24, 12, 0, 0])) + chunk(b"caBX", GPS_MARKER.encode())
    return raw[:iend] + extra + raw[iend:] + b"trailing " + GPS_MARKER.encode()


def _webp_with_metadata() -> bytes:
    output = BytesIO()
    _photo().save(output, format="WEBP", lossless=True, exif=_exif_with_gps(), xmp=_xmp())
    return output.getvalue()


def _gif_with_metadata(frames: int = 1) -> bytes:
    images = [_photo("P") for _ in range(frames)]
    for index, image in enumerate(images):
        image.putpixel((0, 0), index)
    output = BytesIO()
    images[0].save(
        output,
        format="GIF",
        save_all=frames > 1,
        append_images=images[1:],
        comment=GPS_MARKER.encode(),
        duration=80,
        loop=0,
    )
    raw = output.getvalue()
    # An XMP application extension, as Photoshop writes it, before the trailer.
    xmp_block = (
        b"\x21\xff\x0bXMP DataXMP"
        + b"".join(
            bytes([len(part)]) + part
            for part in [_xmp()[i : i + 255] for i in range(0, len(_xmp()), 255)]
        )
        + b"\x00"
    )
    return raw[:-1] + xmp_block + raw[-1:]


def _pixels(data: bytes) -> list:
    with Image.open(BytesIO(data)) as image:
        return [frame.convert("RGBA").tobytes() for frame in ImageSequence.Iterator(image)]


def _prepare(data: bytes) -> dict:
    prepared = run_js("prepare", {"image": b64(data)})
    prepared["bytes"] = unb64(prepared["bytes"])
    return prepared


@pytest.mark.parametrize(
    ("make", "fmt"),
    [
        (
            lambda: (
                _insert_after_soi(
                    _jpeg(exif=_exif_with_gps(), icc_profile=b"\x00" * 128),
                    _segment(0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + _xmp()),
                    _segment(0xED, b"Photoshop 3.0\x00" + GPS_MARKER.encode()),
                    _segment(0xE2, b"MPF\x00" + GPS_MARKER.encode()),
                    _segment(0xFE, GPS_MARKER.encode()),
                )
                + b"motion photo video "
                + GPS_MARKER.encode()
            ),
            "JPEG",
        ),
        (_png_with_metadata, "PNG"),
        (_webp_with_metadata, "WEBP"),
        (_gif_with_metadata, "GIF"),
    ],
    ids=["jpeg", "png", "webp", "gif"],
)
def test_stripping_removes_metadata_and_keeps_every_pixel(make, fmt) -> None:
    original = make()
    assert GPS_MARKER.encode() in original
    prepared = _prepare(original)
    stripped = prepared["bytes"]

    assert prepared["format"] == fmt
    assert GPS_MARKER.encode() not in stripped
    assert _pixels(stripped) == _pixels(original)
    with Image.open(BytesIO(stripped)) as image:
        assert image.format == fmt
        assert (prepared["width"], prepared["height"]) == image.size
        assert not dict(image.getexif())
        assert not any(
            image.info.get(key) for key in ("exif", "xmp", "XML:com.adobe.xmp", "comment")
        )
        if fmt != "GIF":  # the server always re-encodes GIF, so its check is moot
            assert not web._image_has_metadata(image, stripped)


def test_stripping_keeps_the_icc_profile() -> None:
    profile = b"\x00\x00\x02\x0clcms" + b"\x11" * 512
    prepared = _prepare(_jpeg(icc_profile=profile))
    with Image.open(BytesIO(prepared["bytes"])) as image:
        assert image.info.get("icc_profile") == profile


def test_jpeg_orientation_is_reported_so_the_page_can_rotate() -> None:
    prepared = _prepare(_jpeg(exif=_exif_with_gps(orientation=6)))
    assert prepared["orientation"] == 6
    assert GPS_MARKER.encode() not in prepared["bytes"]


def test_jfif_thumbnails_are_dropped() -> None:
    jfif = b"JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x02\x02" + b"\xaa" * 12
    original = _jpeg()
    # Replace Pillow's APP0 with one that carries a 2x2 RGB thumbnail.
    start = original.index(b"\xff\xe0")
    length = int.from_bytes(original[start + 2 : start + 4], "big")
    original = original[:start] + _segment(0xE0, jfif) + original[start + 2 + length :]
    stripped = _prepare(original)["bytes"]
    assert b"\xaa" * 12 not in stripped
    assert _pixels(stripped) == _pixels(original)


@pytest.mark.parametrize("frames", [3])
def test_animation_frames_survive(frames) -> None:
    original = _gif_with_metadata(frames)
    prepared = _prepare(original)
    assert prepared["frames"] == frames
    assert _pixels(prepared["bytes"]) == _pixels(original)

    output = BytesIO()
    frames_list = [_photo() for _ in range(frames)]
    for index, frame in enumerate(frames_list):
        frame.putpixel((index, 0), (255, 0, 0))  # libwebp merges identical frames
    frames_list[0].save(
        output,
        format="WEBP",
        save_all=True,
        append_images=frames_list[1:],
        lossless=True,
        exif=_exif_with_gps(),
        duration=50,
    )
    animated = _prepare(output.getvalue())
    assert animated["frames"] == frames
    assert _pixels(animated["bytes"]) == _pixels(output.getvalue())


def test_bmp_passes_through_and_tiff_is_refused() -> None:
    output = BytesIO()
    _photo().save(output, format="BMP")
    prepared = _prepare(output.getvalue())
    assert prepared["bytes"] == output.getvalue()
    assert (prepared["width"], prepared["height"]) == (48, 32)

    tiff = BytesIO()
    _photo().save(tiff, format="TIFF")
    with pytest.raises(RuntimeError, match="TIFF"):
        _prepare(tiff.getvalue())


@pytest.mark.parametrize(
    "data",
    [
        b"not an image at all",
        _jpeg()[:-200],
        _png_with_metadata()[:60],
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\x0dIHDR"
        + b"\x00" * 17
        + b"\x00\x00\x00\x00ZZZZ\x00\x00\x00\x00",
        b"GIF89a" + b"\x01\x00\x01\x00\x00\x00\x00" + b"\x2c",
    ],
    ids=[
        "garbage",
        "truncated-jpeg",
        "truncated-png",
        "unknown-critical-png-chunk",
        "truncated-gif",
    ],
)
def test_damaged_or_unknown_input_is_refused(data) -> None:
    with pytest.raises(RuntimeError, match="ImageError"):
        _prepare(data)
