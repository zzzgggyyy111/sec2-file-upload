from pathlib import Path

from upguard import (
    check_extension,
    safe_name,
    upload_batch,
)

PNG_1X1 = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR"
    b"\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00"
    b"\x1f\x15\xc4\x89"
    b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)

GIF_1X1 = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00"
    b"\x00\x00\x00\xff\xff\xff"
    b"!\xf9\x04\x01\x00\x00\x00\x00"
    b",\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)


def make_policy(root: Path) -> dict:
    uploads = root / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    return {
        "allowed_extensions": ["png", "jpg", "jpeg", "gif", "webp"],
        "allowed_kinds": ["png", "jpeg", "gif", "webp"],
        "max_bytes": 2_000_000,
        "max_width": 1024,
        "max_height": 1024,
        "storage_root": str(uploads),
    }


def test_valid_png_is_accepted(tmp_path):
    policy = make_policy(tmp_path)
    result = upload_batch([{"name": "avatar.png", "data": PNG_1X1}], policy)

    assert len(result["accepted"]) == 1
    record = result["accepted"][0]
    assert record["kind"] == "png"
    assert "avatar" not in Path(record["path"]).name


def test_extension_whitelist_is_case_insensitive(tmp_path):
    policy = make_policy(tmp_path)

    assert check_extension("AVATAR.PNG", policy["allowed_extensions"]) is True
    assert check_extension("avatar.php", policy["allowed_extensions"]) is False


def test_double_extension_is_rejected(tmp_path):
    policy = make_policy(tmp_path)

    assert check_extension("shell.php.png", policy["allowed_extensions"]) is False


def test_generated_name_is_safe(tmp_path):
    generated = safe_name("../../user-avatar.png")

    assert "/" not in generated
    assert "\\" not in generated
    assert ".." not in generated
    assert "user-avatar" not in generated


def test_batch_files_are_independent(tmp_path):
    policy = make_policy(tmp_path)
    result = upload_batch(
        [
            {"name": "first.png", "data": PNG_1X1},
            {"name": "second.gif", "data": GIF_1X1},
        ],
        policy,
    )

    assert len(result["accepted"]) == 2
    records = {record["name"]: record for record in result["accepted"]}
    assert records["second.gif"]["kind"] == "gif"