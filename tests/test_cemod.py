import hashlib
import json
import os
import pathlib
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
import zlib


ROOT = pathlib.Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from cemodlib import (  # noqa: E402
    CemodError, canonical_signature_digest, inspect_wups, read_package, validate_elf,
    validate_manifest,
)
from verify_cemod import verify_signature  # noqa: E402


def manifest(version=2, payload_format="wups"):
    result = {
        "package_version": version,
        "api_version": 2,
        "execution_mode": "trusted_native",
        "mod_id": "org.example.test",
        "title_ids": ["0005000012345678"],
        "requested_permissions": [],
    }
    if version == 2:
        result["payload"] = {
            "format": payload_format,
            "path": "plugin.wps" if payload_format == "wups" else "mod.elf",
        }
        result["scope"] = {"type": "process", "targets": ["game", "wii_u_menu"]}
        result["permissions"] = {
            "native_memory": True, "function_patching": False,
            "filesystem": {"read": True, "write": False}, "modules": [],
        }
    return result


def wps_image(metadata=b"name=SDK Test\0author=Test\0version=1.0\0license=MIT\0"
                       b"description=Fixture\0wups=0.9.1\0buildtimestamp=Jul 23 2026\0"
                       b"storage_id=sdk.test\0", hook=17):
    sections = [
        ["", 0, 0, 0, 0, 0, 0, b""],
        [".text", 1, 2 | 4, 0x02000000, 0, 0, 4, b"\x4e\x80\x00\x20"],
        [".data", 1, 2 | 1, 0x10000000, 0, 0, 4,
         b"OSReport\0" + b"\0" * 7 + b"my_OSReport\0" + b"\0" * 7 + b"\0" * 29],
        [".wups.meta", 1, 2 | 1, 0x10000100, 0, 0, 4, metadata],
        [".wups.hooks", 1, 2 | 1, 0x10000200, 0, 0, 4,
         struct.pack(">II", hook, 0x02000000)],
        [".wups.load", 1, 2 | 1, 0x10000300, 0, 0, 4,
         struct.pack(">9I", 1, 0, 0, 0x10000000, 2, 0x10000010,
                     0x02000000, 0x10000030, 16)],
        [".fimport_coreinit", 0x80000002, 2 | 4, 0xC0000000, 0, 0, 16, b"\0" * 16],
        [".rela.text", 4, 0, 0, 0, 1, 4, struct.pack(">III", 0x02000000, 0x00000101, 0)],
        [".symtab", 2, 0, 0, 0, 0, 4, bytearray(32)],
        [".strtab", 3, 0, 0, 0, 0, 1, b"\0OSReport\0"],
    ]
    sections[8][4] = 9
    sections[7][4] = 8
    struct.pack_into(">II", sections[8][7], 16, 1, 0xC0000000)
    sections[8][7][28] = 0x12
    struct.pack_into(">H", sections[8][7], 30, 6)
    names = bytearray(b"\0")
    name_offsets = []
    for section in sections:
        name_offsets.append(len(names))
        names += section[0].encode() + b"\0"
    name_index = len(sections)
    name_offsets.append(len(names))
    names += b".shstrtab\0"
    sections.append([".shstrtab", 3, 0, 0, 0, 0, 1, bytes(names)])
    crc_index = len(sections)
    name_offsets.append(0)
    sections.append(["", 0x80000003, 0, 0, 0, 0, 4, b""])
    name_offsets.append(0)
    fileinfo = bytearray(0x60)
    struct.pack_into(">6I", fileinfo, 0, 0xCAFE0402, 0x1000, 0x20, 0x2000, 0x1000, 0x1000)
    sections.append(["", 0x80000004, 0, 0, 0, 0, 4, bytes(fileinfo)])
    crc = bytearray(len(sections) * 4)
    for index, section in enumerate(sections):
        if index != crc_index:
            struct.pack_into(">I", crc, index * 4, zlib.crc32(section[7]))
    sections[crc_index][7] = bytes(crc)

    table_offset = 0x40
    cursor = (table_offset + len(sections) * 40 + 3) & ~3
    offsets = []
    for section in sections:
        offsets.append(cursor if section[7] else 0)
        cursor = (cursor + len(section[7]) + 3) & ~3
    image = bytearray(cursor)
    image[:11] = b"\x7fELF\x01\x02\x01\xca\xfePL"
    struct.pack_into(">HHI", image, 16, 0xFE01, 20, 1)
    struct.pack_into(">II", image, 24, 0x02000000, 0)
    struct.pack_into(">I", image, 32, table_offset)
    struct.pack_into(">HHHHHH", image, 40, 52, 0, 0, 40, len(sections), name_index)
    for index, section in enumerate(sections):
        struct.pack_into(">10I", image, table_offset + index * 40,
                         name_offsets[index], section[1], section[2], section[3], offsets[index],
                         len(section[7]), section[4], section[5], section[6],
                         16 if section[1] == 2 else (12 if section[1] == 4 else 0))
        if section[7]:
            image[offsets[index]:offsets[index] + len(section[7])] = section[7]
    return bytes(image)


def elf_image():
    """Small valid CMB1 trusted-native ELF used by package-side validation."""
    image = bytearray(0x300)
    names = b"\0.shstrtab\0.cemod.bootstrap\0"
    image[0:4] = b"\x7fELF"
    image[4:7] = b"\x01\x02\x01"
    struct.pack_into(">HHI", image, 16, 3, 20, 1)
    struct.pack_into(">II", image, 28, 52, 0x280)
    struct.pack_into(">HHHHHH", image, 40, 52, 32, 1, 40, 3, 1)
    struct.pack_into(">8I", image, 52, 1, 0, 0x10000000, 0, len(image), 0x1000, 5, 0x1000)
    image[0x100:0x100 + len(names)] = names
    bootstrap = 0x180
    struct.pack_into(">IHHI", image, bootstrap, 0x434D4231, 1, 24, 1)
    struct.pack_into(">6I", image, bootstrap + 12, 1, 0x10000120, 0x4e800421,
                     0xFFFFFFFF, 0x10000120, 0)
    struct.pack_into(">10I", image, 0x280, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    struct.pack_into(">10I", image, 0x2a8, 1, 3, 2, 0x10000000, 0x100, len(names), 0, 0, 1, 0)
    struct.pack_into(">10I", image, 0x2d0, 11, 1, 2, 0x10000100, bootstrap, 36, 0, 0, 4, 0)
    return bytes(image)


def write_zip(path, entries, compression=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            for name, data in entries:
                archive.writestr(name, data)


class ManifestTests(unittest.TestCase):
    def test_v1_and_v2(self):
        self.assertEqual(validate_manifest(manifest(1)), ("cemod_elf", "mod.elf"))
        self.assertEqual(validate_manifest(manifest()), ("wups", "plugin.wps"))

    def test_v2_scope_and_permissions(self):
        value = manifest()
        validate_manifest(value)
        value["permissions"]["unknown"] = True
        with self.assertRaisesRegex(CemodError, "unknown"):
            validate_manifest(value)

    def test_descriptor_and_mode_rejections(self):
        value = manifest()
        del value["payload"]
        with self.assertRaisesRegex(CemodError, "payload descriptor"):
            validate_manifest(value)
        value = manifest()
        value["execution_mode"] = "isolated"
        with self.assertRaisesRegex(CemodError, "trusted_native"):
            validate_manifest(value)
        value = manifest()
        value["payload"] = {"format": "future", "path": "plugin.wps"}
        with self.assertRaisesRegex(CemodError, "unknown payload"):
            validate_manifest(value)

    def test_numeric_types_and_isolated_limits(self):
        value = manifest()
        value["package_version"] = True
        with self.assertRaises(CemodError):
            validate_manifest(value)
        value = manifest()
        value["scope"]["targets"] = ["game"] * 17
        with self.assertRaises(CemodError):
            validate_manifest(value)
        value = manifest(1)
        value["execution_mode"] = "isolated"
        value.update({
            "memory": {"code_bytes": 4096, "private_bytes": 4096, "stack_bytes": 4096},
            "cpu": {"instructions_per_frame": 1000, "time_us_per_frame": 500},
            "entrypoint": "cemod_init",
        })
        self.assertEqual(validate_manifest(value), ("cemod_elf", "mod.elf"))
        value["entrypoint"] = "not_cemod_init"
        with self.assertRaises(CemodError):
            validate_manifest(value)


class WupsTests(unittest.TestCase):
    def test_valid_inspection(self):
        result = inspect_wups(wps_image())
        self.assertEqual(result["wups_abi_version"], "0.9.1")
        self.assertEqual(result["metadata"]["name"], "SDK Test")
        self.assertEqual(result["hooks"][0]["name"], "APPLICATION_STARTS")
        self.assertFalse(result["tls"])

    def test_header_crc_metadata_hook_and_version_rejections(self):
        image = bytearray(wps_image())
        image[9] = ord("X")
        with self.assertRaisesRegex(CemodError, "WPS RPL"):
            inspect_wups(bytes(image))
        image = bytearray(wps_image())
        image[-1] ^= 1
        with self.assertRaisesRegex(CemodError, "CRC"):
            inspect_wups(bytes(image))
        with self.assertRaisesRegex(CemodError, "duplicate"):
            inspect_wups(wps_image(b"name=One\0name=Two\0wups=0.9.1\0"))
        with self.assertRaisesRegex(CemodError, "SDK Test.*9.9.9"):
            inspect_wups(wps_image(b"name=SDK Test\0wups=9.9.9\0"))
        with self.assertRaisesRegex(CemodError, "hook"):
            inspect_wups(wps_image(hook=99))
        with self.assertRaisesRegex(CemodError, "malformed"):
            inspect_wups(wps_image(b"name=SDK Test\0wups=0.9\0"))
        with self.assertRaisesRegex(CemodError, "storage_id"):
            inspect_wups(wps_image(b"name=SDK Test\0wups=0.9.1\0storage_id=../escape\0"))


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.directory.name)
        self.encoded = json.dumps(manifest(), separators=(",", ":")).encode()
        self.wps = wps_image()

    def tearDown(self):
        self.directory.cleanup()

    def package(self, name, entries, compression=zipfile.ZIP_DEFLATED):
        path = self.root / f"{name}.cemod"
        write_zip(path, entries, compression)
        return path

    def test_order_independent_valid_package(self):
        path = self.package("valid", [("plugin.wps", self.wps), ("manifest.json", self.encoded)])
        result = read_package(path)
        self.assertEqual(result.payload_format, "wups")
        self.assertEqual(result.wups["metadata"]["name"], "SDK Test")

    def test_payload_missing_multiple_and_mismatch(self):
        for suffix, entries in (
            ("missing", [("manifest.json", self.encoded)]),
            ("multiple", [("manifest.json", self.encoded), ("plugin.wps", self.wps), ("mod.elf", b"x")]),
            ("mismatch", [("manifest.json", json.dumps(manifest(2, "cemod_elf")).encode()),
                          ("plugin.wps", self.wps)]),
        ):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(CemodError, "exactly"):
                read_package(self.package(suffix, entries))

    def test_legacy_elf_payload_and_malformed_elf(self):
        value = manifest(1)
        path = self.package("elf", [("manifest.json", json.dumps(value).encode()),
                                     ("mod.elf", elf_image())])
        result = read_package(path)
        self.assertEqual(result.payload_format, "cemod_elf")
        broken = bytearray(elf_image())
        broken[0] = 0
        with self.assertRaisesRegex(CemodError, "mod.elf"):
            validate_elf(bytes(broken))

    def test_deterministic_package_bytes(self):
        manifest_path = self.root / "manifest.json"
        wps_path = self.root / "plugin.wps"
        golden_manifest = ROOT / "tests/fixtures/golden-manifest-v2.json"
        manifest_path.write_text(golden_manifest.read_text(encoding="utf-8"), encoding="utf-8")
        wps_path.write_bytes(self.wps)
        first = self.root / "first.cemod"
        second = self.root / "second.cemod"
        command = [sys.executable, str(TOOLS / "package_cemod.py"), "--manifest", str(manifest_path),
                   "--wps", str(wps_path), "--output"]
        subprocess.run(command + [str(first)], check=True)
        subprocess.run(command + [str(second)], check=True)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(hashlib.sha256(first.read_bytes()).hexdigest(),
                         "7da84075bc099ef9580078ab07cb8ea9f496e3d651eb27ddcc8ab18e63cfec8b")

    def test_unsafe_duplicate_and_unknown_entries(self):
        cases = {
            "duplicate": [("manifest.json", self.encoded), ("manifest.json", self.encoded),
                          ("plugin.wps", self.wps)],
            "normalized": [("manifest.json", self.encoded), ("./manifest.json", self.encoded),
                           ("plugin.wps", self.wps)],
            "traversal": [("manifest.json", self.encoded), ("../plugin.wps", self.wps)],
            "absolute": [("manifest.json", self.encoded), ("/plugin.wps", self.wps)],
            "unknown": [("manifest.json", self.encoded), ("plugin.wps", self.wps), ("required.new", b"x")],
        }
        for suffix, entries in cases.items():
            with self.subTest(suffix=suffix), self.assertRaises(CemodError):
                read_package(self.package(suffix, entries))

    def test_compression_bomb(self):
        path = self.package("bomb", [("manifest.json", self.encoded), ("plugin.wps", b"0" * (2 << 20))])
        with self.assertRaisesRegex(CemodError, "compression-ratio"):
            read_package(path)

    def test_oversized_archive_and_malformed_json(self):
        oversized = self.root / "oversized.cemod"
        with oversized.open("wb") as output:
            output.seek(64 * 1024 * 1024)
            output.write(b"x")
        with self.assertRaisesRegex(CemodError, "size"):
            read_package(oversized)
        malformed = self.package("malformed", [("manifest.json", b"{"), ("plugin.wps", self.wps)])
        with self.assertRaisesRegex(CemodError, "malformed"):
            read_package(malformed)

    def test_digest_commits_name_length_and_sha256(self):
        entries = {"manifest.json": b"{}", "plugin.wps": b"payload"}
        digest = canonical_signature_digest(entries)
        canonical = b""
        for name in sorted(entries):
            encoded = name.encode()
            data = entries[name]
            canonical += struct.pack(">I", len(encoded)) + encoded
            canonical += struct.pack(">Q", len(data)) + hashlib.sha256(data).digest()
        self.assertEqual(digest, hashlib.sha256(canonical).digest())
        self.assertNotEqual(digest, canonical_signature_digest({"manifest.json": b"{}", "mod.elf": b"payload"}))
        self.assertNotEqual(digest, canonical_signature_digest({"manifest.json": b"{}", "plugin.wps": b"payload!"}))

    @unittest.skipUnless(subprocess.run(["openssl", "version"], stdout=subprocess.DEVNULL).returncode == 0,
                         "OpenSSL is required")
    def test_cli_sign_verify_bad_signature_and_atomic_failure(self):
        manifest_path = self.root / "manifest.json"
        wps_path = self.root / "plugin.wps"
        key_path = self.root / "private.pem"
        output_path = self.root / "signed.cemod"
        manifest_path.write_text(json.dumps(manifest()), encoding="utf-8")
        wps_path.write_bytes(self.wps)
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key_path)], check=True)
        subprocess.run([sys.executable, str(TOOLS / "package_cemod.py"), "--manifest", str(manifest_path),
                        "--wps", str(wps_path), "--private-key", str(key_path), "--output", str(output_path)],
                       check=True)
        subprocess.run([sys.executable, str(TOOLS / "verify_cemod.py"), "--package", str(output_path)], check=True)
        package = read_package(output_path)
        verify_signature(package.entries)
        bad_entries = dict(package.entries)
        bad_entries["signature.ed25519"] = bytes([bad_entries["signature.ed25519"][0] ^ 1]) + \
            bad_entries["signature.ed25519"][1:]
        with self.assertRaisesRegex(CemodError, "signature"):
            verify_signature(bad_entries)
        original = output_path.read_bytes()
        wps_path.write_bytes(b"invalid")
        failed = subprocess.run([sys.executable, str(TOOLS / "package_cemod.py"), "--manifest", str(manifest_path),
                                 "--wps", str(wps_path), "--output", str(output_path)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(output_path.read_bytes(), original)

    def test_cross_repo_cemu_extend_accepts_wps_and_signature(self):
        wups_binary = os.environ.get("CEMUEXTEND_WUPS_BINARY")
        if not wups_binary:
            candidate = ROOT.parent / "CemuExtend" / "build/nix/src/Cafe/wups_binary_tests"
            wups_binary = str(candidate) if candidate.exists() else None
        if not wups_binary:
            self.skipTest("set CEMUEXTEND_WUPS_BINARY to run the C++ WPS conformance test")
        wps_path = self.root / "plugin.wps"
        wps_path.write_bytes(self.wps)
        subprocess.run([wups_binary], check=True, env={**os.environ,
                        "CEMUEXTEND_WPS_CONFORMANCE_IMAGE": str(wps_path)})

        package_path = self.root / "signed.cemod"
        manifest_path = self.root / "manifest.json"
        key_path = self.root / "private.pem"
        manifest_path.write_text(json.dumps(manifest()), encoding="utf-8")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key_path)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run([sys.executable, str(TOOLS / "package_cemod.py"), "--manifest", str(manifest_path),
                        "--wps", str(wps_path), "--private-key", str(key_path), "--output", str(package_path)],
                       check=True)
        package_binary = os.environ.get("CEMUEXTEND_PACKAGE_BINARY")
        if not package_binary:
            candidate = ROOT.parent / "CemuExtend" / "build/nix/src/Cafe/cemod_package_tests"
            package_binary = str(candidate) if candidate.exists() else None
        if not package_binary:
            self.skipTest("set CEMUEXTEND_PACKAGE_BINARY to run the C++ package conformance test")
        subprocess.run([package_binary], check=True, env={**os.environ,
                        "CEMUEXTEND_CEMOD_CONFORMANCE_PACKAGE": str(package_path)})


if __name__ == "__main__":
    unittest.main()
