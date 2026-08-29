import importlib.util
import io
import pathlib
import tarfile
import tempfile
import unittest
import zipfile


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "verify-release-artifact.py"
SPEC = importlib.util.spec_from_file_location("verify_release_artifact", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)


class ArchiveMemberControls(unittest.TestCase):
    def test_marker_split_at_scan_chunk_boundary_is_rejected(self) -> None:
        marker = scanner.FORBIDDEN_MARKERS[0]
        prefix = b"x" * (scanner.SCAN_CHUNK_SIZE - len(marker) + 1)
        with self.assertRaises(SystemExit) as error:
            scanner.scan_bytes("split-marker", prefix + marker)
        self.assertIn("transport-lab marker", str(error.exception))

    def test_missing_expected_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "artifact.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("bin/other", b"daemon")
            with self.assertRaises(SystemExit) as error:
                scanner.scan_archive(path, ["bin/missing"])
            self.assertIn("bin/missing", str(error.exception))

    def test_empty_expected_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "artifact.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("bin/myownmesh", b"")
            with self.assertRaises(SystemExit) as error:
                scanner.scan_archive(path, ["bin/myownmesh"])
            self.assertIn("empty", str(error.exception))

    def test_empty_expected_tar_regular_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "artifact.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                info = tarfile.TarInfo("bin/myownmesh")
                info.size = 0
                archive.addfile(info, io.BytesIO())
            with self.assertRaises(SystemExit) as error:
                scanner.scan_archive(path, ["bin/myownmesh"])
            self.assertIn("empty", str(error.exception))

    def test_expected_nonregular_members_are_rejected_for_zip_and_tar(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            zip_path = pathlib.Path(directory) / "artifact.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("bin/not-file/", b"")
            with self.assertRaises(SystemExit) as zip_error:
                scanner.scan_archive(zip_path, ["bin/not-file/"])
            self.assertIn("regular file", str(zip_error.exception))

            tar_path = pathlib.Path(directory) / "artifact.tar.gz"
            with tarfile.open(tar_path, "w:gz") as archive:
                info = tarfile.TarInfo("bin/not-file")
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            with self.assertRaises(SystemExit) as tar_error:
                scanner.scan_archive(tar_path, ["bin/not-file"])
            self.assertIn("regular file", str(tar_error.exception))

    def test_duplicate_expected_member_entries_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "artifact.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("bin/myownmesh", b"first")
                archive.writestr("bin/myownmesh", b"second")
            with self.assertRaises(SystemExit) as error:
                scanner.scan_archive(path, ["bin/myownmesh"])
            self.assertIn("duplicate", str(error.exception))

    def test_duplicate_expected_member_argument_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "artifact.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                payload = b"daemon"
                info = tarfile.TarInfo("bin/myownmesh")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            with self.assertRaises(SystemExit) as error:
                scanner.scan_archive(path, ["bin/myownmesh", "bin/myownmesh"])
            self.assertIn("duplicate expected member arguments", str(error.exception))

    def test_nonempty_regular_zip_and_tar_members_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            zip_path = pathlib.Path(directory) / "artifact.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("bin/myownmesh", b"daemon")
            scanner.scan_archive(zip_path, ["bin/myownmesh"])

            tar_path = pathlib.Path(directory) / "artifact.tar.gz"
            with tarfile.open(tar_path, "w:gz") as archive:
                payload = b"daemon"
                info = tarfile.TarInfo("bin/myownmesh")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            scanner.scan_archive(tar_path, ["bin/myownmesh"])


if __name__ == "__main__":
    unittest.main()
