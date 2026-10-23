import importlib.util
import hashlib
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest import mock
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

    def test_every_removed_v3_marker_is_rejected_across_scan_chunk_boundary(self) -> None:
        for marker in scanner.REMOVED_V3_MARKERS:
            prefix = b"x" * (scanner.SCAN_CHUNK_SIZE - len(marker) + 1)
            with self.subTest(marker=marker):
                with self.assertRaises(SystemExit) as error:
                    scanner.scan_bytes("split-removed-marker", prefix + marker)
                self.assertIn(marker.decode("ascii"), str(error.exception))

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

    def test_tree_scans_every_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "bundle"
            nested = root / "nested"
            nested.mkdir(parents=True)
            (root / "installer").write_bytes(b"installer")
            (nested / "payload").write_bytes(b"transport-lab")
            with self.assertRaises(SystemExit) as error:
                scanner.scan_tree(root)
            self.assertIn("transport-lab", str(error.exception))

    def test_tree_rejects_empty_or_symlinked_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            empty = pathlib.Path(directory) / "empty"
            empty.mkdir()
            with self.assertRaises(SystemExit) as empty_error:
                scanner.scan_tree(empty)
            self.assertIn("no regular files", str(empty_error.exception))

            target = pathlib.Path(directory) / "target"
            target.write_bytes(b"payload")
            bundle = pathlib.Path(directory) / "symlinked"
            bundle.mkdir()
            link = bundle / "payload"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable on this host")
            with self.assertRaises(SystemExit) as link_error:
                scanner.scan_tree(bundle)
            self.assertIn("unsupported symlink", str(link_error.exception))

    def test_tree_rejects_empty_regular_installer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "bundle"
            root.mkdir()
            (root / "installer").write_bytes(b"")
            with self.assertRaises(SystemExit) as error:
                scanner.scan_tree(root)
            self.assertIn("empty regular file", str(error.exception))

    def test_checksum_sidecars_require_matching_payload_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "signing"
            root.mkdir()
            payload = root / "myownmesh.tar.gz"
            payload.write_bytes(b"daemon")
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            sidecar = root / "myownmesh.tar.gz.sha256"
            sidecar.write_text(f"{digest}  {payload.name}\n", encoding="utf-8")
            scanner.verify_checksum_sidecars(root)

            sidecar.write_text(f"{'0' * 64}  {payload.name}\n", encoding="utf-8")
            with self.assertRaises(SystemExit) as error:
                scanner.verify_checksum_sidecars(root)
            self.assertIn("checksum mismatch", str(error.exception))

    def test_checksum_sidecars_reject_orphans(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "signing"
            root.mkdir()
            (root / "removed.tar.gz.sha256").write_text(
                f"{'0' * 64}  removed.tar.gz\n", encoding="utf-8"
            )
            with self.assertRaises(SystemExit) as error:
                scanner.verify_checksum_sidecars(root)
            self.assertIn("no matching payload", str(error.exception))

    def test_signature_targets_require_every_release_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "signing"
            root.mkdir()
            payload = root / "myownmesh.tar.gz"
            payload.write_bytes(b"daemon")
            (root / "myownmesh.tar.gz.sha256").write_bytes(b"checksum")
            with self.assertRaises(SystemExit) as error:
                scanner.required_signature_targets(root)
            self.assertIn("myownmesh.tar.gz", str(error.exception))

    def test_signature_targets_exclude_checksum_and_signature_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "signing"
            root.mkdir()
            payload = root / "myownmesh.tar.gz"
            payload.write_bytes(b"daemon")
            (root / "myownmesh.tar.gz.sha256").write_bytes(b"checksum")
            (root / "myownmesh.tar.gz.minisig").write_bytes(b"signature")
            self.assertEqual(scanner.required_signature_targets(root), [payload])

    def test_orphan_signature_sidecar_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "signing"
            root.mkdir()
            payload = root / "myownmesh.tar.gz"
            payload.write_bytes(b"daemon")
            (root / "myownmesh.tar.gz.minisig").write_bytes(b"signature")
            (root / "removed-payload.tar.gz.minisig").write_bytes(b"orphan")
            with self.assertRaises(SystemExit) as error:
                scanner.required_signature_targets(root)
            self.assertIn("orphan signature", str(error.exception))

    def test_signature_verification_requires_public_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "signing"
            root.mkdir()
            with self.assertRaises(SystemExit) as error:
                scanner.verify_signature_tree(root, "")
            self.assertIn("non-empty minisign public key", str(error.exception))

    def test_release_binary_must_embed_public_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = pathlib.Path(directory) / "myownmesh"
            binary.write_bytes(b"daemon PUBLICKEY")
            scanner.verify_release_public_key(binary, "PUBLICKEY")
            with self.assertRaises(SystemExit) as error:
                scanner.verify_release_public_key(binary, "OTHERKEY")
            self.assertIn("does not embed", str(error.exception))

    def test_asset_allowlist_binds_names_and_digests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "signing"
            root.mkdir()
            payload = root / "release.tar.gz"
            payload.write_bytes(b"release")
            manifest_root = pathlib.Path(directory) / "allowlists"
            manifest_root.mkdir()
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            (manifest_root / "build.json").write_text(
                '{"assets":{"release.tar.gz":"' + digest + '"}}\n',
                encoding="utf-8",
            )
            scanner.verify_asset_allowlist(root, manifest_root)
            payload.write_bytes(b"stale-draft-payload")
            with self.assertRaises(SystemExit) as error:
                scanner.verify_asset_allowlist(root, manifest_root)
            self.assertIn("digest mismatch", str(error.exception))


class WorkflowControls(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows" / "release.yml"

    def test_release_workflow_has_exact_draft_preflight_and_publisher_dependencies(self) -> None:
        scanner.verify_workflow(self.workflow)

    def test_release_workflow_rejects_tag_interpolation_in_shell(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        for expression in (
            "${{ inputs.tag || github.ref_name }}",
            "${{ github.ref_name }}",
            "${{ inputs['tag'] }}",
            "${{ env.TAG }}",
            "${{\n            github['ref_name']\n          }}",
        ):
            with self.subTest(expression=expression):
                broken = text.replace(
                    '          EXPECTED="${TAG#v}"',
                    f'          TAG="{expression}"\n          EXPECTED="${{TAG#v}}"',
                    1,
                )
                self.assertNotEqual(text, broken)
                with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
                    handle.write(broken)
                    path = pathlib.Path(handle.name)
                try:
                    with self.assertRaises(SystemExit) as error:
                        scanner.verify_workflow(path)
                    self.assertIn("interpolates tag data into shell source", str(error.exception))
                finally:
                    path.unlink()

    def test_release_workflow_requires_tag_data_in_preflight_environment(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        prepare_start = text.index("  prepare-release:\n")
        prepare_end = text.index("  release-gates:\n")
        prepare = text[prepare_start:prepare_end].replace(
            "          TAG: ${{ inputs.tag || github.ref_name }}\n", "", 1
        )
        broken = text[:prepare_start] + prepare + text[prepare_end:]
        self.assertNotEqual(text, broken)
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("prepare-release does not verify TAG:", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_rejects_missing_prepare_dependency(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        broken = text.replace("needs: [prepare-release, release-gates]", "needs: []", 1)
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("does not depend on prepare-release", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_rejects_missing_release_gate_dependency_for_signer(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        broken = text.replace(
            "needs: [prepare-release, release-gates, bundles, daemon-riscv64, daemon-aarch64-musl]",
            "needs: [prepare-release, bundles, daemon-riscv64, daemon-aarch64-musl]",
            1,
        )
        broken = broken.replace(
            "needs: [prepare-release, release-gates]", "needs: prepare-release"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("does not depend on release-gates", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_rejects_missing_release_gate_dependency_for_build_publisher(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        broken = text.replace("needs: [prepare-release, release-gates]", "needs: prepare-release", 1)
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("does not depend on release-gates", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_accepts_multiline_needs_dependency_graph(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        broken = text.replace(
            "needs: [prepare-release, release-gates]",
            "needs:\n      - prepare-release\n      - release-gates",
            1,
        )
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            scanner.verify_workflow(path)
        finally:
            path.unlink()

    def test_release_workflow_rejects_unknown_dependency(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        broken = text.replace(
            "needs: [prepare-release, release-gates]",
            "needs: [prepare-release, missing-job]",
            1,
        )
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("unknown job dependency", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_rejects_dependency_cycle(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        broken = text.replace("needs: prepare-release", "needs: release-gates", 1)
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("dependency cycle", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_requires_post_upload_asset_check(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        publish_start = text.rfind("      - name: Publish signed release\n")
        broken = text[:publish_start] + text[publish_start:].replace(
            "            --verify-release-assets \\\n", "", 1
        )
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("final publish step lacks immediate verification", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_requires_every_release_target(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        broken = text.replace(
            "riscv64gc-unknown-linux-musl", "riscv64gc-missing-target"
        )
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("linux-riscv64", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_rejects_unlisted_command_writer_bypass(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        bypass = '          gh release upload "$TAG" bypass.tar.gz --repo "$GITHUB_REPOSITORY"\n'
        broken = text.replace("          --repository \"$GITHUB_REPOSITORY\"\n", bypass, 1)
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("prepare-release", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_rejects_missing_exact_preflight(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        broken = text.replace("--preflight-release", "--legacy-release-check", 1)
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("--preflight-release", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_rejects_publish_before_signature_verification(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        publish = 'gh release edit "$TAG" --repo "$GITHUB_REPOSITORY" --draft=false'
        broken = text.replace(
            "      - name: Sign and upload signatures",
            f"      - run: {publish}\n\n      - name: Sign and upload signatures",
            1,
        )
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("publishes before signature verification", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_rejects_secret_inside_payload_tree(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        broken = text.replace("$RUNNER_TEMP/myownmesh-minisign.key", "signing/minisign.key")
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("payload tree", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_rejects_non_draft_publisher(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        broken = text.replace("          draft: true\n", "          draft: false\n", 1)
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("non-draft", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_requires_per_tag_concurrency(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        broken = text.replace(
            "concurrency:\n  group: release-${{ inputs.tag || github.ref_name }}\n  cancel-in-progress: false\n\n",
            "",
            1,
        )
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("per-tag concurrency", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_requires_signer_checkout_before_scripts(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        marker = "  sign:\n"
        start = text.index(marker)
        checkout = f"      - uses: {scanner.reviewed_action('actions/checkout')}"
        checkout_index = text.index(checkout, start)
        line_end = text.index("\n", checkout_index) + 1
        broken = text[:checkout_index] + text[line_end:]
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("before checkout", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_requires_late_exact_preflight(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        late = text.rfind("--preflight-release")
        broken = text[:late] + "--legacy-release-check" + text[late + len("--preflight-release") :]
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("re-resolve", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_requires_publication_key_and_allowlist_wiring(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        for needle, expected in (
            ("--release-public-key", "publication-key binding"),
            ("--asset-allowlist", "source-owned release asset allowlists"),
            ("--write-asset-manifest", "source-owned release asset allowlists"),
        ):
            with self.subTest(needle=needle):
                broken = text.replace(needle, "--removed-option")
                with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
                    handle.write(broken)
                    path = pathlib.Path(handle.name)
                try:
                    with self.assertRaises(SystemExit) as error:
                        scanner.verify_workflow(path)
                    self.assertIn(expected, str(error.exception))
                finally:
                    path.unlink()

    def test_release_workflow_requires_tauri_key_equality_proof(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        broken = text.replace(
            '          test "$MYOWNMESH_RELEASE_PUBKEY" = "$MINISIGN_PUBLIC_KEY"\n',
            "",
        )
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("key equality proof", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_requires_manifest_upload_and_pre_sign_gate(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        for broken in (
            text.replace(scanner.reviewed_action("actions/upload-artifact"), "actions/removed-artifact@v4"),
            text.replace(
                "      - name: Refuse stale or tampered draft assets before signing\n",
                "      - name: Removed stale asset gate\n",
                1,
            ).replace(
                "--asset-allowlist \"$GITHUB_WORKSPACE/allowlists\"",
                "--removed-option",
                1,
            ),
        ):
            with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
                handle.write(broken)
                path = pathlib.Path(handle.name)
            try:
                with self.assertRaises(SystemExit) as error:
                    scanner.verify_workflow(path)
                self.assertTrue(
                    "build-owned asset allowlists" in str(error.exception)
                    or "before signing" in str(error.exception)
                )
            finally:
                path.unlink()

    def test_release_workflow_requires_exact_minisign_archive_digest(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        mutations = (
            text.replace(scanner.MINISIGN_ARCHIVE_SHA256, "0" * 64, 1),
            text.replace(
                f'          minisign_archive_sha256="{scanner.MINISIGN_ARCHIVE_SHA256}"\n',
                "",
                1,
            ),
        )
        for broken in mutations:
            with self.subTest(mutation="digest"):
                with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
                    handle.write(broken)
                    path = pathlib.Path(handle.name)
                try:
                    with self.assertRaises(SystemExit) as error:
                        scanner.verify_workflow(path)
                    self.assertIn("minisign archive digest", str(error.exception))
                finally:
                    path.unlink()

    def test_release_workflow_exposes_no_signing_key_before_verified_installer(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        install_start = text.index("      - name: Install minisign\n")
        gate_start = text.index("      - name: Gate on signing key\n", install_start)
        next_step = text.index("\n      - name: Download release artifacts\n", gate_start)
        install_block = text[install_start:gate_start]
        gate_block = text[gate_start:next_step]
        broken = text[:install_start] + gate_block + install_block + text[next_step:]
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("before signer verification", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_rejects_unpinned_checkout(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        broken = text.replace("          ref: ${{ github.sha }}\n", "", 1)
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("exact checkout/origin proof", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_rejects_missing_origin_binding(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        broken = text.replace("          test \"$(git remote get-url origin)\" = \"https://github.com/$GITHUB_REPOSITORY.git\"\n", "", 1)
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("exact checkout/origin proof", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_rejects_final_publish_without_remote_redownload(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        publish_start = text.rfind("      - name: Publish signed release\n")
        broken = text[:publish_start] + text[publish_start:].replace(
            '          gh release download "$TAG" --repo "$GITHUB_REPOSITORY" --dir "$remote_dir" --clobber\n',
            "",
            1,
        )
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("final publish step lacks immediate verification", str(error.exception))
        finally:
            path.unlink()

    def test_release_workflow_rejects_final_publish_without_remote_tree_check(self) -> None:
        text = self.workflow.read_text(encoding="utf-8")
        publish_start = text.rfind("      - name: Publish signed release\n")
        broken = text[:publish_start] + text[publish_start:].replace(
            '            --remote-tree "$remote_dir" \\\n',
            "",
            1,
        )
        with tempfile.NamedTemporaryFile("w", suffix=".yml", encoding="utf-8", delete=False) as handle:
            handle.write(broken)
            path = pathlib.Path(handle.name)
        try:
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
            self.assertIn("final publish step lacks immediate verification", str(error.exception))
        finally:
            path.unlink()
class WorkflowProvenanceControls(unittest.TestCase):
    def setUp(self) -> None:
        workflows = pathlib.Path(__file__).resolve().parents[2] / ".github" / "workflows"
        self.release = workflows / "release.yml"
        self.ci = workflows / "ci.yml"

    def verify_text(self, text: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "workflow.yml"
            path.write_text(text, encoding="utf-8")
            scanner.verify_workflow_provenance(path)

    def test_release_and_ci_use_reviewed_provenance(self) -> None:
        for path in (self.release, self.ci):
            with self.subTest(path=path):
                scanner.verify_workflow_provenance(path)

    def test_release_gate_must_check_ci_provenance(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        broken = text.replace("          --ci-workflow .github/workflows/ci.yml\n", "", 1)
        self.assertNotEqual(text, broken)
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "release.yml"
            path.write_text(broken, encoding="utf-8")
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
        self.assertIn("do not verify CI provenance policy", str(error.exception))

    def test_each_action_rejects_mutable_and_unreviewed_refs(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        for repository in scanner.ACTION_COMMITS:
            original = scanner.reviewed_action(repository)
            self.assertIn(original, text)
            for ref in ("v999", "0" * 40):
                with self.subTest(repository=repository, ref=ref):
                    broken = text.replace(original, f"{repository}@{ref}", 1)
                    with self.assertRaises(SystemExit) as error:
                        self.verify_text(broken)
                    self.assertIn("unreviewed or mutable Action", str(error.exception))

    def test_new_external_action_requires_review(self) -> None:
        text = self.ci.read_text(encoding="utf-8")
        broken = text.replace(
            scanner.reviewed_action("actions/checkout"), "unreviewed/action@" + "1" * 40, 1
        )
        with self.assertRaises(SystemExit) as error:
            self.verify_text(broken)
        self.assertIn("unreviewed or mutable Action", str(error.exception))

    def test_reindented_steps_cannot_escape_invocation_coverage(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        for reference in ("unreviewed/action@main", scanner.reviewed_action("actions/checkout")):
            with self.subTest(reference=reference):
                reindented = text + (
                    "\n  extra:\n    runs-on: ubuntu-22.04\n    steps:\n"
                    f"        - uses: {reference}\n"
                )
                with self.assertRaises(SystemExit) as error:
                    self.verify_text(reindented)
                self.assertIn("uncovered YAML uses invocation", str(error.exception))

    def test_reusable_jobs_cannot_escape_invocation_coverage(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        for key in ("uses:", "uses :"):
            with self.subTest(key=key):
                reusable = text + (
                    "\n  external-workflow:\n"
                    f"    {key} unreviewed/repo/.github/workflows/build.yml@main\n"
                )
                with self.assertRaises(SystemExit) as error:
                    self.verify_text(reusable)
                self.assertIn("uncovered YAML uses invocation", str(error.exception))

    def test_empty_and_no_step_workflows_are_refused(self) -> None:
        for text in (
            "", "# no executable workflow\n", "name: no-jobs\n",
            "jobs:\n  empty-job:\n    runs-on: ubuntu-22.04\n    steps:\n",
            "jobs:\n  run-only:\n    runs-on: ubuntu-22.04\n    steps:\n"
            "      - run: echo no-reviewed-invocations\n",
        ):
            with self.subTest(text=text):
                with self.assertRaises(SystemExit) as error:
                    self.verify_text(text)
                self.assertIn("requires covered step invocations", str(error.exception))

    def test_multiple_invocations_in_one_step_are_refused(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        checkout = "      - uses: " + scanner.reviewed_action("actions/checkout")
        for extra in (
            "\n        uses: " + scanner.reviewed_action("actions/setup-python"),
            "\n        run: echo unexpected-second-invocation",
        ):
            with self.subTest(extra=extra):
                broken = text.replace(checkout, checkout + extra, 1)
                self.assertNotEqual(text, broken)
                with self.assertRaises(SystemExit) as error:
                    self.verify_text(broken)
                self.assertIn("multiple YAML invocations", str(error.exception))

    def test_unsupported_yaml_cannot_hide_invocations(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        for extra in (
            "\n  extra: { uses: unreviewed/repo/.github/workflows/build.yml@main }\n",
            "\n  extra:\n    runs-on: ubuntu-22.04\n"
            "    steps: [ uses: unreviewed/action@main ]\n",
            "\n  extra:\n    runs-on: ubuntu-22.04\n    steps:\n"
            "      - 'uses': unreviewed/action@main\n",
            "\n  extra:\n    runs-on: ubuntu-22.04\n    steps:\n"
            '      - "us\\u0065s": unreviewed/action@main\n',
            "\n  extra:\n    runs-on: ubuntu-22.04\n    steps:\n"
            "      - &shared\n        uses: unreviewed/action@main\n      - *shared\n",
        ):
            with self.subTest(extra=extra):
                with self.assertRaises(SystemExit) as error:
                    self.verify_text(text + extra)
                self.assertIn("unsupported YAML", str(error.exception))

    def test_literal_shell_uses_text_is_not_an_action_invocation(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        self.verify_text(text + (
            "\n      - name: Inert YAML example\n        run: |\n"
            '          printf \'%s\\n\' "uses: unreviewed/action@main"\n'
        ))

    def test_tauri_cargo_lock_flag_must_follow_argument_separator(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        correct = "args: --target ${{ matrix.platform.target }} -- --locked"
        self.assertIn(correct, text)
        for incorrect in (
            "args: --locked --target ${{ matrix.platform.target }}",
            "args: --target ${{ matrix.platform.target }} --locked",
            "args: --target ${{ matrix.platform.target }} --",
        ):
            with self.subTest(incorrect=incorrect):
                broken = text.replace(correct, incorrect, 1)
                with self.assertRaises(SystemExit) as error:
                    self.verify_text(broken)
                self.assertIn("Tauri build must forward Cargo --locked after --", str(error.exception))

    def test_python_and_node_must_have_exact_versions(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        for old, new, expected in (
            (f'python-version: "{scanner.PYTHON_VERSION}"', 'python-version: "3.x"', "Python selection"),
            (f'node-version: "{scanner.NODE_VERSION}"', 'node-version: 20', "Node selection"),
        ):
            with self.subTest(new=new):
                broken = text.replace(old, new, 1)
                self.assertNotEqual(text, broken)
                with self.assertRaises(SystemExit) as error:
                    self.verify_text(broken)
                self.assertIn(expected, str(error.exception))

    def test_missing_rustup_refuses_live_bootstrap_fallback(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        # Keep the step valid so this mutation reaches the Rust-specific guard.
        broken = text.replace(
            "        run: command -v rustup\n",
            "        run: echo rustup-check-removed\n",
            1,
        )
        self.assertNotEqual(text, broken)
        with self.assertRaises(SystemExit) as error:
            self.verify_text(broken)
        self.assertIn("preinstalled-rustup gate", str(error.exception))

    def test_rustup_guard_cannot_be_conditional(self) -> None:
        for path in (self.release, self.ci):
            with self.subTest(path=path):
                text = path.read_text(encoding="utf-8")
                command = "        run: command -v rustup\n"
                broken = text.replace(command, "        if: false\n" + command, 1)
                self.assertNotEqual(text, broken)
                with self.assertRaises(SystemExit) as error:
                    self.verify_text(broken)
                self.assertIn("preinstalled-rustup gate", str(error.exception))

    def test_rustup_guard_cannot_ignore_failure(self) -> None:
        for path in (self.release, self.ci):
            with self.subTest(path=path):
                text = path.read_text(encoding="utf-8")
                command = "        run: command -v rustup\n"
                broken = text.replace(command, "        continue-on-error: true\n" + command, 1)
                self.assertNotEqual(text, broken)
                with self.assertRaises(SystemExit) as error:
                    self.verify_text(broken)
                self.assertIn("preinstalled-rustup gate", str(error.exception))

    def test_cache_cannot_restore_executable_tools(self) -> None:
        text = self.ci.read_text(encoding="utf-8")
        broken = text.replace("          cache-bin: false\n", "", 1)
        self.assertNotEqual(text, broken)
        with self.assertRaises(SystemExit) as error:
            self.verify_text(broken)
        self.assertIn("must not restore executable tools", str(error.exception))

    def test_python_version_comment_cannot_supply_pin(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        pin = f'python-version: "{scanner.PYTHON_VERSION}"'
        broken = text.replace(pin, f'python-version: "3.x" # {pin}', 1)
        self.assertNotEqual(text, broken)
        with self.assertRaises(SystemExit) as error:
            self.verify_text(broken)
        self.assertIn("Python selection", str(error.exception))

    def test_node_version_comment_cannot_supply_pin(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        pin = f'node-version: "{scanner.NODE_VERSION}"'
        broken = text.replace(pin, f'node-version: "20" # {pin}', 1)
        self.assertNotEqual(text, broken)
        with self.assertRaises(SystemExit) as error:
            self.verify_text(broken)
        self.assertIn("Node selection", str(error.exception))

    def test_cache_comment_cannot_disable_executable_restore(self) -> None:
        text = self.ci.read_text(encoding="utf-8")
        broken = text.replace("cache-bin: false", "cache-bin: true # cache-bin: false", 1)
        self.assertNotEqual(text, broken)
        with self.assertRaises(SystemExit) as error:
            self.verify_text(broken)
        self.assertIn("must not restore executable tools", str(error.exception))

    def test_rustup_comment_cannot_supply_guard(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        broken = text.replace(
            "run: command -v rustup", "run: echo skipped # run: command -v rustup", 1,
        )
        self.assertNotEqual(text, broken)
        with self.assertRaises(SystemExit) as error:
            self.verify_text(broken)
        self.assertIn("preinstalled-rustup gate", str(error.exception))

    def test_duplicate_provenance_policy_fields_are_refused(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        for field in (
            f'python-version: "{scanner.PYTHON_VERSION}"',
            f'node-version: "{scanner.NODE_VERSION}"',
            "cache-bin: false",
            "with:",
            "run: command -v rustup",
        ):
            with self.subTest(field=field):
                indent = "        " if field in ("with:", "run: command -v rustup") else "          "
                original = indent + field + "\n"
                self.assertIn(original, text)
                broken = text.replace(original, original + original, 1)
                with self.assertRaises(SystemExit) as error:
                    self.verify_text(broken)
                self.assertRegex(str(error.exception), "duplicate YAML policy field|multiple YAML invocations")

    def test_cross_tool_digest_source_revision_and_lock_are_required(self) -> None:
        for path in (self.release, self.ci):
            text = path.read_text(encoding="utf-8")
            for old, new in (
                (scanner.ZIG_ARCHIVE_SHA256, "0" * 64),
                (scanner.ZIG_ARCHIVE_URL, "https://unreviewed.invalid/zig.tar.xz"),
                (scanner.CARGO_ZIGBUILD_COMMIT, "0" * 40),
                (scanner.CARGO_ZIGBUILD_REPOSITORY, "https://github.com/unreviewed/cargo-zigbuild"),
                (f"--rev {scanner.CARGO_ZIGBUILD_COMMIT} --locked", f"--rev {scanner.CARGO_ZIGBUILD_COMMIT}"),
            ):
                with self.subTest(path=path, old=old):
                    broken = text.replace(old, new, 1)
                    self.assertNotEqual(text, broken)
                    with self.assertRaises(SystemExit) as error:
                        self.verify_text(broken)
                    self.assertIn("reviewed digest/revision custody", str(error.exception))

    def test_cross_tool_continuation_spacing_preserves_exact_arguments(self) -> None:
        for path in (self.release, self.ci):
            text = path.read_text(encoding="utf-8")
            curl = f'curl -fsSL -o "$zig_archive" \\\n            "{scanner.ZIG_ARCHIVE_URL}"'
            cargo = (
                f'cargo install --git {scanner.CARGO_ZIGBUILD_REPOSITORY} \\\n'
                f'            --rev {scanner.CARGO_ZIGBUILD_COMMIT} --locked \\\n'
                '            --root "$cross_root/cargo-zigbuild" cargo-zigbuild'
            )
            for old, new in (
                (curl, curl.replace("\\\n            ", "  ")),
                (cargo, cargo.replace("\\\n            ", "\\\n                ")),
            ):
                with self.subTest(path=path, command=old):
                    spaced = text.replace(old, new, 1)
                    self.assertNotEqual(text, spaced)
                    self.verify_text(spaced)

    def test_cross_tool_preserves_quoted_custody_bytes(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        for old, new in (
            ('curl -fsSL -o "$zig_archive"', 'curl -fsSL -o "$zig_ archive"'),
            (f'"{scanner.ZIG_ARCHIVE_URL}"', f'"{scanner.ZIG_ARCHIVE_URL}" --insecure'),
            ("printf '%s  %s\\n'", "printf '%s %s\\n'"),
        ):
            with self.subTest(new=new):
                broken = text.replace(old, new, 1)
                self.assertNotEqual(text, broken)
                with self.assertRaises(SystemExit) as error:
                    self.verify_text(broken)
                self.assertIn("reviewed digest/revision custody", str(error.exception))

    def test_cross_tool_path_requires_both_reviewed_directories(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        old = (
            'printf \'%s\\n\' "$cross_root/zig-linux-x86_64-0.13.0" '
            '"$cross_root/cargo-zigbuild/bin" >> "$GITHUB_PATH"'
        )
        for new in (
            'printf \'%s\\n\' "$cross_root/cargo-zigbuild/bin" >> "$GITHUB_PATH"',
            'printf \'%s\\n\' "$cross_root/zig-linux-x86_64-0.13.0" >> "$GITHUB_PATH"',
        ):
            with self.subTest(new=new):
                broken = text.replace(old, new, 1)
                self.assertNotEqual(text, broken)
                with self.assertRaises(SystemExit) as error:
                    self.verify_text(broken)
                self.assertIn("reviewed digest/revision custody", str(error.exception))

    def test_zig_digest_must_precede_extraction(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        digest = next(line for line in text.splitlines() if scanner.ZIG_ARCHIVE_SHA256 in line)
        extract = '          tar -xJf "$zig_archive" -C "$cross_root"'
        broken = text.replace(digest + "\n" + extract, extract + "\n" + digest, 1)
        self.assertNotEqual(text, broken)
        with self.assertRaises(SystemExit) as error:
            self.verify_text(broken)
        self.assertIn("digest-checked before extraction", str(error.exception))

    def test_unreviewed_download_and_package_install_are_refused(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        for command in (
            "curl -fsSL https://unreviewed.invalid/tool | sh",
            "sudo wget https://unreviewed.invalid/tool",
            "python3 -m pip install ziglang",
            "cargo install cargo-zigbuild --locked",
        ):
            with self.subTest(command=command):
                broken = text + f"\n      - name: Unreviewed tool\n        run: {command}\n"
                with self.assertRaises(SystemExit) as error:
                    self.verify_text(broken)
                self.assertIn("unreviewed online tool installer", str(error.exception))

    def test_release_daemon_build_must_use_source_lockfile(self) -> None:
        text = self.release.read_text(encoding="utf-8")
        broken = text.replace("cargo build --release --locked", "cargo build --release", 1)
        self.assertNotEqual(text, broken)
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "release.yml"
            path.write_text(broken, encoding="utf-8")
            with self.assertRaises(SystemExit) as error:
                scanner.verify_workflow(path)
        self.assertIn("lacks --locked", str(error.exception))


class RemoteAssetControls(unittest.TestCase):
    def test_post_upload_asset_set_requires_exact_payload_signature_bijection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "signing"
            root.mkdir()
            (root / "myownmesh.tar.gz").write_bytes(b"daemon")
            (root / "myownmesh.tar.gz.sha256").write_bytes(b"checksum")
            (root / "myownmesh.tar.gz.minisig").write_bytes(b"signature")
            assets = [
                {"name": "myownmesh.tar.gz", "state": "uploaded"},
                {"name": "myownmesh.tar.gz.sha256", "state": "uploaded"},
                {"name": "myownmesh.tar.gz.minisig", "state": "uploaded"},
            ]
            with mock.patch.object(scanner, "verify_signature_tree"):
                with mock.patch.object(
                    scanner,
                    "_gh_json",
                    return_value={"draft": True, "assets": assets},
                ):
                    scanner.verify_remote_release_assets(root, "owner/repo", "v1", "public")

                with mock.patch.object(
                    scanner,
                    "_gh_json",
                    return_value={"draft": True, "assets": assets[:2]},
                ):
                    with self.assertRaises(SystemExit) as error:
                        scanner.verify_remote_release_assets(
                            root, "owner/repo", "v1", "public"
                        )
                self.assertIn("asset/signature set mismatch", str(error.exception))

    def test_post_upload_asset_check_requires_draft_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "signing"
            root.mkdir()
            with mock.patch.object(scanner, "verify_signature_tree"):
                with mock.patch.object(
                    scanner,
                    "_gh_json",
                    return_value={"draft": False, "assets": []},
                ):
                    with self.assertRaises(SystemExit) as error:
                        scanner.verify_remote_release_assets(
                            root, "owner/repo", "v1", "public"
                        )
            self.assertIn("no longer a draft", str(error.exception))

    def test_post_upload_asset_check_uses_build_digest_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "signing"
            root.mkdir()
            payload = root / "release.tar.gz"
            payload.write_bytes(b"daemon")
            checksum = root / "release.tar.gz.sha256"
            checksum.write_text(
                hashlib.sha256(payload.read_bytes()).hexdigest() + "  release.tar.gz\n",
                encoding="utf-8",
            )
            signature = root / "release.tar.gz.minisig"
            signature.write_bytes(b"signature")
            allowlist = pathlib.Path(directory) / "allowlists"
            allowlist.mkdir()
            (allowlist / "build.json").write_text(
                json.dumps(
                    {
                        "assets": {
                            "release.tar.gz": hashlib.sha256(payload.read_bytes()).hexdigest(),
                            "release.tar.gz.sha256": hashlib.sha256(checksum.read_bytes()).hexdigest(),
                        }
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(scanner, "verify_signature_tree"):
                with mock.patch.object(
                    scanner,
                    "_gh_json",
                    return_value={
                        "draft": True,
                        "assets": [
                            {"name": "release.tar.gz", "state": "uploaded"},
                            {"name": "release.tar.gz.sha256", "state": "uploaded"},
                            {"name": "release.tar.gz.minisig", "state": "uploaded"},
                        ],
                    },
                ):
                    scanner.verify_remote_release_assets(
                        root, "owner/repo", "v1", "public", allowlist
                    )
            payload.write_bytes(b"stale")
            with self.assertRaises(SystemExit) as error:
                scanner.verify_asset_allowlist(root, allowlist)
            self.assertIn("digest mismatch", str(error.exception))

    def test_post_upload_check_rejects_remote_bytes_that_differ_from_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "signing"
            remote = pathlib.Path(directory) / "remote"
            allowlist = pathlib.Path(directory) / "allowlists"
            root.mkdir()
            remote.mkdir()
            allowlist.mkdir()
            payload = root / "release.tar.gz"
            payload.write_bytes(b"build-owned")
            checksum = root / "release.tar.gz.sha256"
            checksum.write_text(
                hashlib.sha256(payload.read_bytes()).hexdigest() + "  release.tar.gz\n",
                encoding="utf-8",
            )
            signature = root / "release.tar.gz.minisig"
            signature.write_bytes(b"signature")
            (allowlist / "build.json").write_text(
                json.dumps(
                    {
                        "assets": {
                            "release.tar.gz": hashlib.sha256(payload.read_bytes()).hexdigest(),
                            "release.tar.gz.sha256": hashlib.sha256(checksum.read_bytes()).hexdigest(),
                        }
                    }
                ),
                encoding="utf-8",
            )
            (remote / "release.tar.gz").write_bytes(b"tampered-remote")
            (remote / "release.tar.gz.sha256").write_bytes(checksum.read_bytes())
            (remote / "release.tar.gz.minisig").write_bytes(signature.read_bytes())
            assets = [
                {"name": "release.tar.gz", "state": "uploaded"},
                {"name": "release.tar.gz.sha256", "state": "uploaded"},
                {"name": "release.tar.gz.minisig", "state": "uploaded"},
            ]
            with mock.patch.object(scanner, "verify_signature_tree"):
                with mock.patch.object(
                    scanner,
                    "_gh_json",
                    return_value={"draft": True, "assets": assets},
                ):
                    with self.assertRaises(SystemExit) as error:
                        scanner.verify_remote_release_assets(
                            root,
                            "owner/repo",
                            "v1",
                            "public",
                            allowlist,
                            remote,
                        )
            self.assertIn("digest mismatch", str(error.exception))


class ReleasePreflightControls(unittest.TestCase):
    class Completed:
        def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
            self.stdout = stdout
            self.returncode = returncode
            self.stderr = stderr

    def test_release_tag_accepts_canonical_semver(self) -> None:
        for tag in (
            "v0.0.0", "v1.2.3", "v10.20.30", "v1.2.3-rc.1",
            "v1.2.3-0", "v1.2.3-01a", "v1.2.3+build.001",
            "v1.2.3-rc.1+build.001",
        ):
            with self.subTest(tag=tag):
                scanner.validate_release_tag(tag)

    def test_hostile_or_noncanonical_tag_refused_before_any_command(self) -> None:
        # Shell-looking examples are inert data: never pass these to a shell.
        for tag in (
            "v1.2.3$(true)", "v1.2.3`true`", 'v1.2.3";true;#',
            "v1.2.3;true", "v1.2.3${TAG}", "v1.2.3/other",
            "refs/tags/v1.2.3", "--help", "1.2.3", "v1.2", "",
            "v01.2.3", "v1.02.3", "v1.2.03", "v1.2.3-01",
            "v1.2.3-rc..1", "v1.2.3-", "v1.2.3+", "v1.2.3+build..1",
            "v1.2.3\n", " v1.2.3", "v1.2.3 ", "v１.2.3",
        ):
            with self.subTest(tag=tag), mock.patch.object(scanner.subprocess, "run") as run:
                with self.assertRaises(SystemExit) as error:
                    scanner.preflight_release(tag, "abc", "owner/repo")
                self.assertIn("release tag must be", str(error.exception))
                run.assert_not_called()

    def test_missing_tag_refused_before_release_lookup_or_creation(self) -> None:
        with mock.patch.object(scanner, "_gh_json", return_value=None) as query:
            with mock.patch.object(scanner, "_gh_release_create") as create:
                with self.assertRaises(SystemExit) as error:
                    scanner.preflight_release("v1.2.3", "abc", "owner/repo")
        self.assertIn("must already exist", str(error.exception))
        query.assert_called_once_with("owner/repo", "git/ref/tags/v1.2.3")
        create.assert_not_called()

    def test_different_tag_commit_refused_before_release_lookup_or_creation(self) -> None:
        for tag_ref, annotated in (
            ({"object": {"type": "commit", "sha": "other"}}, None),
            ({"object": {"type": "tag", "sha": "tag-object"}}, {"object": {"type": "commit", "sha": "other"}}),
        ):
            replies = [tag_ref] if annotated is None else [tag_ref, annotated]
            with self.subTest(tag_ref=tag_ref), mock.patch.object(scanner, "_gh_json", side_effect=replies) as query:
                with mock.patch.object(scanner, "_gh_release_create") as create:
                    with self.assertRaises(SystemExit) as error:
                        scanner.preflight_release("v1.2.3", "abc", "owner/repo")
                self.assertIn("not the requested commit", str(error.exception))
                self.assertEqual(query.call_count, len(replies))
                create.assert_not_called()

    def test_public_requested_tag_is_refused(self) -> None:
        def run(args: list[str], **_: object) -> ReleasePreflightControls.Completed:
            endpoint = args[2]
            if "/git/ref/tags/" in endpoint:
                return self.Completed('{"object":{"type":"commit","sha":"abc"}}')
            return self.Completed('{"draft":false,"target_commitish":"abc"}')

        with mock.patch.object(scanner.subprocess, "run", side_effect=run):
            with self.assertRaises(SystemExit) as error:
                scanner.preflight_release("v1.2.3", "abc", "owner/repo")
        self.assertIn("already public", str(error.exception))

    def test_annotated_tag_must_resolve_to_requested_commit(self) -> None:
        def run(args: list[str], **_: object) -> ReleasePreflightControls.Completed:
            endpoint = args[2]
            if "/git/ref/tags/" in endpoint:
                return self.Completed('{"object":{"type":"tag","sha":"tag-object"}}')
            if "/git/tags/tag-object" in endpoint:
                return self.Completed('{"object":{"type":"commit","sha":"abc"}}')
            return self.Completed('{"draft":true,"target_commitish":"abc"}')

        with mock.patch.object(scanner.subprocess, "run", side_effect=run):
            scanner.preflight_release("v1.2.3", "abc", "owner/repo")

    def test_missing_release_creates_exact_draft_and_rechecks_it(self) -> None:
        calls: list[list[str]] = []
        created = False

        def run(args: list[str], **_: object) -> ReleasePreflightControls.Completed:
            nonlocal created
            calls.append(args)
            if args[1:2] == ["api"] and "/git/ref/tags/" in args[2]:
                return self.Completed('{"object":{"type":"commit","sha":"abc"}}')
            if args[1:2] == ["api"]:
                if created:
                    return self.Completed('{"draft":true,"target_commitish":"abc"}')
                return self.Completed(returncode=1, stderr="HTTP 404: Not Found")
            if args[1:3] == ["release", "create"]:
                created = True
                return self.Completed()
            raise AssertionError(f"unexpected gh command: {args}")

        with mock.patch.object(scanner.subprocess, "run", side_effect=run):
            scanner.preflight_release("v1.2.3", "abc", "owner/repo")
        create = next(call for call in calls if call[1:3] == ["release", "create"])
        self.assertIn("--draft", create)
        self.assertIn("--verify-tag", create)
        self.assertIn("--target", create)
        self.assertIn("abc", create)

if __name__ == "__main__":
    unittest.main()
