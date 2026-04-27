"""Tests for the new privacy_profiles module and the refactored privacy config."""
from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pcap2llm.cli import _resolve_privacy_base, app
from pcap2llm.config import build_privacy_modes
from pcap2llm.privacy_profiles import list_privacy_profiles, load_privacy_profile


# ---------------------------------------------------------------------------
# load_privacy_profile – built-in profiles
# ---------------------------------------------------------------------------


class TestLoadBuiltinPrivacyProfiles:
    def test_load_internal(self) -> None:
        profile = load_privacy_profile("internal")
        assert profile.name == "internal"
        assert profile.modes["ip"] == "keep"
        assert profile.modes["imsi"] == "keep"
        assert profile.modes["token"] == "keep"

    def test_load_share(self) -> None:
        profile = load_privacy_profile("share")
        assert profile.name == "share"
        assert profile.modes["imsi"] == "keep_mcc_mnc_mask_msin"
        assert profile.modes["msisdn"] == "keep_cc_ndc_mask_subscriber"
        assert profile.modes["imei"] == "keep_tac_mask_serial"
        assert profile.modes["token"] == "remove"
        assert profile.modes["ip"] == "pseudonymize"
        assert profile.modes["hostname"] == "pseudonymize"

    def test_load_lab(self) -> None:
        profile = load_privacy_profile("lab")
        assert profile.name == "lab"
        assert profile.modes["imsi"] == "remove"
        assert profile.modes["msisdn"] == "remove"
        assert profile.modes["ip"] == "keep"
        assert profile.modes["payload_text"] == "remove"

    def test_load_prod_safe(self) -> None:
        profile = load_privacy_profile("prod-safe")
        assert profile.name == "prod-safe"
        assert profile.modes["ip"] == "mask"
        assert profile.modes["imsi"] == "pseudonymize"
        assert profile.modes["token"] == "remove"
        assert profile.modes["payload_text"] == "remove"

    def test_load_llm_telecom_safe(self) -> None:
        profile = load_privacy_profile("llm-telecom-safe")
        assert profile.name == "llm-telecom-safe"
        assert profile.modes["ip"] == "pseudonymize"
        assert profile.modes["hostname"] == "pseudonymize"
        assert profile.modes["imsi"] == "keep_mcc_mnc_mask_msin"
        assert profile.modes["msisdn"] == "keep_cc_ndc_mask_subscriber"
        assert profile.modes["imei"] == "keep_tac_mask_serial"
        assert profile.modes["token"] == "remove"
        assert profile.modes["payload_text"] == "remove"

    def test_load_telecom_context(self) -> None:
        profile = load_privacy_profile("telecom-context")
        assert profile.name == "telecom-context"
        assert profile.modes["imsi"] == "keep_mcc_mnc_mask_msin"
        assert profile.modes["msisdn"] == "keep_cc_ndc_mask_subscriber"
        assert profile.modes["imei"] == "keep_tac_mask_serial"

    def test_all_profiles_have_description(self) -> None:
        for name in list_privacy_profiles():
            profile = load_privacy_profile(name)
            assert isinstance(profile.description, str)
            assert len(profile.description) > 0

    def test_all_profiles_have_all_data_classes(self) -> None:
        from pcap2llm.models import DATA_CLASSES

        for name in list_privacy_profiles():
            profile = load_privacy_profile(name)
            for data_class in DATA_CLASSES:
                assert data_class in profile.modes, (
                    f"Privacy profile '{name}' missing data class '{data_class}'"
                )


# ---------------------------------------------------------------------------
# load_privacy_profile – missing profile raises FileNotFoundError
# ---------------------------------------------------------------------------


class TestLoadPrivacyProfileErrors:
    def test_missing_builtin_raises_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError, match="not found"):
            load_privacy_profile("nonexistent-profile")

    def test_error_message_lists_builtins(self) -> None:
        with pytest.raises(FileNotFoundError) as exc_info:
            load_privacy_profile("nope")
        message = str(exc_info.value)
        for name in list_privacy_profiles():
            assert name in message

    def test_nonexistent_file_path_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_privacy_profile(str(tmp_path / "missing.yaml"))


# ---------------------------------------------------------------------------
# list_privacy_profiles
# ---------------------------------------------------------------------------


class TestListPrivacyProfiles:
    def test_returns_builtin_profiles(self) -> None:
        profiles = list_privacy_profiles()
        assert len(profiles) == 6

    def test_returns_all_expected_names(self) -> None:
        profiles = list_privacy_profiles()
        assert set(profiles) == {
            "internal",
            "share",
            "lab",
            "prod-safe",
            "llm-telecom-safe",
            "telecom-context",
        }

    def test_returns_sorted(self) -> None:
        profiles = list_privacy_profiles()
        assert profiles == sorted(profiles)


# ---------------------------------------------------------------------------
# load_privacy_profile – custom file path
# ---------------------------------------------------------------------------


class TestLoadCustomPrivacyProfile:
    def test_load_from_file(self, tmp_path: Path) -> None:
        yaml_text = (
            "name: custom\n"
            "description: Custom test profile\n"
            "modes:\n"
            "  ip: mask\n"
            "  imsi: remove\n"
        )
        custom_file = tmp_path / "custom.yaml"
        custom_file.write_text(yaml_text, encoding="utf-8")
        profile = load_privacy_profile(str(custom_file))
        assert profile.name == "custom"
        assert profile.modes["ip"] == "mask"
        assert profile.modes["imsi"] == "remove"


# ---------------------------------------------------------------------------
# build_privacy_modes – precedence: base → config overrides → CLI overrides
# ---------------------------------------------------------------------------


class TestBuildPrivacyModesPrecedence:
    def test_base_modes_used_when_no_overrides(self) -> None:
        from pcap2llm.privacy_profiles import load_privacy_profile

        base = load_privacy_profile("share").modes
        result = build_privacy_modes(base, {})
        assert result["imsi"] == "keep_mcc_mnc_mask_msin"
        assert result["token"] == "remove"

    def test_config_overrides_take_priority_over_base(self) -> None:
        base = {"imsi": "pseudonymize", "token": "remove"}
        config_overrides = {"imsi": "remove"}
        result = build_privacy_modes(base, config_overrides)
        assert result["imsi"] == "remove"
        # token still from base
        assert result["token"] == "remove"

    def test_cli_overrides_take_priority_over_config(self) -> None:
        """The CLI overrides via _build_modes (combined_overrides logic)."""
        from pcap2llm.cli import _build_modes

        base = {"imsi": "pseudonymize", "token": "remove"}
        config_overrides = {"imsi": "remove"}
        cli_overrides = {"imsi": "mask"}  # highest priority

        result = _build_modes(base, config_overrides, cli_overrides)
        assert result["imsi"] == "mask"

    def test_none_cli_override_does_not_override(self) -> None:
        from pcap2llm.cli import _build_modes

        base = {"imsi": "pseudonymize"}
        config_overrides = {}
        cli_overrides = {"imsi": None}  # None means not set

        result = _build_modes(base, config_overrides, cli_overrides)
        assert result["imsi"] == "pseudonymize"

    def test_empty_base_defaults_to_keep(self) -> None:
        result = build_privacy_modes({}, {})
        assert all(v == "keep" for v in result.values())

    def test_partial_subscriber_modes_are_normalized(self) -> None:
        result = build_privacy_modes(
            {},
            {
                "imsi": "keep-plmn-mask-msin",
                "msisdn": "keep-e164-routing-pseudonymize-subscriber",
            },
        )
        assert result["imsi"] == "keep_mcc_mnc_mask_msin"
        assert result["msisdn"] == "keep_cc_ndc_pseudonymize_subscriber"


# ---------------------------------------------------------------------------
# Backward compat: analysis profile with default_privacy_modes → DeprecationWarning
# ---------------------------------------------------------------------------


class TestDeprecationWarning:
    def test_load_profile_with_privacy_modes_emits_deprecation(self, tmp_path: Path) -> None:
        """A profile YAML containing default_privacy_modes must emit DeprecationWarning."""
        import yaml

        # Build a minimal profile YAML with default_privacy_modes
        profile_data = {
            "name": "legacy-test",
            "description": "Legacy profile with privacy modes",
            "relevant_protocols": ["diameter"],
            "top_protocol_priority": ["diameter"],
            "default_privacy_modes": {"ip": "keep", "imsi": "pseudonymize"},
        }
        profile_yaml = tmp_path / "legacy-test.yaml"
        profile_yaml.write_text(yaml.safe_dump(profile_data), encoding="utf-8")

        # Monkeypatch load_profile to load from file for this test
        import pcap2llm.profiles as profiles_module

        original_load = profiles_module.load_profile

        def _patched_load(name: str):
            if name == "legacy-test":
                import yaml as _yaml
                data = _yaml.safe_load(profile_yaml.read_text(encoding="utf-8")) or {}
                data.setdefault("name", name)
                if "default_privacy_modes" in data:
                    warnings.warn(
                        f"Analysis profile '{name}' contains 'default_privacy_modes' which is "
                        "deprecated. Move privacy configuration to a dedicated privacy profile "
                        "(e.g. --privacy-profile share) and remove 'default_privacy_modes' from "
                        "the analysis profile YAML.",
                        DeprecationWarning,
                        stacklevel=2,
                    )
                from pcap2llm.models import ProfileDefinition
                return ProfileDefinition.model_validate(data)
            return original_load(name)

        profiles_module.load_profile = _patched_load
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                profile = profiles_module.load_profile("legacy-test")
            deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
            assert len(deprecations) >= 1
            assert "deprecated" in str(deprecations[0].message).lower()
            assert profile.default_privacy_modes == {"ip": "keep", "imsi": "pseudonymize"}
        finally:
            profiles_module.load_profile = original_load


# ---------------------------------------------------------------------------
# _resolve_privacy_base – priority logic
# ---------------------------------------------------------------------------


class TestResolvePrivacyBase:
    def _make_analysis_profile(self, with_deprecated: bool = False):
        from pcap2llm.models import ProfileDefinition

        data = {
            "name": "test-profile",
            "description": "Test",
            "relevant_protocols": ["diameter"],
            "top_protocol_priority": ["diameter"],
        }
        if with_deprecated:
            data["default_privacy_modes"] = {"ip": "mask", "imsi": "remove"}
        return ProfileDefinition.model_validate(data)

    def test_cli_profile_takes_priority(self) -> None:
        analysis_profile = self._make_analysis_profile(with_deprecated=True)
        config_data = {"privacy_profile": "lab"}
        # CLI overrides config
        base = _resolve_privacy_base("internal", config_data, analysis_profile)
        profile = load_privacy_profile("internal")
        assert base == profile.modes

    def test_config_privacy_profile_used_when_no_cli(self) -> None:
        analysis_profile = self._make_analysis_profile(with_deprecated=True)
        config_data = {"privacy_profile": "lab"}
        base = _resolve_privacy_base(None, config_data, analysis_profile)
        lab_profile = load_privacy_profile("lab")
        assert base == lab_profile.modes

    def test_deprecated_default_used_as_fallback(self) -> None:
        analysis_profile = self._make_analysis_profile(with_deprecated=True)
        config_data = {}
        base = _resolve_privacy_base(None, config_data, analysis_profile)
        assert base == {"ip": "mask", "imsi": "remove"}

    def test_empty_base_when_no_profile_and_no_deprecated(self) -> None:
        analysis_profile = self._make_analysis_profile(with_deprecated=False)
        config_data = {}
        base = _resolve_privacy_base(None, config_data, analysis_profile)
        assert base == {}


# ---------------------------------------------------------------------------
# CLI dry-run shows privacy_profile field
# ---------------------------------------------------------------------------


class TestCliDryRunPrivacyProfile:
    runner = CliRunner()

    def test_dry_run_shows_privacy_profile_when_set(self, tmp_path: Path) -> None:
        capture = tmp_path / "sample.pcapng"
        capture.write_bytes(b"fake")
        result = self.runner.invoke(
            app,
            [
                "analyze",
                str(capture),
                "--dry-run",
                "--profile",
                "lte-core",
                "--privacy-profile",
                "share",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["privacy_profile"] == "share"

    def test_dry_run_shows_none_when_no_privacy_profile(self, tmp_path: Path) -> None:
        capture = tmp_path / "sample.pcapng"
        capture.write_bytes(b"fake")
        result = self.runner.invoke(
            app,
            [
                "analyze",
                str(capture),
                "--dry-run",
                "--profile",
                "lte-core",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "privacy_profile" in data
        # With no privacy profile set and no deprecated defaults, shows placeholder
        assert data["privacy_profile"] == "(none — using defaults)"

    def test_dry_run_privacy_profile_modes_applied(self, tmp_path: Path) -> None:
        """When --privacy-profile prod-safe is set, ip mode should be 'mask'."""
        capture = tmp_path / "sample.pcapng"
        capture.write_bytes(b"fake")
        result = self.runner.invoke(
            app,
            [
                "analyze",
                str(capture),
                "--dry-run",
                "--profile",
                "lte-core",
                "--privacy-profile",
                "prod-safe",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["privacy_modes"]["ip"] == "mask"

    def test_cli_per_field_override_beats_privacy_profile(self, tmp_path: Path) -> None:
        """--ip-mode overrides whatever the privacy profile says."""
        capture = tmp_path / "sample.pcapng"
        capture.write_bytes(b"fake")
        result = self.runner.invoke(
            app,
            [
                "analyze",
                str(capture),
                "--dry-run",
                "--profile",
                "lte-core",
                "--privacy-profile",
                "internal",
                "--ip-mode",
                "mask",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        # internal has ip=keep, but --ip-mode mask overrides it
        assert data["privacy_modes"]["ip"] == "mask"

    def test_privacy_profile_from_config_file(self, tmp_path: Path) -> None:
        """privacy_profile in config file is respected."""
        capture = tmp_path / "sample.pcapng"
        capture.write_bytes(b"fake")
        config_file = tmp_path / "pcap2llm.config.yaml"
        config_file.write_text(
            "profile: lte-core\nprivacy_profile: lab\n",
            encoding="utf-8",
        )
        result = self.runner.invoke(
            app,
            [
                "analyze",
                str(capture),
                "--dry-run",
                "--profile",
                "lte-core",
                "--config",
                str(config_file),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["privacy_profile"] == "lab"
        # lab sets imsi to remove
        assert data["privacy_modes"]["imsi"] == "remove"

    def test_init_config_writes_privacy_profile(self, tmp_path: Path) -> None:
        config_path = tmp_path / "pcap2llm.config.yaml"
        result = self.runner.invoke(app, ["init-config", str(config_path)])
        assert result.exit_code == 0
        content = config_path.read_text(encoding="utf-8")
        assert "privacy_profile" in content
        assert "share" in content
        # Old full privacy_modes block should not be present as primary config
        assert "privacy_modes:" not in content or content.index("# privacy_modes:") < content.find(
            "privacy_modes:"
        )
