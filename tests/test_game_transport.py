"""Reject unsafe or ambiguous configurations before changing a live ingress."""

import runpy
from pathlib import Path

import pytest

render = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/game_transport.py"))["render"]


def test_ambiguous_games_are_not_silently_routed_to_first_entry():
    cfg = {"public_ipv4": "1.1.1.1"}
    versions = {"royale": [{"protocol": 3, "major": 16}], "brawl": [{"protocol": 3, "major": 16}]}
    with pytest.raises(ValueError, match="Ambiguous"):
        render(cfg, versions)


@pytest.mark.parametrize(
    "versions",
    [
        {"arbitrary-host.example": [{"protocol": 3, "major": 16}]},
        {"royale": [{"protocol": True, "major": 16}]},
        {"royale": [{"protocol": 3, "major": -1}]},
        {"royale": [{"protocol": 3, "major": 16, "destination": "127.0.0.1"}]},
        {},
    ],
)
def test_untrusted_version_config_cannot_expand_destinations(versions):
    with pytest.raises(ValueError):
        render({"public_ipv4": "1.1.1.1"}, versions)
