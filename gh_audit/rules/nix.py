from github.Repository import Repository

from gh_audit.core import FAIL, OK, RESULT, SKIP, define_rule
from gh_audit.github_api import _get_contents
from gh_audit.rules.general import _required_status_check


@define_rule(
    name="required-lockfile-drv-changed-status-check",
    log_message="Add Ruleset to require 'lockfile-drv-changed' status check",
    level="error",
)
def _required_lockfile_drv_changed_status_check(repo: Repository) -> RESULT:
    return _required_status_check(repo, "lockfile-drv-changed")


@define_rule(
    name="renovate-nix",
    log_message="Configure Renovate for Nix updates",
    level="error",
)
def _renovate_nix(repo: Repository) -> RESULT:
    if not _get_contents(repo, path="flake.nix"):
        return SKIP

    if not _get_contents(repo, path=".github/renovate.json"):
        return FAIL

    return OK
