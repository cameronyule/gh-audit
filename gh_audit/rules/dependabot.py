from github.Repository import Repository

from gh_audit.core import FAIL, OK, RESULT, SKIP, define_rule
from gh_audit.github_api import (
    _dependabot_config,
    _get_contents,
    _has_requirements_txt,
    _requirements_txt_has_ruff,
    _requirements_txt_has_types,
)


def _dependabot_update_schedule_intervals(repo: Repository) -> set[str]:
    return {
        update.get("schedule", {}).get("interval")
        for update in _dependabot_config(repo).get("updates", [])
    }


@define_rule(
    name="allow-auto-merge",
    log_message="Repository should allow auto-merge",
    level="warning",
)
def _auto_merge(repo: Repository) -> RESULT:
    if repo.fork:
        return SKIP
    if not _dependabot_config(repo):
        return SKIP
    if repo.allow_auto_merge:
        return OK
    return FAIL


@define_rule(
    name="dependabot-auto-merge",
    log_message="Set up Dependabot auto-merge",
    level="warning",
)
def _dependabot_auto_merge(repo: Repository) -> RESULT:
    if repo.fork:
        return SKIP
    if not _dependabot_config(repo):
        return SKIP
    if not _get_contents(repo, path=".github/workflows/merge.yml"):
        return FAIL
    return OK


@define_rule(
    name="dependabot-schedule-weekly",
    log_message="Dependabot should be scheduled weekly",
    level="warning",
)
def _dependabot_schedule_weekly(repo: Repository) -> RESULT:
    if not _dependabot_config(repo):
        return SKIP
    if _dependabot_update_schedule_intervals(repo) != {"weekly"}:
        return FAIL
    return OK


@define_rule(
    name="pip-dependabot",
    log_message="Dependabot should be enabled for pip ecosystem",
    level="error",
)
def _pip_dependabot(repo: Repository) -> RESULT:
    if not _has_requirements_txt(repo):
        return SKIP
    for update in _dependabot_config(repo).get("updates", []):
        if update.get("package-ecosystem") == "pip":
            return OK
    return FAIL


@define_rule(
    name="pip-dependabot-ignore-types",
    log_message="Dependabot should ignore types-* packages",
    level="warning",
)
def _dependabot_ignores_pip_types(repo: Repository) -> RESULT:
    if not _has_requirements_txt(repo):
        return SKIP

    if not _requirements_txt_has_types(repo):
        return SKIP

    for update in _dependabot_config(repo).get("updates", []):
        if update.get("package-ecosystem") == "pip":
            for ignored in update.get("ignore", []):
                if ignored.get("dependency-name") == "types-*":
                    return OK

    return FAIL


@define_rule(
    name="pip-dependabot-ignore-ruff-patches",
    log_message="Dependabot should ignore ruff patches",
    level="warning",
)
def _dependabot_ignores_ruff_patches(repo: Repository) -> RESULT:
    if not _has_requirements_txt(repo):
        return SKIP

    if not _requirements_txt_has_ruff(repo):
        return SKIP

    for update in _dependabot_config(repo).get("updates", []):
        if update.get("package-ecosystem") == "pip":
            for ignored in update.get("ignore", []):
                if ignored.get("dependency-name") == "ruff":
                    return OK

    return FAIL
