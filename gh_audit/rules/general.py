from github import GithubException
from github.Repository import Repository

from gh_audit.core import FAIL, OK, RESULT, SKIP, define_rule
from gh_audit.github_api import (
    _get_contents,
    _get_readme,
    _get_repo_rulesets,
    _iter_workflow_jobs,
    _repository_has_changes_since_released,
    _repository_has_recent_changes,
    _repository_is_new,
)


@define_rule(
    name="missing-description",
    log_message="Missing repository description",
    level="error",
)
def _missing_description(repo: Repository) -> RESULT:
    if repo.description:
        return OK
    return FAIL


@define_rule(
    name="missing-license",
    log_message="Missing license file",
    level="error",
)
def _missing_license(repo: Repository) -> RESULT:
    if repo.visibility == "private":
        return SKIP

    try:
        if repo.get_license():
            return OK
    except GithubException:
        pass
    return FAIL


@define_rule(
    name="non-mit-license",
    log_message="Using non-MIT license",
    level="warning",
)
def _non_mit_license(repo: Repository) -> RESULT:
    if repo.visibility == "private":
        return SKIP
    if repo.license and repo.license.name != "MIT License":
        return FAIL
    return OK


@define_rule(
    name="missing-readme",
    log_message="Missing README file",
    level="error",
)
def _missing_readme(repo: Repository) -> RESULT:
    if _get_readme(repo):
        return OK
    return FAIL


@define_rule(
    name="missing-agents",
    log_message="Missing AGENTS.md file",
    level="warning",
)
def _missing_agents(repo: Repository) -> RESULT:
    if _get_contents(repo, path="AGENTS.md"):
        return OK
    return FAIL


@define_rule(
    name="missing-topics",
    log_message="Missing topics",
    level="error",
)
def _missing_topics(repo: Repository) -> RESULT:
    if len(repo.topics) == 0:
        return FAIL
    return OK


@define_rule(
    name="too-few-topics",
    log_message="Only one topic",
    level="warning",
)
def _too_few_topics(repo: Repository) -> RESULT:
    if len(repo.topics) == 1:
        return FAIL
    return OK


@define_rule(
    name="has-issues",
    log_message="Repository doesn't have Issues enabled",
    level="warning",
)
def _has_issues(repo: Repository) -> RESULT:
    if repo.has_issues:
        return OK
    return FAIL


@define_rule(
    name="no-projects",
    log_message="Repository has Projects enabled",
    level="warning",
)
def _no_projects(repo: Repository) -> RESULT:
    if repo.has_projects:
        return FAIL
    return OK


@define_rule(
    name="no-wiki",
    log_message="Repository has Wiki enabled",
    level="error",
)
def _no_wiki(repo: Repository) -> RESULT:
    if repo.has_wiki:
        return FAIL
    return OK


@define_rule(
    name="no-discussions",
    log_message="Repository has Discussions enabled",
    level="error",
)
def _no_discussions(repo: Repository) -> RESULT:
    if repo.has_discussions:
        return FAIL
    return OK


# Check if repo is larger than 1GB
@define_rule(
    name="git-size",
    log_message="Repository size is too large",
    level="error",
)
def _git_size_error(repo: Repository) -> RESULT:
    if repo.size > (1024 * 1024):
        return FAIL
    return OK


# Check if repo is larger than 50MB
@define_rule(
    name="git-size",
    log_message="Repository size is too large",
    level="warning",
)
def _git_size_warning(repo: Repository) -> RESULT:
    if repo.size > (50 * 1024):
        return FAIL
    return OK


@define_rule(
    name="delete-branch-on-merge",
    log_message="Repository should delete branches on merge",
    level="error",
)
def _delete_branch_on_merge(repo: Repository) -> RESULT:
    if repo.delete_branch_on_merge:
        return OK
    return FAIL


@define_rule(
    name="enable-merge-commit",
    log_message="Repository should allow merge commits",
    level="warning",
)
def _enable_merge_commit(repo: Repository) -> RESULT:
    if repo.allow_merge_commit:
        return OK
    return FAIL


@define_rule(
    name="tag-stable-projects",
    log_message="Tag latest repository release",
    level="warning",
)
def _tag_stable_projects(repo: Repository) -> RESULT:
    if repo.private:
        return SKIP

    if _repository_is_new(repo):
        return SKIP

    if _repository_has_recent_changes(repo):
        return SKIP

    if _repository_has_changes_since_released(repo):
        return FAIL

    return OK


def _any_job_defined(repo: Repository, job_name: str) -> bool:
    for name, _ in _iter_workflow_jobs(repo):
        if name == job_name:
            return True
    return False


def _required_status_check(repo: Repository, job_name: str) -> RESULT:
    if not _any_job_defined(repo, job_name):
        return SKIP

    for ruleset in _get_repo_rulesets(repo):
        if ruleset["type"] == "required_status_checks":
            for check in ruleset["parameters"]["required_status_checks"]:
                if check["context"] == job_name or check["context"].startswith(
                    f"{job_name} "
                ):
                    return OK
    return FAIL


@define_rule(
    name="required-status-check",
    log_message="Add Ruleset to require some status check",
    level="error",
)
def _require_some_status_check(repo: Repository) -> RESULT:
    if not repo.allow_auto_merge:
        return SKIP

    if not _get_contents(repo, path=".github/workflows/merge.yml"):
        return SKIP

    rulesets = _get_repo_rulesets(repo)
    for ruleset in rulesets:
        if ruleset["type"] == "required_status_checks":
            return OK
    return FAIL


@define_rule(
    name="required-test-status-check",
    log_message="Add Ruleset to require 'test' status check",
    level="warning",
)
def _required_test_status_check(repo: Repository) -> RESULT:
    return _required_status_check(repo, "test")
