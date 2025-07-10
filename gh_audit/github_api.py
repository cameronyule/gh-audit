import logging
import tomllib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from functools import cache
from pathlib import Path
from typing import Any, cast

import yaml
from github import GithubException
from github.ContentFile import ContentFile
from github.Repository import Repository

from gh_audit.types import (
    RepositoryActionPermissions,
    RepositoryRuleset,
    RepositorySelectedActions,
    RepositoryWorkflowPermissions,
    Workflow,
    WorkflowJob,
    WorkflowStep,
)

logger = logging.getLogger(__name__)


def _get_readme(repo: Repository) -> ContentFile | None:
    try:
        return repo.get_readme()
    except GithubException:
        return None


def _get_contents(repo: Repository, path: str) -> ContentFile | None:
    try:
        contents = repo.get_contents(path=path)
    except GithubException:
        return None
    if isinstance(contents, list):
        return None
    return contents


@cache
def _get_contents_text(repo: Repository, path: str) -> str:
    if contents := _get_contents(repo, path=path):
        return contents.decoded_content.decode("utf-8")
    else:
        return ""


@cache
def _ls_tree(repo: Repository) -> list[Path]:
    return [Path(item.path) for item in repo.get_git_tree("HEAD", recursive=True).tree]


@cache
def _file_extnames(repo: Repository) -> set[str]:
    return {path.suffix for path in _ls_tree(repo)} - {""}


@cache
def _load_pyproject(repo: Repository) -> dict[str, Any]:
    logger.debug("Loading pyproject.toml for %s", repo.full_name)
    contents = _get_contents(repo, path="pyproject.toml")
    if not contents:
        return dict()
    try:
        return tomllib.loads(contents.decoded_content.decode("utf-8"))
    except tomllib.TOMLDecodeError:
        return dict()


@cache
def _has_requirements_txt(repo: Repository) -> bool:
    if _get_contents(repo, path="requirements.txt"):
        return True
    return False


@cache
def _has_uv_lock(repo: Repository) -> bool:
    if _get_contents(repo, path="uv.lock"):
        return True
    return False


@cache
def _requirements_txt(repo: Repository) -> str:
    return _get_contents_text(repo, path="requirements.txt")


@cache
def _requirements_txt_is_exact(repo: Repository) -> bool:
    if text := _requirements_txt(repo):
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            if "@" in line:
                continue
            if "==" not in line:
                return False
        return True
    else:
        return True


@cache
def _requirements_txt_has_types(repo: Repository) -> bool:
    if text := _requirements_txt(repo):
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            if "types-" in line:
                return True
        return False
    else:
        return False


@cache
def _requirements_txt_has_ruff(repo: Repository) -> bool:
    if text := _requirements_txt(repo):
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            if "ruff==" in line:
                return True
    return False


@cache
def _dependabot_config(repo: Repository) -> dict[str, Any]:
    logger.debug("Loading .github/dependabot.yml for %s", repo.full_name)
    contents = _get_contents(repo, path=".github/dependabot.yml")
    if not contents:
        return dict()
    try:
        return cast(
            dict[str, Any],
            yaml.safe_load(contents.decoded_content.decode("utf-8")),
        )
    except yaml.YAMLError:
        return dict()


@cache
def _get_actions_permissions(repo: Repository) -> RepositoryActionPermissions:
    _, data = repo._requester.requestJsonAndCheck(
        "GET", f"{repo.url}/actions/permissions"
    )
    return cast(RepositoryActionPermissions, data)


@cache
def _get_repo_actions_selected_actions(repo: Repository) -> RepositorySelectedActions:
    _, data = repo._requester.requestJsonAndCheck(
        "GET", f"{repo.url}/actions/permissions/selected-actions"
    )
    return cast(RepositorySelectedActions, data)


@cache
def _get_workflow_permissions(repo: Repository) -> RepositoryWorkflowPermissions:
    _, data = repo._requester.requestJsonAndCheck(
        "GET", f"{repo.url}/actions/permissions/workflow"
    )
    return cast(RepositoryWorkflowPermissions, data)


# TODO: Deprecate this util
@cache
def _get_workflow(repo: Repository, name: str) -> Workflow:
    return _get_workflow_by_path(repo, Path(f".github/workflows/{name}.yml"))


@cache
def _get_workflow_by_path(repo: Repository, path: Path) -> Workflow:
    assert str(path).startswith(".github/workflows/"), path
    contents = _get_contents(repo, path=str(path))
    empty_workflow: Workflow = {
        "name": "",
        "on": "",
        "jobs": {},
    }
    if not contents:
        return empty_workflow
    try:
        workflow = yaml.safe_load(contents.decoded_content.decode("utf-8"))
        # Workaround stupid YAML parsing bug
        if True in workflow:
            workflow["on"] = workflow.pop(True)
        return cast(Workflow, workflow)
    except yaml.YAMLError:
        return empty_workflow


@cache
def _get_workflow_paths(repo: Repository) -> list[Path]:
    paths: list[Path] = []
    for path in _ls_tree(repo):
        if (
            len(path.parts) == 3
            and path.parts[0] == ".github"
            and path.parts[1] == "workflows"
        ):
            assert path.suffix == ".yml" or path.suffix == ".yaml"
            paths.append(path)
    return paths


def _iter_workflow_jobs(repo: Repository) -> Iterator[tuple[str, WorkflowJob]]:
    for path in _get_workflow_paths(repo):
        workflow = _get_workflow_by_path(repo, path)
        yield from workflow.get("jobs", {}).items()


def _iter_workflow_steps(repo: Repository) -> Iterator[WorkflowStep]:
    for path in _get_workflow_paths(repo):
        workflow = _get_workflow_by_path(repo, path)
        for job in workflow.get("jobs", {}).values():
            yield from job.get("steps", [])


@cache
def _get_repo_rulesets(
    repo: Repository, branch: str = "main"
) -> list[RepositoryRuleset]:
    _, data = repo._requester.requestJsonAndCheck(
        "GET", f"{repo.url}/rules/branches/{branch}"
    )
    return cast(list[RepositoryRuleset], data)


@cache
def _repo_gh_pages_source(repo: Repository) -> str | None:
    if not repo.has_pages:
        return None
    _, data = repo._requester.requestJsonAndCheck("GET", f"{repo.url}/pages")

    branch_name = data.get("source", {}).get("branch", "") or "gh-pages"
    for branch in repo.get_branches():
        if branch.name == branch_name:
            return branch_name
    return None


@cache
def _has_workflow_files(repo: Repository) -> bool:
    for path in _ls_tree(repo):
        if str(path).startswith(".github/workflows/"):
            return True
    return False


@cache
def _repository_has_recent_changes(repo: Repository) -> bool:
    since = datetime.now(tz=UTC) - timedelta(days=90)
    for commit in repo.get_commits(since=since, author=repo.owner):
        if len(commit.parents) > 1:
            continue
        return True
    return False


@cache
def _repository_has_changes_since_released(repo: Repository) -> bool:
    try:
        release = repo.get_latest_release()
    except GithubException:
        return True

    for commit in repo.get_commits(since=release.created_at, author=repo.owner):
        if len(commit.parents) > 1:
            continue
        return True

    return False


@cache
def _repository_is_new(repo: Repository) -> bool:
    return repo.created_at > datetime.now(tz=UTC) - timedelta(days=90)


@cache
def _treefmt_nix_configured(repo: Repository) -> bool:
    if _get_contents(repo, path="treefmt.nix"):
        return True
    if _get_contents(repo, path="internal/treefmt.nix"):
        return True
    return False
