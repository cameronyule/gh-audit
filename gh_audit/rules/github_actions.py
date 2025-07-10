import re

from github.Repository import Repository

from gh_audit.core import FAIL, OK, RESULT, SKIP, define_rule
from gh_audit.github_api import (
    _dependabot_config,
    _get_actions_permissions,
    _get_contents,
    _get_repo_actions_selected_actions,
    _get_workflow,
    _get_workflow_by_path,
    _get_workflow_paths,
    _get_workflow_permissions,
    _has_requirements_txt,
    _has_workflow_files,
    _iter_workflow_jobs,
    _iter_workflow_steps,
    _repo_gh_pages_source,
)
from gh_audit.types import WorkflowJob


@define_rule(
    name="disable-actions",
    log_message="Repository without workflows should disable Actions",
    level="error",
)
def _disable_actions(repo: Repository) -> RESULT:
    if _get_workflow_paths(repo):
        return SKIP
    permissions = _get_actions_permissions(repo)
    if permissions["enabled"]:
        return FAIL
    else:
        return OK


@define_rule(
    name="disable-all-actions",
    log_message="Repository should not allow all actions",
    level="warning",
)
def _actions_allowed_actions_all(repo: Repository) -> RESULT:
    if repo.visibility == "private":
        return SKIP
    permissions = _get_actions_permissions(repo)
    if permissions["enabled"] is False:
        return SKIP
    allowed_actions = permissions.get("allowed_actions")
    if allowed_actions == "all":
        return FAIL
    return OK


def _workflow_step_uses(repo: Repository, pattern: re.Pattern[str]) -> bool:
    for step in _iter_workflow_steps(repo):
        step_uses = step.get("uses", "")
        if re.match(pattern, step_uses):
            return True
    return False


@define_rule(
    name="allow-github-owned-actions",
    log_message="Repository allow actions created by GitHub",
    level="error",
)
def _actions_github_owned_allowed(repo: Repository) -> RESULT:
    if not _workflow_step_uses(repo, re.compile("actions/")):
        return SKIP

    permissions = _get_actions_permissions(repo)
    if permissions["enabled"] is False:
        return SKIP
    elif permissions.get("allowed_actions") == "all":
        return OK
    elif permissions.get("allowed_actions") == "local_only":
        return FAIL
    elif permissions.get("allowed_actions") == "selected":
        selected_actions = _get_repo_actions_selected_actions(repo)
        if selected_actions["github_owned_allowed"]:
            return OK
        else:
            return FAIL
    else:
        return OK


def _allow_org_owned_actions(repo: Repository, trusted_org: str) -> RESULT:
    org_pattern = re.compile(f"{trusted_org}/")
    if not _workflow_step_uses(repo, org_pattern):
        return SKIP
    permissions = _get_actions_permissions(repo)
    if permissions["enabled"] is False:
        return SKIP
    elif permissions.get("allowed_actions") == "all":
        return OK
    elif permissions.get("allowed_actions") == "local_only":
        return FAIL
    elif permissions.get("allowed_actions") == "selected":
        selected_actions = _get_repo_actions_selected_actions(repo)
        if f"{trusted_org}/*" in selected_actions["patterns_allowed"]:
            return OK
        else:
            return FAIL
    else:
        return OK


@define_rule(
    name="allow-astral-owned-actions",
    log_message="Repository allow actions created by astral-sh",
    level="error",
)
def _allow_astral_owned_actions(repo: Repository) -> RESULT:
    return _allow_org_owned_actions(repo, "astral-sh")


@define_rule(
    name="allow-aws-owned-actions",
    log_message="Repository allow actions created by aws-actions",
    level="error",
)
def _allow_aws_owned_actions(repo: Repository) -> RESULT:
    return _allow_org_owned_actions(repo, "aws-actions")


@define_rule(
    name="allow-dependabot-owned-actions",
    log_message="Repository allow actions created by dependabot",
    level="error",
)
def _allow_dependabot_owned_actions(repo: Repository) -> RESULT:
    return _allow_org_owned_actions(repo, "dependabot")


@define_rule(
    name="allow-docker-owned-actions",
    log_message="Repository allow actions created by docker",
    level="error",
)
def _allow_docker_owned_actions(repo: Repository) -> RESULT:
    return _allow_org_owned_actions(repo, "docker")


@define_rule(
    name="allow-determinate-systems-owned-actions",
    log_message="Repository allow actions created by DeterminateSystems",
    level="error",
)
def _allow_determinate_systems_owned_actions(repo: Repository) -> RESULT:
    return _allow_org_owned_actions(repo, "DeterminateSystems")


@define_rule(
    name="allow-cachix-owned-actions",
    log_message="Repository allow actions created by cachix",
    level="error",
)
def _allow_cachix_owned_actions(repo: Repository) -> RESULT:
    return _allow_org_owned_actions(repo, "cachix")


@define_rule(
    name="default-workflow-permissions",
    log_message="Actions should default to read permissions",
    level="error",
)
def _default_workflow_permissions(repo: Repository) -> RESULT:
    if repo.fork:
        return SKIP
    if not _get_actions_permissions(repo)["enabled"]:
        return SKIP
    permissions = _get_workflow_permissions(repo)
    if permissions["default_workflow_permissions"] == "write":
        return FAIL
    return OK


@define_rule(
    name="allow-actions-approve-prs",
    log_message="Allow Actions to approve pull request reviews",
    level="warning",
)
def _allow_actions_approve_prs(repo: Repository) -> RESULT:
    if repo.fork:
        return SKIP
    if not _get_actions_permissions(repo)["enabled"]:
        return SKIP
    permissions = _get_workflow_permissions(repo)
    if permissions["can_approve_pull_request_reviews"]:
        return OK
    return FAIL


def _job_defined(repo: Repository, workflows: list[str], name: str) -> bool:
    for workflow in workflows:
        if name in _get_workflow(repo, workflow).get("jobs", {}):
            return True
    return False


@define_rule(
    name="use-uv-pip",
    log_message="Use uv to install pip dependencies",
    level="warning",
)
def _use_uv_pip(repo: Repository) -> RESULT:
    if not _has_requirements_txt(repo):
        return SKIP

    for step in _iter_workflow_steps(repo):
        run = step.get("run", "")
        if re.search("pip install", run) and not re.search("uv pip install", run):
            return FAIL

    return OK


@define_rule(
    name="setup-uv",
    log_message="Use astral-sh/setup-uv",
    level="error",
)
def _setup_uv(repo: Repository) -> RESULT:
    for step in _iter_workflow_steps(repo):
        run = step.get("run", "")
        if re.search("pipx install uv", run):
            return FAIL
    return OK


@define_rule(
    name="uv-pip-install-with-requirements",
    log_message="Use uv pip install with requirements.txt",
    level="error",
)
def _uv_pip_install_with_requirements(repo: Repository) -> RESULT:
    if not _has_requirements_txt(repo):
        return SKIP

    for step in _iter_workflow_steps(repo):
        run = step.get("run", "")
        if re.search("uv pip install", run) and not re.search("requirements.txt", run):
            return FAIL

    return OK


@define_rule(
    name="setup-python-with-python-version-file",
    log_message="setup-python should use pyproject.toml",
    level="error",
)
def _setup_python_with_python_version_file(repo: Repository) -> RESULT:
    for step in _iter_workflow_steps(repo):
        if not step.get("uses", "").startswith("actions/setup-python"):
            continue
        if "matrix" in step.get("with", {}).get("python-version", ""):
            continue
        if step.get("with", {}).get("python-version-file", "") != "pyproject.toml":
            return FAIL

    return OK


def _job_uses_uv(job: WorkflowJob) -> bool:
    for step in job.get("steps", []):
        if re.search("uv ", step.get("run", "")):
            return True
    return False


@define_rule(
    name="disable-setup-python-cache",
    log_message="setup-python cache should be disabled when using uv",
    level="error",
)
def _disable_setup_python_cache(repo: Repository) -> RESULT:
    for name, job in _iter_workflow_jobs(repo):
        if not _job_uses_uv(job):
            continue

        for step in job.get("steps", []):
            if step.get("uses", "").startswith("actions/setup-python"):
                if step.get("with", {}).get("cache", None) is not None:
                    return FAIL

    return OK


@define_rule(
    name="no-flake-checker-action",
    log_message="Do not use DeterminateSystems/flake-checker-action",
    level="warning",
)
def _no_flake_checker_action(repo: Repository) -> RESULT:
    for step in _iter_workflow_steps(repo):
        if step.get("uses", "").startswith("DeterminateSystems/flake-checker-action"):
            return FAIL
    return OK


@define_rule(
    name="nix-flake-check-no-checkout",
    log_message="Use direct repo URI instead of checkout for 'nix flake check'",
    level="warning",
)
def _nix_flake_check_no_checkout(repo: Repository) -> RESULT:
    if not _get_contents(repo, path="flake.nix"):
        return SKIP

    for job_name, job in _iter_workflow_jobs(repo):
        job_has_nix_flake_check = False
        job_has_checkout = False

        for step in job.get("steps", []):
            if step.get("uses", "").startswith("actions/checkout"):
                job_has_checkout = True

            if "nix flake check" in step.get("run", ""):
                job_has_nix_flake_check = True

        if job_has_nix_flake_check and job_has_checkout:
            return FAIL

    return OK


@define_rule(
    name="git-commit-name",
    log_message="Git commit name to github-actions",
    level="error",
)
def _git_commit_name(repo: Repository) -> RESULT:
    for step in _iter_workflow_steps(repo):
        run = step.get("run", "")
        if re.search("git config", run) and re.search("user.name", run):
            if not re.search("github-actions\\[bot\\]|outputs\\.app-slug", run):
                return FAIL
    return OK


@define_rule(
    name="git-commit-email",
    log_message="Git commit email to github-actions",
    level="error",
)
def _git_commit_email(repo: Repository) -> RESULT:
    for step in _iter_workflow_steps(repo):
        run = step.get("run", "")
        if re.search("git config", run) and re.search("user.email", run):
            if not re.search(
                "41898282\\+github-actions\\[bot\\]@users\\.noreply\\.github\\.com|outputs\\.app-slug",
                run,
            ):
                return FAIL
    return OK


@define_rule(
    name="no-workflow-env-secrets",
    log_message="Do not expose secrets to entire workflow environment",
    level="warning",
)
def _no_workflow_env_secrets(repo: Repository) -> RESULT:
    for path in _get_workflow_paths(repo):
        workflow = _get_workflow_by_path(repo, path)
        env = workflow.get("env", {})
        for value in env.values():
            if "${{ secrets." in value:
                return FAIL
    return OK


@define_rule(
    name="no-job-env-secrets",
    log_message="Do not expose secrets to entire job environment",
    level="warning",
)
def _no_job_env_secrets(repo: Repository) -> RESULT:
    for _, job in _iter_workflow_jobs(repo):
        env = job.get("env", {})
        for value in env.values():
            if "${{ secrets." in value:
                return FAIL
    return OK


@define_rule(
    name="wip-gh-pages-branch",
    log_message="Avoid using gh-pages branch",
    level="warning",
)
def _gh_pages_branch(repo: Repository) -> RESULT:
    if _repo_gh_pages_source(repo) == "gh-pages":
        return FAIL
    return OK


@define_rule(
    name="git-push-concurrency-group",
    log_message="Jobs that use git push must be in a concurrency group",
    level="error",
)
def _git_push_concurrency_group(repo: Repository) -> RESULT:
    for path in _get_workflow_paths(repo):
        workflow = _get_workflow_by_path(repo, path)
        workflow_has_concurrency_group = "concurrency" in workflow

        for name, job in workflow.get("jobs", {}).items():
            job_has_concurrency_group = (
                workflow_has_concurrency_group or "concurrency" in job
            )
            job_has_git_push = False
            for step in job.get("steps", []):
                if re.search("git push", step.get("run", "")):
                    job_has_git_push = True
            if job_has_git_push and not job_has_concurrency_group:
                return FAIL
    return OK


@define_rule(
    name="git-push-if-commited",
    log_message="git push step should only run if changes are commited",
    level="error",
)
def _git_push_if_commited(repo: Repository) -> RESULT:
    for step in _iter_workflow_steps(repo):
        run = step.get("run", "")
        if re.search("git push", run) and "if" not in step:
            return FAIL
    return OK


def _workflow_job_uses_git_push(job: WorkflowJob) -> bool:
    for step in job.get("steps", []):
        step_run = step.get("run", "")
        if re.search("git push", step_run):
            return True
    return False


@define_rule(
    name="enable-write-contents-permission",
    log_message="Workflows using git push must have contents write permission",
    level="error",
)
def _enable_write_contents_permission(repo: Repository) -> RESULT:
    if not _get_actions_permissions(repo)["enabled"]:
        return SKIP

    for path in _get_workflow_paths(repo):
        workflow = _get_workflow_by_path(repo, path)
        workflow_has_write_permission = (
            workflow.get("permissions", {}).get("contents") == "write"
        )

        for job in workflow.get("jobs", {}).values():
            job_has_write_permission = (
                job.get("permissions", {}).get("contents") == "write"
            )
            has_write_permission = (
                job_has_write_permission or workflow_has_write_permission
            )
            uses_git_push = _workflow_job_uses_git_push(job)
            if uses_git_push and not has_write_permission:
                return FAIL

    return OK


def _workflow_job_git_push_branch(job: WorkflowJob, branch: str) -> bool:
    for step in job.get("steps", []):
        step_run = step.get("run", "")
        if re.search("git push", step_run) and re.search(branch, step_run):
            return True
    return False


def _workflow_job_checkout_uses_token(job: WorkflowJob) -> bool:
    for step in job.get("steps", []):
        step_uses = step.get("uses", "")
        step_with = step.get("with", {})
        if step_uses.startswith("actions/checkout") and step_with.get("token"):
            return True
    return False


def _workflow_job_checkout(job: WorkflowJob, branch: str) -> bool:
    for step in job.get("steps", []):
        step_uses = step.get("uses", "")
        step_with = step.get("with", {})
        if step_uses.startswith("actions/checkout") and step_with.get("ref") == branch:
            return True
    return False


@define_rule(
    name="git-push-pat",
    log_message="Use PAT when git pushing",
    level="warning",
)
def _github_push_pat(repo: Repository) -> RESULT:
    for job_name, job in _iter_workflow_jobs(repo):
        if _workflow_job_checkout_uses_token(job):
            continue
        if not _workflow_job_uses_git_push(job):
            continue
        if _workflow_job_checkout(job, branch="secrets"):
            continue
        if _workflow_job_checkout(job, branch="data"):
            continue

        # Ignore gh-pages pushes
        gh_pages_branch = _repo_gh_pages_source(repo)
        if gh_pages_branch and _workflow_job_git_push_branch(job, gh_pages_branch):
            continue

        return FAIL

    return OK


@define_rule(
    name="dependabot-github-actions",
    log_message="Dependabot should be enabled for GitHub Actions if workflows are present",
    level="error",
)
def _github_actions_dependabot(repo: Repository) -> RESULT:
    if not _has_workflow_files(repo):
        return SKIP
    for update in _dependabot_config(repo).get("updates", []):
        if update.get("package-ecosystem") == "github-actions":
            return OK
    return FAIL


@define_rule(
    name="runner-os",
    log_message="Lock GitHub Actions runner to a specific version",
    level="error",
)
def _runner_os(repo: Repository) -> RESULT:
    for _, job in _iter_workflow_jobs(repo):
        runs_on = job.get("runs-on", "")
        if "-latest" in runs_on:
            return FAIL

        matrix = job.get("strategy", {}).get("matrix", {})
        if isinstance(matrix, dict):
            for vs in matrix.values():
                if not isinstance(vs, list):
                    continue
                for v in vs:
                    if isinstance(v, str) and v.endswith("-latest"):
                        return FAIL

    return OK


_OUTDATED_RUNNER_IMAGES = [
    "ubuntu-22.04",
    "ubuntu-20.04",
    "macos-12",
]


@define_rule(
    name="runner-os-outdated",
    log_message="Use latest runner image",
    level="warning",
)
def _runner_os_outdated(repo: Repository) -> RESULT:
    for _, job in _iter_workflow_jobs(repo):
        runs_on = job.get("runs-on", "")
        for os in _OUTDATED_RUNNER_IMAGES:
            if os in runs_on:
                return FAIL

        matrix = job.get("strategy", {}).get("matrix", {})
        if isinstance(matrix, dict):
            for vs in matrix.values():
                if not isinstance(vs, list):
                    continue
                for v in vs:
                    if not isinstance(v, str):
                        continue
                    for os in _OUTDATED_RUNNER_IMAGES:
                        if os in v:
                            return FAIL

    return OK


@define_rule(
    name="arm64-qemu",
    log_message="Use native ARM64 runner instead of QEMU",
    level="error",
)
def _arm64_qemu(repo: Repository) -> RESULT:
    for step in _iter_workflow_steps(repo):
        step_uses = step.get("uses", "")
        step_platforms = step.get("with", {}).get("platforms", "")
        if step_uses.startswith("docker/setup-qemu-action"):
            if "arm64" in step_platforms:
                return FAIL

    return OK
