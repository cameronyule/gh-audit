from typing import Any, cast

from github.Repository import Repository

from gh_audit.core import FAIL, OK, RESULT, SKIP, define_rule
from gh_audit.github_api import (
    _file_extnames,
    _has_requirements_txt,
    _has_uv_lock,
    _iter_workflow_steps,
    _load_pyproject,
    _requirements_txt,
    _requirements_txt_is_exact,
)
from gh_audit.rules.general import _required_status_check


@define_rule(
    name="missing-pyproject",
    log_message="Missing pyproject.toml",
    level="error",
)
def _missing_pyproject(repo: Repository) -> RESULT:
    if repo.language != "Python":
        return SKIP
    if _load_pyproject(repo):
        return OK
    return FAIL


@define_rule(
    name="missing-pyproject-project-name",
    log_message="project.name missing in pyproject.toml",
    level="error",
)
def _missing_pyproject_project_name(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if pyproject.get("project", {}).get("name") is None:
        return FAIL
    return OK


def _pyproject_classifiers(repo: Repository) -> set[str]:
    return set(_load_pyproject(repo).get("project", {}).get("classifiers", []))


_MIT_LICENSE_CLASSIFIER = "License :: OSI Approved :: MIT License"


@define_rule(
    name="pyproject-mit-license-classifier",
    log_message="License classifier missing in pyproject.toml",
    level="error",
)
def _pyproject_mit_license_classifier(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP
    if not repo.license:
        return SKIP
    if repo.license.name != "MIT License":
        return SKIP

    if _MIT_LICENSE_CLASSIFIER in _pyproject_classifiers(repo):
        return OK
    return FAIL


def _pyproject_author_names(repo: Repository) -> set[str]:
    names: set[str] = set()
    for author in _load_pyproject(repo).get("project", {}).get("authors", []):
        if name := author.get("name"):
            names.add(name)
    return names


def _pyproject_author_emails(repo: Repository) -> set[str]:
    emails: set[str] = set()
    for author in _load_pyproject(repo).get("project", {}).get("authors", []):
        if email := author.get("email"):
            emails.add(email)
    return emails


@define_rule(
    name="pyproject-omit-license",
    log_message="License classifier should be omitted when using MIT License",
    level="warning",
)
def _pyproject_omit_license(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP
    if not repo.license:
        return SKIP
    if repo.license.name != "MIT License":
        return SKIP

    if "license" in _load_pyproject(repo).get("project", {}):
        return FAIL
    return OK


@define_rule(
    name="pyproject-author-name",
    log_message="project.authors[0].name missing in pyproject.toml",
    level="warning",
)
def _pyproject_author_name(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if len(_pyproject_author_names(repo)) == 0:
        return FAIL
    return OK


@define_rule(
    name="pyproject-omit-author-email",
    log_message="project.authors[0].email should be omitted for privacy",
    level="warning",
)
def _pyproject_omit_author_email(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if len(_pyproject_author_emails(repo)) > 0:
        return FAIL
    return OK


@define_rule(
    name="pyproject-readme",
    log_message="project.readme missing in pyproject.toml",
    level="error",
)
def _pyproject_readme(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if pyproject.get("project", {}).get("readme") is None:
        return FAIL
    return OK


def _pyproject_requires_python(repo: Repository) -> str:
    return cast(
        str, _load_pyproject(repo).get("project", {}).get("requires-python", "")
    )


@define_rule(
    name="missing-pyproject-requires-python",
    log_message="project.requires-python missing in pyproject.toml",
    level="error",
)
def _missing_pyproject_requires_python(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if _pyproject_requires_python(repo):
        return OK
    return FAIL


def _pyproject_all_dependencies(repo: Repository) -> set[str]:
    deps: set[str] = set()
    project = _load_pyproject(repo).get("project", {})
    for dep in project.get("dependencies", []):
        deps.add(dep)
    for extra_deps in project.get("optional-dependencies", {}).values():
        for dep in extra_deps:
            deps.add(dep)
    return deps


def _pydep_has_lower_bound(dep: str) -> bool:
    return "==" in dep or ">" in dep or "~=" in dep or "@" in dep


@define_rule(
    name="pyproject-dependency-lower-bound",
    log_message="Dependencies should have lower bound",
    level="error",
)
def _pyproject_dependency_lower_bound(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    for dep in _pyproject_all_dependencies(repo):
        if not _pydep_has_lower_bound(dep):
            return FAIL
    return OK


@define_rule(
    name="pyproject-optional-dependencies-name",
    log_message="pyproject optional-dependencies should be named 'dev'",
    level="warning",
)
def _project_optional_dependencies_name(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    deps = pyproject.get("project", {}).get("optional-dependencies", {})
    if not deps:
        return OK
    if list(deps.keys()) != ["dev"]:
        return FAIL
    return OK


@define_rule(
    name="pyproject-depends-on-requests",
    log_message="Avoid requests dependency",
    level="warning",
)
def _pyproject_depends_on_requests(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    for dep in _pyproject_all_dependencies(repo):
        if dep.startswith("requests"):
            return FAIL
    return OK


def _ruff_extend_select(repo: Repository) -> list[str]:
    return cast(
        list[str],
        _load_pyproject(repo)
        .get("tool", {})
        .get("ruff", {})
        .get("lint", {})
        .get("extend-select", []),
    )


@define_rule(
    name="missing-pyproject-ruff-isort-rules",
    log_message="tool.ruff.lint.extend-select missing 'I' to enable isort rules",
    level="error",
)
def _missing_pyproject_ruff_isort_rules(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if "I" in _ruff_extend_select(repo):
        return OK
    return FAIL


@define_rule(
    name="missing-pyproject-ruff-pyupgrade-rules",
    log_message="tool.ruff.lint.extend-select missing 'UP' to enable pyupgrade rules",
    level="error",
)
def _missing_pyproject_ruff_pyupgrade_rules(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if "UP" in _ruff_extend_select(repo):
        return OK
    return FAIL


def _mypy_strict(repo: Repository) -> bool | None:
    return cast(
        bool | None,
        _load_pyproject(repo).get("tool", {}).get("mypy", {}).get("strict"),
    )


@define_rule(
    name="mypy-strict-declared",
    log_message="mypy strict mode is not declared",
    level="error",
)
def _mypy_strict_declared(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if _mypy_strict(repo) is None:
        return FAIL
    return OK


@define_rule(
    name="mypy-strict",
    log_message="mypy strict mode is not enabled",
    level="warning",
)
def _mypy_strict_enabled(repo: Repository) -> RESULT:
    pyproject = _load_pyproject(repo)
    if not pyproject:
        return SKIP

    if _mypy_strict(repo) is False:
        return FAIL
    return OK


@define_rule(
    name="requirements-txt-exact",
    log_message="Use exact versions in requirements.txt",
    level="error",
)
def _requirements_txt_exact(repo: Repository) -> RESULT:
    if not _has_requirements_txt(repo):
        return SKIP
    if _requirements_txt_is_exact(repo) is False:
        return FAIL
    return OK


@define_rule(
    name="requirements-txt-uv-compiled",
    log_message="requirements.txt is not compiled by uv",
    level="warning",
)
def _requirements_txt_uv_compiled(repo: Repository) -> RESULT:
    if not _has_requirements_txt(repo):
        return SKIP
    if "uv pip compile" in _requirements_txt(repo):
        return OK
    return FAIL


@define_rule(
    name="prefer-uv-lock",
    log_message="Prefer uv.lock instead of requirements.txt",
    level="warning",
)
def _prefer_uv_lock(repo: Repository) -> RESULT:
    if not _has_requirements_txt(repo):
        return SKIP
    if _has_uv_lock(repo):
        return OK
    return FAIL


@define_rule(
    name="missing-ruff",
    log_message="Missing GitHub Actions workflow for ruff linting",
    level="error",
)
def _missing_ruff_error(repo: Repository) -> RESULT:
    if repo.language != "Python":
        return SKIP

    for step in _iter_workflow_steps(repo):
        if "ruff " in step.get("run", ""):
            return OK

    return OK


@define_rule(
    name="missing-ruff",
    log_message="Missing GitHub Actions workflow for ruff linting",
    level="warning",
)
def _missing_ruff_warning(repo: Repository) -> RESULT:
    if ".py" not in _file_extnames(repo):
        return SKIP

    for step in _iter_workflow_steps(repo):
        if "ruff " in step.get("run", ""):
            return OK

    return OK


@define_rule(
    name="required-ruff-status-check",
    log_message="Add Ruleset to require 'ruff' status check",
    level="warning",
)
def _required_ruff_status_check(repo: Repository) -> RESULT:
    return _required_status_check(repo, "ruff")


@define_rule(
    name="missing-mypy",
    log_message="Missing GitHub Actions workflow for mypy type checking",
    level="error",
)
def _missing_mypy(repo: Repository) -> RESULT:
    if repo.language != "Python":
        return SKIP

    for step in _iter_workflow_steps(repo):
        if "mypy " in step.get("run", ""):
            return OK

    return OK


@define_rule(
    name="required-mypy-status-check",
    log_message="Add Ruleset to require 'mypy' status check",
    level="warning",
)
def _required_mypy_status_check(repo: Repository) -> RESULT:
    return _required_status_check(repo, "mypy")
