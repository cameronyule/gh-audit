from typing import Any, Literal, NotRequired, TypedDict

WorkflowStep = TypedDict(
    "WorkflowStep",
    {
        "name": NotRequired[str],
        "uses": NotRequired[str],
        "run": NotRequired[str],
        "with": NotRequired[dict[str, str]],
        "env": NotRequired[dict[str, str]],
    },
)


class WorkflowMatrixConfiguration(TypedDict):
    include: NotRequired[list[str]]
    exclude: NotRequired[list[str]]


class WorkflowStrategy(TypedDict):
    matrix: dict[str, list[str]] | WorkflowMatrixConfiguration


WorkflowJob = TypedDict(
    "WorkflowJob",
    {
        "runs-on": str,
        "strategy": NotRequired[WorkflowStrategy],
        "env": NotRequired[dict[str, str]],
        "permissions": NotRequired[dict[str, str]],
        "timeout-minutes": NotRequired[int],
        "steps": list[WorkflowStep],
    },
)


class Workflow(TypedDict):
    name: str
    on: str | list[str] | dict[str, Any]
    permissions: NotRequired[dict[str, str]]
    concurrency: NotRequired[Any]
    env: NotRequired[dict[str, str]]
    jobs: dict[str, WorkflowJob]


class RepositoryActionPermissions(TypedDict):
    enabled: bool
    allowed_actions: NotRequired[Literal["all", "local_only", "selected"]]


class RepositoryWorkflowPermissions(TypedDict):
    default_workflow_permissions: Literal["read", "write"]
    can_approve_pull_request_reviews: bool


class RepositorySelectedActions(TypedDict):
    github_owned_allowed: bool
    verified_allowed: bool
    patterns_allowed: list[str]


class RepositoryRulesetRequiredStatusCheck(TypedDict):
    context: str


class RepositoryRulesetRequiredStatusChecksParameters(TypedDict):
    required_status_checks: list[RepositoryRulesetRequiredStatusCheck]


class RepositoryRulesetRequiredStatusChecks(TypedDict):
    type: Literal["required_status_checks"]
    parameters: RepositoryRulesetRequiredStatusChecksParameters


RepositoryRuleset = RepositoryRulesetRequiredStatusChecks
