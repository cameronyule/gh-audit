import logging
import subprocess
from typing import Any, Literal

import click
from github import Auth, Github

from gh_audit import rules  # noqa: F401, pylint: disable=unused-import
from gh_audit.core import RULES, Rule, rule_message_format

logger = logging.getLogger(__name__)


def _gh_auth_token() -> str | None:
    try:
        p = subprocess.run(
            ["gh", "auth", "token"],
            check=True,
            capture_output=True,
            encoding="utf-8",
        )
        return p.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


class RuleParamType(click.ParamType):
    name = "rule"

    def convert(self, value: str, param: Any, ctx: Any) -> "Rule":
        for rule in RULES:
            if rule.name == value:
                return rule
        self.fail(f"Unknown rule: {value}", param, ctx)


_RULE_TYPE = RuleParamType()


@click.command()
@click.argument("repository", nargs=-1)
@click.option(
    "--active", is_flag=True, help="Include all your non-archived repositories"
)
@click.option(
    "--github-token",
    envvar="GITHUB_TOKEN",
    help="GitHub API token",
    metavar="TOKEN",
    required=True,
    default=_gh_auth_token(),
)
@click.option("--verbose", is_flag=True, default=False, help="Enable debug logging")
@click.option(
    "--rule",
    "override_rules",
    type=_RULE_TYPE,
    multiple=True,
    help="Specify rules to run",
)
@click.option(
    "--format",
    type=click.Choice(["repo", "rule"], case_sensitive=False),
    default="repo",
    required=True,
)
@click.version_option()
def main(
    repository: list[str],
    active: bool,
    override_rules: tuple["Rule", ...],
    format: Literal["repo", "rule"],
    github_token: str,
    verbose: bool,
) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO)

    rules_to_apply: list[Rule] = RULES
    if override_rules:
        rules_to_apply = list(override_rules)
    logger.debug("Applying %d rules", len(rules_to_apply))

    global rule_message_format
    if format == "repo":
        rule_message_format = "{repo}: {level} {log_message} [{rule}]"
    elif format == "rule":
        rule_message_format = "{rule}: {level} {log_message} [{repo}]"

    with Github(auth=Auth.Token(github_token)) as g:
        user = g.get_user()

        for name in repository:
            repo = user.get_repo(name)
            for rule in rules_to_apply:
                rule(repo=repo)

        if active:
            for repo in user.get_repos():
                if repo.owner.login != user.login:
                    continue
                if repo.archived or repo.fork:
                    continue
                for rule in rules_to_apply:
                    rule(repo=repo)


if __name__ == "__main__":
    main()
