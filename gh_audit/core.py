from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final, Literal

import click
from github.Repository import Repository

OK: Final = "OK"
SKIP: Final = "OK"
FAIL: Final = "FAIL"
RESULT = Literal["OK", "FAIL"]
rule_message_format = "{repo}: {level} {log_message} [{name}]"


@dataclass
class Rule:
    name: str
    log_message: str
    level: Literal["error", "warning"]
    check: Callable[[Repository], RESULT]

    def __call__(self, repo: Repository) -> bool:
        if self.check(repo) is FAIL:
            if self.level == "warning":
                level = "\033[33mwarn:\033[0m"
            elif self.level == "error":
                level = "\033[31merror:\033[0m"

            formatted_message = rule_message_format.format(
                name=self.name,  # Changed 'rule' to 'name'
                repo=repo.full_name,
                level=level,
                log_message=self.log_message,
            )
            click.echo(formatted_message)

            return False
        return True


RULES: list[Rule] = []


def define_rule(**kwargs: Any) -> Callable[[Callable[[Repository], RESULT]], None]:
    def _inner_define_rule(check: Callable[[Repository], RESULT]) -> None:
        rule = Rule(check=check, **kwargs)
        RULES.append(rule)

    return _inner_define_rule
