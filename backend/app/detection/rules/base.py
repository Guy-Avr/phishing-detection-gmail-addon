"""Base classes for the rule framework. Every rule inherits from BaseRule."""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.parsing.email_parser import ParsedEmail


@dataclass(frozen=True)
class RuleResult:
    """
    Output of a single rule evaluation.

    rule_id: Identifies which rule produced this (same as BaseRule.rule_id).
    score:   Concern level in [0, 1]. 0 = no concern, 1 = maximum concern.
    reasons: Human-readable explanations (e.g. "Link points to IP address").
    """

    rule_id: str
    score: float
    reasons: list[str]


class BaseRule(ABC):
    """
    Abstract base for all detection rules.

    Subclasses must set rule_id and weight, and implement evaluate().
    A rule returns RuleResult when it fires, or None when it has nothing to say.
    The engine skips None results so they don't affect the aggregated score.
    """

    rule_id: str
    weight: float = 1.0

    @abstractmethod
    def evaluate(self, email: ParsedEmail) -> RuleResult | None:
        """
        Evaluate the parsed email against this rule.

        Return RuleResult with score and reasons if the rule fires.
        Return None if the rule does not apply (e.g. no links to check).
        """
        ...
