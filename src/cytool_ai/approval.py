# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Approval-mode descriptions adapted from Google Gemini CLI.

Adapted from packages/core/src/utils/approvalModeUtils.ts, with cytool-AI
modes and wording. See THIRD_PARTY_NOTICES.md.
"""

from __future__ import annotations

from enum import StrEnum


class ApprovalMode(StrEnum):
    PLAN = "plan"
    CONFIRM = "confirm"
    APPROVED = "approved"


def description(mode: ApprovalMode) -> str:
    match mode:
        case ApprovalMode.PLAN:
            return "Plan mode: no commands execute."
        case ApprovalMode.CONFIRM:
            return "Confirm mode: commands are previewed and recorded, but do not execute."
        case ApprovalMode.APPROVED:
            return "Approved mode: an operator-approved, policy-allowed command may execute locally."


def transition_message(new_mode: ApprovalMode, manual: bool = False) -> str:
    prefix = "Operator selected mode." if manual else "Approval updated."
    return f"{prefix} {description(new_mode)}"
