from fastapi import FastAPI
from pydantic import BaseModel
from typing import Literal
import re


app = FastAPI()


# -----------------------------
# Request Models
# -----------------------------

class Permissions(BaseModel):
    contents: str
    packages: str
    id_token: str


class Action(BaseModel):
    owner: str
    name: str
    ref: str


class Workflow(BaseModel):
    trigger: Literal[
        "pull_request",
        "pull_request_target",
        "push"
    ]

    permissions: Permissions

    testsPassed: bool
    matrixComplete: bool
    failFast: bool

    actions: list[Action]

    # Production needs this field.
    # If it isn't provided, it behaves as False.
    environmentApproval: bool = False


class Image(BaseModel):
    multiStage: bool
    runsAsRoot: bool

    secretMode: Literal[
        "none",
        "buildkit",
        "arg",
        "copy"
    ]

    criticalVulnerabilities: int
    digestPinned: bool


class ReleaseRequest(BaseModel):
    target: Literal["preview", "production"]

    event: Literal[
        "pull_request",
        "push"
    ]

    ref: str

    workflow: Workflow
    image: Image


# -----------------------------
# Release Gate
# -----------------------------

@app.post("/release-gate")
def release_gate(request: ReleaseRequest):

    violations = []

    # ---------------------------------
    # 1. Check permissions
    # ---------------------------------

    permissions = request.workflow.permissions.model_dump()

    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id_token": "none"
    }

    if permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")


    # ---------------------------------
    # 2. Check Pull Request rules
    # ---------------------------------

    if request.event == "pull_request":

        # PR must use pull_request trigger
        if request.workflow.trigger != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

        # Tests must pass
        # Entire matrix must complete
        # failFast must be false
        if (
            request.workflow.testsPassed is not True
            or request.workflow.matrixComplete is not True
            or request.workflow.failFast is not False
        ):
            violations.append("TESTS_INCOMPLETE")


    # ---------------------------------
    # 3. Check GitHub Actions pinning
    # ---------------------------------

    full_sha = re.compile(r"^[0-9a-f]{40}$")

    for action in request.workflow.actions:

        # Official actions owned by "actions"
        # are allowed to use version tags.
        if action.owner == "actions":
            continue

        # Every third-party action must use
        # a complete lowercase 40-character SHA.
        if not full_sha.fullmatch(action.ref):
            violations.append("MUTABLE_ACTION")
            break


    # ---------------------------------
    # 4. Docker image checks
    # ---------------------------------

    # Must use multi-stage Docker build
    if request.image.multiStage is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # Container must not run as root
    if request.image.runsAsRoot is not False:
        violations.append("ROOT_RUNTIME")

    # Only "none" and "buildkit" are safe
    if request.image.secretMode not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")

    # No critical vulnerabilities
    if request.image.criticalVulnerabilities != 0:
        violations.append("CRITICAL_CVE")

    # Image must be digest pinned
    if request.image.digestPinned is not True:
        violations.append("UNPINNED_IMAGE")


    # ---------------------------------
    # 5. Production-only checks
    # ---------------------------------

    if request.target == "production":

        # Must be a push
        # to refs/heads/main
        if (
            request.event != "push"
            or request.ref != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        # Production requires approval
        if request.workflow.environmentApproval is not True:
            violations.append("APPROVAL_REQUIRED")


    # ---------------------------------
    # 6. Final decision
    # ---------------------------------

    if len(violations) == 0:
        decision = "promote"
    else:
        decision = "block"

    return {
        "decision": decision,
        "violations": violations
    }