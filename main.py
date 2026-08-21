from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import Literal
import re

app = FastAPI()


class Permissions(BaseModel):
    contents: str
    packages: str
    id_token: str = Field(alias="id-token")

    class Config:
        populate_by_name = True


class Action(BaseModel):
    owner: str
    name: str
    ref: str


class Workflow(BaseModel):
    trigger: Literal["pull_request", "pull_request_target", "push"]
    permissions: Permissions
    testsPassed: bool
    matrixComplete: bool
    failFast: bool
    actions: list[Action]
    environmentApproval: bool = False


class Image(BaseModel):
    multiStage: bool
    runsAsRoot: bool
    secretMode: Literal["none", "buildkit", "arg", "copy"]
    criticalVulnerabilities: int
    digestPinned: bool


class ReleaseRequest(BaseModel):
    target: Literal["preview", "production"]
    event: Literal["pull_request", "push"]
    ref: str
    workflow: Workflow
    image: Image


@app.post("/release-gate")
def release_gate(request: ReleaseRequest):
    violations = []

    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id_token": "none"
    }

    if request.workflow.permissions.model_dump() != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    if request.event == "pull_request":
        if request.workflow.trigger != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

        if (
            request.workflow.testsPassed is not True
            or request.workflow.matrixComplete is not True
            or request.workflow.failFast is not False
        ):
            violations.append("TESTS_INCOMPLETE")

    full_sha = re.compile(r"^[0-9a-f]{40}$")

    for action in request.workflow.actions:
        if action.owner != "actions" and not full_sha.fullmatch(action.ref):
            violations.append("MUTABLE_ACTION")
            break

    if not request.image.multiStage:
        violations.append("SINGLE_STAGE_IMAGE")

    if request.image.runsAsRoot:
        violations.append("ROOT_RUNTIME")

    if request.image.secretMode not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")

    if request.image.criticalVulnerabilities != 0:
        violations.append("CRITICAL_CVE")

    if not request.image.digestPinned:
        violations.append("UNPINNED_IMAGE")

    if request.target == "production":
        if request.event != "push" or request.ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if not request.workflow.environmentApproval:
            violations.append("APPROVAL_REQUIRED")

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations
    }