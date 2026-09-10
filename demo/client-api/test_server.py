#!/usr/bin/env python3
"""Low-resource unit tests for the client-side direct-user curl gateway."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


MODULE_PATH = Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("mongodb_dam_direct_user_api", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load direct-user API module")
SERVER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SERVER
SPEC.loader.exec_module(SERVER)


class CanonicalArnTests(unittest.TestCase):
    def test_canonicalizes_assumed_role(self) -> None:
        self.assertEqual(
            SERVER.canonical_iam_arn(
                "arn:aws:sts::111122223333:assumed-role/team/dam-user/demo-session"
            ),
            "arn:aws:iam::111122223333:role/team/dam-user",
        )

    def test_preserves_iam_user(self) -> None:
        arn = "arn:aws:iam::111122223333:user/dam-demo-alice"
        self.assertEqual(SERVER.canonical_iam_arn(arn), arn)


class ExecutorTests(unittest.TestCase):
    principal = "arn:aws:iam::111122223333:user/dam-demo-alice"

    def executor_without_init(self) -> object:
        executor = object.__new__(SERVER.DirectMongoExecutor)
        executor.expected_principal = self.principal
        executor.secret_id = "mongodb-dam/demo/direct-user"
        return executor

    def credential_json(self) -> str:
        return json.dumps(
            {
                "status": "active",
                "iam_principal_arn": self.principal,
                "mongo_username": "iam-demo",
                "mongo_password": "not-logged",
                "auth_database": "admin",
                "database": "dam_demo",
            }
        )

    def test_loads_only_matching_active_credential(self) -> None:
        executor = self.executor_without_init()
        executor._aws = Mock(side_effect=[self.principal, self.credential_json()])
        caller, credential = executor.load_credential()
        self.assertEqual(caller, self.principal)
        self.assertEqual(credential.mongo_username, "iam-demo")
        self.assertEqual(credential.database, "dam_demo")

    def test_rejects_wrong_aws_caller_before_secret_lookup(self) -> None:
        executor = self.executor_without_init()
        executor._aws = Mock(return_value="arn:aws:iam::111122223333:user/other")
        with self.assertRaises(SERVER.ApiError) as raised:
            executor.load_credential()
        self.assertEqual(raised.exception.status, HTTPStatus.FORBIDDEN)
        self.assertEqual(raised.exception.code, "identity_mismatch")
        executor._aws.assert_called_once()

    def test_access_denial_is_sanitized(self) -> None:
        executor = self.executor_without_init()
        executor.aws_cli = "aws"
        executor.aws_region = "ap-south-1"
        denied = subprocess.CalledProcessError(
            254,
            ["aws"],
            stderr="AccessDeniedException: explicit deny",
        )
        with patch.object(subprocess, "run", side_effect=denied):
            with self.assertRaises(SERVER.ApiError) as raised:
                executor._aws("secretsmanager", "get-secret-value")
        self.assertEqual(raised.exception.status, HTTPStatus.FORBIDDEN)
        self.assertEqual(raised.exception.code, "secret_access_denied")
        self.assertNotIn("AccessDeniedException", raised.exception.message)

    def test_bulk_marker_is_written_after_credential_resolution(self) -> None:
        executor = self.executor_without_init()
        executor.mongodb_host = "127.0.0.1"
        executor.mongodb_port = 27018
        executor.mongodb_client_image = "mongo:test"
        executor.mongosh_bin = "mongosh"
        executor.use_local_mongosh = True
        executor.load_credential = Mock(
            return_value=(
                self.principal,
                SERVER.Credential(
                    self.principal,
                    "iam-demo",
                    "not-logged",
                    "admin",
                    "dam_demo",
                ),
            )
        )
        executor._mongosh_command = Mock(return_value=["mock-mongosh"])
        with tempfile.TemporaryDirectory() as directory:
            executor.run_marker_file = Path(directory) / "marker"
            completed = subprocess.CompletedProcess(
                ["mock-mongosh"],
                0,
                stdout=f'{SERVER.RESULT_PREFIX}{json.dumps({"deleted_count": 35})}\n',
                stderr="",
            )
            with patch.object(subprocess, "run", return_value=completed):
                response = executor.execute(SERVER.BULK_DELETE, mark_activity=True)
            self.assertEqual(response["result"]["deleted_count"], 35)
            self.assertGreater(response["activity_not_before_epoch"], 0)
            self.assertTrue(executor.run_marker_file.is_file())
            self.assertEqual(executor.run_marker_file.stat().st_mode & 0o777, 0o600)


class HttpRouteTests(unittest.TestCase):
    class FakeExecutor:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, str] | None, bool]] = []

        def execute(
            self,
            javascript: str,
            operation_env: dict[str, str] | None = None,
            *,
            mark_activity: bool = False,
        ) -> dict[str, object]:
            self.calls.append((javascript, operation_env, mark_activity))
            response: dict[str, object] = {
                "iam_principal_arn": "arn:aws:iam::111122223333:user/dam-demo-alice",
                "database": "dam_demo",
                "result": {"ok": True},
            }
            if mark_activity:
                response["activity_not_before_epoch"] = 12345
            return response

    def setUp(self) -> None:
        self.executor = self.FakeExecutor()
        self.handler = object.__new__(SERVER.DirectUserHandler)
        self.handler.server = SimpleNamespace(executor=self.executor)
        self.handler.send_json = Mock()

    def test_bulk_delete_route_marks_activity(self) -> None:
        self.handler.path = "/v1/customer-records?demo_batch=iam-bulk-delete"
        self.handler._do_delete()
        status, body = self.handler.send_json.call_args.args
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(body["activity_not_before_epoch"], 12345)
        self.assertEqual(len(self.executor.calls), 1)
        javascript, operation_env, mark_activity = self.executor.calls[0]
        self.assertEqual(javascript, SERVER.BULK_DELETE)
        self.assertIsNone(operation_env)
        self.assertTrue(mark_activity)

    def test_bulk_delete_rejects_any_other_filter(self) -> None:
        self.handler.path = "/v1/customer-records?demo_batch=other"
        with self.assertRaises(SERVER.ApiError) as raised:
            self.handler._do_delete()
        self.assertEqual(raised.exception.status, HTTPStatus.BAD_REQUEST)
        self.assertEqual(raised.exception.code, "invalid_demo_batch")
        self.assertEqual(self.executor.calls, [])


if __name__ == "__main__":
    unittest.main()
