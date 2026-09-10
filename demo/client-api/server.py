#!/usr/bin/env python3
"""Loopback-only curl gateway for the IAM-attributed MongoDB DAM demo.

The process runs on the AWS-logged client machine. Every database request first
resolves the current AWS caller and retrieves that caller's mapped SCRAM secret,
then launches a direct mongosh operation against the local MongoDB tunnel.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


LOG = logging.getLogger("mongodb-dam-direct-user-api")
RESULT_PREFIX = "__MONGODB_DAM_RESULT__"
ORDER_PATH = re.compile(r"^/v1/orders/([^/]+)$")
IAM_PRINCIPAL = re.compile(r"^arn:[^:]+:iam::[0-9]{12}:(?:user|role)/.+$")
ALLOWED_STATUSES = {"pending", "paid", "processing", "shipped", "cancelled"}
MAX_BODY_BYTES = 64 * 1024


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Credential:
    iam_principal_arn: str
    mongo_username: str
    mongo_password: str
    auth_database: str
    database: str


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def canonical_iam_arn(value: str) -> str:
    parts = value.split(":", 5)
    if len(parts) != 6:
        return value
    arn, partition, service, _, account, resource = parts
    if arn == "arn" and service == "sts" and resource.startswith("assumed-role/"):
        role_and_session = resource.removeprefix("assumed-role/")
        role_path, separator, _ = role_and_session.rpartition("/")
        if separator and role_path:
            return f"arn:{partition}:iam::{account}:role/{role_path}"
    return value


def first(query: dict[str, list[str]], name: str) -> str | None:
    values = query.get(name)
    return values[0] if values else None


class DirectMongoExecutor:
    def __init__(self) -> None:
        self.aws_cli = os.environ.get("AWS_CLI_BIN", "aws")
        self.aws_region = required_env("AWS_REGION")
        self.expected_principal = required_env("DEMO_IAM_PRINCIPAL_ARN")
        if IAM_PRINCIPAL.fullmatch(self.expected_principal) is None:
            raise RuntimeError("DEMO_IAM_PRINCIPAL_ARN must be an IAM user or role ARN")
        self.secret_id = os.environ.get(
            "DEMO_AWS_SECRET_ID", "mongodb-dam/demo/direct-user"
        )
        self.mongodb_host = os.environ.get("MONGODB_HOST", "127.0.0.1")
        self.mongodb_port = int(os.environ.get("MONGODB_PORT", "27018"))
        self.mongodb_client_image = os.environ.get(
            "MONGODB_CLIENT_IMAGE", "mongo:8.0.29-noble"
        )
        self.mongosh_bin = os.environ.get("MONGOSH_BIN", "mongosh")
        marker = os.environ.get("DIRECT_USER_RUN_MARKER_FILE", "").strip()
        self.run_marker_file = Path(
            marker or f"/tmp/mongodb-dam-direct-user-last-run-{os.getuid()}"
        )
        mode = os.environ.get("DIRECT_USER_MONGOSH_MODE", "auto").lower()
        if mode not in {"auto", "local", "docker"}:
            raise RuntimeError("DIRECT_USER_MONGOSH_MODE must be auto, local, or docker")
        self.use_local_mongosh = mode == "local" or (
            mode == "auto" and shutil.which(self.mongosh_bin) is not None
        )
        if mode == "local" and shutil.which(self.mongosh_bin) is None:
            raise RuntimeError(f"MONGOSH_BIN is not executable: {self.mongosh_bin}")
        if not self.use_local_mongosh and shutil.which("docker") is None:
            raise RuntimeError("docker is required when a local mongosh is unavailable")

    def _aws(self, *arguments: str) -> str:
        command = [
            self.aws_cli,
            "--region",
            self.aws_region,
            *arguments,
        ]
        try:
            completed = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except subprocess.TimeoutExpired as error:
            raise ApiError(
                HTTPStatus.GATEWAY_TIMEOUT,
                "aws_timeout",
                "AWS identity or secret lookup timed out",
            ) from error
        except subprocess.CalledProcessError as error:
            stderr = error.stderr or ""
            if "AccessDenied" in stderr or "not authorized" in stderr.lower():
                raise ApiError(
                    HTTPStatus.FORBIDDEN,
                    "secret_access_denied",
                    "the current AWS identity cannot retrieve the MongoDB credential",
                ) from error
            raise ApiError(
                HTTPStatus.BAD_GATEWAY,
                "aws_request_failed",
                "AWS identity or secret lookup failed",
            ) from error
        return completed.stdout.strip()

    def load_credential(self) -> tuple[str, Credential]:
        caller = self._aws(
            "sts", "get-caller-identity", "--query", "Arn", "--output", "text"
        )
        canonical_caller = canonical_iam_arn(caller)
        if canonical_caller != self.expected_principal:
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "identity_mismatch",
                "the current AWS identity is not the configured MongoDB demo user",
            )

        secret_text = self._aws(
            "secretsmanager",
            "get-secret-value",
            "--secret-id",
            self.secret_id,
            "--query",
            "SecretString",
            "--output",
            "text",
        )
        try:
            secret = json.loads(secret_text)
            if secret.get("status") != "active":
                raise ValueError("credential is not active")
            fields = (
                "iam_principal_arn",
                "mongo_username",
                "mongo_password",
                "auth_database",
                "database",
            )
            if any(
                not isinstance(secret.get(field), str) or not secret[field]
                for field in fields
            ):
                raise ValueError("credential contains an empty or non-string field")
            credential = Credential(
                iam_principal_arn=secret["iam_principal_arn"],
                mongo_username=secret["mongo_username"],
                mongo_password=secret["mongo_password"],
                auth_database=secret["auth_database"],
                database=secret["database"],
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise ApiError(
                HTTPStatus.BAD_GATEWAY,
                "invalid_credential_secret",
                "the mapped MongoDB credential secret is invalid or inactive",
            ) from error
        if credential.iam_principal_arn != canonical_caller:
            raise ApiError(
                HTTPStatus.FORBIDDEN,
                "credential_identity_mismatch",
                "the retrieved MongoDB credential belongs to another AWS identity",
            )
        return caller, credential

    def _mongosh_command(self, variable_names: list[str]) -> list[str]:
        shell = (
            'exec "$DAM_MONGOSH_BIN" --quiet '
            '--host "$DAM_DEMO_MONGO_HOST" --port "$DAM_DEMO_MONGO_PORT" '
            '--username "$DAM_DEMO_MONGO_USERNAME" '
            '--password "$DAM_DEMO_MONGO_PASSWORD" '
            '--authenticationDatabase "$DAM_DEMO_AUTH_DATABASE" '
            '--eval "$DAM_MONGO_EVAL"'
        )
        if self.use_local_mongosh:
            return ["sh", "-ceu", shell]
        command = ["docker", "run", "--rm", "--network", "host"]
        for name in variable_names:
            command.extend(["--env", name])
        command.extend(
            [
                self.mongodb_client_image,
                "sh",
                "-ceu",
                shell,
            ]
        )
        return command

    def execute(
        self,
        javascript: str,
        operation_env: dict[str, str] | None = None,
        *,
        mark_activity: bool = False,
    ) -> dict[str, Any]:
        caller, credential = self.load_credential()
        activity_not_before = self.mark_activity_start() if mark_activity else None
        command_env = os.environ.copy()
        command_env.update(
            {
                "DAM_MONGOSH_BIN": self.mongosh_bin if self.use_local_mongosh else "mongosh",
                "DAM_DEMO_MONGO_HOST": self.mongodb_host,
                "DAM_DEMO_MONGO_PORT": str(self.mongodb_port),
                "DAM_DEMO_MONGO_USERNAME": credential.mongo_username,
                "DAM_DEMO_MONGO_PASSWORD": credential.mongo_password,
                "DAM_DEMO_AUTH_DATABASE": credential.auth_database,
                "DAM_DEMO_DATABASE": credential.database,
                "DAM_MONGO_EVAL": javascript,
            }
        )
        if operation_env:
            command_env.update(operation_env)
        variable_names = [name for name in command_env if name.startswith("DAM_")]
        try:
            completed = subprocess.run(
                self._mongosh_command(variable_names),
                env=command_env,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired as error:
            raise ApiError(
                HTTPStatus.GATEWAY_TIMEOUT,
                "mongodb_timeout",
                "the direct MongoDB operation timed out",
            ) from error
        except subprocess.CalledProcessError as error:
            stderr = error.stderr or ""
            if "E11000" in stderr:
                status = HTTPStatus.CONFLICT
                code = "duplicate_document"
            else:
                status = HTTPStatus.SERVICE_UNAVAILABLE
                code = "mongodb_request_failed"
            raise ApiError(status, code, "the direct MongoDB operation failed") from error

        result_line = next(
            (
                line.removeprefix(RESULT_PREFIX)
                for line in reversed(completed.stdout.splitlines())
                if line.startswith(RESULT_PREFIX)
            ),
            None,
        )
        if result_line is None:
            raise ApiError(
                HTTPStatus.BAD_GATEWAY,
                "invalid_mongodb_response",
                "mongosh did not return the expected result",
            )
        try:
            result = json.loads(result_line)
        except json.JSONDecodeError as error:
            raise ApiError(
                HTTPStatus.BAD_GATEWAY,
                "invalid_mongodb_response",
                "mongosh returned invalid JSON",
            ) from error
        response = {
            "iam_principal_arn": canonical_iam_arn(caller),
            "database": credential.database,
            "result": result,
        }
        if activity_not_before is not None:
            response["activity_not_before_epoch"] = activity_not_before
        return response

    def mark_activity_start(self) -> int:
        started = int(time.time())
        self.run_marker_file.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(
            self.run_marker_file,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as marker:
            marker.write(f"{started}\n")
        return started


PING = f"""
const database = db.getSiblingDB(process.env.DAM_DEMO_DATABASE);
const result = database.runCommand({{ping: 1}});
print("{RESULT_PREFIX}" + JSON.stringify({{command: "ping", ok: result.ok === 1}}));
"""

FIND_CUSTOMERS = f"""
const database = db.getSiblingDB(process.env.DAM_DEMO_DATABASE);
const email = process.env.DAM_QUERY_EMAIL || "";
const filter = email ? {{email: email}} : {{}};
const documents = database.customers.find(filter).sort({{_id: 1}}).limit(50).toArray();
print("{RESULT_PREFIX}" + JSON.stringify({{
  command: "find", collection: "customers", count: documents.length, documents: documents
}}));
"""

FIND_ORDERS = f"""
const database = db.getSiblingDB(process.env.DAM_DEMO_DATABASE);
const filter = {{}};
if (process.env.DAM_QUERY_CUSTOMER_ID) filter.customer_id = process.env.DAM_QUERY_CUSTOMER_ID;
if (process.env.DAM_QUERY_STATUS) filter.status = process.env.DAM_QUERY_STATUS;
const documents = database.orders.find(filter).sort({{_id: 1}}).limit(50).toArray();
print("{RESULT_PREFIX}" + JSON.stringify({{
  command: "find", collection: "orders", count: documents.length, documents: documents
}}));
"""

INSERT_ORDER = f"""
const database = db.getSiblingDB(process.env.DAM_DEMO_DATABASE);
const order = JSON.parse(process.env.DAM_REQUEST_JSON);
order.created_at = new Date();
database.orders.insertOne(order);
print("{RESULT_PREFIX}" + JSON.stringify({{
  command: "insert", collection: "orders", inserted_id: order._id, document: order
}}));
"""

UPDATE_ORDER = f"""
const database = db.getSiblingDB(process.env.DAM_DEMO_DATABASE);
const orderId = process.env.DAM_ORDER_ID;
const status = process.env.DAM_ORDER_STATUS;
const result = database.orders.updateOne(
  {{_id: orderId}}, {{$set: {{status: status, updated_at: new Date()}}}}
);
if (result.matchedCount === 0) throw new Error("order not found");
const document = database.orders.findOne({{_id: orderId}});
print("{RESULT_PREFIX}" + JSON.stringify({{
  command: "update", collection: "orders", matched_count: result.matchedCount,
  modified_count: result.modifiedCount, document: document
}}));
"""

DELETE_ORDER = f"""
const database = db.getSiblingDB(process.env.DAM_DEMO_DATABASE);
const orderId = process.env.DAM_ORDER_ID;
const result = database.orders.deleteOne({{_id: orderId}});
if (result.deletedCount === 0) throw new Error("order not found");
print("{RESULT_PREFIX}" + JSON.stringify({{
  command: "delete", collection: "orders", delete_scope: "single",
  deleted_count: result.deletedCount, order_id: orderId
}}));
"""

AGGREGATE_REVENUE = f"""
const database = db.getSiblingDB(process.env.DAM_DEMO_DATABASE);
const documents = database.orders.aggregate([
  {{$group: {{_id: "$status", orders: {{$sum: 1}}, revenue: {{$sum: "$amount"}}}}}},
  {{$sort: {{revenue: -1}}}}
]).toArray();
print("{RESULT_PREFIX}" + JSON.stringify({{
  command: "aggregate", collection: "orders", results: documents
}}));
"""

BULK_DELETE = f"""
const database = db.getSiblingDB(process.env.DAM_DEMO_DATABASE);
const collection = database.customer_records;
const filter = {{demo_batch: "iam-bulk-delete"}};
const before = collection.countDocuments(filter);
if (before < 10) {{
  throw new Error(`expected at least 10 seeded records, found ${{before}}`);
}}
const result = collection.deleteMany(filter);
print("{RESULT_PREFIX}" + JSON.stringify({{
  command: "delete", collection: "customer_records", delete_scope: "multi",
  matching_before_delete: before, deleted_count: result.deletedCount
}}));
"""


class DirectUserHandler(BaseHTTPRequestHandler):
    server: "DirectUserServer"
    protocol_version = "HTTP/1.1"
    server_version = "mongodb-dam-direct-user-api/0.1"

    def log_message(self, message: str, *args: Any) -> None:
        LOG.info("client=%s %s", self.client_address[0], message % args)

    def send_json(self, status: HTTPStatus, body: Any) -> None:
        encoded = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def read_json(self) -> dict[str, Any]:
        try:
            content_length = int(self.headers.get("content-length", "0"))
        except ValueError as error:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_body", "invalid content-length") from error
        if content_length <= 0 or content_length > MAX_BODY_BYTES:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "invalid_body",
                f"body must be between 1 and {MAX_BODY_BYTES} bytes",
            )
        try:
            decoded = json.loads(self.rfile.read(content_length))
        except json.JSONDecodeError as error:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_body", "body must be valid JSON") from error
        if not isinstance(decoded, dict):
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_body", "body must be a JSON object")
        return decoded

    def dispatch(self, action: Any) -> None:
        try:
            action()
        except ApiError as error:
            self.send_json(
                error.status,
                {"error": error.code, "message": error.message},
            )
        except Exception:
            LOG.exception("unexpected request failure")
            self.send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "internal_error", "message": "unexpected gateway failure"},
            )

    def do_GET(self) -> None:  # noqa: N802
        self.dispatch(self._do_get)

    def _do_get(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/":
            self.send_json(
                HTTPStatus.OK,
                {
                    "service": "mongodb-dam-direct-user-api",
                    "identity_source": "local AWS credential chain",
                    "endpoints": [
                        "GET /v1/access-check",
                        "GET /v1/customers?email=...",
                        "GET /v1/orders?customer_id=...&status=...",
                        "POST /v1/orders",
                        "PATCH /v1/orders/{order_id}",
                        "DELETE /v1/orders/{order_id}",
                        "GET /v1/analytics/revenue-by-status",
                        "DELETE /v1/customer-records?demo_batch=iam-bulk-delete",
                    ],
                },
            )
        elif parsed.path == "/health":
            self.send_json(HTTPStatus.OK, {"status": "ready"})
        elif parsed.path == "/v1/access-check":
            self.send_json(HTTPStatus.OK, self.server.executor.execute(PING))
        elif parsed.path == "/v1/customers":
            self.send_json(
                HTTPStatus.OK,
                self.server.executor.execute(
                    FIND_CUSTOMERS,
                    {"DAM_QUERY_EMAIL": first(query, "email") or ""},
                ),
            )
        elif parsed.path == "/v1/orders":
            status = first(query, "status") or ""
            if status and status not in ALLOWED_STATUSES:
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_status", "unsupported order status")
            self.send_json(
                HTTPStatus.OK,
                self.server.executor.execute(
                    FIND_ORDERS,
                    {
                        "DAM_QUERY_CUSTOMER_ID": first(query, "customer_id") or "",
                        "DAM_QUERY_STATUS": status,
                    },
                ),
            )
        elif parsed.path == "/v1/analytics/revenue-by-status":
            self.send_json(HTTPStatus.OK, self.server.executor.execute(AGGREGATE_REVENUE))
        else:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "route_not_found"})

    def do_POST(self) -> None:  # noqa: N802
        self.dispatch(self._do_post)

    def _do_post(self) -> None:
        if urlparse(self.path).path != "/v1/orders":
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "route_not_found"})
            return
        payload = self.read_json()
        for field in ("customer_id", "product", "amount"):
            if field not in payload:
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_order", f"{field} is required")
        if not isinstance(payload["customer_id"], str) or not payload["customer_id"].strip():
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_order", "customer_id must be a string")
        if not isinstance(payload["product"], str) or not payload["product"].strip():
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_order", "product must be a string")
        if isinstance(payload["amount"], bool) or not isinstance(payload["amount"], (int, float)):
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_order", "amount must be numeric")
        if payload["amount"] < 0:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_order", "amount must be non-negative")
        status = payload.get("status", "pending")
        if status not in ALLOWED_STATUSES:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_status", "unsupported order status")
        order = {
            "_id": payload.get("order_id", f"order-{uuid.uuid4().hex[:12]}"),
            "customer_id": payload["customer_id"],
            "product": payload["product"],
            "amount": float(payload["amount"]),
            "status": status,
        }
        self.send_json(
            HTTPStatus.CREATED,
            self.server.executor.execute(
                INSERT_ORDER,
                {"DAM_REQUEST_JSON": json.dumps(order, separators=(",", ":"))},
            ),
        )

    def do_PATCH(self) -> None:  # noqa: N802
        self.dispatch(self._do_patch)

    def _do_patch(self) -> None:
        match = ORDER_PATH.fullmatch(urlparse(self.path).path)
        if match is None:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "route_not_found"})
            return
        payload = self.read_json()
        status = payload.get("status")
        if status not in ALLOWED_STATUSES:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_status", "unsupported order status")
        self.send_json(
            HTTPStatus.OK,
            self.server.executor.execute(
                UPDATE_ORDER,
                {
                    "DAM_ORDER_ID": unquote(match.group(1)),
                    "DAM_ORDER_STATUS": str(status),
                },
            ),
        )

    def do_DELETE(self) -> None:  # noqa: N802
        self.dispatch(self._do_delete)

    def _do_delete(self) -> None:
        parsed = urlparse(self.path)
        match = ORDER_PATH.fullmatch(parsed.path)
        if match is not None:
            self.send_json(
                HTTPStatus.OK,
                self.server.executor.execute(
                    DELETE_ORDER,
                    {"DAM_ORDER_ID": unquote(match.group(1))},
                ),
            )
            return
        if parsed.path == "/v1/customer-records":
            query = parse_qs(parsed.query)
            if first(query, "demo_batch") != "iam-bulk-delete":
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_demo_batch",
                    "demo_batch must equal iam-bulk-delete",
                )
            response = self.server.executor.execute(BULK_DELETE, mark_activity=True)
            self.send_json(HTTPStatus.OK, response)
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "route_not_found"})


class DirectUserServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], executor: DirectMongoExecutor) -> None:
        self.executor = executor
        super().__init__(address, DirectUserHandler)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    listen_host = "127.0.0.1"
    listen_port = int(os.environ.get("DIRECT_USER_API_LOCAL_PORT", "18082"))
    executor = DirectMongoExecutor()
    server = DirectUserServer((listen_host, listen_port), executor)
    LOG.info(
        "direct-user API listening on http://%s:%d as expected principal %s",
        listen_host,
        listen_port,
        executor.expected_principal,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
