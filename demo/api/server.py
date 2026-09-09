#!/usr/bin/env python3
"""Small, deliberately constrained REST application for the MongoDB DAM demo."""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from bson import ObjectId
from pymongo import ASCENDING, MongoClient
from pymongo.errors import DuplicateKeyError, PyMongoError


LOG = logging.getLogger("mongodb-dam-demo-api")
ORDER_PATH = re.compile(r"^/orders/([^/]+)$")
ALLOWED_STATUSES = {"pending", "paid", "processing", "shipped", "cancelled"}
MAX_BODY_BYTES = 64 * 1024


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def json_default(value: Any) -> Any:
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    raise TypeError(f"cannot serialize {type(value).__name__}")


class DemoApplication:
    def __init__(self) -> None:
        host = required_env("MONGODB_HOST")
        port = int(os.environ.get("MONGODB_PORT", "27017"))
        database_name = os.environ.get("MONGODB_DATABASE", "dam_demo").strip()
        if not database_name or not re.fullmatch(r"[A-Za-z0-9_-]+", database_name):
            raise RuntimeError("MONGODB_DATABASE contains unsupported characters")

        options: dict[str, Any] = {
            "host": host,
            "port": port,
            "appname": "mongodb-dam-demo-api",
            "serverSelectionTimeoutMS": 3000,
            "connectTimeoutMS": 3000,
            "tz_aware": True,
        }
        username = os.environ.get("MONGODB_USERNAME", "").strip()
        password = os.environ.get("MONGODB_PASSWORD", "")
        if username:
            options.update(
                username=username,
                password=password,
                authSource=os.environ.get("MONGODB_AUTH_SOURCE", "admin"),
            )
        self.client = MongoClient(**options)
        self.database = self.client[database_name]
        self.customers = self.database["customers"]
        self.orders = self.database["orders"]
        self.customer_records = self.database["customer_records"]

    def health(self) -> dict[str, Any]:
        self.client.admin.command("ping")
        return {"status": "ok", "database": self.database.name}

    def seed(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        customers = [
            {"_id": "cust-001", "name": "Aarav Sharma", "email": "aarav@example.test", "tier": "gold", "created_at": now},
            {"_id": "cust-002", "name": "Maya Patel", "email": "maya@example.test", "tier": "silver", "created_at": now},
            {"_id": "cust-003", "name": "Noah Williams", "email": "noah@example.test", "tier": "bronze", "created_at": now},
            {"_id": "cust-004", "name": "Sofia Garcia", "email": "sofia@example.test", "tier": "gold", "created_at": now},
            {"_id": "cust-005", "name": "Kenji Sato", "email": "kenji@example.test", "tier": "silver", "created_at": now},
        ]
        orders = [
            {"_id": "order-1001", "customer_id": "cust-001", "product": "vector-search-demo", "amount": 149.00, "status": "paid", "created_at": now},
            {"_id": "order-1002", "customer_id": "cust-001", "product": "audit-export", "amount": 79.00, "status": "shipped", "created_at": now},
            {"_id": "order-1003", "customer_id": "cust-002", "product": "dam-starter", "amount": 299.00, "status": "processing", "created_at": now},
            {"_id": "order-1004", "customer_id": "cust-003", "product": "dam-starter", "amount": 299.00, "status": "pending", "created_at": now},
            {"_id": "order-1005", "customer_id": "cust-004", "product": "regional-cell", "amount": 899.00, "status": "paid", "created_at": now},
            {"_id": "order-1006", "customer_id": "cust-004", "product": "audit-export", "amount": 79.00, "status": "cancelled", "created_at": now},
            {"_id": "order-1007", "customer_id": "cust-005", "product": "dam-starter", "amount": 299.00, "status": "shipped", "created_at": now},
            {"_id": "order-1008", "customer_id": "cust-005", "product": "vector-search-demo", "amount": 149.00, "status": "paid", "created_at": now},
        ]
        customer_records = [
            {
                "_id": f"demo-record-{index:03d}",
                "demo_batch": "iam-bulk-delete",
                "owner": f"dummy-user-{index:03d}@example.test",
                "classification": "demo-confidential",
                "created_at": now,
            }
            for index in range(1, 36)
        ]

        self.orders.delete_many({})
        self.customers.delete_many({})
        # Drop/recreate makes reseeding deterministic without generating a
        # misleading bulk-delete finding for the privileged demo API itself.
        self.customer_records.drop()
        self.customers.create_index([("email", ASCENDING)], unique=True)
        self.orders.create_index([("customer_id", ASCENDING), ("status", ASCENDING)])
        self.customers.insert_many(customers)
        self.orders.insert_many(orders)
        self.customer_records.insert_many(customer_records)
        return {
            "status": "seeded",
            "database": self.database.name,
            "customers": len(customers),
            "orders": len(orders),
            "customer_records": len(customer_records),
        }

    def list_customers(self, email: str | None) -> list[dict[str, Any]]:
        query = {"email": email} if email else {}
        return list(self.customers.find(query).sort("_id", ASCENDING).limit(50))

    def list_orders(self, customer_id: str | None, status: str | None) -> list[dict[str, Any]]:
        query: dict[str, Any] = {}
        if customer_id:
            query["customer_id"] = customer_id
        if status:
            query["status"] = status
        return list(self.orders.find(query).sort("_id", ASCENDING).limit(50))

    def create_order(self, payload: dict[str, Any]) -> dict[str, Any]:
        for field in ("customer_id", "product", "amount"):
            if field not in payload:
                raise ValueError(f"{field} is required")
        if not isinstance(payload["customer_id"], str) or not payload["customer_id"].strip():
            raise ValueError("customer_id must be a non-empty string")
        if not isinstance(payload["product"], str) or not payload["product"].strip():
            raise ValueError("product must be a non-empty string")
        if not isinstance(payload["amount"], (int, float)) or payload["amount"] < 0:
            raise ValueError("amount must be a non-negative number")
        status = payload.get("status", "pending")
        if status not in ALLOWED_STATUSES:
            raise ValueError(f"status must be one of {sorted(ALLOWED_STATUSES)}")
        if self.customers.find_one({"_id": payload["customer_id"]}) is None:
            raise ValueError("customer_id does not exist")

        order = {
            "_id": payload.get("order_id", f"order-{uuid.uuid4().hex[:12]}"),
            "customer_id": payload["customer_id"],
            "product": payload["product"],
            "amount": float(payload["amount"]),
            "status": status,
            "created_at": datetime.now(timezone.utc),
        }
        self.orders.insert_one(order)
        return order

    def update_order(self, order_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        status = payload.get("status")
        if status not in ALLOWED_STATUSES:
            raise ValueError(f"status must be one of {sorted(ALLOWED_STATUSES)}")
        result = self.orders.update_one(
            {"_id": order_id},
            {"$set": {"status": status, "updated_at": datetime.now(timezone.utc)}},
        )
        if result.matched_count == 0:
            raise LookupError("order not found")
        return self.orders.find_one({"_id": order_id}) or {}

    def delete_order(self, order_id: str) -> dict[str, Any]:
        result = self.orders.delete_one({"_id": order_id})
        if result.deleted_count == 0:
            raise LookupError("order not found")
        return {"status": "deleted", "order_id": order_id}

    def revenue_by_status(self) -> list[dict[str, Any]]:
        return list(
            self.orders.aggregate(
                [
                    {"$group": {"_id": "$status", "orders": {"$sum": 1}, "revenue": {"$sum": "$amount"}}},
                    {"$sort": {"revenue": -1}},
                ]
            )
        )

    def workload(self) -> dict[str, Any]:
        """Generate a recognizable find/insert/update/aggregate/delete sequence."""
        customer = self.customers.find_one({"email": "aarav@example.test"})
        if customer is None:
            raise ValueError("seed the demo before running the workload")
        order = self.create_order(
            {
                "customer_id": customer["_id"],
                "product": "live-demo-order",
                "amount": 42.50,
                "status": "pending",
            }
        )
        updated = self.update_order(order["_id"], {"status": "paid"})
        aggregation = self.revenue_by_status()
        deleted = self.delete_order(order["_id"])
        return {
            "status": "completed",
            "operations": ["find", "insert", "update", "aggregate", "delete"],
            "temporary_order": updated,
            "cleanup": deleted,
            "aggregation": aggregation,
        }


class DemoHandler(BaseHTTPRequestHandler):
    server: "DemoServer"
    protocol_version = "HTTP/1.1"
    server_version = "mongodb-dam-demo-api/0.1"

    def log_message(self, message: str, *args: Any) -> None:
        LOG.info("client=%s %s", self.client_address[0], message % args)

    def send_json(self, status: HTTPStatus, body: Any) -> None:
        encoded = json.dumps(body, default=json_default, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def read_json(self) -> dict[str, Any]:
        try:
            content_length = int(self.headers.get("content-length", "0"))
        except ValueError as error:
            raise ValueError("invalid content-length") from error
        if content_length <= 0 or content_length > MAX_BODY_BYTES:
            raise ValueError(f"body must be between 1 and {MAX_BODY_BYTES} bytes")
        try:
            decoded = json.loads(self.rfile.read(content_length))
        except json.JSONDecodeError as error:
            raise ValueError("body must be valid JSON") from error
        if not isinstance(decoded, dict):
            raise ValueError("body must be a JSON object")
        return decoded

    def dispatch(self, action: Any) -> None:
        try:
            action()
        except ValueError as error:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
        except LookupError as error:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": str(error)})
        except DuplicateKeyError:
            self.send_json(HTTPStatus.CONFLICT, {"error": "document already exists"})
        except PyMongoError as error:
            LOG.exception("MongoDB request failed")
            self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": type(error).__name__})
        except Exception:
            LOG.exception("unexpected request failure")
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"})

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self.dispatch(self._do_get)

    def _do_get(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/":
            self.send_json(
                HTTPStatus.OK,
                {
                    "service": "mongodb-dam-demo-api",
                    "endpoints": [
                        "POST /demo/seed",
                        "POST /demo/workload",
                        "GET /customers?email=...",
                        "GET /orders?customer_id=...&status=...",
                        "POST /orders",
                        "PATCH /orders/{order_id}",
                        "DELETE /orders/{order_id}",
                        "GET /analytics/revenue-by-status",
                    ],
                },
            )
        elif parsed.path == "/health":
            self.send_json(HTTPStatus.OK, self.server.application.health())
        elif parsed.path == "/customers":
            self.send_json(
                HTTPStatus.OK,
                {"customers": self.server.application.list_customers(first(query, "email"))},
            )
        elif parsed.path == "/orders":
            self.send_json(
                HTTPStatus.OK,
                {
                    "orders": self.server.application.list_orders(
                        first(query, "customer_id"), first(query, "status")
                    )
                },
            )
        elif parsed.path == "/analytics/revenue-by-status":
            self.send_json(
                HTTPStatus.OK,
                {"results": self.server.application.revenue_by_status()},
            )
        else:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "route not found"})

    def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self.dispatch(self._do_post)

    def _do_post(self) -> None:
        path = urlparse(self.path).path
        if path == "/demo/seed":
            self.send_json(HTTPStatus.OK, self.server.application.seed())
        elif path == "/demo/workload":
            self.send_json(HTTPStatus.OK, self.server.application.workload())
        elif path == "/orders":
            self.send_json(
                HTTPStatus.CREATED,
                self.server.application.create_order(self.read_json()),
            )
        else:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "route not found"})

    def do_PATCH(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self.dispatch(self._do_patch)

    def _do_patch(self) -> None:
        match = ORDER_PATH.fullmatch(urlparse(self.path).path)
        if match is None:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "route not found"})
            return
        self.send_json(
            HTTPStatus.OK,
            self.server.application.update_order(unquote(match.group(1)), self.read_json()),
        )

    def do_DELETE(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        self.dispatch(self._do_delete)

    def _do_delete(self) -> None:
        match = ORDER_PATH.fullmatch(urlparse(self.path).path)
        if match is None:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "route not found"})
            return
        self.send_json(
            HTTPStatus.OK,
            self.server.application.delete_order(unquote(match.group(1))),
        )


class DemoServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], application: DemoApplication) -> None:
        self.application = application
        super().__init__(address, DemoHandler)


def first(query: dict[str, list[str]], name: str) -> str | None:
    values = query.get(name)
    return values[0] if values else None


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    listen_host = os.environ.get("DEMO_API_LISTEN_HOST", "0.0.0.0")
    listen_port = int(os.environ.get("DEMO_API_LISTEN_PORT", "8080"))
    application = DemoApplication()
    server = DemoServer((listen_host, listen_port), application)
    LOG.info("demo API listening on %s:%d", listen_host, listen_port)
    server.serve_forever()


if __name__ == "__main__":
    main()
