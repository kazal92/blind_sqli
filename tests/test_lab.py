import os
import unittest
from unittest.mock import Mock, patch

from test_web.app import create_app


class LabTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(
            os.environ,
            {"DB2_DATABASE": "lab", "DB2_USER": "example", "DB2_PASSWORD": "test-only-password"},
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.driver = Mock()
        self.driver.connect.return_value = "connection"
        self.driver.prepare.return_value = "statement"
        self.app = create_app(self.driver)
        self.app.testing = True
        self.client = self.app.test_client()

    def test_html_success_failure_and_connection_cleanup(self):
        self.driver.fetch_assoc.return_value = {"ID": 1}
        success = self.client.get(
            "/db2", query_string={"username": "example", "password": "example"}
        )
        self.driver.fetch_assoc.return_value = False
        failure = self.client.post("/db2", data={"username": "example", "password": "wrong"})
        self.assertEqual(success.status_code, 200)
        self.assertEqual(failure.status_code, 200)
        self.assertGreater(len(success.data) - len(failure.data), 20)
        self.assertEqual(self.driver.close.call_count, 2)
        self.assertEqual(self.driver.free_stmt.call_count, 2)

    def test_json_support_and_response_length_difference(self):
        self.driver.fetch_assoc.return_value = {"ID": 1}
        success = self.client.post("/api/db2", json={"username": "a", "password": "b"})
        self.driver.fetch_assoc.return_value = False
        failure = self.client.post("/api/db2", json={"username": "a", "password": "wrong"})
        self.assertEqual((success.status_code, failure.status_code), (200, 200))
        self.assertEqual(failure.json["status"], 401)
        self.assertGreater(len(success.data) - len(failure.data), 20)

    def test_missing_and_malformed_json(self):
        for body in [None, [], {}, {"username": 123, "password": "a"}]:
            with self.subTest(body=body):
                response = self.client.post("/api/db2", json=body)
                self.assertEqual(response.status_code, 400)
        self.driver.connect.assert_not_called()

    def test_driver_failure_does_not_expose_credentials(self):
        self.driver.execute.side_effect = RuntimeError("test-only-password")
        response = self.client.post("/api/db2", json={"username": "a", "password": "b"})
        self.assertEqual(response.status_code, 500)
        self.assertNotIn(b"test-only-password", response.data)
        self.driver.close.assert_called_once_with("connection")
        self.driver.free_stmt.assert_called_once_with("statement")

    def test_missing_environment_returns_controlled_failure(self):
        with patch.dict(os.environ, {}, clear=True):
            response = self.client.get("/api/ping-db2")
        self.assertEqual(response.status_code, 500)
        self.driver.connect.assert_not_called()
