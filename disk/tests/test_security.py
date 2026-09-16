import io
import json
import tempfile
import unittest
from pathlib import Path

from app import app


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        app.config.update(
            TESTING=True,
            UPLOAD_FOLDER=self.temporary.name,
            SESSION_COOKIE_SECURE=False,
        )
        self.client = app.test_client()

    def tearDown(self):
        self.temporary.cleanup()

    def login_session(self, username="user1"):
        with self.client.session_transaction() as state:
            state["user"] = username
            state["csrf_token"] = "course-test-token"
            state.permanent = True

    def test_01_unauthenticated_core_routes_are_denied(self):
        self.assertEqual(self.client.get("/listfiles").status_code, 401)
        self.assertEqual(self.client.get("/upload").status_code, 401)
        self.assertEqual(self.client.get("/download?filename=a.txt").status_code, 401)
        self.assertEqual(self.client.post("/delete").status_code, 401)

    def test_02_path_traversal_is_blocked_for_download_and_delete(self):
        self.login_session()
        outside = Path(self.temporary.name).parent / "course_outside_file.txt"
        outside.write_text("must survive", encoding="utf-8")
        try:
            response = self.client.get("/download?filename=../course_outside_file.txt")
            self.assertEqual(response.status_code, 403)
            response = self.client.post(
                "/delete",
                data={"filename": "../course_outside_file.txt", "csrf_token": "course-test-token"},
            )
            self.assertEqual(response.status_code, 403)
            self.assertTrue(outside.exists())
        finally:
            outside.unlink(missing_ok=True)

    def test_03_script_and_fake_image_uploads_are_rejected(self):
        self.login_session()
        script = self.client.post(
            "/upload",
            data={
                "csrf_token": "course-test-token",
                "file": (io.BytesIO(b"COURSE_UPLOAD_TEST_ONLY"), "test.php"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(script.status_code, 415)

        fake_image = self.client.post(
            "/upload",
            data={
                "csrf_token": "course-test-token",
                "file": (io.BytesIO(b"COURSE_FAKE_IMAGE_TEST"), "fake.png"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(fake_image.status_code, 415)

    def test_04_valid_text_upload_is_renamed_and_isolated_by_owner(self):
        self.login_session("user1")
        response = self.client.post(
            "/upload",
            data={
                "csrf_token": "course-test-token",
                "file": (io.BytesIO("这是user1的文件".encode("utf-8")), "user1_secret.txt"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)

        metadata_files = list(Path(self.temporary.name).glob("*/.metadata.json"))
        self.assertEqual(len(metadata_files), 1)
        metadata = json.loads(metadata_files[0].read_text(encoding="utf-8"))
        stored_name = next(iter(metadata))
        self.assertRegex(stored_name, r"^[0-9a-f]{32}\.txt$")
        self.assertEqual(metadata[stored_name]["original_name"], "user1_secret.txt")
        download = self.client.get(f"/download?filename={stored_name}", buffered=True)
        self.assertEqual(download.status_code, 200)
        download.close()

        self.login_session("user2")
        self.assertEqual(self.client.get(f"/download?filename={stored_name}").status_code, 404)

    def test_05_ssti_probe_is_rendered_as_data_not_template(self):
        self.login_session("{{7*7}}")
        page = self.client.get("/listfiles").get_data(as_text=True)
        self.assertIn("{{7*7}}", page)
        self.assertNotIn(">49 的文件<", page)

    def test_06_csrf_is_required_for_state_changes(self):
        self.login_session()
        response = self.client.post(
            "/upload",
            data={"file": (io.BytesIO(b"safe"), "safe.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.post("/logout").status_code, 403)

    def test_07_logout_clears_session_and_old_access_fails(self):
        self.login_session()
        response = self.client.post(
            "/logout", data={"csrf_token": "course-test-token"}, follow_redirects=False
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/listfiles").status_code, 401)

    def test_08_cookie_security_attributes_are_present(self):
        response = self.client.get("/login")
        cookie = response.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_09_no_shell_execution_api_is_used(self):
        source = (Path(__file__).parents[1] / "app.py").read_text(encoding="utf-8")
        for dangerous in ("os.system(", "os.popen(", "shell=True", "render_template_string("):
            self.assertNotIn(dangerous, source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
