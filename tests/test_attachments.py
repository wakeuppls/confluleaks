import unittest

from scanner.attachments import (
    attachment_media_type,
    attachment_size,
    decode_text_attachment,
    is_text_attachment,
)


class AttachmentClassificationTest(unittest.TestCase):
    def test_accepts_text_mime_type(self):
        attachment = {"title": "notes.unknown", "metadata": {"mediaType": "text/plain"}}

        self.assertTrue(is_text_attachment(attachment))

    def test_accepts_safe_extension_for_generic_mime_type(self):
        attachment = {
            "title": "deployment.env",
            "extensions": {"mediaType": "application/octet-stream"},
        }

        self.assertTrue(is_text_attachment(attachment))

    def test_binary_mime_type_overrides_a_text_extension(self):
        attachment = {"title": "renamed.txt", "mediaType": "application/pdf"}

        self.assertFalse(is_text_attachment(attachment))

    def test_unknown_extension_is_not_accepted_without_text_mime(self):
        self.assertFalse(is_text_attachment({"title": "payload.bin"}))

    def test_malformed_nested_metadata_is_treated_as_missing(self):
        attachment = {
            "title": "notes.txt",
            "metadata": None,
            "extensions": "invalid",
        }

        self.assertTrue(is_text_attachment(attachment))
        self.assertIsNone(attachment_size(attachment))

    def test_reads_cloud_and_data_center_metadata_shapes(self):
        cloud = {"mediaType": "application/json", "fileSize": 12}
        data_center = {
            "metadata": {"mediaType": "text/csv; charset=utf-8"},
            "extensions": {"fileSize": "34"},
        }

        self.assertEqual(attachment_media_type(cloud), "application/json")
        self.assertEqual(attachment_size(cloud), 12)
        self.assertEqual(attachment_media_type(data_center), "text/csv")
        self.assertEqual(attachment_size(data_center), 34)


class AttachmentDecodingTest(unittest.TestCase):
    def test_decodes_utf8_and_utf16_bom(self):
        self.assertEqual(decode_text_attachment("ключ=value".encode()), "ключ=value")
        self.assertEqual(
            decode_text_attachment("token=value".encode("utf-16")),
            "token=value",
        )

    def test_rejects_invalid_utf8_and_nul_bytes(self):
        self.assertIsNone(decode_text_attachment(b"\xffbroken"))
        self.assertIsNone(decode_text_attachment(b"abc\x00def"))


if __name__ == "__main__":
    unittest.main()
