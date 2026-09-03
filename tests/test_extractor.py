import unittest

from scanner.extractor import extract_text


class ExtractorTest(unittest.TestCase):
    def test_extracts_storage_html_and_preserves_blocks(self):
        storage = "<h1>Deploy</h1><p>password: value&amp;more</p><pre>a=1\nb=2</pre>"

        text = extract_text(storage)

        self.assertEqual(text, "Deploy\npassword: value&more\na=1\nb=2")

    def test_ignores_script_and_style_content(self):
        storage = "<p>visible</p><script>secret=hidden</script><style>token</style>"

        self.assertEqual(extract_text(storage), "visible")


if __name__ == "__main__":
    unittest.main()
