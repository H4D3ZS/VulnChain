"""Tests for Payload Engine"""

import tempfile
from pathlib import Path

import pytest

from app.core.payload_engine import (
    EncodingType,
    MutationStrategy,
    Payload,
    PayloadEngine,
)


class TestPayloadEngineWordlistManagement:
    """Test wordlist loading and management"""

    def test_load_wordlist_success(self, tmp_path):
        """Test loading a valid wordlist"""
        # Create test wordlist
        wordlist = tmp_path / "test.txt"
        wordlist.write_text("payload1\npayload2\npayload3\n")

        engine = PayloadEngine()
        count = engine.load_wordlist(str(wordlist), "test")

        assert count == 3
        assert engine.get_payload_count("test") == 3

    def test_load_wordlist_with_comments(self, tmp_path):
        """Test loading wordlist with comments"""
        wordlist = tmp_path / "test.txt"
        wordlist.write_text("# Comment\npayload1\n# Another comment\npayload2\n")

        engine = PayloadEngine()
        count = engine.load_wordlist(str(wordlist), "test")

        assert count == 2
        assert engine.get_payload_count("test") == 2

    def test_load_wordlist_with_empty_lines(self, tmp_path):
        """Test loading wordlist with empty lines"""
        wordlist = tmp_path / "test.txt"
        wordlist.write_text("payload1\n\npayload2\n\n\npayload3\n")

        engine = PayloadEngine()
        count = engine.load_wordlist(str(wordlist), "test")

        assert count == 3

    def test_load_wordlist_file_not_found(self):
        """Test loading non-existent wordlist"""
        engine = PayloadEngine()

        with pytest.raises(FileNotFoundError):
            engine.load_wordlist("/nonexistent/file.txt", "test")

    def test_load_wordlist_empty_file(self, tmp_path):
        """Test loading empty wordlist"""
        wordlist = tmp_path / "empty.txt"
        wordlist.write_text("")

        engine = PayloadEngine()

        with pytest.raises(ValueError, match="empty"):
            engine.load_wordlist(str(wordlist), "test")

    def test_load_multiple_wordlists_same_category(self, tmp_path):
        """Test loading multiple wordlists into same category"""
        wordlist1 = tmp_path / "test1.txt"
        wordlist1.write_text("payload1\npayload2\n")

        wordlist2 = tmp_path / "test2.txt"
        wordlist2.write_text("payload3\npayload4\n")

        engine = PayloadEngine()
        engine.load_wordlist(str(wordlist1), "test")
        engine.load_wordlist(str(wordlist2), "test")

        assert engine.get_payload_count("test") == 4

    def test_add_custom_payload(self):
        """Test adding custom payloads"""
        engine = PayloadEngine()
        engine.add_custom_payload("custom1", "test")
        engine.add_custom_payload("custom2", "test")

        assert engine.get_payload_count("test") == 2

    def test_get_categories(self, tmp_path):
        """Test getting all categories"""
        wordlist = tmp_path / "test.txt"
        wordlist.write_text("payload1\n")

        engine = PayloadEngine()
        engine.load_wordlist(str(wordlist), "sqli")
        engine.add_custom_payload("custom", "xss")

        categories = engine.get_categories()
        assert "sqli" in categories
        assert "xss" in categories
        assert len(categories) == 2

    def test_clear_category(self, tmp_path):
        """Test clearing a category"""
        wordlist = tmp_path / "test.txt"
        wordlist.write_text("payload1\npayload2\n")

        engine = PayloadEngine()
        engine.load_wordlist(str(wordlist), "test")
        assert engine.get_payload_count("test") == 2

        engine.clear_category("test")
        assert engine.get_payload_count("test") == 0


class TestPayloadEngineIteration:
    """Test payload iteration and delivery"""

    def test_get_payloads_no_encoding(self, tmp_path):
        """Test getting payloads without encoding"""
        wordlist = tmp_path / "test.txt"
        wordlist.write_text("payload1\npayload2\n")

        engine = PayloadEngine()
        engine.load_wordlist(str(wordlist), "test")

        payloads = list(engine.get_payloads("test"))
        assert len(payloads) == 2
        assert payloads[0].original == "payload1"
        assert payloads[0].encoded == "payload1"
        assert payloads[1].original == "payload2"

    def test_get_payloads_empty_category(self):
        """Test getting payloads from empty category"""
        engine = PayloadEngine()
        payloads = list(engine.get_payloads("nonexistent"))
        assert len(payloads) == 0

    def test_get_payloads_with_filters_max_length(self, tmp_path):
        """Test filtering by max length"""
        wordlist = tmp_path / "test.txt"
        wordlist.write_text("a\nbb\nccc\ndddd\n")

        engine = PayloadEngine()
        engine.load_wordlist(str(wordlist), "test")

        payloads = list(engine.get_payloads("test", filters={"max_length": 2}))
        assert len(payloads) == 2
        assert all(len(p.original) <= 2 for p in payloads)

    def test_get_payloads_with_filters_contains(self, tmp_path):
        """Test filtering by contains"""
        wordlist = tmp_path / "test.txt"
        wordlist.write_text("select\nunion\ninsert\nupdate\n")

        engine = PayloadEngine()
        engine.load_wordlist(str(wordlist), "test")

        payloads = list(engine.get_payloads("test", filters={"contains": "se"}))
        assert len(payloads) == 2  # select, insert

    def test_get_payloads_with_filters_regex(self, tmp_path):
        """Test filtering by regex"""
        wordlist = tmp_path / "test.txt"
        wordlist.write_text("test1\ntest2\nother\n")

        engine = PayloadEngine()
        engine.load_wordlist(str(wordlist), "test")

        payloads = list(engine.get_payloads("test", filters={"regex": r"test\d"}))
        assert len(payloads) == 2


class TestPayloadEngineEncoding:
    """Test payload encoding"""

    def test_encode_url(self):
        """Test URL encoding"""
        engine = PayloadEngine()
        encoded = engine.encode_payload("hello world", "url")
        assert encoded == "hello%20world"

    def test_encode_double_url(self):
        """Test double URL encoding"""
        engine = PayloadEngine()
        encoded = engine.encode_payload("hello world", "double_url")
        assert encoded == "hello%2520world"

    def test_encode_html_entity(self):
        """Test HTML entity encoding"""
        engine = PayloadEngine()
        encoded = engine.encode_payload("<script>", "html_entity")
        assert "&lt;" in encoded
        assert "&gt;" in encoded

    def test_encode_base64(self):
        """Test Base64 encoding"""
        engine = PayloadEngine()
        encoded = engine.encode_payload("hello", "base64")
        assert encoded == "aGVsbG8="

    def test_encode_unicode(self):
        """Test Unicode encoding"""
        engine = PayloadEngine()
        encoded = engine.encode_payload("ab", "unicode")
        assert encoded == "\\u0061\\u0062"

    def test_encode_hex(self):
        """Test Hex encoding"""
        engine = PayloadEngine()
        encoded = engine.encode_payload("ab", "hex")
        assert encoded == "\\x61\\x62"

    def test_encode_invalid_type(self):
        """Test invalid encoding type"""
        engine = PayloadEngine()
        with pytest.raises(ValueError):
            engine.encode_payload("test", "invalid")

    def test_encoding_chain(self, tmp_path):
        """Test applying multiple encodings"""
        wordlist = tmp_path / "test.txt"
        wordlist.write_text("test\n")

        engine = PayloadEngine()
        engine.load_wordlist(str(wordlist), "test")

        payloads = list(engine.get_payloads("test", encoding=["url", "base64"]))
        assert len(payloads) == 1
        # First URL encoded, then Base64
        assert payloads[0].encoded != "test"
        assert payloads[0].encoding_chain == ["url", "base64"]

    def test_encoding_preserves_original(self, tmp_path):
        """Test that encoding preserves original payload"""
        wordlist = tmp_path / "test.txt"
        wordlist.write_text("test\n")

        engine = PayloadEngine()
        engine.load_wordlist(str(wordlist), "test")

        payloads = list(engine.get_payloads("test", encoding=["url"]))
        assert payloads[0].original == "test"
        assert payloads[0].encoded == "test"  # "test" has no special chars


class TestPayloadEngineMutation:
    """Test payload mutation"""

    def test_mutate_encoding_variation(self):
        """Test encoding variation mutations"""
        engine = PayloadEngine()
        mutations = engine.mutate_payload(
            "test", MutationStrategy.ENCODING_VARIATION, count=5
        )

        assert len(mutations) <= 5
        assert len(mutations) > 0
        # Should have different encodings
        assert len(set(mutations)) > 1

    def test_mutate_case_variation(self):
        """Test case variation mutations"""
        engine = PayloadEngine()
        mutations = engine.mutate_payload(
            "TeSt", MutationStrategy.CASE_VARIATION, count=5
        )

        assert len(mutations) == 5
        # Should have different cases
        assert "test" in mutations or "TEST" in mutations

    def test_mutate_syntax_variation(self):
        """Test syntax variation mutations"""
        engine = PayloadEngine()
        mutations = engine.mutate_payload(
            "SELECT * FROM users", MutationStrategy.SYNTAX_VARIATION, count=5
        )

        assert len(mutations) == 5
        # Should have variations
        assert len(set(mutations)) > 1

    def test_mutate_genetic(self):
        """Test genetic algorithm mutations"""
        engine = PayloadEngine()
        mutations = engine.mutate_payload(
            "test payload", MutationStrategy.GENETIC, count=10
        )

        assert len(mutations) == 10
        # Should have variety
        assert len(set(mutations)) > 3

    def test_mutate_preserves_semantics(self):
        """Test that mutations preserve semantic meaning"""
        engine = PayloadEngine()
        original = "SELECT * FROM users"
        mutations = engine.mutate_payload(
            original, MutationStrategy.SYNTAX_VARIATION, count=5
        )

        # All mutations should contain key SQL keywords
        for mutation in mutations:
            # At least some SQL structure should be preserved
            assert any(
                keyword in mutation.upper()
                for keyword in ["SELECT", "FROM", "USERS", "*"]
            )


class TestPayloadEngineIntegration:
    """Integration tests"""

    def test_complete_workflow(self, tmp_path):
        """Test complete payload workflow"""
        # Create wordlist
        wordlist = tmp_path / "sqli.txt"
        wordlist.write_text("' OR 1=1--\n' UNION SELECT NULL--\n")

        # Initialize engine
        engine = PayloadEngine()
        engine.load_wordlist(str(wordlist), "sqli")
        engine.add_custom_payload("admin' --", "sqli")

        # Get payloads with encoding
        payloads = list(engine.get_payloads("sqli", encoding=["url"]))

        assert len(payloads) == 3
        assert all(isinstance(p, Payload) for p in payloads)
        assert all(p.category == "sqli" for p in payloads)

    def test_multiple_categories(self, tmp_path):
        """Test managing multiple categories"""
        sqli_list = tmp_path / "sqli.txt"
        sqli_list.write_text("' OR 1=1--\n")

        xss_list = tmp_path / "xss.txt"
        xss_list.write_text("<script>alert(1)</script>\n")

        engine = PayloadEngine()
        engine.load_wordlist(str(sqli_list), "sqli")
        engine.load_wordlist(str(xss_list), "xss")

        assert engine.get_payload_count("sqli") == 1
        assert engine.get_payload_count("xss") == 1
        assert len(engine.get_categories()) == 2
