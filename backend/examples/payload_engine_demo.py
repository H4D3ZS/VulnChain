"""
Payload Engine Demo

This script demonstrates the usage of the Payload Engine for:
- Loading wordlists
- Managing payloads with categories
- Applying encodings
- Generating mutations
"""

import tempfile
from pathlib import Path

from app.core.payload_engine import MutationStrategy, PayloadEngine


def demo_wordlist_management():
    """Demonstrate wordlist loading and management"""
    print("=" * 60)
    print("WORDLIST MANAGEMENT DEMO")
    print("=" * 60)

    # Create temporary wordlist files
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create SQL injection wordlist
        sqli_file = Path(tmpdir) / "sqli.txt"
        sqli_file.write_text(
            """# SQL Injection Payloads
' OR 1=1--
' UNION SELECT NULL--
admin' --
' AND 1=2 UNION SELECT NULL--
"""
        )

        # Create XSS wordlist
        xss_file = Path(tmpdir) / "xss.txt"
        xss_file.write_text(
            """<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"""
        )

        # Initialize Payload Engine
        engine = PayloadEngine()

        # Load wordlists
        sqli_count = engine.load_wordlist(str(sqli_file), "sqli")
        xss_count = engine.load_wordlist(str(xss_file), "xss")

        print(f"\nLoaded {sqli_count} SQL injection payloads")
        print(f"Loaded {xss_count} XSS payloads")

        # Add custom payloads
        engine.add_custom_payload("1' OR '1'='1", "sqli")
        engine.add_custom_payload("<iframe src=javascript:alert(1)>", "xss")

        print(f"\nTotal categories: {len(engine.get_categories())}")
        print(f"Categories: {engine.get_categories()}")
        print(f"SQL injection payloads: {engine.get_payload_count('sqli')}")
        print(f"XSS payloads: {engine.get_payload_count('xss')}")

        # Get payloads without encoding
        print("\n--- SQL Injection Payloads (No Encoding) ---")
        for i, payload in enumerate(engine.get_payloads("sqli"), 1):
            print(f"{i}. {payload.original}")


def demo_encoding():
    """Demonstrate payload encoding"""
    print("\n" + "=" * 60)
    print("ENCODING DEMO")
    print("=" * 60)

    engine = PayloadEngine()
    engine.add_custom_payload("<script>alert('XSS')</script>", "xss")

    # Single encodings
    print("\n--- Single Encodings ---")
    encodings = ["url", "html_entity", "base64", "unicode", "hex"]

    for encoding in encodings:
        payloads = list(engine.get_payloads("xss", encoding=[encoding]))
        if payloads:
            print(f"\n{encoding.upper()}:")
            print(f"  Original: {payloads[0].original}")
            print(f"  Encoded:  {payloads[0].encoded}")

    # Encoding chains
    print("\n--- Encoding Chains ---")
    payloads = list(engine.get_payloads("xss", encoding=["url", "base64"]))
    if payloads:
        print(f"\nURL + Base64:")
        print(f"  Original: {payloads[0].original}")
        print(f"  Encoded:  {payloads[0].encoded}")

    # Double URL encoding
    payloads = list(engine.get_payloads("xss", encoding=["double_url"]))
    if payloads:
        print(f"\nDouble URL:")
        print(f"  Original: {payloads[0].original}")
        print(f"  Encoded:  {payloads[0].encoded}")


def demo_filtering():
    """Demonstrate payload filtering"""
    print("\n" + "=" * 60)
    print("FILTERING DEMO")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create wordlist with various lengths
        wordlist = Path(tmpdir) / "test.txt"
        wordlist.write_text(
            """a
bb
ccc
dddd
eeeee
select
insert
update
delete
"""
        )

        engine = PayloadEngine()
        engine.load_wordlist(str(wordlist), "test")

        # Filter by max length
        print("\n--- Filter by Max Length (3) ---")
        payloads = list(engine.get_payloads("test", filters={"max_length": 3}))
        for payload in payloads:
            print(f"  {payload.original} (length: {len(payload.original)})")

        # Filter by contains
        print("\n--- Filter by Contains ('se') ---")
        payloads = list(engine.get_payloads("test", filters={"contains": "se"}))
        for payload in payloads:
            print(f"  {payload.original}")

        # Filter by regex
        print("\n--- Filter by Regex (starts with 'e') ---")
        payloads = list(engine.get_payloads("test", filters={"regex": r"^e"}))
        for payload in payloads:
            print(f"  {payload.original}")


def demo_mutation():
    """Demonstrate payload mutation"""
    print("\n" + "=" * 60)
    print("MUTATION DEMO")
    print("=" * 60)

    engine = PayloadEngine()
    original = "SELECT * FROM users WHERE id=1"

    # Case variation
    print("\n--- Case Variation ---")
    mutations = engine.mutate_payload(original, MutationStrategy.CASE_VARIATION, count=5)
    for i, mutation in enumerate(mutations[:5], 1):
        print(f"{i}. {mutation}")

    # Syntax variation
    print("\n--- Syntax Variation ---")
    mutations = engine.mutate_payload(
        original, MutationStrategy.SYNTAX_VARIATION, count=5
    )
    for i, mutation in enumerate(mutations[:5], 1):
        print(f"{i}. {mutation}")

    # Encoding variation
    print("\n--- Encoding Variation ---")
    mutations = engine.mutate_payload(
        original, MutationStrategy.ENCODING_VARIATION, count=5
    )
    for i, mutation in enumerate(mutations[:5], 1):
        print(f"{i}. {mutation[:60]}...")  # Truncate for display

    # Genetic algorithm
    print("\n--- Genetic Algorithm ---")
    mutations = engine.mutate_payload(original, MutationStrategy.GENETIC, count=5)
    for i, mutation in enumerate(mutations[:5], 1):
        print(f"{i}. {mutation[:60]}...")  # Truncate for display


def demo_complete_workflow():
    """Demonstrate complete attack workflow"""
    print("\n" + "=" * 60)
    print("COMPLETE WORKFLOW DEMO")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create wordlist
        wordlist = Path(tmpdir) / "sqli.txt"
        wordlist.write_text("' OR 1=1--\nadmin' --\n")

        # Initialize engine
        engine = PayloadEngine()
        engine.load_wordlist(str(wordlist), "sqli")

        print("\n--- Original Payloads ---")
        for payload in engine.get_payloads("sqli"):
            print(f"  {payload.original}")

        print("\n--- URL Encoded Payloads ---")
        for payload in engine.get_payloads("sqli", encoding=["url"]):
            print(f"  {payload.encoded}")

        print("\n--- Mutations of First Payload ---")
        first_payload = "' OR 1=1--"
        mutations = engine.mutate_payload(
            first_payload, MutationStrategy.GENETIC, count=3
        )
        for i, mutation in enumerate(mutations, 1):
            print(f"  {i}. {mutation}")


if __name__ == "__main__":
    demo_wordlist_management()
    demo_encoding()
    demo_filtering()
    demo_mutation()
    demo_complete_workflow()

    print("\n" + "=" * 60)
    print("DEMO COMPLETE")
    print("=" * 60)
