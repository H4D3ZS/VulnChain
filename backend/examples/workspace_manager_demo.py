"""Demo script for Workspace Manager"""

import sys
from pathlib import Path
from datetime import datetime, timezone

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.workspace_manager import WorkspaceManager, Finding
from app.models.target import TargetConfig, Session


def main():
    """Demonstrate Workspace Manager functionality"""
    
    print("=" * 60)
    print("Workspace Manager Demo")
    print("=" * 60)
    print()
    
    # Initialize workspace manager with demo directory
    demo_path = Path("./demo_workspaces")
    manager = WorkspaceManager(base_path=demo_path)
    
    # 1. Create workspaces
    print("1. Creating workspaces...")
    workspace1 = manager.create_workspace(
        name="HackTheBox - Easy Web Challenge",
        metadata={
            "platform": "HackTheBox",
            "difficulty": "Easy",
            "category": "Web",
            "points": 20
        }
    )
    print(f"   Created: {workspace1.name} ({workspace1.workspace_id})")
    
    workspace2 = manager.create_workspace(
        name="CTFd - SQL Injection Challenge",
        metadata={
            "platform": "CTFd",
            "difficulty": "Medium",
            "category": "Web",
            "points": 50
        }
    )
    print(f"   Created: {workspace2.name} ({workspace2.workspace_id})")
    print()
    
    # 2. List workspaces
    print("2. Listing all workspaces...")
    workspaces = manager.list_workspaces()
    for ws in workspaces:
        print(f"   - {ws.name} (ID: {ws.workspace_id[:8]}...)")
    print()
    
    # 3. Update target configuration
    print("3. Updating target configuration...")
    target = TargetConfig(
        url="https://example.com",
        custom_headers={
            "X-API-Key": "demo-key-123",
            "User-Agent": "VulnChain/1.0"
        },
        waf_bypass_profile="cloudflare"
    )
    manager.update_target(workspace1.workspace_id, target)
    print(f"   Target URL: {target.url}")
    print(f"   Custom headers: {len(target.custom_headers)} headers")
    print()
    
    # 4. Update session
    print("4. Updating session...")
    session = Session(
        session_id="demo-session-123",
        domain="example.com",
        cookies={"session": "abc123", "user": "admin"},
        headers={"Authorization": "Bearer token123"}
    )
    manager.update_session(workspace1.workspace_id, session)
    print(f"   Session ID: {session.session_id}")
    print(f"   Cookies: {len(session.cookies)} cookies")
    print()
    
    # 5. Save findings
    print("5. Saving findings...")
    
    finding1 = Finding(
        finding_id="finding-001",
        workspace_id=workspace1.workspace_id,
        vulnerability_type="SQL Injection",
        severity="critical",
        title="SQL Injection in login form",
        description="The login form is vulnerable to SQL injection via the username parameter.",
        affected_url="https://example.com/login",
        proof_of_concept="Username: ' OR '1'='1' --\nPassword: anything",
        remediation="Use parameterized queries or prepared statements.",
        discovered_at=datetime.now(timezone.utc),
        flags=["CTF{sql_injection_is_easy}"]
    )
    manager.save_finding(workspace1.workspace_id, finding1)
    print(f"   Saved: {finding1.title}")
    
    finding2 = Finding(
        finding_id="finding-002",
        workspace_id=workspace1.workspace_id,
        vulnerability_type="XSS",
        severity="high",
        title="Reflected XSS in search parameter",
        description="The search parameter reflects user input without sanitization.",
        affected_url="https://example.com/search?q=<script>alert(1)</script>",
        proof_of_concept="<script>alert(document.cookie)</script>",
        remediation="Implement proper output encoding and Content Security Policy.",
        discovered_at=datetime.now(timezone.utc),
        flags=["CTF{xss_reflected}"]
    )
    manager.save_finding(workspace1.workspace_id, finding2)
    print(f"   Saved: {finding2.title}")
    
    finding3 = Finding(
        finding_id="finding-003",
        workspace_id=workspace1.workspace_id,
        vulnerability_type="Information Disclosure",
        severity="medium",
        title="Exposed .git directory",
        description="The .git directory is publicly accessible.",
        affected_url="https://example.com/.git/",
        proof_of_concept="curl https://example.com/.git/config",
        remediation="Block access to .git directory in web server configuration.",
        discovered_at=datetime.now(timezone.utc),
        flags=[]
    )
    manager.save_finding(workspace1.workspace_id, finding3)
    print(f"   Saved: {finding3.title}")
    print()
    
    # 6. Retrieve findings
    print("6. Retrieving findings...")
    all_findings = manager.get_findings(workspace1.workspace_id)
    print(f"   Total findings: {len(all_findings)}")
    
    critical_findings = manager.get_findings(workspace1.workspace_id, severity="critical")
    print(f"   Critical findings: {len(critical_findings)}")
    
    sqli_findings = manager.get_findings(workspace1.workspace_id, vulnerability_type="SQL Injection")
    print(f"   SQL Injection findings: {len(sqli_findings)}")
    print()
    
    # 7. Get workspace statistics
    print("7. Workspace statistics...")
    stats = manager.get_workspace_stats(workspace1.workspace_id)
    print(f"   Workspace: {stats['name']}")
    print(f"   Total findings: {stats['total_findings']}")
    print(f"   Severity breakdown:")
    print(f"     - Critical: {stats['severity_counts']['critical']}")
    print(f"     - High: {stats['severity_counts']['high']}")
    print(f"     - Medium: {stats['severity_counts']['medium']}")
    print(f"     - Low: {stats['severity_counts']['low']}")
    print(f"     - Info: {stats['severity_counts']['info']}")
    print(f"   Total flags: {stats['total_flags']}")
    print(f"   Has target: {stats['has_target']}")
    print(f"   Has session: {stats['has_session']}")
    print()
    
    # 8. Switch workspace
    print("8. Switching workspace...")
    current = manager.get_current_workspace()
    print(f"   Current workspace: {current.name}")
    
    manager.switch_workspace(workspace2.workspace_id)
    current = manager.get_current_workspace()
    print(f"   Switched to: {current.name}")
    print()
    
    # 9. Export workspace
    print("9. Exporting workspace...")
    archive_data = manager.export_workspace(workspace1.workspace_id)
    print(f"   Exported {len(archive_data)} bytes")
    
    # Save to file
    export_file = demo_path / "workspace_export.tar.gz"
    with open(export_file, "wb") as f:
        f.write(archive_data)
    print(f"   Saved to: {export_file}")
    print()
    
    # 10. Import workspace (simulate by deleting and re-importing)
    print("10. Testing workspace import...")
    
    # Delete the workspace
    manager.delete_workspace(workspace1.workspace_id)
    print(f"   Deleted workspace: {workspace1.workspace_id[:8]}...")
    
    # Re-import from archive
    with open(export_file, "rb") as f:
        archive_data = f.read()
    
    imported_workspace = manager.import_workspace(archive_data)
    print(f"   Imported workspace: {imported_workspace.name}")
    print(f"   Findings restored: {len(imported_workspace.findings)}")
    print(f"   Target restored: {imported_workspace.target is not None}")
    print(f"   Session restored: {imported_workspace.session is not None}")
    print()
    
    # 11. Verify round-trip
    print("11. Verifying round-trip integrity...")
    restored_findings = manager.get_findings(imported_workspace.workspace_id)
    print(f"   Original findings: 3")
    print(f"   Restored findings: {len(restored_findings)}")
    
    restored_stats = manager.get_workspace_stats(imported_workspace.workspace_id)
    print(f"   Original flags: 2")
    print(f"   Restored flags: {restored_stats['total_flags']}")
    
    if len(restored_findings) == 3 and restored_stats['total_flags'] == 2:
        print("   ✓ Round-trip successful!")
    else:
        print("   ✗ Round-trip failed!")
    print()
    
    print("=" * 60)
    print("Demo completed successfully!")
    print("=" * 60)
    print()
    print(f"Demo workspaces created in: {demo_path.absolute()}")
    print("You can inspect the workspace structure and files.")


if __name__ == "__main__":
    main()
