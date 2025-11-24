"""Unit tests for Workspace Manager"""

import pytest
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone

from app.core.workspace_manager import WorkspaceManager, Workspace, Finding
from app.models.target import TargetConfig, Session


@pytest.fixture
def temp_workspace_dir():
    """Create a temporary directory for workspaces"""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    # Cleanup
    shutil.rmtree(temp_dir)


@pytest.fixture
def manager(temp_workspace_dir):
    """Create a WorkspaceManager instance with temporary directory"""
    return WorkspaceManager(base_path=temp_workspace_dir)


@pytest.fixture
def sample_target():
    """Create a sample target configuration"""
    return TargetConfig(
        url="https://example.com",
        custom_headers={"X-API-Key": "test-key"},
        waf_bypass_profile="cloudflare"
    )


@pytest.fixture
def sample_session():
    """Create a sample session"""
    return Session(
        session_id="test-session-123",
        domain="example.com",
        cookies={"session": "abc123"},
        headers={"Authorization": "Bearer token"}
    )


@pytest.fixture
def sample_finding():
    """Create a sample finding"""
    return Finding(
        finding_id="finding-001",
        workspace_id="test-workspace",
        vulnerability_type="SQL Injection",
        severity="critical",
        title="SQL Injection in login",
        description="SQL injection vulnerability found",
        affected_url="https://example.com/login",
        proof_of_concept="' OR '1'='1",
        remediation="Use parameterized queries",
        discovered_at=datetime.now(timezone.utc),
        flags=["CTF{test_flag}"]
    )


class TestFinding:
    """Test suite for Finding model"""
    
    def test_finding_creation(self, sample_finding):
        """Test creating a Finding object"""
        assert sample_finding.finding_id == "finding-001"
        assert sample_finding.vulnerability_type == "SQL Injection"
        assert sample_finding.severity == "critical"
        assert len(sample_finding.flags) == 1
    
    def test_finding_to_dict(self, sample_finding):
        """Test converting finding to dictionary"""
        data = sample_finding.to_dict()
        
        assert data["finding_id"] == "finding-001"
        assert data["vulnerability_type"] == "SQL Injection"
        assert data["severity"] == "critical"
        assert isinstance(data["discovered_at"], str)
        assert len(data["flags"]) == 1
    
    def test_finding_from_dict(self, sample_finding):
        """Test creating finding from dictionary"""
        data = sample_finding.to_dict()
        restored = Finding.from_dict(data)
        
        assert restored.finding_id == sample_finding.finding_id
        assert restored.vulnerability_type == sample_finding.vulnerability_type
        assert restored.severity == sample_finding.severity
        assert len(restored.flags) == len(sample_finding.flags)
    
    def test_finding_round_trip(self, sample_finding):
        """Test finding serialization round-trip"""
        data = sample_finding.to_dict()
        restored = Finding.from_dict(data)
        
        assert restored.finding_id == sample_finding.finding_id
        assert restored.title == sample_finding.title
        assert restored.flags == sample_finding.flags


class TestWorkspace:
    """Test suite for Workspace model"""
    
    def test_workspace_creation(self):
        """Test creating a Workspace object"""
        workspace = Workspace(
            workspace_id="test-id",
            name="Test Workspace"
        )
        
        assert workspace.workspace_id == "test-id"
        assert workspace.name == "Test Workspace"
        assert workspace.target is None
        assert len(workspace.findings) == 0
        assert workspace.session is None
    
    def test_workspace_to_dict(self, sample_target, sample_session, sample_finding):
        """Test converting workspace to dictionary"""
        workspace = Workspace(
            workspace_id="test-id",
            name="Test Workspace",
            target=sample_target,
            session=sample_session,
            findings=[sample_finding]
        )
        
        data = workspace.to_dict()
        
        assert data["workspace_id"] == "test-id"
        assert data["name"] == "Test Workspace"
        assert data["target"] is not None
        assert data["session"] is not None
        assert len(data["findings"]) == 1
    
    def test_workspace_from_dict(self, sample_target, sample_session, sample_finding):
        """Test creating workspace from dictionary"""
        workspace = Workspace(
            workspace_id="test-id",
            name="Test Workspace",
            target=sample_target,
            session=sample_session,
            findings=[sample_finding]
        )
        
        data = workspace.to_dict()
        restored = Workspace.from_dict(data)
        
        assert restored.workspace_id == workspace.workspace_id
        assert restored.name == workspace.name
        assert restored.target is not None
        assert restored.session is not None
        assert len(restored.findings) == 1


class TestWorkspaceManager:
    """Test suite for WorkspaceManager"""
    
    def test_manager_initialization(self, manager, temp_workspace_dir):
        """Test WorkspaceManager initialization"""
        assert manager.base_path == temp_workspace_dir
        assert temp_workspace_dir.exists()
        assert len(manager.list_workspaces()) == 0
    
    def test_create_workspace(self, manager):
        """Test creating a workspace"""
        workspace = manager.create_workspace(
            name="Test Workspace",
            metadata={"platform": "HackTheBox"}
        )
        
        assert workspace is not None
        assert workspace.name == "Test Workspace"
        assert workspace.metadata["platform"] == "HackTheBox"
        assert workspace.workspace_id is not None
        
        # Verify workspace directory was created
        workspace_path = manager._get_workspace_path(workspace.workspace_id)
        assert workspace_path.exists()
        assert (workspace_path / "workspace.json").exists()
        assert (workspace_path / "findings").exists()
        assert (workspace_path / "logs").exists()
        assert (workspace_path / "evidence").exists()
    
    def test_create_workspace_sets_current(self, manager):
        """Test that first workspace becomes current"""
        workspace = manager.create_workspace(name="First Workspace")
        
        current = manager.get_current_workspace()
        assert current is not None
        assert current.workspace_id == workspace.workspace_id
    
    def test_load_workspace(self, manager):
        """Test loading a workspace"""
        # Create workspace
        created = manager.create_workspace(name="Test Workspace")
        
        # Clear from memory
        manager._workspaces.clear()
        
        # Load workspace
        loaded = manager.load_workspace(created.workspace_id)
        
        assert loaded is not None
        assert loaded.workspace_id == created.workspace_id
        assert loaded.name == created.name
    
    def test_load_workspace_not_found(self, manager):
        """Test loading non-existent workspace raises error"""
        with pytest.raises(ValueError, match="Workspace .* not found"):
            manager.load_workspace("non-existent-id")
    
    def test_get_workspace(self, manager):
        """Test getting a workspace"""
        created = manager.create_workspace(name="Test Workspace")
        
        workspace = manager.get_workspace(created.workspace_id)
        assert workspace is not None
        assert workspace.workspace_id == created.workspace_id
    
    def test_get_workspace_not_found(self, manager):
        """Test getting non-existent workspace returns None"""
        workspace = manager.get_workspace("non-existent-id")
        assert workspace is None
    
    def test_list_workspaces(self, manager):
        """Test listing workspaces"""
        # Create multiple workspaces
        ws1 = manager.create_workspace(name="Workspace 1")
        ws2 = manager.create_workspace(name="Workspace 2")
        ws3 = manager.create_workspace(name="Workspace 3")
        
        workspaces = manager.list_workspaces()
        
        assert len(workspaces) == 3
        workspace_ids = [ws.workspace_id for ws in workspaces]
        assert ws1.workspace_id in workspace_ids
        assert ws2.workspace_id in workspace_ids
        assert ws3.workspace_id in workspace_ids
    
    def test_switch_workspace(self, manager):
        """Test switching between workspaces"""
        ws1 = manager.create_workspace(name="Workspace 1")
        ws2 = manager.create_workspace(name="Workspace 2")
        
        # Switch to workspace 2
        manager.switch_workspace(ws2.workspace_id)
        current = manager.get_current_workspace()
        assert current.workspace_id == ws2.workspace_id
        
        # Switch back to workspace 1
        manager.switch_workspace(ws1.workspace_id)
        current = manager.get_current_workspace()
        assert current.workspace_id == ws1.workspace_id
    
    def test_switch_workspace_not_found(self, manager):
        """Test switching to non-existent workspace raises error"""
        with pytest.raises(ValueError, match="Workspace .* not found"):
            manager.switch_workspace("non-existent-id")
    
    def test_update_workspace(self, manager):
        """Test updating workspace fields"""
        workspace = manager.create_workspace(name="Original Name")
        
        updated = manager.update_workspace(
            workspace.workspace_id,
            name="Updated Name",
            metadata={"new_field": "value"}
        )
        
        assert updated.name == "Updated Name"
        assert updated.metadata["new_field"] == "value"
        
        # Verify persistence
        loaded = manager.load_workspace(workspace.workspace_id)
        assert loaded.name == "Updated Name"
    
    def test_update_target(self, manager, sample_target):
        """Test updating workspace target configuration"""
        workspace = manager.create_workspace(name="Test Workspace")
        
        manager.update_target(workspace.workspace_id, sample_target)
        
        loaded = manager.load_workspace(workspace.workspace_id)
        assert loaded.target is not None
        assert loaded.target.url == sample_target.url
        assert loaded.target.waf_bypass_profile == sample_target.waf_bypass_profile
    
    def test_update_session(self, manager, sample_session):
        """Test updating workspace session"""
        workspace = manager.create_workspace(name="Test Workspace")
        
        manager.update_session(workspace.workspace_id, sample_session)
        
        loaded = manager.load_workspace(workspace.workspace_id)
        assert loaded.session is not None
        assert loaded.session.session_id == sample_session.session_id
        assert loaded.session.domain == sample_session.domain
    
    def test_save_finding(self, manager, sample_finding):
        """Test saving a finding to workspace"""
        workspace = manager.create_workspace(name="Test Workspace")
        sample_finding.workspace_id = workspace.workspace_id
        
        manager.save_finding(workspace.workspace_id, sample_finding)
        
        # Verify finding was saved
        loaded = manager.load_workspace(workspace.workspace_id)
        assert len(loaded.findings) == 1
        assert loaded.findings[0].finding_id == sample_finding.finding_id
        
        # Verify finding file was created
        workspace_path = manager._get_workspace_path(workspace.workspace_id)
        finding_file = workspace_path / "findings" / f"{sample_finding.finding_id}.json"
        assert finding_file.exists()
    
    def test_save_multiple_findings(self, manager):
        """Test saving multiple findings"""
        workspace = manager.create_workspace(name="Test Workspace")
        
        for i in range(3):
            finding = Finding(
                finding_id=f"finding-{i:03d}",
                workspace_id=workspace.workspace_id,
                vulnerability_type="Test",
                severity="medium",
                title=f"Finding {i}",
                description="Test finding",
                affected_url="https://example.com",
                proof_of_concept="test",
                remediation="test",
                discovered_at=datetime.now(timezone.utc)
            )
            manager.save_finding(workspace.workspace_id, finding)
        
        loaded = manager.load_workspace(workspace.workspace_id)
        assert len(loaded.findings) == 3
    
    def test_get_findings(self, manager):
        """Test retrieving findings"""
        workspace = manager.create_workspace(name="Test Workspace")
        
        # Create findings with different severities
        for severity in ["critical", "high", "medium"]:
            finding = Finding(
                finding_id=f"finding-{severity}",
                workspace_id=workspace.workspace_id,
                vulnerability_type="Test",
                severity=severity,
                title=f"{severity} finding",
                description="Test",
                affected_url="https://example.com",
                proof_of_concept="test",
                remediation="test",
                discovered_at=datetime.now(timezone.utc)
            )
            manager.save_finding(workspace.workspace_id, finding)
        
        # Get all findings
        all_findings = manager.get_findings(workspace.workspace_id)
        assert len(all_findings) == 3
        
        # Filter by severity
        critical = manager.get_findings(workspace.workspace_id, severity="critical")
        assert len(critical) == 1
        assert critical[0].severity == "critical"
    
    def test_get_findings_by_vulnerability_type(self, manager):
        """Test filtering findings by vulnerability type"""
        workspace = manager.create_workspace(name="Test Workspace")
        
        # Create findings with different types
        for vuln_type in ["SQL Injection", "XSS", "SQL Injection"]:
            finding = Finding(
                finding_id=f"finding-{vuln_type.replace(' ', '-')}",
                workspace_id=workspace.workspace_id,
                vulnerability_type=vuln_type,
                severity="medium",
                title=f"{vuln_type} finding",
                description="Test",
                affected_url="https://example.com",
                proof_of_concept="test",
                remediation="test",
                discovered_at=datetime.now(timezone.utc)
            )
            manager.save_finding(workspace.workspace_id, finding)
        
        # Filter by vulnerability type
        sqli = manager.get_findings(
            workspace.workspace_id,
            vulnerability_type="SQL Injection"
        )
        assert len(sqli) == 2
    
    def test_delete_workspace(self, manager):
        """Test deleting a workspace"""
        workspace = manager.create_workspace(name="Test Workspace")
        workspace_id = workspace.workspace_id
        workspace_path = manager._get_workspace_path(workspace_id)
        
        # Verify workspace exists
        assert workspace_path.exists()
        
        # Delete workspace
        manager.delete_workspace(workspace_id)
        
        # Verify workspace is gone
        assert not workspace_path.exists()
        assert manager.get_workspace(workspace_id) is None
    
    def test_delete_workspace_not_found(self, manager):
        """Test deleting non-existent workspace raises error"""
        with pytest.raises(ValueError, match="Workspace .* not found"):
            manager.delete_workspace("non-existent-id")
    
    def test_get_workspace_stats(self, manager):
        """Test getting workspace statistics"""
        workspace = manager.create_workspace(name="Test Workspace")
        
        # Add findings with different severities
        severities = ["critical", "critical", "high", "medium", "low", "info"]
        for i, severity in enumerate(severities):
            finding = Finding(
                finding_id=f"finding-{i:03d}",
                workspace_id=workspace.workspace_id,
                vulnerability_type="Test",
                severity=severity,
                title=f"Finding {i}",
                description="Test",
                affected_url="https://example.com",
                proof_of_concept="test",
                remediation="test",
                discovered_at=datetime.now(timezone.utc),
                flags=[f"CTF{{flag_{i}}}"] if i < 3 else []
            )
            manager.save_finding(workspace.workspace_id, finding)
        
        stats = manager.get_workspace_stats(workspace.workspace_id)
        
        assert stats["total_findings"] == 6
        assert stats["severity_counts"]["critical"] == 2
        assert stats["severity_counts"]["high"] == 1
        assert stats["severity_counts"]["medium"] == 1
        assert stats["severity_counts"]["low"] == 1
        assert stats["severity_counts"]["info"] == 1
        assert stats["total_flags"] == 3
        assert stats["has_target"] is False
        assert stats["has_session"] is False
    
    def test_export_workspace(self, manager, sample_target, sample_session, sample_finding):
        """Test exporting workspace to archive"""
        workspace = manager.create_workspace(name="Test Workspace")
        
        # Add data to workspace
        manager.update_target(workspace.workspace_id, sample_target)
        manager.update_session(workspace.workspace_id, sample_session)
        sample_finding.workspace_id = workspace.workspace_id
        manager.save_finding(workspace.workspace_id, sample_finding)
        
        # Export workspace
        archive_data = manager.export_workspace(workspace.workspace_id)
        
        assert isinstance(archive_data, bytes)
        assert len(archive_data) > 0
    
    def test_export_workspace_not_found(self, manager):
        """Test exporting non-existent workspace raises error"""
        with pytest.raises(ValueError, match="Workspace .* not found"):
            manager.export_workspace("non-existent-id")
    
    def test_import_workspace(self, manager, sample_target, sample_session, sample_finding):
        """Test importing workspace from archive"""
        # Create and export workspace
        workspace = manager.create_workspace(name="Test Workspace")
        manager.update_target(workspace.workspace_id, sample_target)
        manager.update_session(workspace.workspace_id, sample_session)
        sample_finding.workspace_id = workspace.workspace_id
        manager.save_finding(workspace.workspace_id, sample_finding)
        
        archive_data = manager.export_workspace(workspace.workspace_id)
        
        # Delete workspace
        manager.delete_workspace(workspace.workspace_id)
        
        # Import workspace
        imported = manager.import_workspace(archive_data)
        
        assert imported is not None
        assert imported.workspace_id == workspace.workspace_id
        assert imported.name == workspace.name
        assert imported.target is not None
        assert imported.session is not None
        assert len(imported.findings) == 1
    
    def test_import_workspace_already_exists(self, manager):
        """Test importing workspace that already exists raises error"""
        workspace = manager.create_workspace(name="Test Workspace")
        archive_data = manager.export_workspace(workspace.workspace_id)
        
        # Try to import again (workspace still exists)
        with pytest.raises(ValueError, match="Workspace .* already exists"):
            manager.import_workspace(archive_data)
    
    def test_workspace_export_import_round_trip(self, manager, sample_target, sample_session):
        """Test complete export-import round-trip"""
        # Create workspace with full data
        workspace = manager.create_workspace(
            name="Round Trip Test",
            metadata={"test": "value"}
        )
        
        manager.update_target(workspace.workspace_id, sample_target)
        manager.update_session(workspace.workspace_id, sample_session)
        
        # Add multiple findings
        for i in range(3):
            finding = Finding(
                finding_id=f"finding-{i:03d}",
                workspace_id=workspace.workspace_id,
                vulnerability_type="Test",
                severity="medium",
                title=f"Finding {i}",
                description="Test finding",
                affected_url="https://example.com",
                proof_of_concept="test",
                remediation="test",
                discovered_at=datetime.now(timezone.utc),
                flags=[f"CTF{{flag_{i}}}"]
            )
            manager.save_finding(workspace.workspace_id, finding)
        
        # Export
        archive_data = manager.export_workspace(workspace.workspace_id)
        
        # Delete
        manager.delete_workspace(workspace.workspace_id)
        
        # Import
        imported = manager.import_workspace(archive_data)
        
        # Verify all data preserved
        assert imported.workspace_id == workspace.workspace_id
        assert imported.name == workspace.name
        assert imported.metadata == workspace.metadata
        assert imported.target is not None
        assert imported.target.url == sample_target.url
        assert imported.session is not None
        assert imported.session.session_id == sample_session.session_id
        assert len(imported.findings) == 3
        
        # Verify findings
        findings = manager.get_findings(imported.workspace_id)
        assert len(findings) == 3
        assert all(len(f.flags) == 1 for f in findings)
    
    def test_workspace_persistence(self, manager, temp_workspace_dir):
        """Test that workspaces persist across manager instances"""
        # Create workspace
        workspace = manager.create_workspace(name="Persistent Workspace")
        workspace_id = workspace.workspace_id
        
        # Create new manager instance
        new_manager = WorkspaceManager(base_path=temp_workspace_dir)
        
        # Verify workspace was discovered
        workspaces = new_manager.list_workspaces()
        assert len(workspaces) == 1
        assert workspaces[0].workspace_id == workspace_id
        assert workspaces[0].name == "Persistent Workspace"
