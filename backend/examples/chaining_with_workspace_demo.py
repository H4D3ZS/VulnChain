"""Demonstration of vulnerability chaining with workspace integration

This example shows how to use vulnerability chaining with the workspace manager
to analyze findings from a real workspace.
"""

import asyncio
from pathlib import Path

from app.core.vulnerability_chaining import (
    VulnerabilityChainAnalyzer,
    VulnerabilityChainExecutor,
)
from app.core.workspace_manager import WorkspaceManager


async def demo_workspace_chaining():
    """Demonstrate chaining with workspace integration"""
    print("=" * 80)
    print("VULNERABILITY CHAINING WITH WORKSPACE INTEGRATION")
    print("=" * 80)
    print()
    
    # Initialize workspace manager
    workspace_manager = WorkspaceManager(base_path=Path("./demo_workspaces"))
    
    # List available workspaces
    workspaces = workspace_manager.list_workspaces()
    
    if not workspaces:
        print("No workspaces found. Please create a workspace first.")
        return
    
    print(f"Found {len(workspaces)} workspace(s):")
    for ws in workspaces:
        print(f"  - {ws.name} (ID: {ws.workspace_id})")
        print(f"    Findings: {len(ws.findings)}")
    print()
    
    # Use the first workspace
    workspace = workspaces[0]
    print(f"Analyzing workspace: {workspace.name}")
    print(f"Total findings: {len(workspace.findings)}\n")
    
    if not workspace.findings:
        print("No findings in workspace. Cannot perform chain analysis.")
        return
    
    # Display findings
    print("Findings in workspace:")
    for finding in workspace.findings:
        print(f"  - {finding.vulnerability_type.upper()}: {finding.title}")
        print(f"    Severity: {finding.severity}")
        print(f"    URL: {finding.affected_url}")
    print()
    
    # Analyze for chains
    analyzer = VulnerabilityChainAnalyzer()
    chains = analyzer.analyze_findings(workspace.findings)
    
    if not chains:
        print("No vulnerability chains identified.")
        return
    
    print(f"Identified {len(chains)} vulnerability chain(s):\n")
    
    for i, chain in enumerate(chains, 1):
        print(f"{i}. {chain.name}")
        print(f"   Type: {chain.chain_type.value}")
        print(f"   Severity: {chain.severity.upper()}")
        print(f"   Impact: {chain.impact}")
        print(f"   Steps: {len(chain.steps)}")
        print(f"   Findings: {', '.join(f.vulnerability_type for f in chain.findings)}")
        print()
    
    # Get recommendations
    print("=" * 80)
    print("CHAIN RECOMMENDATIONS")
    print("=" * 80)
    print()
    
    recommendations = analyzer.get_chain_recommendations(workspace.findings)
    
    print(f"Top {min(3, len(recommendations))} recommended chains:\n")
    
    for i, rec in enumerate(recommendations[:3], 1):
        print(f"{i}. {rec['name']}")
        print(f"   Priority Score: {rec['priority_score']:.1f}/100")
        print(f"   Severity: {rec['severity'].upper()}")
        print(f"   Automated: {'Yes' if rec['automated'] else 'No'}")
        print()
    
    # Generate workflow for top chain
    if chains:
        print("=" * 80)
        print("DETAILED WORKFLOW FOR TOP CHAIN")
        print("=" * 80)
        print()
        
        top_chain = chains[0]
        executor = VulnerabilityChainExecutor()
        workflow = executor.generate_workflow_description(top_chain)
        
        print(workflow)
    
    # Get workspace statistics
    print("\n" + "=" * 80)
    print("WORKSPACE STATISTICS")
    print("=" * 80)
    print()
    
    stats = workspace_manager.get_workspace_stats(workspace.workspace_id)
    
    print(f"Workspace: {stats['name']}")
    print(f"Total Findings: {stats['total_findings']}")
    print(f"Total Flags: {stats['total_flags']}")
    print(f"Has Target: {stats['has_target']}")
    print(f"Has Session: {stats['has_session']}")
    print()
    
    print("Findings by Severity:")
    for severity, count in stats['severity_counts'].items():
        if count > 0:
            print(f"  {severity.upper()}: {count}")


async def demo_chain_execution_with_workspace():
    """Demonstrate executing a chain and saving results to workspace"""
    print("\n" + "=" * 80)
    print("CHAIN EXECUTION WITH WORKSPACE PERSISTENCE")
    print("=" * 80)
    print()
    
    # Initialize workspace manager
    workspace_manager = WorkspaceManager(base_path=Path("./demo_workspaces"))
    workspaces = workspace_manager.list_workspaces()
    
    if not workspaces or not workspaces[0].findings:
        print("No workspace with findings available.")
        return
    
    workspace = workspaces[0]
    
    # Analyze for chains
    analyzer = VulnerabilityChainAnalyzer()
    chains = analyzer.analyze_findings(workspace.findings)
    
    if not chains:
        print("No chains to execute.")
        return
    
    chain = chains[0]
    print(f"Executing chain: {chain.name}")
    print(f"Workspace: {workspace.name}\n")
    
    # Execute chain (with mock callbacks)
    async def mock_callback(step, state):
        """Mock callback for demonstration"""
        print(f"  [Step {step.step_number}] Executing: {step.description}")
        await asyncio.sleep(0.3)
        return {
            "success": True,
            "step_id": step.step_id,
            "mock_data": f"result_from_step_{step.step_number}",
        }
    
    # Create callbacks for all vulnerability types in the chain
    callbacks = {}
    for finding in chain.findings:
        vuln_type = finding.vulnerability_type.lower()
        callbacks[vuln_type] = mock_callback
    
    executor = VulnerabilityChainExecutor()
    result = await executor.execute_chain(chain, callbacks)
    
    print(f"\nExecution Result:")
    print(f"  Success: {result.success}")
    print(f"  Steps Executed: {result.steps_executed}/{len(chain.steps)}")
    print(f"  Execution Time: {result.execution_time:.2f}s")
    
    # Note: In a real implementation, you would save the chain execution
    # result as a new finding in the workspace
    print("\nNote: Chain execution results can be saved as findings in the workspace")
    print("for future reference and reporting.")


async def main():
    """Run all demonstrations"""
    await demo_workspace_chaining()
    await demo_chain_execution_with_workspace()


if __name__ == "__main__":
    asyncio.run(main())
