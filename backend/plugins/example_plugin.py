"""Example plugin demonstrating the plugin system

This is a sample plugin that shows how to create custom attack modules
and integrate them with the VulnChain framework.
"""

from app.core.plugin_system import Plugin, AttackModule, PluginMetadata, ModuleResult
from typing import Dict, Any, List, Type
import time


class CustomXSSModule(AttackModule):
    """Custom XSS testing module"""
    
    async def execute(self, target: Any, params: Dict[str, Any]) -> ModuleResult:
        """Execute custom XSS testing"""
        start_time = time.time()
        
        # Custom XSS testing logic here
        # This is just an example
        
        execution_time = time.time() - start_time
        
        return ModuleResult(
            success=True,
            vulnerability_found=False,
            findings=[],
            execution_time=execution_time,
            metadata={'module': 'CustomXSS'}
        )
    
    def get_name(self) -> str:
        return "Custom XSS Scanner"
    
    def get_description(self) -> str:
        return "Custom XSS testing with advanced payloads"
    
    def get_parameters(self) -> Dict[str, Any]:
        return {
            'parameter': {
                'type': 'string',
                'description': 'Parameter to test',
                'required': True
            },
            'depth': {
                'type': 'integer',
                'description': 'Testing depth',
                'default': 3
            }
        }


class ExamplePlugin(Plugin):
    """Example plugin implementation"""
    
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata"""
        return PluginMetadata(
            name="Example Plugin",
            version="1.0.0",
            author="VulnChain Team",
            description="Example plugin demonstrating the plugin system",
            dependencies=["requests"],
            config_schema={
                'api_key': {
                    'type': 'string',
                    'description': 'API key for external service',
                    'required': False
                },
                'timeout': {
                    'type': 'integer',
                    'description': 'Request timeout in seconds',
                    'default': 30
                }
            }
        )
    
    def initialize(self, core_engine: Any):
        """Initialize plugin with core engine access"""
        self.core_engine = core_engine
        print(f"[*] {self.get_metadata().name} initialized")
    
    def get_modules(self) -> List[Type[AttackModule]]:
        """Get attack modules provided by this plugin"""
        return [CustomXSSModule]
    
    def get_payloads(self) -> Dict[str, List[str]]:
        """Get custom payloads"""
        return {
            'xss': [
                '<script>alert("custom1")</script>',
                '<img src=x onerror="alert(\'custom2\')">',
                '<svg onload="alert(\'custom3\')">',
            ],
            'sqli': [
                "' OR '1'='1' -- custom",
                "admin' --",
            ]
        }
