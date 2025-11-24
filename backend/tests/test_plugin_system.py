"""Tests for plugin system"""

import pytest
from pathlib import Path
import tempfile
import shutil

from app.core.plugin_system import (
    PluginSystem,
    Plugin,
    AttackModule,
    PluginMetadata,
    ModuleResult,
    LoadedPlugin,
)


# Test plugin implementation
class TestAttackModule(AttackModule):
    """Test attack module"""
    
    async def execute(self, target, params):
        return ModuleResult(
            success=True,
            vulnerability_found=False,
            findings=[],
            execution_time=0.1
        )
    
    def get_name(self):
        return "Test Module"
    
    def get_description(self):
        return "Test module for testing"


class TestPlugin(Plugin):
    """Test plugin implementation"""
    
    def get_metadata(self):
        return PluginMetadata(
            name="Test Plugin",
            version="1.0.0",
            author="Test Author",
            description="Test plugin",
            dependencies=[],
            config_schema={'key': {'type': 'string'}}
        )
    
    def initialize(self, core_engine):
        self.core_engine = core_engine
    
    def get_modules(self):
        return [TestAttackModule]
    
    def get_payloads(self):
        return {
            'test': ['payload1', 'payload2']
        }


class TestPluginSystem:
    """Test plugin system functionality"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.plugin_system = PluginSystem(plugin_dir=self.temp_dir)
    
    def teardown_method(self):
        """Clean up test fixtures"""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def test_plugin_system_initialization(self):
        """Test plugin system initialization"""
        assert self.plugin_system.plugin_dir == self.temp_dir
        assert len(self.plugin_system.plugins) == 0
    
    def test_register_module(self):
        """Test registering a standalone module"""
        self.plugin_system.register_module(TestAttackModule)
        
        modules = self.plugin_system.get_all_modules()
        assert len(modules) == 1
        assert modules[0] == TestAttackModule
    
    def test_get_plugins_empty(self):
        """Test getting plugins when none are loaded"""
        plugins = self.plugin_system.get_plugins()
        assert len(plugins) == 0
    
    def test_enable_disable_plugin(self):
        """Test enabling and disabling plugins"""
        # Register a module to create a plugin
        self.plugin_system.register_module(TestAttackModule)
        
        plugins = self.plugin_system.get_plugins()
        assert len(plugins) == 1
        
        plugin_id = plugins[0].plugin_id
        
        # Plugin should be enabled by default
        assert plugins[0].enabled is True
        
        # Disable plugin
        self.plugin_system.disable_plugin(plugin_id)
        plugin = self.plugin_system.get_plugin(plugin_id)
        assert plugin.enabled is False
        
        # Enable plugin
        self.plugin_system.enable_plugin(plugin_id)
        plugin = self.plugin_system.get_plugin(plugin_id)
        assert plugin.enabled is True
    
    def test_get_enabled_plugins(self):
        """Test getting only enabled plugins"""
        # Register two modules
        self.plugin_system.register_module(TestAttackModule)
        
        plugins = self.plugin_system.get_plugins()
        plugin_id = plugins[0].plugin_id
        
        # Disable one plugin
        self.plugin_system.disable_plugin(plugin_id)
        
        enabled = self.plugin_system.get_enabled_plugins()
        assert len(enabled) == 0
    
    def test_get_all_modules(self):
        """Test getting all modules from enabled plugins"""
        self.plugin_system.register_module(TestAttackModule)
        
        modules = self.plugin_system.get_all_modules()
        assert len(modules) == 1
        assert modules[0] == TestAttackModule
    
    def test_get_all_payloads_empty(self):
        """Test getting payloads when none exist"""
        payloads = self.plugin_system.get_all_payloads()
        assert len(payloads) == 0
    
    def test_set_get_plugin_config(self):
        """Test setting and getting plugin configuration"""
        self.plugin_system.register_module(TestAttackModule)
        
        plugins = self.plugin_system.get_plugins()
        plugin_id = plugins[0].plugin_id
        
        config = {'key': 'value', 'number': 42}
        self.plugin_system.set_plugin_config(plugin_id, config)
        
        retrieved_config = self.plugin_system.get_plugin_config(plugin_id)
        assert retrieved_config == config
    
    def test_get_plugin_config_nonexistent(self):
        """Test getting config for nonexistent plugin"""
        config = self.plugin_system.get_plugin_config('nonexistent')
        assert config == {}
    
    def test_get_plugin(self):
        """Test getting a specific plugin"""
        self.plugin_system.register_module(TestAttackModule)
        
        plugins = self.plugin_system.get_plugins()
        plugin_id = plugins[0].plugin_id
        
        plugin = self.plugin_system.get_plugin(plugin_id)
        assert plugin is not None
        assert plugin.plugin_id == plugin_id
    
    def test_get_plugin_nonexistent(self):
        """Test getting a nonexistent plugin"""
        plugin = self.plugin_system.get_plugin('nonexistent')
        assert plugin is None
    
    def test_get_plugin_info(self):
        """Test getting plugin information"""
        self.plugin_system.register_module(TestAttackModule)
        
        plugins = self.plugin_system.get_plugins()
        plugin_id = plugins[0].plugin_id
        
        info = self.plugin_system.get_plugin_info(plugin_id)
        assert info is not None
        assert 'plugin_id' in info
        assert 'name' in info
        assert 'version' in info
        assert 'enabled' in info
    
    def test_get_plugin_info_nonexistent(self):
        """Test getting info for nonexistent plugin"""
        info = self.plugin_system.get_plugin_info('nonexistent')
        assert info is None
    
    def test_list_plugins(self):
        """Test listing all plugins"""
        self.plugin_system.register_module(TestAttackModule)
        
        plugin_list = self.plugin_system.list_plugins()
        assert len(plugin_list) == 1
        assert plugin_list[0]['name'] == 'TestAttackModule'
    
    def test_save_load_plugin_configs(self):
        """Test saving and loading plugin configurations"""
        self.plugin_system.register_module(TestAttackModule)
        
        plugins = self.plugin_system.get_plugins()
        plugin_id = plugins[0].plugin_id
        
        # Set config
        config = {'key': 'value'}
        self.plugin_system.set_plugin_config(plugin_id, config)
        
        # Disable plugin
        self.plugin_system.disable_plugin(plugin_id)
        
        # Save configs
        config_file = self.temp_dir / 'plugin_config.json'
        self.plugin_system.save_plugin_configs(config_file)
        
        assert config_file.exists()
        
        # Reset plugin state
        self.plugin_system.enable_plugin(plugin_id)
        self.plugin_system.set_plugin_config(plugin_id, {})
        
        # Load configs
        self.plugin_system.load_plugin_configs(config_file)
        
        # Verify config was restored
        loaded_config = self.plugin_system.get_plugin_config(plugin_id)
        assert loaded_config == config
        
        # Verify enabled state was restored
        plugin = self.plugin_system.get_plugin(plugin_id)
        assert plugin.enabled is False
    
    def test_load_plugin_configs_nonexistent_file(self):
        """Test loading configs from nonexistent file"""
        config_file = self.temp_dir / 'nonexistent.json'
        # Should not raise an error
        self.plugin_system.load_plugin_configs(config_file)
    
    def test_set_core_engine(self):
        """Test setting core engine"""
        mock_engine = object()
        self.plugin_system.set_core_engine(mock_engine)
        assert self.plugin_system.core_engine is mock_engine
    
    def test_plugin_metadata(self):
        """Test plugin metadata creation"""
        metadata = PluginMetadata(
            name="Test",
            version="1.0.0",
            author="Author",
            description="Description",
            dependencies=["dep1", "dep2"],
            config_schema={'key': {'type': 'string'}}
        )
        
        assert metadata.name == "Test"
        assert metadata.version == "1.0.0"
        assert len(metadata.dependencies) == 2
    
    def test_module_result(self):
        """Test module result creation"""
        result = ModuleResult(
            success=True,
            vulnerability_found=True,
            findings=['finding1'],
            execution_time=1.5,
            error=None,
            metadata={'key': 'value'}
        )
        
        assert result.success is True
        assert result.vulnerability_found is True
        assert len(result.findings) == 1
        assert result.execution_time == 1.5
    
    @pytest.mark.asyncio
    async def test_attack_module_execution(self):
        """Test attack module execution"""
        module = TestAttackModule()
        result = await module.execute(None, {})
        
        assert result.success is True
        assert result.execution_time > 0
    
    def test_attack_module_metadata(self):
        """Test attack module metadata methods"""
        module = TestAttackModule()
        
        assert module.get_name() == "Test Module"
        assert module.get_description() == "Test module for testing"
        assert isinstance(module.get_parameters(), dict)
