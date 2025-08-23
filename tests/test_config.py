"""Tests for configuration management"""

import pytest
import os
from unittest.mock import patch
from core.config import BotConfig, ConfigError, get_config

class TestBotConfig:
    """Test configuration management"""
    
    def test_rizon_config(self):
        """Test Rizon network configuration"""
        config = BotConfig("rizon")
        assert config.HOST == "irc.rizon.net"
        assert config.COMMAND_PREFIX == "!"
        assert "#8bitvape" in config.CHANNELS
    
    def test_libera_config(self):
        """Test Libera network configuration"""
        config = BotConfig("libera")
        assert config.HOST == "irc.libera.chat"
        assert config.COMMAND_PREFIX == "~"
        assert "#bakedbeans" in config.CHANNELS
    
    @patch.dict(os.environ, {}, clear=True)
    def test_missing_api_key(self):
        """Test error when API key is missing"""
        with pytest.raises(ConfigError):
            BotConfig("rizon")
    
    @patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'})
    def test_valid_config(self):
        """Test valid configuration"""
        config = BotConfig("rizon")
        config.validate()  # Should not raise
    
    def test_get_config_singleton(self):
        """Test configuration singleton behavior"""
        with patch.dict(os.environ, {'GEMINI_API_KEY': 'test-key'}):
            config1 = get_config("rizon")
            config2 = get_config("rizon")
            assert config1 is config2