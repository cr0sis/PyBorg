"""Temperature monitoring and conversion commands"""

import os
import logging
import re
from core.plugin_system import command

# Mock GPIO for non-Raspberry Pi systems
os.environ['GPIOZERO_PIN_FACTORY'] = os.environ.get('GPIOZERO_PIN_FACTORY', 'mock')

logger = logging.getLogger(__name__)

@command(
    pattern=r'temp$',
    description="Get CPU temperature",
    category="system"
)
def temp(msg):
    """Get CPU temperature"""
    try:
        from gpiozero import CPUTemperature
        cpu = CPUTemperature()
        temp_c = cpu.temperature
        temp_f = (temp_c * 9/5) + 32
        return f"CPU Temperature: {temp_c:.1f}°C ({temp_f:.1f}°F)"
    except Exception as e:
        logger.error(f"Error getting CPU temperature: {e}")
        return "CPU temperature not available"

@command(
    pattern=r'temp2$',
    description="Get alternate temperature reading",
    category="system"
)
def temp2(msg):
    """Get alternate temperature reading"""
    try:
        # Try to read from /sys/class/thermal if available
        thermal_path = "/sys/class/thermal/thermal_zone0/temp"
        if os.path.exists(thermal_path):
            with open(thermal_path, 'r') as f:
                temp_millicelsius = int(f.read().strip())
                temp_c = temp_millicelsius / 1000
                temp_f = (temp_c * 9/5) + 32
                return f"System Temperature: {temp_c:.1f}°C ({temp_f:.1f}°F)"
        else:
            return "System temperature not available"
    except Exception as e:
        logger.error(f"Error getting system temperature: {e}")
        return "System temperature not available"

def setup_plugin(plugin_manager):
    """Setup function called by plugin loader"""
    from core.plugin_system import auto_register_commands
    import sys
    
    auto_register_commands(plugin_manager, sys.modules[__name__])
