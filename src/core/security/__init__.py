"""Security hardening services used by the desktop application."""

from .activity_monitor import ActivityMonitor, ActivitySnapshot
from .config import (
    ActivitySensitivity,
    DeviceType,
    SecurityHardeningConfig,
    SecurityProfile,
)
from .memory_guard import (
    MemoryGuard,
    ProtectedMemory,
    ProtectedSecret,
    ProtectionStatus,
)
from .panic_mode import PanicInterruptedError, PanicMode, PanicResult
from .platform_security import LinuxKernelKeyring, PlatformCapabilities
from .side_channel_protection import SideChannelProtection

__all__ = [
    "ActivityMonitor",
    "ActivitySensitivity",
    "ActivitySnapshot",
    "DeviceType",
    "LinuxKernelKeyring",
    "MemoryGuard",
    "PanicInterruptedError",
    "PanicMode",
    "PanicResult",
    "PlatformCapabilities",
    "ProtectedMemory",
    "ProtectedSecret",
    "ProtectionStatus",
    "SecurityHardeningConfig",
    "SecurityProfile",
    "SideChannelProtection",
]
