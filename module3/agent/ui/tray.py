"""
System Tray Icon and Transparency UI (Section 14 & Design Principle 2)
Provides visual indication to the employee that the agent is running and transparently
documents what metadata is monitored and what is explicitly excluded (zero keystrokes, zero content).
"""

import threading
import logging
from typing import Callable, Optional
from PIL import Image, ImageDraw

try:
    import pystray
except ImportError:
    pystray = None

logger = logging.getLogger("cyber_sentinel_agent.ui")

TRANSPARENCY_NOTE = (
    "Cyber Sentinel - Endpoint DLP Agent\n\n"
    "Status: Monitoring Active\n"
    "Data Minimization Assurances:\n"
    "- Monitors USB drive attachments and aggregate file write volumes.\n"
    "- Detects sensitive text copied while AI tools are focused.\n"
    "- NEVER collects file names, file contents, or window titles.\n"
    "- NEVER records keystrokes or screenshots."
)

def create_tray_image():
    # Generate 64x64 high-visibility shield icon
    width = 64
    height = 64
    image = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    # Draw vibrant blue shield with white border
    draw.polygon([(32, 2), (60, 14), (50, 56), (32, 62), (14, 56), (4, 14)], fill=(0, 122, 255), outline=(255, 255, 255), width=2)
    # Draw bright green center check / circle
    draw.ellipse((20, 20, 44, 44), fill=(0, 225, 110), outline=(255, 255, 255), width=1)
    return image

class AgentTrayIcon:
    def __init__(self, on_exit_callback: Optional[Callable[[], None]] = None):
        self.on_exit_callback = on_exit_callback
        self.icon = None

    def _show_transparency_info(self, icon, item):
        try:
            import win32api
            import win32con
            win32api.MessageBox(0, TRANSPARENCY_NOTE, "Cyber Sentinel - Privacy & Transparency", win32con.MB_ICONINFORMATION)
        except Exception:
            logger.info(TRANSPARENCY_NOTE)

    def _exit_agent(self, icon, item):
        logger.info("User requested agent exit from tray menu.")
        if icon:
            icon.stop()
        if self.on_exit_callback:
            self.on_exit_callback()

    def run(self):
        if not pystray:
            logger.info("pystray not installed, running in headless/console mode.")
            return

        image = create_tray_image()
        menu = pystray.Menu(
            pystray.MenuItem("Cyber Sentinel (Active)", lambda: None, enabled=False),
            pystray.MenuItem("Privacy & Transparency Policy", self._show_transparency_info),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit Agent", self._exit_agent)
        )
        self.icon = pystray.Icon("CyberSentinel", image, "Cyber Sentinel - AI DLP Agent", menu)
        self.icon.run()

    def stop(self):
        if self.icon:
            self.icon.stop()
