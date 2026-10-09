import os
import subprocess
from typing import Any, Dict

MAX_TITLE_LEN = 256
MAX_MSG_LEN = 1024

_TOAST_PS_SCRIPT = (
    "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; "
    "$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
    "$textNodes = $template.GetElementsByTagName('text'); "
    "$textNodes.Item(0).AppendChild($template.CreateTextNode($env:PB_TITLE)) > $null; "
    "$textNodes.Item(1).AppendChild($template.CreateTextNode($env:PB_MSG)) > $null; "
    "$toast = [Windows.UI.Notifications.ToastNotification]::new($template); "
    "$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Protocol Brain MCP'); "
    "$notifier.Show($toast)"
)


def send_windows_notification(title: str, message: str) -> Dict[str, Any]:
    """
    Sends a native Windows Toast notification safely.
    Uses environment variable parameterization (PB_TITLE, PB_MSG) with length clamping.
    The PowerShell command string is strictly static, ensuring zero argv/script interpolation.
    """
    safe_title = str(title)[:MAX_TITLE_LEN] if title is not None else ""
    safe_message = str(message)[:MAX_MSG_LEN] if message is not None else ""

    env = os.environ.copy()
    env["PB_TITLE"] = safe_title
    env["PB_MSG"] = safe_message
    # Keep legacy keys for compatibility
    env["PB_NOTIF_TITLE"] = safe_title
    env["PB_NOTIF_MSG"] = safe_message

    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _TOAST_PS_SCRIPT],
            env=env,
            capture_output=True,
            timeout=5,
        )
        return {"success": True, "title": safe_title, "message": safe_message}
    except Exception as e:
        return {"success": False, "error": str(e)}


