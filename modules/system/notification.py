import os
import subprocess
from typing import Any, Dict


def send_windows_notification(title: str, message: str) -> Dict[str, Any]:
    """
    Sends a native Windows Toast notification safely.
    Uses environment variable parameterization to prevent PowerShell command escape.
    """
    env = os.environ.copy()
    env["PB_NOTIF_TITLE"] = str(title)
    env["PB_NOTIF_MSG"] = str(message)

    ps_script = """
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
    $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
    $textNodes = $template.GetElementsByTagName('text')
    $textNodes.Item(0).AppendChild($template.CreateTextNode($env:PB_NOTIF_TITLE)) > $null
    $textNodes.Item(1).AppendChild($template.CreateTextNode($env:PB_NOTIF_MSG)) > $null
    $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Protocol Brain MCP')
    $notifier.Show($toast)
    """

    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            env=env,
            capture_output=True,
            timeout=5,
        )
        return {"success": True, "title": title, "message": message}
    except Exception as e:
        return {"success": False, "error": str(e)}

