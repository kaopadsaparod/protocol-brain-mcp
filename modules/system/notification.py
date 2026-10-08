import subprocess
from typing import Any, Dict


def send_windows_notification(title: str, message: str) -> Dict[str, Any]:
    """
    Sends a native Windows Toast notification so the user doesn't have to wait and watch the terminal.
    """
    escaped_title = title.replace('"', '`"').replace("'", "''")
    escaped_msg = message.replace('"', '`"').replace("'", "''")

    ps_script = f"""
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
    $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
    $textNodes = $template.GetElementsByTagName('text')
    $textNodes.Item(0).AppendChild($template.CreateTextNode('{escaped_title}')) > $null
    $textNodes.Item(1).AppendChild($template.CreateTextNode('{escaped_msg}')) > $null
    $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Protocol Brain MCP')
    $notifier.Show($toast)
    """

    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            timeout=5,
        )
        return {"success": True, "title": title, "message": message}
    except Exception as e:
        return {"success": False, "error": str(e)}
