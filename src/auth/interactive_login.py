"""
Interactive login system for PlexTrac authentication.
"""

import getpass
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.text import Text

from ..utils.logger import get_logger
from ..utils.validators import validate_url
from .token_cache import token_cache


class InteractiveLogin:
    """Interactive login system with token caching."""

    def __init__(self):
        self.logger = get_logger(__name__)
        self.console = Console()

    def login(
        self, url: Optional[str] = None, username: Optional[str] = None, force_new: bool = False
    ) -> Optional[Dict[str, str]]:
        """Interactive login with token caching."""

        # Show welcome message
        self._show_welcome()

        # Get URL
        if not url:
            url = self._get_plextrac_url()

        if not url:
            return None

        # Get username
        if not username:
            username = self._get_username()

        if not username:
            return None

        # Check for cached token
        if not force_new:
            cached_token = token_cache.load_token(url, username)
            if cached_token:
                if self._confirm_use_cached_token(cached_token):
                    return {
                        "url": url,
                        "username": username,
                        "token": cached_token["token"],
                        "from_cache": True,
                    }
                else:
                    # User chose not to use cached token, remove it
                    token_cache.remove_token(url, username)

        # Get password interactively
        password = self._get_password()
        if not password:
            return None

        # Get MFA token if needed
        mfa_token = self._get_mfa_token()

        return {
            "url": url,
            "username": username,
            "password": password,
            "mfa_token": mfa_token,
            "from_cache": False,
        }

    def _show_welcome(self) -> None:
        """Show welcome message."""
        welcome_text = Text.assemble(
            ("🔐 ", "bold blue"),
            ("PlexTrac Authentication", "bold white"),
            ("\nSecure login with token caching", "dim white"),
        )

        panel = Panel(
            welcome_text,
            title="Prowler OCSF to PlexTrac Importer",
            border_style="blue",
            padding=(1, 2),
        )

        self.console.print()
        self.console.print(panel)
        self.console.print()

    def _get_plextrac_url(self) -> Optional[str]:
        """Get PlexTrac URL from user."""
        while True:
            url = Prompt.ask("🌐 Enter your PlexTrac URL", default="", show_default=False)

            if not url:
                if not Confirm.ask("❌ URL is required. Continue?"):
                    return None
                continue

            # Add https:// if not present
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            # Validate URL
            if not validate_url(url):
                self.console.print("❌ Invalid URL format. Please try again.", style="red")
                continue

            # Parse URL to show user what we'll use
            parsed = urlparse(url)
            clean_url = f"{parsed.scheme}://{parsed.netloc}"

            self.console.print(f"✅ Using: {clean_url}", style="green")
            return clean_url

    def _get_username(self) -> Optional[str]:
        """Get username from user."""
        username = Prompt.ask("👤 Enter your PlexTrac username", default="", show_default=False)

        if not username:
            self.console.print("❌ Username is required.", style="red")
            return None

        return username.strip()

    def _get_password(self) -> Optional[str]:
        """Get password securely from user."""
        self.console.print("🔑 Enter your PlexTrac password:")
        password = getpass.getpass("Password: ")

        if not password:
            self.console.print("❌ Password is required.", style="red")
            return None

        return password

    def _get_mfa_token(self) -> Optional[str]:
        """Get MFA token from user if needed."""
        if Confirm.ask("🔐 Do you need to enter an MFA token?", default=False):
            mfa_token = Prompt.ask(
                "Enter your MFA token (6 digits)", default="", show_default=False
            )
            return mfa_token.strip() if mfa_token else None

        return None

    def _confirm_use_cached_token(self, cached_token: Dict) -> bool:
        """Ask user if they want to use cached token."""
        from datetime import datetime

        expires_at = datetime.fromisoformat(cached_token["expires_at"])
        time_left = expires_at - datetime.now()

        # Format time remaining
        if time_left.days > 0:
            time_str = f"{time_left.days} days"
        elif time_left.seconds > 3600:
            hours = time_left.seconds // 3600
            time_str = f"{hours} hours"
        else:
            minutes = time_left.seconds // 60
            time_str = f"{minutes} minutes"

        # Show token info
        token_info = Text.assemble(
            ("🎫 Found cached authentication token", "bold green"),
            "\n",
            ("Username: ", "dim"),
            (cached_token["username"], "white"),
            "\n",
            ("URL: ", "dim"),
            (cached_token["plextrac_url"], "white"),
            "\n",
            ("Expires in: ", "dim"),
            (time_str, "yellow"),
            "\n",
        )

        panel = Panel(
            token_info, title="Cached Token Available", border_style="green", padding=(1, 2)
        )

        self.console.print(panel)

        return Confirm.ask("✨ Use cached token?", default=True)

    def show_cached_tokens(self) -> None:
        """Show all cached tokens."""
        tokens = token_cache.list_cached_tokens()

        if not tokens:
            self.console.print("📭 No cached tokens found.", style="yellow")
            return

        self.console.print("\n🎫 Cached Authentication Tokens:", style="bold blue")
        self.console.print()

        for i, token in enumerate(tokens, 1):
            status = "❌ Expired" if token["is_expired"] else "✅ Valid"
            status_style = "red" if token["is_expired"] else "green"

            token_info = Text.assemble(
                (f"{i}. ", "dim"),
                (token["username_hint"], "white"),
                " @ ",
                (token["url_hint"], "cyan"),
                "\n",
                ("   ", ""),
                (status, status_style),
                "\n",
                ("   Saved: ", "dim"),
                (token["saved_at"][:19], "white"),
                "\n",
                ("   Expires: ", "dim"),
                (token["expires_at"][:19], "white"),
            )

            self.console.print(token_info)
            self.console.print()

    def clear_tokens_interactive(self) -> None:
        """Interactive token management."""
        tokens = token_cache.list_cached_tokens()

        if not tokens:
            self.console.print("📭 No cached tokens found.", style="yellow")
            return

        self.show_cached_tokens()

        # Ask what to do
        choice = Prompt.ask(
            "Choose action",
            choices=["clear-all", "clear-expired", "clear-specific", "cancel"],
            default="cancel",
        )

        if choice == "clear-all":
            if Confirm.ask("❗ Are you sure you want to clear ALL cached tokens?", default=False):
                token_cache.clear_cache()
                self.console.print("✅ All tokens cleared.", style="green")

        elif choice == "clear-expired":
            removed = token_cache.cleanup_expired_tokens()
            if removed > 0:
                self.console.print(f"✅ Removed {removed} expired tokens.", style="green")
            else:
                self.console.print("ℹ️ No expired tokens found.", style="blue")

        elif choice == "clear-specific":
            self._clear_specific_token(tokens)

        else:
            self.console.print("Operation cancelled.", style="yellow")

    def _clear_specific_token(self, tokens: list) -> None:
        """Clear a specific token."""
        if not tokens:
            return

        self.console.print("Select token to remove:")
        for i, token in enumerate(tokens, 1):
            self.console.print(f"{i}. {token['username_hint']} @ {token['url_hint']}")

        try:
            choice = int(Prompt.ask("Enter number", default="0")) - 1
            if 0 <= choice < len(tokens):
                token = tokens[choice]
                if Confirm.ask(f"Remove token for {token['full_username']} @ {token['full_url']}?"):
                    token_cache.remove_token(token["full_url"], token["full_username"])
                    self.console.print("✅ Token removed.", style="green")
            else:
                self.console.print("❌ Invalid selection.", style="red")
        except ValueError:
            self.console.print("❌ Invalid input.", style="red")

    def show_login_help(self) -> None:
        """Show login help information."""
        help_text = Text.assemble(
            ("🔐 PlexTrac Authentication Help", "bold blue"),
            "\n\n",
            ("Token Caching:", "bold"),
            "\n",
            ("• Your JWT tokens are securely cached locally", "dim"),
            "\n",
            ("• Tokens are encrypted using system-generated keys", "dim"),
            "\n",
            ("• Cache location: ~/.prowltrac/", "dim"),
            "\n",
            ("• Tokens auto-expire and refresh as needed", "dim"),
            "\n\n",
            ("Security Notes:", "bold"),
            "\n",
            ("• Passwords are never stored locally", "dim"),
            "\n",
            ("• Only encrypted tokens are cached", "dim"),
            "\n",
            ("• Cache files have restricted permissions", "dim"),
            "\n",
            ("• You can clear cache at any time", "dim"),
            "\n\n",
            ("Commands:", "bold"),
            "\n",
            ("• --clear-cache: Clear all cached tokens", "dim"),
            "\n",
            ("• --show-cache: Show cached token info", "dim"),
            "\n",
            ("• --force-login: Force new login", "dim"),
        )

        panel = Panel(help_text, title="Authentication Help", border_style="blue", padding=(1, 2))

        self.console.print(panel)


# Global interactive login instance
interactive_login = InteractiveLogin()
