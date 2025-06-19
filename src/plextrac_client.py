"""
High-level PlexTrac client for OCSF finding imports.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from .api.endpoints import Client, Finding, PlexTracAPI, PlexTracAPIError, Report
from .auth.auth_handler import AuthenticationError, AuthHandler
from .utils.config import get_config
from .utils.logger import get_logger


@dataclass
class ImportResult:
    """Result of importing findings to PlexTrac."""

    success: bool
    total_findings: int
    imported_findings: int
    duplicate_findings: int
    failed_findings: int
    created_report: Optional[Report] = None
    errors: List[str] = None
    import_time: Optional[datetime] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.import_time is None:
            self.import_time = datetime.now()

    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.total_findings == 0:
            return 0.0
        return (self.imported_findings / self.total_findings) * 100


class PlexTracClient:
    """High-level client for PlexTrac operations."""

    def __init__(self, auth_handler: Optional[AuthHandler] = None):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.auth = auth_handler or AuthHandler()
        self.api = PlexTracAPI(self.auth)
        # Set authenticated state based on auth handler status
        self._authenticated = self.auth.is_authenticated()
        self._cached_clients = None

        # If already authenticated, pre-cache clients
        if self._authenticated:
            self._cache_clients()

    def authenticate(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        mfa_token: Optional[str] = None,
        url: Optional[str] = None,
        force_new: bool = False,
    ) -> bool:
        """Authenticate with PlexTrac."""
        try:
            success = self.auth.authenticate(username, password, mfa_token, url, force_new)
            self._authenticated = success

            if success:
                # Test the connection by trying to get user info
                # If that works, we're definitely connected
                user_info = self.auth.get_current_user()
                if user_info:
                    self.logger.info("Connection test successful")
                else:
                    self.logger.debug(
                        "User info endpoint not available, but authentication successful"
                    )

                # Pre-cache clients on successful authentication
                self._cache_clients()

            return success

        except AuthenticationError as e:
            self.logger.error(f"Authentication failed: {str(e)}")
            return False

    def is_authenticated(self) -> bool:
        """Check if authenticated."""
        return self._authenticated and self.auth.is_authenticated()

    def _cache_clients(self) -> None:
        """Cache clients for faster access."""
        try:
            self._cached_clients = self.api.get_clients()
            self.logger.info(f"Cached {len(self._cached_clients)} clients")
        except Exception as e:
            self.logger.warning(f"Failed to cache clients: {str(e)}")
            self._cached_clients = []

    def get_clients(self, use_cache: bool = True) -> List[Client]:
        """Get all clients with error handling."""
        if not self.is_authenticated():
            raise PlexTracAPIError("Not authenticated")

        # Use cached clients if available and requested
        if use_cache and self._cached_clients is not None:
            return self._cached_clients

        try:
            clients = self.api.get_clients()
            # Update cache
            if use_cache:
                self._cached_clients = clients
            return clients
        except Exception as e:
            self.logger.error(f"Failed to get clients: {str(e)}")
            raise

    def get_reports(self, client_id: str) -> List[Report]:
        """Get reports for a client with error handling."""
        if not self.is_authenticated():
            raise PlexTracAPIError("Not authenticated")

        try:
            return self.api.get_reports(client_id)
        except Exception as e:
            self.logger.error(f"Failed to get reports for client {client_id}: {str(e)}")
            raise

    def create_report_if_needed(
        self, client_id: str, report_name: str, template_id: Optional[str] = None
    ) -> Report:
        """Create a report if it doesn't exist, or return existing one."""
        if not self.is_authenticated():
            raise PlexTracAPIError("Not authenticated")

        try:
            # Check if report already exists
            reports = self.get_reports(client_id)
            existing_report = next((r for r in reports if r.name == report_name), None)

            if existing_report:
                self.logger.info(f"Using existing report: {report_name}")
                return existing_report

            # Create new report
            if self.config.import_.auto_create_reports:
                template_id = template_id or self.config.import_.default_report_template_id
                report = self.api.create_report(client_id, report_name, template_id)
                self.logger.info(f"Created new report: {report_name}")
                return report
            else:
                raise PlexTracAPIError(
                    f"Report '{report_name}' does not exist and auto-creation is disabled"
                )

        except Exception as e:
            self.logger.error(f"Failed to create/get report '{report_name}': {str(e)}")
            raise

    def import_findings(
        self,
        client_id: str,
        report_id: str,
        findings: List[Finding],
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> ImportResult:
        """Import findings to PlexTrac with progress tracking."""
        if not self.is_authenticated():
            raise PlexTracAPIError("Not authenticated")

        start_time = datetime.now()
        total_findings = len(findings)
        imported_findings = 0
        duplicate_findings = 0
        errors = []

        self.logger.info(f"Starting import of {total_findings} findings to report {report_id}")

        if progress_callback:
            progress_callback(0, total_findings, "Starting import...")

        try:
            # Use batch import if available, otherwise import one by one
            batch_size = self.config.import_.batch_size

            for i in range(0, total_findings, batch_size):
                batch = findings[i : i + batch_size]
                batch_num = i // batch_size + 1
                total_batches = (total_findings + batch_size - 1) // batch_size

                if progress_callback:
                    progress_callback(
                        i, total_findings, f"Processing batch {batch_num}/{total_batches}"
                    )

                # Import batch
                for j, finding in enumerate(batch):
                    try:
                        self.api.create_finding(client_id, report_id, finding)
                        imported_findings += 1

                        # Update progress for individual findings
                        current_progress = i + j + 1
                        if progress_callback:
                            progress_callback(
                                current_progress,
                                total_findings,
                                f"Imported: {finding.title[:50]}...",
                            )

                    except Exception as e:
                        error_str = str(e)

                        # Handle duplicates gracefully
                        if (
                            "title already exists" in error_str.lower()
                            or "duplicate" in error_str.lower()
                        ):
                            duplicate_findings += 1
                            current_progress = i + j + 1
                            if progress_callback:
                                progress_callback(
                                    current_progress,
                                    total_findings,
                                    f"Duplicate: {finding.title[:50]}...",
                                )
                            self.logger.debug(f"Duplicate finding skipped: '{finding.title}'")
                        else:
                            error_msg = f"Failed to import finding '{finding.title}': {error_str}"
                            errors.append(error_msg)
                            self.logger.error(error_msg)

        except Exception as e:
            error_msg = f"Import process failed: {str(e)}"
            errors.append(error_msg)
            self.logger.error(error_msg)

        # Create result
        result = ImportResult(
            success=imported_findings > 0,
            total_findings=total_findings,
            imported_findings=imported_findings,
            duplicate_findings=duplicate_findings,
            failed_findings=total_findings - imported_findings - duplicate_findings,
            errors=errors,
            import_time=datetime.now() - start_time,
        )

        if progress_callback:
            progress_callback(
                total_findings,
                total_findings,
                f"Import complete: {imported_findings} new, {duplicate_findings} duplicates",
            )

        self.logger.info(
            f"Import completed: {imported_findings} imported, {duplicate_findings} duplicates, {len(errors)} errors"
        )

        if errors:
            self.logger.warning(f"Import had {len(errors)} errors")

        return result

    def import_findings_to_new_report(
        self,
        client_id: str,
        report_name: str,
        findings: List[Finding],
        template_id: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> ImportResult:
        """Import findings to a new report."""
        try:
            # Create or get report
            report = self.create_report_if_needed(client_id, report_name, template_id)

            # Import findings
            result = self.import_findings(client_id, report.id, findings, progress_callback)
            result.created_report = report

            return result

        except Exception as e:
            self.logger.error(f"Failed to import findings to new report: {str(e)}")
            return ImportResult(
                success=False,
                total_findings=len(findings),
                imported_findings=0,
                duplicate_findings=0,
                failed_findings=len(findings),
                errors=[str(e)],
            )

    def search_clients(self, query: str) -> List[Client]:
        """Search clients by name."""
        if not self.is_authenticated():
            raise PlexTracAPIError("Not authenticated")

        return self.api.search_clients(query)

    def search_reports(self, client_id: str, query: str) -> List[Report]:
        """Search reports by name."""
        if not self.is_authenticated():
            raise PlexTracAPIError("Not authenticated")

        return self.api.search_reports(client_id, query)

    def validate_import_target(
        self, client_id: str, report_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validate that client and optionally report exist."""
        result = {
            "valid": False,
            "client_exists": False,
            "report_exists": False,
            "client": None,
            "report": None,
            "errors": [],
        }

        try:
            # Check client
            client = self.api.get_client(client_id)
            if client:
                result["client_exists"] = True
                result["client"] = client
            else:
                result["errors"].append(f"Client {client_id} not found")

            # Check report if provided
            if report_id and result["client_exists"]:
                report = self.api.get_report(client_id, report_id)
                if report:
                    result["report_exists"] = True
                    result["report"] = report
                else:
                    result["errors"].append(f"Report {report_id} not found")

            result["valid"] = result["client_exists"] and (not report_id or result["report_exists"])

        except Exception as e:
            result["errors"].append(str(e))

        return result

    def get_import_preview(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate preview information for findings import."""
        if not findings:
            return {"total_findings": 0, "by_severity": {}, "by_status": {}, "sample_findings": []}

        # Count by severity
        by_severity = {}
        by_status = {}

        for finding in findings:
            severity = finding.severity
            status = finding.status

            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_status[status] = by_status.get(status, 0) + 1

        # Get sample findings (first 5)
        sample_findings = []
        for finding in findings[:5]:
            sample_findings.append(
                {
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": finding.status,
                    "description_preview": (
                        finding.description[:100] + "..."
                        if len(finding.description) > 100
                        else finding.description
                    ),
                }
            )

        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_status": by_status,
            "sample_findings": sample_findings,
        }

    def disconnect(self):
        """Disconnect from PlexTrac."""
        try:
            self.auth.logout()
            self._authenticated = False
            self.logger.info("Disconnected from PlexTrac")
        except Exception as e:
            self.logger.warning(f"Error during disconnect: {str(e)}")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
