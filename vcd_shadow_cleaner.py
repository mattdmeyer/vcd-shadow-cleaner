#!/usr/bin/env python3
"""
VMware Cloud Director Shadow VM Cleanup Tool
Author: Burke Azbill
Last Update: 2025-12-16
Description:
A cross-platform GUI application for managing Shadow VMs in VMware Cloud Director.
Supports system tenant (provider) login with the ability to switch to specific tenants.

Requirements:
    - Python 3.8+
    - PySide6
    - requests

Usage:
    GUI Mode:   python vcd_shadow_cleaner.py 
    CLI Mode:   python vcd_shadow_cleaner.py --cli --server <vcd_host> --token <api_token> 
                    --tenant <tenant_name> --catalog <catalog_name> --datastore <datastore_name>
                    [--dry-run]
"""

import argparse
import sys
import json
import urllib3
import os
import time # Import the time module for delays
from dataclasses import dataclass
from typing import Optional, List, Tuple
from datetime import datetime

import requests

# Suppress SSL warnings for development (should be removed in production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def load_env_file(env_path: str = ".env"):
    """
    Load environment variables from a .env file if it exists.
    Simple implementation to avoid external dependencies.
    """
    if not os.path.exists(env_path):
        return

    try:
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                # Split on first =
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Remove quotes if present
                    if (value.startswith('"') and value.endswith('"')) or \
                       (value.startswith("'") and value.endswith("'")):
                        value = value[1:-1]
                    
                    # Set env var if not already set
                    if key not in os.environ:
                        os.environ[key] = value
    except Exception as e:
        print(f"Warning: Failed to load .env file: {e}")


@dataclass
class ShadowVM:
    """Represents a Shadow VM in VCD."""
    name: str
    href: str
    container_name: str  # Parent vApp Template name (if resolved)
    container_id: str    # Parent vApp Template ID/HREF
    datastore_name: str
    vm_id: str
    primary_vm_href: str # Link to the primary VM
    catalog_name: str = ""


@dataclass
class VAppTemplate:
    """Represents a vApp Template in VCD."""
    name: str
    href: str
    id: str
    catalog_name: str


class VCDClient:
    """VMware Cloud Director API Client."""

    def __init__(self, host: str, verify_ssl: bool = False):
        self.host = host.rstrip('/')
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.access_token: Optional[str] = None
        self.api_version = "38.0"  # VCD API version
        self.current_org: Optional[str] = None

    def _get_headers(self) -> dict:
        """Get common API headers."""
        headers = {
            "Accept": f"application/*+json;version={self.api_version}",
            "Content-Type": "application/json"
        }
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        return headers

    def authenticate_with_token(self, api_token: str, org: str = "system") -> bool:
        """
        Authenticate to VCD using an API token.
        
        Args:
            api_token: The VCD API refresh token
            org: The organization ('system' for provider login)
            
        Returns:
            True if authentication successful, False otherwise
        """
        try:
            if org.lower() == "system":
                uri = f"https://{self.host}/oauth/provider/token"
            else:
                uri = f"https://{self.host}/oauth/tenant/{org}/token"

            body = f"grant_type=refresh_token&refresh_token={api_token}"
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded"
            }

            response = self.session.post(uri, headers=headers, data=body)
            response.raise_for_status()

            data = response.json()
            self.access_token = data.get("access_token")
            self.current_org = org
            return True
        except Exception as e:
            print(f"Authentication failed: {e}")
            return False

    def authenticate_with_credentials(self, username: str, password: str, org: str = "system") -> bool:
        """
        Authenticate to VCD using username and password.
        
        Tries multiple authentication methods in order:
        1. CloudAPI sessions (modern VCD 10.x+)
        2. Legacy /api/sessions
        
        Args:
            username: VCD username
            password: VCD password
            org: The organization ('system' for provider login)
            
        Returns:
            True if authentication successful, False otherwise
        """
        # Try CloudAPI sessions first (VCD 10.x+)
        if self._authenticate_cloudapi(username, password, org):
            return True
        
        # Try legacy /api/sessions
        if self._authenticate_legacy(username, password, org):
            return True
        
        print("All authentication methods failed.")
        return False

    def _authenticate_cloudapi(self, username: str, password: str, org: str = "system") -> bool:
        """
        Modern CloudAPI authentication using /cloudapi/1.0.0/sessions.
        Works with VCD 10.x and later.
        """
        try:
            # For provider (system) login, use /cloudapi/1.0.0/sessions/provider
            if org.lower() == "system":
                uri = f"https://{self.host}/cloudapi/1.0.0/sessions/provider"
            else:
                uri = f"https://{self.host}/cloudapi/1.0.0/sessions"

            headers = {
                "Accept": f"application/json;version={self.api_version}",
                "Content-Type": "application/json"
            }

            # Use Basic Auth
            import base64
            if org.lower() == "system":
                auth_string = f"{username}@system"
            else:
                auth_string = f"{username}@{org}"
            
            credentials = base64.b64encode(f"{auth_string}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"

            response = self.session.post(uri, headers=headers)
            response.raise_for_status()

            # Get the access token from response header
            self.access_token = response.headers.get("X-VMWARE-VCLOUD-ACCESS-TOKEN")
            if not self.access_token:
                # Try getting from response body
                try:
                    data = response.json()
                    self.access_token = data.get("accessToken") or data.get("token")
                except:
                    pass
            
            if self.access_token:
                self.current_org = org
                print(f"CloudAPI authentication successful")
                return True
            else:
                print("CloudAPI auth: No access token in response")
                return False
                
        except requests.exceptions.HTTPError as e:
            print(f"CloudAPI authentication failed: {e}")
            return False
        except Exception as e:
            print(f"CloudAPI authentication error: {e}")
            return False

    def _authenticate_legacy(self, username: str, password: str, org: str = "system") -> bool:
        """
        Legacy authentication using /api/sessions (for older VCD versions).
        """
        try:
            uri = f"https://{self.host}/api/sessions"
            
            # For system org, use username@system format
            if org.lower() == "system":
                auth_user = f"{username}@system"
            else:
                auth_user = f"{username}@{org}"

            headers = {
                "Accept": f"application/*+json;version={self.api_version}",
            }

            response = self.session.post(
                uri, 
                headers=headers, 
                auth=(auth_user, password)
            )
            response.raise_for_status()

            # Get the auth token from header
            self.access_token = response.headers.get("X-VMWARE-VCLOUD-ACCESS-TOKEN")
            self.current_org = org
            print("Legacy authentication successful")
            return True
        except Exception as e:
            print(f"Legacy authentication failed: {e}")
            return False

    def get_organizations(self) -> List[dict]:
        """Get list of organizations (tenants) visible to the authenticated user."""
        try:
            uri = f"https://{self.host}/api/org"
            response = self.session.get(uri, headers=self._get_headers())
            response.raise_for_status()
            
            data = response.json()
            orgs = []
            for org in data.get("org", []):
                orgs.append({
                    "name": org.get("name"),
                    "href": org.get("href")
                })
            return sorted(orgs, key=lambda x: x.get("name", ""))
        except Exception as e:
            print(f"Failed to get organizations: {e}")
            return []

    def switch_to_org(self, org_name: str) -> bool:
        """Switch context to a specific organization."""
        self.current_org = org_name
        return True

    def get_catalogs(self, org_name: Optional[str] = None) -> List[dict]:
        """
        Get list of catalogs visible to the authenticated user.
        
        Args:
            org_name: Optional organization name to filter catalogs by.
                      If provided, only returns catalogs belonging to or shared with that org.
        """
        catalogs = []
        
        # Build filter based on org if provided
        org_filter = ""
        if org_name and org_name.lower() != "system":
            # Filter by org name - this will get catalogs owned by this org
            org_filter = f"&filter=orgName=={org_name}"
        
        # Try adminCatalog first (for provider/system admin access)
        query_types = ["adminCatalog", "catalog"]
        
        for query_type in query_types:
            try:
                page = 1
                page_size = 100
                total_fetched = 0
                
                while True:
                    uri = f"https://{self.host}/api/query?type={query_type}&format=records&page={page}&pageSize={page_size}{org_filter}"
                    response = self.session.get(uri, headers=self._get_headers())
                    
                    if response.status_code == 403:
                        # Not authorized for this query type, try next
                        break
                    
                    response.raise_for_status()
                    data = response.json()
                    
                    records = data.get("record", [])
                    if not records:
                        break
                    
                    for record in records:
                        catalog_entry = {
                            "name": record.get("name"),
                            "href": record.get("href"),
                            "orgName": record.get("orgName", record.get("org", "N/A")),
                            "isShared": record.get("isShared", False),
                            "isPublished": record.get("isPublished", False),
                        }
                        # Avoid duplicates
                        if not any(c["name"] == catalog_entry["name"] and c["orgName"] == catalog_entry["orgName"] for c in catalogs):
                            catalogs.append(catalog_entry)
                    
                    total_fetched += len(records)
                    
                    # Check if there are more pages
                    total_records = int(data.get("total", 0))
                    if total_fetched >= total_records or len(records) < page_size:
                        break
                    
                    page += 1
                
                # If we got catalogs with adminCatalog, no need to try catalog
                if catalogs:
                    break
                    
            except requests.exceptions.HTTPError as e:
                print(f"Query type {query_type} failed: {e}")
                continue
            except Exception as e:
                print(f"Error fetching catalogs with {query_type}: {e}")
                continue
        
        # If org filter was applied but we also need shared catalogs, fetch those too
        if org_name and org_name.lower() != "system":
            shared_catalogs = self._get_shared_catalogs_for_org(org_name)
            for cat in shared_catalogs:
                if not any(c["name"] == cat["name"] for c in catalogs):
                    catalogs.append(cat)
        
        print(f"Found {len(catalogs)} catalogs for org '{org_name or 'all'}'")
        return sorted(catalogs, key=lambda x: (x.get("orgName", ""), x.get("name", "")))

    def _get_shared_catalogs_for_org(self, org_name: str) -> List[dict]:
        """Get catalogs that are shared/published and accessible to the specified org."""
        catalogs = []
        page = 1
        page_size = 100

        try:
            while True:
                uri = f"https://{self.host}/api/query?type=adminCatalog&format=records&filter=isPublished==true&page={page}&pageSize={page_size}"
                response = self.session.get(uri, headers=self._get_headers())
                if response.status_code != 200:
                    break

                data = response.json()
                records = data.get("record", [])

                if not records:
                    break

                for record in records:
                    catalogs.append({
                        "name": record.get("name"),
                        "href": record.get("href"),
                        "orgName": record.get("orgName", "N/A"),
                        "isShared": True,
                        "isPublished": True,
                    })

                total_records = int(data.get("total", 0))
                if len(catalogs) >= total_records or len(records) < page_size:
                    break

                page += 1

        except Exception as e:
            print(f"Error fetching shared catalogs: {e}")
        return catalogs

    def get_datastores(self) -> List[dict]:
        """Get list of datastores (requires provider-level access)."""
        datastores = []
        page = 1
        page_size = 100

        try:
            while True:
                uri = f"https://{self.host}/api/query?type=datastore&format=records&page={page}&pageSize={page_size}"
                response = self.session.get(uri, headers=self._get_headers())
                response.raise_for_status()

                data = response.json()
                records = data.get("record", [])

                if not records:
                    break

                for record in records:
                    datastores.append({
                        "name": record.get("name"),
                        "href": record.get("href"),
                        "vcName": record.get("vcName", ""),
                        "datastoreType": record.get("datastoreType", "")
                    })

                total_records = int(data.get("total", 0))
                if len(datastores) >= total_records or len(records) < page_size:
                    break

                page += 1

            return sorted(datastores, key=lambda x: x.get("name", ""))
        except Exception as e:
            print(f"Failed to get datastores: {e}")
            return []

    def get_vapp_templates_in_catalog(self, catalog_name: str) -> List[VAppTemplate]:
        """Get all vApp templates in a specific catalog."""
        templates = []
        page = 1
        page_size = 100

        try:
            while True:
                uri = f"https://{self.host}/api/query?type=adminVAppTemplate&format=records&filter=catalogName=={catalog_name}&page={page}&pageSize={page_size}"
                response = self.session.get(uri, headers=self._get_headers())
                response.raise_for_status()

                data = response.json()
                records = data.get("record", [])

                if not records:
                    break

                for record in records:
                    templates.append(VAppTemplate(
                        name=record.get("name", ""),
                        href=record.get("href", ""),
                        id=record.get("id", "") or record.get("href", ""),
                        catalog_name=record.get("catalogName", "")
                    ))

                total_records = int(data.get("total", 0))
                if len(templates) >= total_records or len(records) < page_size:
                    break

                page += 1

            return templates
        except Exception as e:
            print(f"Failed to get vApp templates: {e}")
            return []

    def get_shadow_vms_on_datastore(self, datastore_name: str, debug: bool = False) -> List[ShadowVM]:
        """Get all Shadow VMs on a specific datastore."""
        shadows = []
        page = 1
        page_size = 100
        
        try:
            while True:
                uri = f"https://{self.host}/api/query?type=adminShadowVM&format=records&filter=datastoreName=={datastore_name}&page={page}&pageSize={page_size}"
                response = self.session.get(uri, headers=self._get_headers())
                response.raise_for_status()
                
                data = response.json()
                records = data.get("record", [])
                
                if not records:
                    break
                
                # Debug: print first record to see available fields
                if debug and page == 1 and records:
                    print(f"DEBUG: Sample Shadow VM record fields: {list(records[0].keys())}")
                    print(f"DEBUG: Sample Shadow VM record: {records[0]}")
                
                for record in records:
                    # The container/parent template reference might be in different fields
                    # Check multiple possible field names for NAME
                    container_name = (
                        record.get("containerName") or 
                        record.get("container") or 
                        record.get("vappTemplate") or
                        record.get("catalogItem") or
                        record.get("name", "").split(" ")[0] if " " in record.get("name", "") else ""
                    )
                    
                    # Capture the container/parent reference ID/HREF
                    # Based on debug output, primaryVAppTemplate is the key field
                    container_id = (
                        record.get("primaryVAppTemplate") or 
                        record.get("container") or 
                        record.get("vAppTemplate") or 
                        record.get("entity") or
                        ""
                    )
                    
                    # Also capture the primary template reference if available
                    primary_vm_name = record.get("primaryVmName", "")
                    primary_vm_href = record.get("primaryVM", "")
                    
                    shadows.append(ShadowVM(
                        name=record.get("name", ""),
                        href=record.get("href", ""),
                        container_name=container_name,
                        container_id=container_id,
                        datastore_name=record.get("datastoreName", ""),
                        vm_id=record.get("href", "").split("/")[-1] if record.get("href") else "",
                        primary_vm_href=primary_vm_href
                    ))
                
                # Check pagination
                total_records = int(data.get("total", 0))
                if len(shadows) >= total_records or len(records) < page_size:
                    break
                page += 1
                
            return shadows
        except Exception as e:
            print(f"Failed to get Shadow VMs: {e}")
            return []

    def delete_shadow_vm(self, shadow_vm: ShadowVM) -> Tuple[bool, str]:
        """
        Delete a Shadow VM.
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            response = self.session.delete(shadow_vm.href, headers=self._get_headers())
            
            if response.status_code in [200, 202, 204]:
                return True, f"Successfully deleted {shadow_vm.name}"
            else:
                return False, f"Failed to delete {shadow_vm.name}: {response.status_code}"
        except Exception as e:
            return False, f"Error deleting {shadow_vm.name}: {e}"

    def disconnect(self):
        """Disconnect from VCD."""
        try:
            if self.access_token:
                uri = f"https://{self.host}/api/session"
                self.session.delete(uri, headers=self._get_headers())
        except:
            pass
        finally:
            self.access_token = None
            self.current_org = None


def scan_shadow_vms(client: VCDClient, catalog_names: List[str], datastore_name: str, debug: bool = True) -> List[ShadowVM]:
    """
    Scan for Shadow VMs on a datastore that belong to templates in one or more catalogs.

    Args:
        client: Authenticated VCDClient
        catalog_names: List of catalog names (or a single name) to scan
        datastore_name: Datastore to scan for shadow VMs
        debug: Enable debug output

    Returns:
        List of matching shadow VMs with catalog_name populated
    """
    if isinstance(catalog_names, str):
        catalog_names = [catalog_names]

    print(f"\nScanning for Shadow VMs...")
    print(f"  Catalogs: {', '.join(catalog_names)}")
    print(f"  Datastore: {datastore_name}")

    # Build combined lookup structures across all catalogs
    # Maps template HREF/ID -> (template_name, catalog_name)
    template_ids: dict[str, tuple[str, str]] = {}
    # Maps template name -> catalog_name (first catalog wins for name-based matching)
    template_name_to_catalog: dict[str, str] = {}

    for cat_name in catalog_names:
        templates = client.get_vapp_templates_in_catalog(cat_name)
        print(f"  Found {len(templates)} templates in catalog '{cat_name}'")
        if debug and templates:
            print(f"  DEBUG: Sample template names ({cat_name}): {[t.name for t in templates[:5]]}")

        for t in templates:
            if t.href:
                template_ids[t.href] = (t.name, cat_name)
            if t.id:
                template_ids[t.id] = (t.name, cat_name)
            if t.name not in template_name_to_catalog:
                template_name_to_catalog[t.name] = cat_name

    template_names = set(template_name_to_catalog.keys())

    all_shadows = client.get_shadow_vms_on_datastore(datastore_name, debug=debug)
    print(f"  Found {len(all_shadows)} Shadow VMs on datastore")

    if debug and all_shadows:
        print(f"  DEBUG: Sample Shadow VM container_names: {[s.container_name for s in all_shadows[:5]]}")
        print(f"  DEBUG: Sample Shadow VM container_ids: {[s.container_id for s in all_shadows[:5]]}")
        print(f"  DEBUG: Sample Shadow VM names: {[s.name for s in all_shadows[:5]]}")

    matching_shadows = []

    for shadow in all_shadows:
        # Strategy 1: Direct container_id match (HREF/ID)
        if shadow.container_id and shadow.container_id in template_ids:
            tpl_name, cat_name = template_ids[shadow.container_id]
            shadow.container_name = tpl_name
            shadow.catalog_name = cat_name
            matching_shadows.append(shadow)
            continue

        # Strategy 2: Direct container_name match
        if shadow.container_name in template_names:
            shadow.catalog_name = template_name_to_catalog[shadow.container_name]
            matching_shadows.append(shadow)
            continue

        # Strategy 3: Check if shadow VM name contains any template name
        for tpl_name in template_names:
            if shadow.name.startswith(tpl_name) or tpl_name in shadow.name:
                shadow.container_name = tpl_name
                shadow.catalog_name = template_name_to_catalog[tpl_name]
                matching_shadows.append(shadow)
                break

    # Deduplicate by href
    seen_hrefs = set()
    unique_shadows = []
    for s in matching_shadows:
        if s.href not in seen_hrefs:
            seen_hrefs.add(s.href)
            unique_shadows.append(s)

    print(f"  Matched {len(unique_shadows)} Shadow VMs to catalog templates")

    return unique_shadows


def print_shadow_vm_table(shadows: List[ShadowVM]):
    """Print Shadow VMs in ASCII table format."""
    if not shadows:
        print("\nNo Shadow VMs found matching the criteria.")
        return

    # Calculate column widths
    name_width = max(len(s.name) for s in shadows)
    name_width = max(name_width, len("Shadow VM Name"))

    template_width = max(len(s.container_name) for s in shadows)
    template_width = max(template_width, len("Parent Template"))

    cat_width = max(len(s.catalog_name) for s in shadows)
    cat_width = max(cat_width, len("Catalog"))

    ds_width = max(len(s.datastore_name) for s in shadows)
    ds_width = max(ds_width, len("Datastore"))

    total_width = name_width + template_width + cat_width + ds_width + 13

    # Print header
    print("\n" + "=" * total_width)
    print(f"| {'Shadow VM Name':<{name_width}} | {'Parent Template':<{template_width}} | {'Catalog':<{cat_width}} | {'Datastore':<{ds_width}} |")
    print("|" + "-" * (name_width + 2) + "|" + "-" * (template_width + 2) + "|" + "-" * (cat_width + 2) + "|" + "-" * (ds_width + 2) + "|")

    # Print rows
    for shadow in shadows:
        print(f"| {shadow.name:<{name_width}} | {shadow.container_name:<{template_width}} | {shadow.catalog_name:<{cat_width}} | {shadow.datastore_name:<{ds_width}} |")

    # Print footer
    print("=" * total_width)
    print(f"\nTotal Shadow VMs: {len(shadows)}")


def run_cli(args):
    """Run in CLI mode."""
    print("=" * 60)
    print("VMware Cloud Director Shadow VM Cleanup Tool")
    print("=" * 60)
    
    if args.dry_run:
        print("\n*** DRY RUN MODE - No changes will be made ***\n")
    
    # Initialize client
    client = VCDClient(args.server, verify_ssl=not args.skip_ssl_verify)
    
    # Authenticate
    print(f"\nConnecting to {args.server}...")
    if args.token:
        if not client.authenticate_with_token(args.token, "system"):
            print("ERROR: Authentication failed")
            return 1
    elif args.username and args.password:
        if not client.authenticate_with_credentials(args.username, args.password, "system"):
            print("ERROR: Authentication failed")
            return 1
    else:
        print("ERROR: Either --token or --username/--password must be provided")
        return 1
    
    print("Connected successfully!")
    
    # Switch to tenant if specified
    if args.tenant and args.tenant.lower() != "system":
        print(f"Switching to tenant: {args.tenant}")
        client.switch_to_org(args.tenant)
    
    # Scan for Shadow VMs (support comma-separated catalog names from CLI)
    catalog_names = [c.strip() for c in args.catalog.split(",")]
    shadows = scan_shadow_vms(client, catalog_names, args.datastore)
    
    # Print results
    print_shadow_vm_table(shadows)
    
    if not shadows:
        client.disconnect()
        return 0
    
    if args.dry_run:
        print("\n*** DRY RUN COMPLETE - No Shadow VMs were deleted ***")
        client.disconnect()
        return 0
    
    # Prompt for confirmation
    print(f"\nAre you sure you want to delete {len(shadows)} Shadow VMs?")
    response = input("Type 'yes' to confirm: ").strip().lower()
    
    if response != 'yes':
        print("Operation cancelled.")
        client.disconnect()
        return 0
    
    # Delete Shadow VMs
    print("\nDeleting Shadow VMs...")
    success_count = 0
    fail_count = 0
    
    for i, shadow in enumerate(shadows, 1):
        print(f"  [{i}/{len(shadows)}] Deleting {shadow.name}...", end=" ")
        success, message = client.delete_shadow_vm(shadow)
        if success:
            print("OK")
            success_count += 1
        else:
            print(f"FAILED - {message}")
            fail_count += 1
    
    print(f"\nDeletion complete: {success_count} succeeded, {fail_count} failed")
    
    client.disconnect()
    return 0 if fail_count == 0 else 1


def run_gui():
    """Run in GUI mode with PySide6."""
    try:
        from PySide6.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
            QLabel, QLineEdit, QPushButton, QComboBox, QTableView,
            QGroupBox, QFormLayout, QProgressBar,
            QMessageBox, QCheckBox, QTextEdit, QHeaderView,
            QFrame, QListWidget, QListWidgetItem,
            QDialog, QDialogButtonBox, QAbstractItemView, QMenu
        )
        from PySide6.QtCore import (
            Qt, QThread, Signal, QSortFilterProxyModel, QModelIndex
        )
        from PySide6.QtGui import (
            QFont, QPalette, QColor, QIcon, QStandardItemModel, QStandardItem,
            QAction
        )
    except ImportError:
        print("ERROR: PySide6 is required for GUI mode.")
        print("Install it with: pip install PySide6")
        return 1

    SHADOW_VM_ROLE = Qt.ItemDataRole.UserRole + 1
    COL_CHECK = 0
    COL_CATALOG = 1
    COL_TEMPLATE = 2
    COL_VMNAME = 3
    COL_DATASTORE = 4
    COLUMN_HEADERS = ["", "Catalog", "Parent Template", "Shadow VM Name", "Datastore"]
    FILTERABLE_COLUMNS = {COL_CATALOG, COL_TEMPLATE, COL_DATASTORE}

    class ColumnFilterProxyModel(QSortFilterProxyModel):
        """Proxy that filters rows based on per-column allowed-value sets."""

        def __init__(self, parent=None):
            super().__init__(parent)
            self._filters: dict[int, set[str]] = {}

        def set_column_filter(self, col: int, allowed: set[str] | None):
            if allowed is None:
                self._filters.pop(col, None)
            else:
                self._filters[col] = allowed
            self.invalidateFilter()

        def clear_all_filters(self):
            self._filters.clear()
            self.invalidateFilter()

        def active_filters(self) -> dict[int, set[str]]:
            return dict(self._filters)

        def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
            model = self.sourceModel()
            for col, allowed in self._filters.items():
                idx = model.index(source_row, col)
                value = model.data(idx, Qt.ItemDataRole.DisplayRole) or ""
                if value not in allowed:
                    return False
            return True

    class FilterPopupDialog(QDialog):
        """Excel-style multi-select filter popup for a column."""

        def __init__(self, parent, title: str, all_values: list[str], checked_values: set[str] | None):
            super().__init__(parent)
            self.setWindowTitle(f"Filter: {title}")
            self.setMinimumSize(280, 350)
            self.result_set: set[str] | None = None

            layout = QVBoxLayout(self)

            btn_row = QHBoxLayout()
            select_all_btn = QPushButton("Select All")
            select_all_btn.clicked.connect(self._select_all)
            deselect_all_btn = QPushButton("Deselect All")
            deselect_all_btn.clicked.connect(self._deselect_all)
            clear_filter_btn = QPushButton("Clear Filter")
            clear_filter_btn.clicked.connect(self._clear_filter)
            btn_row.addWidget(select_all_btn)
            btn_row.addWidget(deselect_all_btn)
            btn_row.addWidget(clear_filter_btn)
            layout.addLayout(btn_row)

            self._list = QListWidget()
            self._list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
            sorted_values = sorted(set(all_values))
            for val in sorted_values:
                item = QListWidgetItem(val)
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                if checked_values is None or val in checked_values:
                    item.setCheckState(Qt.CheckState.Checked)
                else:
                    item.setCheckState(Qt.CheckState.Unchecked)
                self._list.addItem(item)
            layout.addWidget(self._list)

            buttons = QDialogButtonBox(
                QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
            )
            buttons.accepted.connect(self._on_ok)
            buttons.rejected.connect(self.reject)
            layout.addWidget(buttons)

        def _select_all(self):
            for i in range(self._list.count()):
                self._list.item(i).setCheckState(Qt.CheckState.Checked)

        def _deselect_all(self):
            for i in range(self._list.count()):
                self._list.item(i).setCheckState(Qt.CheckState.Unchecked)

        def _clear_filter(self):
            self.result_set = None
            self.accept()

        def _on_ok(self):
            self.result_set = set()
            for i in range(self._list.count()):
                item = self._list.item(i)
                if item.checkState() == Qt.CheckState.Checked:
                    self.result_set.add(item.text())
            self.accept()

    class FilterHeaderView(QHeaderView):
        """Header view that supports right-click filter menus on filterable columns."""
        filter_requested = Signal(int)

        def __init__(self, orientation, parent=None):
            super().__init__(orientation, parent)
            self.setSectionsClickable(True)
            self._filtered_columns: set[int] = set()

        def set_filtered(self, col: int, is_filtered: bool):
            if is_filtered:
                self._filtered_columns.add(col)
            else:
                self._filtered_columns.discard(col)
            self.viewport().update()

        def mousePressEvent(self, event):
            if event.button() == Qt.MouseButton.RightButton:
                logical = self.logicalIndexAt(event.pos())
                if logical in FILTERABLE_COLUMNS:
                    menu = QMenu(self)
                    col = logical
                    action = QAction("Filter...", self)
                    action.triggered.connect(lambda checked=False, c=col: self.filter_requested.emit(c))
                    menu.addAction(action)
                    if col in self._filtered_columns:
                        clear_action = QAction("Clear this filter", self)
                        clear_action.triggered.connect(lambda checked=False, c=col: self.filter_requested.emit(-c))
                        menu.addAction(clear_action)
                    menu.exec(event.globalPosition().toPoint())
                    return
            super().mousePressEvent(event)

    class WorkerThread(QThread):
        """Background worker thread for long-running operations."""
        finished = Signal(object)
        progress = Signal(int, str)
        error = Signal(str)

        def __init__(self, func, *args, **kwargs):
            super().__init__()
            self.func = func
            self.args = args
            self.kwargs = kwargs

        def run(self):
            try:
                result = self.func(*self.args, **self.kwargs)
                self.finished.emit(result)
            except Exception as e:
                self.error.emit(str(e))

    class MainWindow(QMainWindow):
        class ConnectionWorker(QThread):
            finished = Signal(bool, object)

            def __init__(self, parent, client_args, auth_method, auth_args):
                super().__init__(parent)
                self.client_args = client_args
                self.auth_method = auth_method
                self.auth_args = auth_args

            def run(self):
                client = VCDClient(*self.client_args)
                success = False
                error_message = ""
                try:
                    if self.auth_method == "token":
                        success = client.authenticate_with_token(self.auth_args["token"], "system")
                    elif self.auth_method == "credentials":
                        success = client.authenticate_with_credentials(
                            self.auth_args["username"], self.auth_args["password"], "system"
                        )
                    else:
                        error_message = "Invalid authentication method"
                except Exception as e:
                    error_message = str(e)
                if success:
                    self.finished.emit(True, client)
                else:
                    self.finished.emit(False, error_message)

        def __init__(self):
            super().__init__()
            self.client: Optional[VCDClient] = None
            self.shadow_vms: List[ShadowVM] = []
            self.worker: Optional[WorkerThread] = None
            self._select_all_state = False

            self.init_ui()
            self.reset_connection_ui()

        def init_ui(self):
            self.setWindowTitle("VMware Cloud Director Shadow VM Cleanup")
            self.setWindowIcon(QIcon("vcd_shadow_cleaner.svg"))
            self.setMinimumSize(1000, 700)

            central_widget = QWidget()
            self.setCentralWidget(central_widget)

            main_layout = QVBoxLayout(central_widget)
            main_layout.setSpacing(10)
            main_layout.setContentsMargins(15, 15, 15, 15)

            # --- Connection Group ---
            conn_group = QGroupBox("VCD Connection")
            conn_layout = QFormLayout()
            conn_layout.setSpacing(8)

            self.server_input = QLineEdit()
            self.server_input.setPlaceholderText("e.g., vcd.example.com")
            conn_layout.addRow("VCD Server:", self.server_input)

            auth_layout = QHBoxLayout()
            self.auth_token_radio = QCheckBox("Use API Token")
            self.auth_token_radio.setChecked(False)
            self.auth_token_radio.stateChanged.connect(self.toggle_auth_mode)
            auth_layout.addWidget(self.auth_token_radio)
            auth_layout.addStretch()
            conn_layout.addRow("", auth_layout)

            self.token_input = QLineEdit()
            self.token_input.setPlaceholderText("Enter VCD API Token")
            self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.token_input.setVisible(False)
            self.token_label = QLabel("API Token:")
            self.token_label.setVisible(False)
            conn_layout.addRow(self.token_label, self.token_input)

            self.username_input = QLineEdit()
            self.username_input.setPlaceholderText("Username")
            self.username_input.setEnabled(True)
            conn_layout.addRow("Username:", self.username_input)

            self.password_input = QLineEdit()
            self.password_input.setPlaceholderText("Password")
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.password_input.setEnabled(True)
            self.show_password_check = QCheckBox("Show Password")
            self.show_password_check.stateChanged.connect(self.toggle_password_visibility)
            self.show_password_check.setEnabled(True)
            pwd_layout = QHBoxLayout()
            pwd_layout.addWidget(self.password_input)
            pwd_layout.addWidget(self.show_password_check)
            conn_layout.addRow("Password:", pwd_layout)

            self.skip_ssl_check = QCheckBox("Skip SSL Verification")
            conn_layout.addRow("", self.skip_ssl_check)

            self.connect_btn = QPushButton("Connect to VCD")
            self.connect_btn.clicked.connect(self.connect_to_vcd)
            self.connect_btn.setMinimumHeight(35)
            self.disconnect_btn = QPushButton("Disconnect")
            self.disconnect_btn.clicked.connect(self.disconnect_from_vcd)
            self.disconnect_btn.setMinimumHeight(35)
            self.disconnect_btn.setEnabled(False)
            btn_layout_conn = QHBoxLayout()
            btn_layout_conn.addWidget(self.connect_btn)
            btn_layout_conn.addWidget(self.disconnect_btn)
            conn_layout.addRow("", btn_layout_conn)

            conn_group.setLayout(conn_layout)
            main_layout.addWidget(conn_group)

            # --- Selection Group ---
            select_group = QGroupBox("Selection")
            select_layout = QFormLayout()
            select_layout.setSpacing(8)

            self.tenant_combo = QComboBox()
            self.tenant_combo.setEnabled(False)
            self.tenant_combo.currentTextChanged.connect(self.on_tenant_changed)
            select_layout.addRow("Tenant:", self.tenant_combo)

            catalog_container = QVBoxLayout()
            catalog_btn_row = QHBoxLayout()
            catalog_btn_row.setSpacing(4)
            self.catalog_select_all_btn = QPushButton("Select All")
            self.catalog_select_all_btn.setMaximumHeight(22)
            self.catalog_select_all_btn.setEnabled(False)
            self.catalog_select_all_btn.clicked.connect(self._catalog_select_all)
            self.catalog_deselect_all_btn = QPushButton("Deselect All")
            self.catalog_deselect_all_btn.setMaximumHeight(22)
            self.catalog_deselect_all_btn.setEnabled(False)
            self.catalog_deselect_all_btn.clicked.connect(self._catalog_deselect_all)
            catalog_btn_row.addWidget(self.catalog_select_all_btn)
            catalog_btn_row.addWidget(self.catalog_deselect_all_btn)
            catalog_btn_row.addStretch()
            catalog_container.addLayout(catalog_btn_row)

            self.catalog_list = QListWidget()
            self.catalog_list.setEnabled(False)
            self.catalog_list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
            self.catalog_list.setMaximumHeight(120)
            catalog_container.addWidget(self.catalog_list)

            catalog_widget = QWidget()
            catalog_widget.setLayout(catalog_container)
            select_layout.addRow("Catalog(s):", catalog_widget)

            self.datastore_combo = QComboBox()
            self.datastore_combo.setEnabled(False)
            select_layout.addRow("Datastore:", self.datastore_combo)

            btn_layout = QHBoxLayout()
            self.scan_btn = QPushButton("Scan for Shadow VMs")
            self.scan_btn.clicked.connect(self.scan_shadow_vms)
            self.scan_btn.setEnabled(False)
            self.scan_btn.setMinimumHeight(35)
            btn_layout.addWidget(self.scan_btn)

            self.cleanup_btn = QPushButton("Cleanup Shadows")
            self.cleanup_btn.clicked.connect(self.cleanup_shadows)
            self.cleanup_btn.setEnabled(False)
            self.cleanup_btn.setMinimumHeight(35)
            self.cleanup_btn.setStyleSheet("background-color: #d32f2f; color: white;")
            btn_layout.addWidget(self.cleanup_btn)

            select_layout.addRow("", btn_layout)
            select_group.setLayout(select_layout)
            main_layout.addWidget(select_group)

            # --- Results Group ---
            results_group = QGroupBox("Shadow VMs Found")
            results_layout = QVBoxLayout()

            self.summary_label = QLabel("No scan performed yet.")
            self.summary_label.setStyleSheet("font-weight: bold; padding: 5px;")
            results_layout.addWidget(self.summary_label)

            # Filter button row
            filter_row = QHBoxLayout()
            filter_row.setSpacing(6)
            filter_label = QLabel("Filters:")
            filter_label.setStyleSheet("font-weight: bold; padding-right: 4px;")
            filter_row.addWidget(filter_label)

            self._filter_buttons: dict[int, QPushButton] = {}
            for col in sorted(FILTERABLE_COLUMNS):
                btn = QPushButton(f"{COLUMN_HEADERS[col]} \u25BC")
                btn.setMaximumHeight(24)
                btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")
                btn.clicked.connect(lambda checked=False, c=col: self._on_filter_requested(c))
                filter_row.addWidget(btn)
                self._filter_buttons[col] = btn

            clear_all_btn = QPushButton("Clear All Filters")
            clear_all_btn.setMaximumHeight(24)
            clear_all_btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")
            clear_all_btn.clicked.connect(self._clear_all_filters)
            filter_row.addWidget(clear_all_btn)

            filter_row.addStretch()
            results_layout.addLayout(filter_row)

            # Source model
            self._source_model = QStandardItemModel(0, len(COLUMN_HEADERS))
            self._source_model.setHorizontalHeaderLabels(COLUMN_HEADERS)

            # Proxy model for filtering
            self._proxy_model = ColumnFilterProxyModel()
            self._proxy_model.setSourceModel(self._source_model)
            self._proxy_model.setDynamicSortFilter(True)

            # Table view
            self.results_table = QTableView()
            self.results_table.setModel(self._proxy_model)
            self.results_table.setAlternatingRowColors(True)
            self.results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            self.results_table.setSortingEnabled(True)
            self.results_table.verticalHeader().setVisible(False)

            # Custom header
            header = FilterHeaderView(Qt.Orientation.Horizontal, self.results_table)
            self.results_table.setHorizontalHeader(header)
            header.setSectionsClickable(True)
            header.sectionClicked.connect(self._on_header_clicked)
            header.filter_requested.connect(self._on_filter_requested)

            header.setSectionResizeMode(COL_CHECK, QHeaderView.ResizeMode.Fixed)
            self.results_table.setColumnWidth(COL_CHECK, 40)
            for c in (COL_CATALOG, COL_TEMPLATE, COL_VMNAME, COL_DATASTORE):
                header.setSectionResizeMode(c, QHeaderView.ResizeMode.Stretch)

            self._source_model.itemChanged.connect(self._on_item_changed)

            results_layout.addWidget(self.results_table)
            results_group.setLayout(results_layout)
            main_layout.addWidget(results_group, stretch=1)

            # --- Progress bar ---
            self.progress_bar = QProgressBar()
            self.progress_bar.setVisible(False)
            main_layout.addWidget(self.progress_bar)

            # --- Log area ---
            log_group = QGroupBox("Log")
            log_layout = QVBoxLayout()
            self.log_text = QTextEdit()
            self.log_text.setReadOnly(True)
            self.log_text.setMaximumHeight(100)
            self.log_text.setStyleSheet("font-family: \"Courier New\";")
            log_layout.addWidget(self.log_text)
            log_group.setLayout(log_layout)
            main_layout.addWidget(log_group)

            self.statusBar().showMessage("Ready")

        # ---- helpers ----

        def log(self, message: str):
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.log_text.append(f"[{timestamp}] {message}")

        def _get_all_column_values(self, col: int) -> list[str]:
            """Collect all unique values from the source model for a column."""
            values = []
            for row in range(self._source_model.rowCount()):
                item = self._source_model.item(row, col)
                if item:
                    values.append(item.text())
            return values

        def _on_header_clicked(self, logical_index: int):
            if logical_index == COL_CHECK:
                self._toggle_all_visible_checkboxes()

        def _toggle_all_visible_checkboxes(self):
            self._select_all_state = not self._select_all_state
            new_check = Qt.CheckState.Checked if self._select_all_state else Qt.CheckState.Unchecked
            self._source_model.blockSignals(True)
            for proxy_row in range(self._proxy_model.rowCount()):
                source_idx = self._proxy_model.mapToSource(self._proxy_model.index(proxy_row, COL_CHECK))
                item = self._source_model.itemFromIndex(source_idx)
                if item:
                    item.setCheckState(new_check)
            self._source_model.blockSignals(False)
            self._update_selected_count()

        def _on_filter_requested(self, col_signal: int):
            header = self.results_table.horizontalHeader()
            if col_signal <= 0:
                col = -col_signal
                self._proxy_model.set_column_filter(col, None)
                header.set_filtered(col, False)
                self._update_filter_button(col, False)
                self._update_summary()
                return

            col = col_signal
            all_values = self._get_all_column_values(col)
            current_filters = self._proxy_model.active_filters()
            current_checked = current_filters.get(col)

            dlg = FilterPopupDialog(self, COLUMN_HEADERS[col], all_values, current_checked)
            if dlg.exec() == QDialog.DialogCode.Accepted:
                result = dlg.result_set
                if result is None:
                    self._proxy_model.set_column_filter(col, None)
                    header.set_filtered(col, False)
                    self._update_filter_button(col, False)
                else:
                    all_unique = set(all_values)
                    is_filtered = result != all_unique
                    self._proxy_model.set_column_filter(col, result)
                    header.set_filtered(col, is_filtered)
                    self._update_filter_button(col, is_filtered)
                self._update_summary()

        def _clear_all_filters(self):
            self._proxy_model.clear_all_filters()
            header = self.results_table.horizontalHeader()
            for c in FILTERABLE_COLUMNS:
                header.set_filtered(c, False)
                self._update_filter_button(c, False)
            self._update_summary()

        def _update_filter_button(self, col: int, is_filtered: bool):
            btn = self._filter_buttons.get(col)
            if btn:
                name = COLUMN_HEADERS[col]
                if is_filtered:
                    btn.setText(f"{name} \u25BC *")
                    btn.setStyleSheet("font-size: 11px; padding: 2px 8px; color: #4fc3f7; font-weight: bold;")
                else:
                    btn.setText(f"{name} \u25BC")
                    btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")

        def _on_item_changed(self, item: QStandardItem):
            if item.column() == COL_CHECK:
                self._update_selected_count()

        def _update_selected_count(self):
            selected = 0
            for row in range(self._source_model.rowCount()):
                chk = self._source_model.item(row, COL_CHECK)
                if chk and chk.checkState() == Qt.CheckState.Checked:
                    selected += 1
            self.statusBar().showMessage(f"Selected Shadow VMs: {selected}")

        def _update_summary(self):
            total = self._source_model.rowCount()
            visible = self._proxy_model.rowCount()
            if total == visible:
                self.summary_label.setText(f"Found {total} Shadow VMs")
            else:
                self.summary_label.setText(f"Showing {visible} of {total} Shadow VMs (filtered)")

        # ---- auth toggles ----

        def toggle_auth_mode(self, state):
            use_token = state == Qt.CheckState.Checked.value
            self.token_input.setVisible(use_token)
            self.token_label.setVisible(use_token)
            self.token_input.setEnabled(use_token)
            self.username_input.setEnabled(not use_token)
            self.password_input.setEnabled(not use_token)
            self.show_password_check.setEnabled(not use_token)

        def toggle_password_visibility(self, state):
            checked = state == Qt.CheckState.Checked.value
            mode = QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
            self.password_input.setEchoMode(mode)

        # ---- connection ----

        def connect_to_vcd(self):
            server = self.server_input.text().strip()
            if not server:
                QMessageBox.warning(self, "Error", "Please enter a VCD server address.")
                return

            self.log(f"Attempting to connect to {server}...")
            self.statusBar().showMessage("Connecting...")
            self.connect_btn.setText("Connecting...")
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(False)
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)

            client_args = (server, not self.skip_ssl_check.isChecked())
            auth_method = ""
            auth_args = {}

            if self.auth_token_radio.isChecked():
                token = self.token_input.text().strip()
                if not token:
                    QMessageBox.warning(self, "Error", "Please enter an API token.")
                    self.reset_connection_ui()
                    return
                auth_method = "token"
                auth_args = {"token": token}
            else:
                username = self.username_input.text().strip()
                password = self.password_input.text()
                if not username or not password:
                    QMessageBox.warning(self, "Error", "Please enter username and password.")
                    self.reset_connection_ui()
                    return
                auth_method = "credentials"
                auth_args = {"username": username, "password": password}

            self.connection_worker = self.ConnectionWorker(self, client_args, auth_method, auth_args)
            self.connection_worker.finished.connect(self.on_connection_finished)
            self.connection_worker.start()

        def on_connection_finished(self, success: bool, result_or_error):
            self.progress_bar.setVisible(False)
            if success:
                self.client = result_or_error
                self.log("Connected successfully!")
                self.statusBar().showMessage("Connected")
                self.connect_btn.setText("Connected")
                self.connect_btn.setStyleSheet("background-color: green;")
                self.connect_btn.setEnabled(False)
                self.disconnect_btn.setEnabled(True)
                self.load_dropdowns()
            else:
                error_message = result_or_error
                self.log(f"Connection failed: {error_message}")
                self.statusBar().showMessage("Connection failed")
                QMessageBox.critical(self, "Error", f"Failed to connect to VCD: {error_message}")
                self.reset_connection_ui()

        def disconnect_from_vcd(self):
            if self.client:
                self.client.disconnect()
                self.client = None
            self.log("Disconnected.")
            self.statusBar().showMessage("Disconnected")
            self.reset_connection_ui()

        def reset_connection_ui(self):
            self.connect_btn.setText("Connect to VCD")
            self.connect_btn.setStyleSheet("")
            self.connect_btn.setEnabled(True)
            self.disconnect_btn.setEnabled(False)
            self.progress_bar.setVisible(False)

            self.tenant_combo.clear()
            self.tenant_combo.setEnabled(False)
            self.catalog_list.clear()
            self.catalog_list.setEnabled(False)
            self.catalog_select_all_btn.setEnabled(False)
            self.catalog_deselect_all_btn.setEnabled(False)
            self.datastore_combo.clear()
            self.datastore_combo.setEnabled(False)

            self.scan_btn.setEnabled(False)
            self.cleanup_btn.setEnabled(False)

            self._source_model.removeRows(0, self._source_model.rowCount())
            self._proxy_model.clear_all_filters()
            header = self.results_table.horizontalHeader()
            for c in FILTERABLE_COLUMNS:
                header.set_filtered(c, False)
                self._update_filter_button(c, False)
            self._select_all_state = False
            self.summary_label.setText("No scan performed yet.")

        # ---- dropdowns ----

        def load_dropdowns(self):
            if not self.client:
                return

            self.log("Loading organizations...")
            orgs = self.client.get_organizations()
            self.tenant_combo.clear()
            self.tenant_combo.addItem("-- Select Tenant --")
            for org in orgs:
                self.tenant_combo.addItem(org["name"])
            self.tenant_combo.setEnabled(True)

            self.log("Loading catalogs...")
            catalogs = self.client.get_catalogs()
            self._populate_catalog_list(catalogs)
            self.log(f"Loaded {len(catalogs)} catalogs")

            self.log("Loading datastores...")
            datastores = self.client.get_datastores()
            self.datastore_combo.clear()
            self.datastore_combo.addItem("-- Select Datastore --")
            for ds in datastores:
                self.datastore_combo.addItem(ds["name"])
            self.datastore_combo.setEnabled(True)

            self.scan_btn.setEnabled(True)
            self.log("Ready to scan.")

        def on_tenant_changed(self, tenant_name: str):
            if self.client and tenant_name and not tenant_name.startswith("--"):
                self.client.switch_to_org(tenant_name)
                self.log(f"Switched to tenant: {tenant_name}")
                self.log(f"Loading catalogs for tenant '{tenant_name}'...")
                self.statusBar().showMessage(f"Loading catalogs for {tenant_name}...")
                QApplication.processEvents()

                catalogs = self.client.get_catalogs(org_name=tenant_name)
                self._populate_catalog_list(catalogs)
                self.log(f"Loaded {len(catalogs)} catalogs for tenant '{tenant_name}'")
                self.statusBar().showMessage("Ready")

        def _populate_catalog_list(self, catalogs: list):
            self.catalog_list.clear()
            for catalog in catalogs:
                flags = []
                if catalog.get('isShared'):
                    flags.append("Shared")
                if catalog.get('isPublished'):
                    flags.append("Published")
                flag_str = f" [{', '.join(flags)}]" if flags else ""
                display_name = f"{catalog['name']} ({catalog.get('orgName', 'N/A')}){flag_str}"
                item = QListWidgetItem(display_name)
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(Qt.CheckState.Unchecked)
                item.setData(Qt.ItemDataRole.UserRole, catalog['name'])
                self.catalog_list.addItem(item)
            self.catalog_list.setEnabled(True)
            self.catalog_select_all_btn.setEnabled(True)
            self.catalog_deselect_all_btn.setEnabled(True)

        def _catalog_select_all(self):
            for i in range(self.catalog_list.count()):
                self.catalog_list.item(i).setCheckState(Qt.CheckState.Checked)

        def _catalog_deselect_all(self):
            for i in range(self.catalog_list.count()):
                self.catalog_list.item(i).setCheckState(Qt.CheckState.Unchecked)

        def _get_selected_catalog_names(self) -> list:
            selected = []
            for i in range(self.catalog_list.count()):
                item = self.catalog_list.item(i)
                if item.checkState() == Qt.CheckState.Checked:
                    selected.append(item.data(Qt.ItemDataRole.UserRole))
            return selected

        # ---- scan ----

        def scan_shadow_vms(self):
            if not self.client:
                return

            selected_catalogs = self._get_selected_catalog_names()
            if not selected_catalogs:
                QMessageBox.warning(self, "Error", "Please select at least one catalog.")
                return

            datastore_name = self.datastore_combo.currentText()
            if not datastore_name or datastore_name.startswith("--"):
                QMessageBox.warning(self, "Error", "Please select a datastore.")
                return

            self.log(f"Scanning {len(selected_catalogs)} catalog(s) on datastore '{datastore_name}'...")
            self.statusBar().showMessage("Scanning...")
            self.scan_btn.setEnabled(False)
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)
            QApplication.processEvents()

            self.shadow_vms = scan_shadow_vms(
                self.client, selected_catalogs, datastore_name, debug=False
            )

            # Clear filters and rebuild model
            self._proxy_model.clear_all_filters()
            header = self.results_table.horizontalHeader()
            for c in FILTERABLE_COLUMNS:
                header.set_filtered(c, False)
                self._update_filter_button(c, False)
            self._select_all_state = False

            self._source_model.removeRows(0, self._source_model.rowCount())

            sorted_shadows = sorted(
                self.shadow_vms,
                key=lambda s: (s.catalog_name.lower(), s.container_name.lower() if s.container_name else '')
            )

            for shadow in sorted_shadows:
                chk_item = QStandardItem()
                chk_item.setCheckable(True)
                chk_item.setCheckState(Qt.CheckState.Unchecked)
                chk_item.setEditable(False)

                cat_item = QStandardItem(shadow.catalog_name)
                cat_item.setData(shadow, SHADOW_VM_ROLE)
                cat_item.setEditable(False)

                tpl_item = QStandardItem(shadow.container_name)
                tpl_item.setEditable(False)

                vm_item = QStandardItem(shadow.name)
                vm_item.setEditable(False)

                ds_item = QStandardItem(shadow.datastore_name)
                ds_item.setEditable(False)

                self._source_model.appendRow([chk_item, cat_item, tpl_item, vm_item, ds_item])

            self._source_model.setHorizontalHeaderLabels(COLUMN_HEADERS)

            self.summary_label.setText(f"Found {len(self.shadow_vms)} Shadow VMs")
            self.progress_bar.setVisible(False)
            self.scan_btn.setEnabled(True)
            self.cleanup_btn.setEnabled(len(self.shadow_vms) > 0)
            self.statusBar().showMessage(f"Scan complete: {len(self.shadow_vms)} Shadow VMs found")
            self.log(f"Scan complete: {len(self.shadow_vms)} Shadow VMs")
            self._update_selected_count()

        # ---- cleanup ----

        def cleanup_shadows(self):
            if not self.client:
                return

            selected_shadow_vms = []
            for row in range(self._source_model.rowCount()):
                chk = self._source_model.item(row, COL_CHECK)
                if chk and chk.checkState() == Qt.CheckState.Checked:
                    cat_item = self._source_model.item(row, COL_CATALOG)
                    if cat_item:
                        shadow = cat_item.data(SHADOW_VM_ROLE)
                        if shadow:
                            selected_shadow_vms.append(shadow)

            if not selected_shadow_vms:
                QMessageBox.information(self, "No Selection", "No Shadow VMs selected for deletion.")
                return

            reply = QMessageBox.question(
                self, "Confirm Deletion",
                f"Are you sure you want to delete {len(selected_shadow_vms)} selected Shadow VMs?\n\n"
                "This action cannot be undone!",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

            self.log("Starting Shadow VM deletion...")
            self.statusBar().showMessage("Deleting Shadow VMs...")
            self.cleanup_btn.setEnabled(False)
            self.scan_btn.setEnabled(False)
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, len(selected_shadow_vms))
            self.progress_bar.setValue(0)

            success_count = 0
            fail_count = 0
            deleted_shadows = set()

            for i, shadow in enumerate(selected_shadow_vms):
                self.progress_bar.setValue(i + 1)
                self.statusBar().showMessage(f"Deleting {i+1}/{len(selected_shadow_vms)}: {shadow.name}")
                QApplication.processEvents()

                success, message = self.client.delete_shadow_vm(shadow)
                if success:
                    self.log(f"Deleted: {shadow.name}")
                    success_count += 1
                    deleted_shadows.add(id(shadow))
                else:
                    self.log(f"Failed: {shadow.name} - {message}")
                    fail_count += 1

                if i < len(selected_shadow_vms) - 1:
                    time.sleep(3)

            # Remove deleted rows from source model (reverse to preserve indices)
            rows_to_remove = []
            for row in range(self._source_model.rowCount()):
                cat_item = self._source_model.item(row, COL_CATALOG)
                if cat_item:
                    s = cat_item.data(SHADOW_VM_ROLE)
                    if s and id(s) in deleted_shadows:
                        rows_to_remove.append(row)
            for row in reversed(rows_to_remove):
                self._source_model.removeRow(row)

            self.shadow_vms = [s for s in self.shadow_vms if id(s) not in deleted_shadows]

            self.progress_bar.setVisible(False)
            self.scan_btn.setEnabled(True)
            self.cleanup_btn.setEnabled(len(self.shadow_vms) > 0)
            self._update_summary()
            self.statusBar().showMessage(f"Deletion complete: {success_count} succeeded, {fail_count} failed")
            self.log(f"Deletion complete: {success_count} succeeded, {fail_count} failed")
            self._update_selected_count()

            QMessageBox.information(
                self, "Deletion Complete",
                f"Deletion complete!\n\nSuccessful: {success_count}\nFailed: {fail_count}"
            )

        def closeEvent(self, event):
            if self.client and self.client.access_token:
                self.client.disconnect()
            event.accept()

    # Run the application
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(25, 25, 25))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
    app.setPalette(palette)

    window = MainWindow()
    window.show()

    return app.exec()


def main():
    # Load .env file if present
    load_env_file()

    parser = argparse.ArgumentParser(
        description="VMware Cloud Director Shadow VM Cleanup Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Run in GUI mode (default)
    python vcd_shadow_cleaner.py
    
    # Run in CLI mode with API token
    python vcd_shadow_cleaner.py --cli --server vcd.example.com --token YOUR_API_TOKEN \\
        --tenant MyTenant --catalog MyCatalog --datastore MyDatastore
    
    # Run in CLI mode using environment variables (VCD_SERVER, VCD_TOKEN, etc.)
    # .env file is also supported
    python vcd_shadow_cleaner.py --cli --tenant MyTenant --catalog MyCatalog --datastore MyDatastore
        """
    )

    parser.add_argument("--cli", action="store_true", help="Run in command-line interface mode (default is GUI)")
    
    # Connection args (can be loaded from env vars)
    parser.add_argument("--server", "-s", default=os.environ.get("VCD_SERVER"), help="VCD server hostname or IP")
    parser.add_argument("--token", "-t", default=os.environ.get("VCD_TOKEN"), help="VCD API token")
    parser.add_argument("--username", "-u", default=os.environ.get("VCD_USER"), help="VCD username (alternative to token)")
    parser.add_argument("--password", "-p", default=os.environ.get("VCD_PASSWORD"), help="VCD password (alternative to token)")
    
    parser.add_argument("--tenant", default=os.environ.get("VCD_TENANT"), help="Target tenant/organization name")
    parser.add_argument("--catalog", "-c", default=os.environ.get("VCD_CATALOG"), help="Catalog name to scan")
    parser.add_argument("--datastore", "-d", default=os.environ.get("VCD_DATASTORE"), help="Datastore name to scan")
    
    parser.add_argument("--dry-run", action="store_true", help="Show what would be deleted without making changes")
    parser.add_argument("--skip-ssl-verify", action="store_true", default=os.environ.get("VCD_SKIP_SSL", "false").lower() == "true", help="Skip SSL certificate verification")
    
    args = parser.parse_args()
    
    # Default to GUI if --cli is not specified
    if not args.cli:
        return run_gui()
    else:
        # CLI mode requires certain arguments
        if not args.server:
            print("ERROR: --server is required in CLI mode (or set VCD_SERVER env var).")
            return 1
        if not args.catalog:
            print("ERROR: --catalog is required in CLI mode (or set VCD_CATALOG env var).")
            return 1
        if not args.datastore:
            print("ERROR: --datastore is required in CLI mode (or set VCD_DATASTORE env var).")
            return 1
        
        return run_cli(args)


if __name__ == "__main__":
    sys.exit(main())
