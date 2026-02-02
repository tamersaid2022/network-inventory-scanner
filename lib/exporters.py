"""
Network Inventory Scanner - Export Formatters
Author: Tamer Khalifa (CCIE #68867)

Export inventory data to JSON, CSV, Excel, and HTML.
"""

import json
import csv
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger(__name__)


class Exporter:
    """Export inventory data to multiple formats"""

    def __init__(self, output_dir: str = "./inventory"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_json(self, devices: List[Dict], filename: str = None) -> str:
        """Export to JSON"""
        filename = filename or f"inventory_{datetime.now():%Y%m%d}.json"
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump({"scan_date": datetime.now().isoformat(),
                       "devices": devices}, f, indent=2, default=str)
        logger.info(f"Exported JSON: {filepath}")
        return str(filepath)

    def export_csv(self, devices: List[Dict], filename: str = None) -> str:
        """Export to CSV"""
        filename = filename or f"inventory_{datetime.now():%Y%m%d}.csv"
        filepath = self.output_dir / filename
        if devices:
            with open(filepath, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=devices[0].keys())
                writer.writeheader()
                writer.writerows(devices)
        logger.info(f"Exported CSV: {filepath}")
        return str(filepath)

    def export_excel(self, devices: List[Dict], filename: str = None) -> str:
        """Export to Excel with multiple sheets"""
        try:
            import pandas as pd
            filename = filename or f"inventory_{datetime.now():%Y%m%d}.xlsx"
            filepath = self.output_dir / filename
            df = pd.DataFrame(devices)
            with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Summary', index=False)
            logger.info(f"Exported Excel: {filepath}")
            return str(filepath)
        except ImportError:
            logger.warning("pandas/openpyxl not available for Excel export")
            return ""

    def export_html(self, devices: List[Dict], filename: str = None) -> str:
        """Export to HTML report"""
        filename = filename or f"inventory_{datetime.now():%Y%m%d}.html"
        filepath = self.output_dir / filename
        try:
            from jinja2 import Environment, FileSystemLoader
            env = Environment(loader=FileSystemLoader("templates"))
            template = env.get_template("report.html.j2")
            html = template.render(
                scan_date=datetime.now().strftime('%Y-%m-%d %H:%M'),
                devices=devices,
                active_hosts=len(devices),
                network_devices=sum(1 for d in devices if d.get("vendor")),
                total_ips=len(devices),
                networks=set(d.get("network", "") for d in devices)
            )
            with open(filepath, 'w') as f:
                f.write(html)
            logger.info(f"Exported HTML: {filepath}")
        except Exception as e:
            logger.error(f"HTML export failed: {e}")
        return str(filepath)
