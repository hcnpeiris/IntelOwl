import json
import logging

from bbot.scanner import Scanner

from api_app.analyzers_manager import classes
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class Bbot(classes.ObservableAnalyzer):

    presets: str

    def run(self):
        logger.info(
            f"running Bbot  Analyzer on {self.observable_name} using {self.presets}"
        )
        scan = Scanner(self.observable_name, presets=[self.presets])
        result = {
            "scan_id": None,
            "scan_name": None,
            "target": None,
            "preset": None,
            "status": None,
            "started_at": None,
            "finished_at": None,
            "duration": None,
            "domains": [],
            "subdomains": [],
            "related_urls": []
        }
        for event in scan.start():
            data = event.data

            if isinstance(data, dict): 
                if "id" in data and "name" in data:
                    if result["scan_id"] is None:  
                        result["scan_id"] = data["id"]
                        result["scan_name"] = data["name"]
                        result["target"] = data.get("target")
                        result["preset"] = data.get("preset")
                        result["status"] = data.get("status")
                        result["started_at"] = data.get("started_at")
                    else: 
                        result["finished_at"] = data.get("finished_at")
                        result["duration"] = data.get("duration")

                elif "url" in data:  
                    result["related_urls"].append(data)

            elif isinstance(data, str):  
                if "." in data:
                    if data.startswith("ns-") or data.startswith("alt"):
                        result["subdomains"].append(data)
                    else:
                        result["domains"].append(data)

        return json.dumps(result)


