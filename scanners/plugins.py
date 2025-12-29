import os
import requests
from typing import List, Dict
from core.http_client import HTTPClient
from utils.logger import logger

class WPPluginScanner:
    def __init__(self, target: str, api_token: str = None):
        self.target = target.rstrip("/")
        self.http = HTTPClient()
        self.api_token = api_token

        # 🔹 قائمة افتراضية (تقدر تكبرها براحتك)
        self.plugin_list = [
            "elementor",
            "contact-form-7",
            "woocommerce",
            "yoast-seo",
            "wpforms",
            "revslider",
            "wordfence",
            "all-in-one-seo-pack",
            "wp-super-cache",
        ]

        # 🔹 تحميل قائمة إضافية من ملف (إن وجد)
        self.load_custom_plugin_list()

    # ==================================================
    # 📥 تحميل قائمة ضخمة من ملف خارجي
    # ==================================================
    def load_custom_plugin_list(self):
        file_path = "data/plugin_list.txt"

        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        plugin = line.strip()
                        if plugin and plugin not in self.plugin_list:
                            self.plugin_list.append(plugin)

                logger.info(f"[WP-PLUGINS] Loaded {len(self.plugin_list)} plugins from list")

            except Exception as e:
                logger.error(f"[WP-PLUGINS] Failed loading plugin list: {e}")

    # ==================================================
    # 🔍 فحص وجود البلوقن
    # ==================================================
    def check_plugin_exists(self, plugin: str) -> bool:
        url = f"{self.target}/wp-content/plugins/{plugin}/"
        response = self.http.get(url)

        if response and response.status_code in [200, 403]:
            return True
        return False

    # ==================================================
    # 🔎 استخراج نسخة البلوقن (إن أمكن)
    # ==================================================
    def detect_plugin_version(self, plugin: str) -> str:
        readme_url = f"{self.target}/wp-content/plugins/{plugin}/readme.txt"
        response = self.http.get(readme_url)

        if response and response.status_code == 200:
            for line in response.text.splitlines():
                if "Stable tag" in line:
                    return line.split(":")[-1].strip()

        return "unknown"

    # ==================================================
    # 🧠 جلب معلومات + CVEs من WPScan API
    # ==================================================
    def fetch_wpscan_data(self, plugin: str) -> Dict:
        if not self.api_token:
            return {}

        api_url = f"https://wpscan.com/api/v3/plugins/{plugin}"
        headers = {
            "Authorization": f"Token token={self.api_token}",
            "User-Agent": "Exp0sive-SOC"
        }

        try:
            r = requests.get(api_url, headers=headers, timeout=10)
            if r.status_code == 200:
                return r.json().get(plugin, {})
        except Exception as e:
            logger.error(f"[WPScan API] Error: {e}")

        return {}

    # ==================================================
    # 🚀 تشغيل الفحص
    # ==================================================
    def run(self) -> List[Dict]:
        logger.info("[WP-PLUGINS] Scanning plugins...")
        results = []

        for plugin in self.plugin_list:
            if self.check_plugin_exists(plugin):
                logger.success(f"[FOUND] Plugin detected: {plugin}")

                version = self.detect_plugin_version(plugin)
                wpscan_data = self.fetch_wpscan_data(plugin)

                results.append({
                    "plugin": plugin,
                    "version": version,
                    "vulnerabilities": wpscan_data.get("vulnerabilities", []),
                    "confidence": "high"
                })

        return results
