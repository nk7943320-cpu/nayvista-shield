"""
SentinelScan - Technology Stack Detector
Passively identifies web technologies through:
- HTTP response headers (Server, X-Powered-By, Via).
- HTML meta generator tags.
- Script patterns and DOM signatures.
- Cookie naming conventions.
"""

from typing import List, Dict, Any, Tuple, Set
from scanner.crawler import CrawledPage
from scanner.normalizer import create_finding

class TechDetector:
    def scan(self, pages: List[CrawledPage]) -> Tuple[List[Dict[str, Any]], Dict[str, List[str]]]:
        findings: List[Dict[str, Any]] = []

        web_servers: Set[str] = set()
        backend_frameworks: Set[str] = set()
        cms_platforms: Set[str] = set()
        frontend_frameworks: Set[str] = set()
        libraries: Set[str] = set()

        for page in pages:
            headers = {k.lower(): v for k, v in page.headers.items()}

            # 1. Header signatures
            server = headers.get("server", "").lower()
            if "nginx" in server:
                web_servers.add("Nginx")
            if "apache" in server:
                web_servers.add("Apache HTTP Server")
            if "cloudflare" in server:
                web_servers.add("Cloudflare")
            if "caddy" in server:
                web_servers.add("Caddy")
            if "microsoft-iis" in server:
                web_servers.add("Microsoft IIS")
            if "litespeed" in server:
                web_servers.add("LiteSpeed")

            powered_by = headers.get("x-powered-by", "").lower()
            if "express" in powered_by:
                backend_frameworks.add("Express.js (Node.js)")
            if "php" in powered_by:
                backend_frameworks.add("PHP")
            if "asp.net" in powered_by:
                backend_frameworks.add("ASP.NET")
            if "next.js" in powered_by:
                frontend_frameworks.add("Next.js (React)")

            # Cookie signatures
            set_cookie = headers.get("set-cookie", "").lower()
            if "phpsessid" in set_cookie:
                backend_frameworks.add("PHP")
            if "connect.sid" in set_cookie:
                backend_frameworks.add("Express.js / Node.js Session")
            if "jsessionid" in set_cookie:
                backend_frameworks.add("Java / Spring")
            if "csrftoken" in set_cookie:
                backend_frameworks.add("Django / Python")

            # 2. HTML & Script signatures
            if page.status_code == 200 and page.text:
                text_lower = page.text.lower()
                soup = page.get_soup()

                # Meta generator
                meta_gen = soup.find("meta", attrs={"name": lambda n: n and n.lower() == "generator"})
                if meta_gen and meta_gen.get("content"):
                    gen_val = meta_gen["content"]
                    gen_lower = gen_val.lower()
                    if "wordpress" in gen_lower:
                        cms_platforms.add(f"WordPress ({gen_val})")
                    elif "drupal" in gen_lower:
                        cms_platforms.add(f"Drupal ({gen_val})")
                    elif "joomla" in gen_lower:
                        cms_platforms.add(f"Joomla ({gen_val})")
                    elif "ghost" in gen_lower:
                        cms_platforms.add(f"Ghost ({gen_val})")
                    else:
                        cms_platforms.add(gen_val)

                # Script tag sources
                for script in soup.find_all("script", src=True):
                    src_lower = script["src"].lower()
                    if "react" in src_lower:
                        frontend_frameworks.add("React")
                    if "vue" in src_lower:
                        frontend_frameworks.add("Vue.js")
                    if "angular" in src_lower:
                        frontend_frameworks.add("Angular")
                    if "jquery" in src_lower:
                        libraries.add("jQuery")
                    if "bootstrap" in src_lower:
                        libraries.add("Bootstrap")
                    if "tailwind" in src_lower:
                        libraries.add("Tailwind CSS")

                # Inline markers
                if "__next_data__" in text_lower:
                    frontend_frameworks.add("Next.js")
                if "__nuxt" in text_lower:
                    frontend_frameworks.add("Nuxt.js")
                if "wp-content" in text_lower:
                    cms_platforms.add("WordPress")
                if "reactroot" in text_lower or "_reactlistening" in text_lower:
                    frontend_frameworks.add("React")

        tech_summary = {
            "web_servers": sorted(list(web_servers)),
            "backend": sorted(list(backend_frameworks)),
            "cms": sorted(list(cms_platforms)),
            "frontend": sorted(list(frontend_frameworks)),
            "libraries": sorted(list(libraries)),
        }

        all_identified = (
            list(web_servers) + list(backend_frameworks) + list(cms_platforms) +
            list(frontend_frameworks) + list(libraries)
        )

        if all_identified:
            evidence_str = f"Detected: {', '.join(all_identified)}"
            target_url = pages[0].url if pages else "Target"
            findings.append(create_finding(
                scanner="tech_detector",
                title="Technology Stack Fingerprinted",
                severity="INFO",
                confidence="HIGH",
                category="Security Misconfiguration",
                owasp_key="SECURITY_MISCONFIGURATION",
                url=target_url,
                evidence=evidence_str,
                description="Passive fingerprinting identified active server, framework, or client technologies in use.",
                impact="Understanding the software stack aids in vulnerability lifecycle management and identifying outdated components.",
                remediation="Ensure all detected libraries, CMS components, and servers are routinely patched to their latest stable releases."
            ))

        return findings, tech_summary
