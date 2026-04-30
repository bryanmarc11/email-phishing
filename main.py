#!/usr/bin/env python3
"""
main.py — Phishing Email Analyzer CLI
--------------------------------------
Usage examples:
  python main.py suspicious.eml
  python main.py suspicious.eml --output reports/ --format html
  python main.py suspicious.eml --no-vt
  python main.py --batch samples/*.eml --output reports/
  python main.py suspicious.eml -v
"""

import argparse
import glob
import json
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv

load_dotenv()

from phishing_analyzer import (
    EmailParser,
    HeaderAnalyzer,
    URLExtractor,
    VirusTotalClient,
    RiskScorer,
    Reporter,
)

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("phish_analyzer.log", encoding="utf-8"),
        ],
    )


logger = logging.getLogger("main")


# ---------------------------------------------------------------------------
# Single file analysis
# ---------------------------------------------------------------------------

def analyze_file(
    eml_path: str,
    output_dir: str = "reports",
    fmt: str = "json",
    use_vt: bool = True,
    vt_client: Optional[VirusTotalClient] = None,
    max_urls_to_check: int = 10,
) -> dict:
    logger.info("=" * 60)
    logger.info("Analyzing: %s", eml_path)

    # ── Step 1: Parse EML ─────────────────────────────────────────
    logger.info("[1/5] Parsing EML file…")
    parser       = EmailParser(eml_path)
    parsed_email = parser.parse()

    meta = parsed_email.get("metadata", {})
    logger.info("  From:    %s", meta.get("from", "—"))
    logger.info("  Subject: %s", meta.get("subject", "—"))
    logger.info("  Date:    %s", meta.get("date", "—"))

    # ── Step 2: Header forensics ───────────────────────────────────
    logger.info("[2/5] Analyzing headers…")
    header_analyzer = HeaderAnalyzer(parsed_email)
    header_analysis = header_analyzer.analyze()

    summary = header_analysis.get("summary", {})
    logger.info(
        "  Hops: %d | SPF: %s | DKIM: %s | DMARC: %s | Anomalies: %d",
        summary.get("total_hops", 0),
        summary.get("spf", "?"),
        summary.get("dkim", "?"),
        summary.get("dmarc", "?"),
        summary.get("anomaly_count", 0),
    )

    # ── Step 3: URL extraction ─────────────────────────────────────
    logger.info("[3/5] Extracting URLs…")
    url_extractor = URLExtractor(parsed_email)
    url_analysis  = url_extractor.extract()
    suspicious_urls = [u for u in url_analysis if u["suspicious"]]
    logger.info("  Total URLs: %d | Suspicious: %d", len(url_analysis), len(suspicious_urls))

    # ── Step 4: VirusTotal checks ──────────────────────────────────
    vt_results: List[dict] = []
    if use_vt and vt_client:
        logger.info("[4/5] Checking URLs against VirusTotal…")
        urls_to_check = [u["url"] for u in suspicious_urls[:max_urls_to_check]]
        if not urls_to_check and url_analysis:
            urls_to_check = [u["url"] for u in url_analysis[:3]]
        if urls_to_check:
            vt_results = vt_client.check_urls(urls_to_check)
            malicious_vt = sum(1 for r in vt_results if r["verdict"] in ("malicious", "suspicious"))
            logger.info("  Checked %d URLs | VT malicious/suspicious: %d", len(vt_results), malicious_vt)
        else:
            logger.info("  No URLs to check.")

        # Check IPs from hop chain
        public_ips = header_analysis.get("public_ips", [])
        if public_ips:
            logger.info("  Checking %d public IPs…", len(public_ips))
            ip_results = vt_client.check_ips(public_ips[:5])
            for ip_r in ip_results:
                if ip_r.get("verdict") in ("malicious", "suspicious"):
                    logger.warning("  MALICIOUS IP: %s (%s)", ip_r["ip"], ip_r.get("as_owner", ""))
    else:
        logger.info("[4/5] VirusTotal check skipped (--no-vt or no API key).")

    # ── Step 5: Risk scoring ───────────────────────────────────────
    logger.info("[5/5] Computing risk score…")
    scorer      = RiskScorer(header_analysis, url_analysis, vt_results, parsed_email)
    risk_result = scorer.score()
    v = risk_result.get("verdict", {})
    logger.info(
        "  Score: %d/100 — %s %s",
        risk_result["score"],
        v.get("icon", ""),
        v.get("label", ""),
    )
    logger.info("  Recommendation: %s", v.get("recommendation", ""))

    # ── Report generation ──────────────────────────────────────────
    reporter = Reporter(parsed_email, header_analysis, url_analysis, vt_results, risk_result)

    saved_files = []
    if fmt in ("json", "both"):
        json_path = reporter.save_json(output_dir)
        saved_files.append(str(json_path))
    if fmt in ("html", "both"):
        html_path = reporter.save_html(output_dir)
        saved_files.append(str(html_path))
    if fmt == "json":
        json_path = reporter.save_json(output_dir)
        saved_files.append(str(json_path))

    logger.info("Reports saved: %s", ", ".join(saved_files))

    # Print summary to stdout
    print("\n" + "=" * 55)
    print(f"  {v.get('icon','')}  PHISHING ANALYSIS COMPLETE")
    print(f"  File:    {Path(eml_path).name}")
    print(f"  Score:   {risk_result['score']}/100 — {v.get('label','')}")
    print(f"  Advice:  {v.get('recommendation','')}")
    print(f"  Reports: {', '.join(saved_files)}")
    print("=" * 55 + "\n")

    return reporter.to_json()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Phishing Email Analyzer — parse, score, and report on suspicious emails.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py email.eml
  python main.py email.eml --output reports/ --format html
  python main.py email.eml --no-vt
  python main.py --batch samples/*.eml --output reports/
        """,
    )
    p.add_argument("eml_file", nargs="?", help="Path to .eml file to analyze")
    p.add_argument("--batch",  nargs="+", metavar="GLOB", help="Analyze multiple .eml files")
    p.add_argument("--output", default="reports", help="Output directory (default: reports/)")
    p.add_argument("--format", choices=["json", "html", "both"], default="json",
                   dest="fmt", help="Report format (default: json)")
    p.add_argument("--no-vt",  action="store_true", help="Skip VirusTotal lookups")
    p.add_argument("--max-urls", type=int, default=10,
                   help="Max suspicious URLs to check against VT (default: 10)")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p


def main() -> None:
    parser = build_arg_parser()
    args   = parser.parse_args()

    setup_logging(args.verbose)

    # Collect files to process
    eml_files: List[str] = []
    if args.batch:
        for pattern in args.batch:
            eml_files.extend(glob.glob(pattern))
    elif args.eml_file:
        eml_files = [args.eml_file]
    else:
        parser.print_help()
        sys.exit(0)

    if not eml_files:
        logger.error("No .eml files found matching the specified path(s).")
        sys.exit(1)

    # Initialize VT client
    vt_client: Optional[VirusTotalClient] = None
    if not args.no_vt:
        api_key = os.getenv("VT_API_KEY", "")
        if api_key:
            try:
                vt_client = VirusTotalClient(api_key=api_key)
                logger.info("VirusTotal API client initialized.")
            except ValueError as e:
                logger.warning("VT client init failed: %s — proceeding without VT.", e)
        else:
            logger.warning("VT_API_KEY not set in .env — proceeding without VirusTotal checks.")

    # Process each file
    all_results = []
    for i, eml_path in enumerate(eml_files, 1):
        logger.info("Processing file %d/%d: %s", i, len(eml_files), eml_path)
        try:
            result = analyze_file(
                eml_path      = eml_path,
                output_dir    = args.output,
                fmt           = args.fmt,
                use_vt        = not args.no_vt,
                vt_client     = vt_client,
                max_urls_to_check = args.max_urls,
            )
            all_results.append(result)
        except FileNotFoundError as e:
            logger.error("File not found: %s", e)
        except Exception as e:
            logger.exception("Unexpected error processing %s: %s", eml_path, e)

    if len(eml_files) > 1:
        logger.info("Batch complete: %d/%d files processed.", len(all_results), len(eml_files))


if __name__ == "__main__":
    main()
