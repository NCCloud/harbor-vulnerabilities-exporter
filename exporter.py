#!/usr/bin/env python3
"""
Prometheus exporter for vulnerabilities of the latest pushed images in Harbor (Trivy scanner).

Harbor is crawled in a background thread every COLLECT_INTERVAL seconds. Every crawl is rendered once
into a ready-to-serve (plain and gzipped) exposition snapshot, so scrapes never wait for Harbor.
"""

import concurrent.futures
import gzip
import logging
import os
import re
import signal
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

import requests
from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from prometheus_client.exposition import CONTENT_TYPE_PLAIN_0_0_4
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ordered from the lowest to the highest
SEVERITIES = ('Unknown', 'Low', 'Medium', 'High', 'Critical')
# labels which can be enabled for harbor_image_vulnerability via VULNERABILITY_LABELS (project and repository are always set)
DETAIL_LABELS = ('id', 'package', 'version', 'fix_version', 'severity', 'digest')
DEFAULT_DETAIL_LABELS = 'id,package,version,fix_version,severity'
VULNERABILITY_MIME_TYPES = ', '.join([
    'application/vnd.security.vulnerability.report; version=1.1',
    'application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0',
])
NOT_SCANNED = 'not_scanned'
PAGE_SIZE = 100


def parse_bool(value):
    return value.strip().lower() in ('1', 'true', 'yes', 'on')


def parse_csv(value):
    return [item.strip() for item in value.split(',') if item.strip()]


def normalize_severity(severity):
    severity = (severity or '').capitalize()
    return severity if severity in SEVERITIES else 'Unknown'


@dataclass(frozen=True)
class Config:
    # for example: 'http://harbor-harbor-harbor-core.harbor/api/v2.0'
    harbor_api_url: str
    username: str = None
    password: str = None
    exporter_port: int = 8000
    # number of parallel threads to use in API requests
    threads: int = 5
    # seconds between the starts of two Harbor crawls
    collect_interval: int = 300
    request_timeout: int = 30
    # full project/repository names, for example: 'project/repo1'
    ignore_repositories: frozenset = frozenset()
    include_projects: re.Pattern = None
    ignore_projects: re.Pattern = None
    # per-vulnerability metric (harbor_image_vulnerability) and its filters
    detailed_metrics: bool = False
    min_severity: str = 'High'
    only_fixable: bool = False
    vulnerability_labels: tuple = tuple(parse_csv(DEFAULT_DETAIL_LABELS))
    # description is exposed once per vulnerability id in harbor_vulnerability_info
    include_description: bool = False
    # maximum number of characters of the description, None means no limit
    description_max_length: int = None

    @classmethod
    def from_env(cls, env=os.environ):
        harbor_api_url = env.get('HARBOR_API_URL')
        if not harbor_api_url:
            raise ValueError('harbor api url was not specified. You have to set HARBOR_API_URL env variable.')

        min_severity = env.get('MIN_SEVERITY', 'High').strip().capitalize()
        if min_severity not in SEVERITIES:
            raise ValueError(f'MIN_SEVERITY must be one of {", ".join(SEVERITIES)}, got: {min_severity}')

        vulnerability_labels = tuple(parse_csv(env.get('VULNERABILITY_LABELS', DEFAULT_DETAIL_LABELS)))
        unknown_labels = set(vulnerability_labels) - set(DETAIL_LABELS)
        if unknown_labels:
            raise ValueError(f'VULNERABILITY_LABELS supports only {", ".join(DETAIL_LABELS)}, got: {", ".join(sorted(unknown_labels))}')

        include_description = parse_bool(env.get('INCLUDE_DESCRIPTION', 'false'))
        if include_description and 'id' not in vulnerability_labels:
            raise ValueError('INCLUDE_DESCRIPTION requires "id" in VULNERABILITY_LABELS to join descriptions')

        def integer(name, default):
            try:
                return int(env.get(name, default))
            except ValueError:
                raise ValueError(f'{name} must be an integer, got: {env.get(name)}') from None

        def regex(name):
            value = env.get(name, '').strip()
            try:
                return re.compile(value) if value else None
            except re.error as e:
                raise ValueError(f'{name} is not a valid regular expression: {e}') from None

        return cls(
            harbor_api_url=harbor_api_url.rstrip('/'),
            username=env.get('HARBOR_USERNAME') or None,
            password=env.get('HARBOR_PASSWORD') or None,
            exporter_port=integer('EXPORTER_PORT', 8000),
            threads=integer('THREADS', 5),
            collect_interval=integer('COLLECT_INTERVAL', 300),
            request_timeout=integer('REQUEST_TIMEOUT', 30),
            ignore_repositories=frozenset(parse_csv(env.get('IGNORE_REPOSITORIES', ''))),
            include_projects=regex('INCLUDE_PROJECTS'),
            ignore_projects=regex('IGNORE_PROJECTS'),
            detailed_metrics=parse_bool(env.get('DETAILED_METRICS', 'false')),
            min_severity=min_severity,
            only_fixable=parse_bool(env.get('ONLY_FIXABLE', 'false')),
            vulnerability_labels=vulnerability_labels,
            include_description=include_description,
            description_max_length=integer('DESCRIPTION_MAX_LENGTH', 0) or None,
        )

    def project_selected(self, project):
        if self.include_projects and not self.include_projects.fullmatch(project):
            return False
        return not (self.ignore_projects and self.ignore_projects.fullmatch(project))

    def severity_selected(self, severity):
        return SEVERITIES.index(normalize_severity(severity)) >= SEVERITIES.index(self.min_severity)


@dataclass
class ScanOverview:
    status: str = NOT_SCANNED
    end_time: float = None
    # severity -> number of vulnerabilities, empty when Harbor has no summary for the artifact
    counts: dict = field(default_factory=dict)
    fixable: int = 0


@dataclass
class RepositoryReport:
    project: str
    repository: str
    digest: str = ''
    scan: ScanOverview = field(default_factory=ScanOverview)
    # unique label values of harbor_image_vulnerability in Config.vulnerability_labels order
    vulnerabilities: set = field(default_factory=set)
    # vulnerability id -> description
    descriptions: dict = field(default_factory=dict)


def parse_time(value):
    """Convert Harbor timestamp to unix time, Harbor uses 0001-01-01T00:00:00Z for unset values."""
    try:
        timestamp = datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except (AttributeError, ValueError):
        return None
    return timestamp if timestamp > 0 else None


def parse_scan_overview(artifact):
    """Read scan status and vulnerabilities summary of an artifact listed with with_scan_overview=true."""
    # scan_overview has one report per accepted mime type, Trivy returns a single one
    for report in (artifact.get('scan_overview') or {}).values():
        if not isinstance(report, dict):
            continue
        overview = ScanOverview(status=report.get('scan_status') or 'Unknown', end_time=parse_time(report.get('end_time')))
        summary = report.get('summary')
        if summary:
            overview.counts = dict.fromkeys(SEVERITIES, 0)
            for severity, count in (summary.get('summary') or {}).items():
                overview.counts[normalize_severity(severity)] += int(count)
            overview.fixable = int(summary.get('fixable') or 0)
        return overview
    return ScanOverview()


def encode_repository(repository):
    repository = repository.replace("/library", "")
    # this is needed for getting repos like proxy.docker.io/bitnami/nginx
    return quote(quote(repository, safe=""), safe="")


class HarborClient:
    def __init__(self, cfg):
        self.base_url = cfg.harbor_api_url
        self.timeout = cfg.request_timeout
        self.session = requests.Session()
        if cfg.username and cfg.password:
            self.session.auth = (cfg.username, cfg.password)
        retry = Retry(total=3, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504), allowed_methods=frozenset(['GET']), raise_on_status=False)
        adapter = HTTPAdapter(pool_connections=cfg.threads, pool_maxsize=cfg.threads, max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        # response code -> number of requests, 'error' for connection errors
        self.requests_total = Counter()
        self._lock = threading.Lock()

    def _count(self, code):
        with self._lock:
            self.requests_total[code] += 1

    def get(self, path, params=None, headers=None):
        try:
            response = self.session.get(self.base_url + path, params=params, headers=headers, timeout=self.timeout)
        except requests.exceptions.RequestException:
            self._count('error')
            raise
        self._count(str(response.status_code))
        response.raise_for_status()
        return response

    def requests_snapshot(self):
        with self._lock:
            return dict(self.requests_total)

    def paginate(self, path, params=None):
        page = 1
        while True:
            items = self.get(path, params={**(params or {}), 'page': page, 'page_size': PAGE_SIZE}).json()
            yield from items
            if len(items) < PAGE_SIZE:
                return
            page += 1

    def projects(self):
        return [project['name'] for project in self.paginate('/projects')]

    def repositories(self, project):
        return [repository['name'] for repository in self.paginate(f'/projects/{project}/repositories')]

    def latest_artifact(self, project, repository):
        params = {
            'page': 1,
            'page_size': 1,
            'sort': '-push_time',
            'with_scan_overview': 'true',
            'with_tag': 'false',
            'with_label': 'false',
        }
        url = f'/projects/{project}/repositories/{encode_repository(repository)}/artifacts'
        artifacts = self.get(url, params=params, headers={'X-Accept-Vulnerabilities': VULNERABILITY_MIME_TYPES}).json()
        # if you have proxy cache repos and cache is expired - there will be no artifacts
        return artifacts[0] if artifacts else None

    def vulnerabilities(self, artifact):
        href = artifact['addition_links']['vulnerabilities']['href']
        path = href.removeprefix('/api/v2.0')
        report = self.get(path, headers={'X-Accept-Vulnerabilities': VULNERABILITY_MIME_TYPES}).json()
        for value in report.values():
            return value.get('vulnerabilities') or []
        return []


def summarize_vulnerabilities(vulnerabilities, cfg, digest=''):
    """Filter vulnerabilities and reduce them to unique label values of harbor_image_vulnerability."""
    rows = set()
    descriptions = {}
    for vulnerability in vulnerabilities:
        if not cfg.severity_selected(vulnerability.get('severity')):
            continue
        if cfg.only_fixable and not vulnerability.get('fix_version'):
            continue
        values = {**vulnerability, 'severity': normalize_severity(vulnerability.get('severity')), 'digest': digest}
        rows.add(tuple(str(values.get(label) or '') for label in cfg.vulnerability_labels))
        if cfg.include_description and vulnerability.get('id') and vulnerability.get('description'):
            # collapse new lines and repeated spaces, descriptions are rendered as a single line label value
            description = ' '.join(vulnerability['description'].split())
            descriptions.setdefault(vulnerability['id'], description[:cfg.description_max_length])
    return rows, descriptions


class Crawler:
    """Walks over all projects and repositories in Harbor and builds a report for the latest artifact of every repository."""

    def __init__(self, cfg, client):
        self.cfg = cfg
        self.client = client
        # (project, repository) -> RepositoryReport of the last crawl, reused for repositories which failed this time
        self.reports = {}

    def needs_details(self, scan):
        if not self.cfg.detailed_metrics or (self.cfg.only_fixable and not scan.fixable):
            return False
        return any(count for severity, count in scan.counts.items() if self.cfg.severity_selected(severity))

    def repository_report(self, project, name):
        repository = name.split('/', maxsplit=1)[1]
        artifact = self.client.latest_artifact(project, repository)
        if artifact is None:
            logging.debug(f'No artifacts found for repository {name}')
            return None

        digest = artifact.get('digest', '')
        report = RepositoryReport(project=project, repository=repository, digest=digest, scan=parse_scan_overview(artifact))
        if self.needs_details(report.scan):
            try:
                vulnerabilities = self.client.vulnerabilities(artifact)
            except requests.exceptions.HTTPError as e:
                if e.response is None or e.response.status_code != 404:
                    raise
                logging.debug(f'No vulnerabilities report for repository {name}: {e}')
            else:
                report.vulnerabilities, report.descriptions = summarize_vulnerabilities(vulnerabilities, self.cfg, digest)
        return report

    def crawl(self):
        """
        Returns:
            tuple: reports by (project, repository) and number of failed projects and repositories.
        """
        reports = {}
        errors = 0
        repositories = []
        for project in self.client.projects():
            if not self.cfg.project_selected(project):
                continue
            try:
                names = self.client.repositories(project)
            except requests.exceptions.RequestException as e:
                logging.error(f'Error processing project {project}: {e}')
                errors += 1
                reports.update({key: report for key, report in self.reports.items() if key[0] == project})
                continue
            repositories += [(project, name) for name in names if name not in self.cfg.ignore_repositories]

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.cfg.threads) as executor:
            futures = {executor.submit(self.repository_report, project, name): (project, name) for project, name in repositories}
            for future in concurrent.futures.as_completed(futures):
                project, name = futures[future]
                key = (project, name.split('/', maxsplit=1)[1])
                try:
                    report = future.result()
                except Exception as e:
                    logging.error(f'Error processing repository {name}: {e}')
                    errors += 1
                    if key in self.reports:
                        reports[key] = self.reports[key]
                    continue
                if report is not None:
                    reports[key] = report

        self.reports = reports
        return reports, errors


@dataclass
class CollectStats:
    duration: float = 0.0
    last_success: float = 0.0
    errors_total: int = 0
    # response code -> number of Harbor API requests
    requests_total: dict = field(default_factory=dict)


class SnapshotCollector:
    """Turns crawl results into Prometheus metric families."""

    def __init__(self, reports, stats, cfg):
        self.reports = sorted(reports.values(), key=lambda r: (r.project, r.repository))
        self.stats = stats
        self.cfg = cfg

    def collect(self):
        repository_labels = ['project', 'repository']

        counts = GaugeMetricFamily('harbor_image_vulnerabilities_total', 'Number of vulnerabilities by severity in the latest pushed image of the repository', labels=repository_labels + ['severity'])
        fixable = GaugeMetricFamily('harbor_image_vulnerabilities_fixable', 'Number of vulnerabilities with a fix version in the latest pushed image of the repository', labels=repository_labels)
        scan_time = GaugeMetricFamily('harbor_image_scan_timestamp_seconds', 'Time when the latest pushed image of the repository was scanned', labels=repository_labels)
        scan_status = GaugeMetricFamily('harbor_image_scan_status', 'Scan status of the latest pushed image of the repository', labels=repository_labels + ['status'])
        for report in self.reports:
            labels = [report.project, report.repository]
            scan_status.add_metric(labels + [report.scan.status], 1)
            if report.scan.end_time:
                scan_time.add_metric(labels, report.scan.end_time)
            if report.scan.counts:
                for severity in SEVERITIES:
                    counts.add_metric(labels + [severity], report.scan.counts[severity])
                fixable.add_metric(labels, report.scan.fixable)
        yield from (counts, fixable, scan_time, scan_status)

        if self.cfg.detailed_metrics:
            vulnerability = GaugeMetricFamily('harbor_image_vulnerability', 'Vulnerability found in the latest pushed image of the repository', labels=repository_labels + list(self.cfg.vulnerability_labels))
            descriptions = {}
            for report in self.reports:
                for values in sorted(report.vulnerabilities):
                    vulnerability.add_metric([report.project, report.repository, *values], 1)
                for vulnerability_id, description in report.descriptions.items():
                    descriptions.setdefault(vulnerability_id, description)
            yield vulnerability

            if self.cfg.include_description:
                info = GaugeMetricFamily('harbor_vulnerability_info', 'Description of the vulnerability, join it by id label', labels=['id', 'description'])
                for vulnerability_id in sorted(descriptions):
                    info.add_metric([vulnerability_id, descriptions[vulnerability_id]], 1)
                yield info

        duration = GaugeMetricFamily('harbor_exporter_collect_duration_seconds', 'Duration of the latest Harbor crawl')
        duration.add_metric([], self.stats.duration)
        last_success = GaugeMetricFamily('harbor_exporter_last_success_timestamp_seconds', 'Time of the latest completed Harbor crawl')
        last_success.add_metric([], self.stats.last_success)
        errors = CounterMetricFamily('harbor_exporter_collect_errors', 'Number of failed project, repository or crawl operations')
        errors.add_metric([], self.stats.errors_total)
        api_requests = CounterMetricFamily('harbor_exporter_api_requests', 'Number of Harbor API requests by response code', labels=['code'])
        for code in sorted(self.stats.requests_total):
            api_requests.add_metric([code], self.stats.requests_total[code])
        yield from (duration, last_success, errors, api_requests)


@dataclass(frozen=True)
class Snapshot:
    body: bytes
    gzipped: bytes


def render(reports, stats, cfg):
    registry = CollectorRegistry(auto_describe=False)
    registry.register(SnapshotCollector(reports, stats, cfg))
    body = generate_latest(registry)
    return Snapshot(body=body, gzipped=gzip.compress(body, compresslevel=6))


class Exporter:
    def __init__(self, cfg, client=None):
        self.cfg = cfg
        self.client = client or HarborClient(cfg)
        self.crawler = Crawler(cfg, self.client)
        self.stats = CollectStats()
        self.snapshot = None
        self.stop = threading.Event()
        self.thread = None

    def refresh(self):
        started = time.monotonic()
        try:
            reports, errors = self.crawler.crawl()
            self.stats.last_success = time.time()
        except Exception:
            logging.exception('Error crawling Harbor, serving the previous results')
            reports, errors = self.crawler.reports, 1
        self.stats.duration = time.monotonic() - started
        self.stats.errors_total += errors
        self.stats.requests_total = self.client.requests_snapshot()
        # replacing the reference is atomic, scrapes always get a complete snapshot
        self.snapshot = render(reports, self.stats, self.cfg)
        logging.info(
            f'Collected {len(reports)} repositories with {sum(len(r.vulnerabilities) for r in reports.values())} detailed vulnerabilities '
            f'in {self.stats.duration:.1f}s, {errors} errors, snapshot size {len(self.snapshot.body)} bytes'
        )

    def run(self):
        while not self.stop.is_set():
            started = time.monotonic()
            self.refresh()
            self.stop.wait(max(0.0, self.cfg.collect_interval - (time.monotonic() - started)))

    def start(self):
        self.thread = threading.Thread(target=self.run, name='refresher', daemon=True)
        self.thread.start()


def make_handler(exporter):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split('?', maxsplit=1)[0]
            if path == '/metrics':
                self.metrics()
            elif path == '/healthz':
                alive = exporter.thread is None or exporter.thread.is_alive()
                self.reply(200 if alive else 503, b'ok\n' if alive else b'refresher is not running\n')
            elif path == '/ready':
                ready = exporter.snapshot is not None
                self.reply(200 if ready else 503, b'ok\n' if ready else b'first collection is in progress\n')
            else:
                self.reply(404, b'not found\n')

        def metrics(self):
            snapshot = exporter.snapshot
            if snapshot is None:
                self.reply(503, b'first collection is in progress\n')
                return
            if 'gzip' in self.headers.get('Accept-Encoding', ''):
                self.reply(200, snapshot.gzipped, CONTENT_TYPE_PLAIN_0_0_4, {'Content-Encoding': 'gzip'})
            else:
                self.reply(200, snapshot.body, CONTENT_TYPE_PLAIN_0_0_4)

        def reply(self, code, body, content_type='text/plain; charset=utf-8', headers=None):
            self.send_response(code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            logging.debug(f'{self.address_string()} - {format % args}')

    return Handler


def main():
    logging.basicConfig(level=os.environ.get('LOG_LEVEL', 'INFO').upper(), format='%(asctime)s - %(levelname)s - %(message)s')
    try:
        cfg = Config.from_env()
    except ValueError as e:
        logging.error(str(e))
        sys.exit(2)

    exporter = Exporter(cfg)
    exporter.start()
    server = ThreadingHTTPServer(('', cfg.exporter_port), make_handler(exporter))
    # python running as PID 1 in a container ignores SIGTERM without a handler
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    logging.info(f'Listening on port {cfg.exporter_port}, collecting every {cfg.collect_interval}s')
    server.serve_forever()


if __name__ == '__main__':
    main()
