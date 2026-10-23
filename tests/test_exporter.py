import gzip
import http.client
import logging
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import MagicMock

import requests

from exporter import (
    NOT_SCANNED,
    Config,
    Crawler,
    Exporter,
    HarborClient,
    RepositoryReport,
    ScanOverview,
    encode_repository,
    make_handler,
    parse_scan_overview,
    render,
    summarize_vulnerabilities,
)

# expected errors of failure scenarios are not interesting in the test output
logging.disable(logging.CRITICAL)

MIME_TYPE = 'application/vnd.security.vulnerability.report; version=1.1'


def make_config(**env):
    return Config.from_env({'HARBOR_API_URL': 'http://harbor/api/v2.0', **env})


def make_artifact(counts=None, fixable=0, status='Success', digest='sha256:abc'):
    artifact = {
        'digest': digest,
        'addition_links': {'vulnerabilities': {'href': f'/api/v2.0/projects/p/repositories/r/artifacts/{digest}/additions/vulnerabilities'}},
        'scan_overview': None,
    }
    if counts is not None:
        artifact['scan_overview'] = {
            MIME_TYPE: {
                'scan_status': status,
                'end_time': '2026-10-18T00:55:37.000Z',
                'summary': {'total': sum(counts.values()), 'fixable': fixable, 'summary': counts},
            }
        }
    return artifact


def make_vulnerability(id, severity='High', fix_version='1.0.1', package='openssl', version='1.0.0', description='Description of vulnerability'):
    return {'id': id, 'package': package, 'version': version, 'fix_version': fix_version, 'severity': severity, 'description': description}


def samples(body):
    return [line for line in body.decode().splitlines() if line and not line.startswith('#')]


class TestConfig(unittest.TestCase):

    def test_requires_harbor_api_url(self):
        with self.assertRaises(ValueError):
            Config.from_env({})

    def test_defaults(self):
        cfg = make_config()
        self.assertFalse(cfg.detailed_metrics)
        self.assertEqual(cfg.min_severity, 'High')
        self.assertEqual(cfg.vulnerability_labels, ('id', 'package', 'version', 'fix_version', 'severity'))
        self.assertIsNone(cfg.description_max_length)

    def test_rejects_unknown_severity_and_labels(self):
        with self.assertRaises(ValueError):
            make_config(MIN_SEVERITY='severe')
        with self.assertRaises(ValueError):
            make_config(VULNERABILITY_LABELS='id,cvss')

    def test_rejects_invalid_numbers_and_regex(self):
        with self.assertRaisesRegex(ValueError, 'THREADS'):
            make_config(THREADS='many')
        with self.assertRaisesRegex(ValueError, 'IGNORE_PROJECTS'):
            make_config(IGNORE_PROJECTS='proxy(')

    def test_description_requires_id_label(self):
        with self.assertRaises(ValueError):
            make_config(INCLUDE_DESCRIPTION='true', VULNERABILITY_LABELS='package,severity')

    def test_project_filters(self):
        cfg = make_config(INCLUDE_PROJECTS='infra.*|devops', IGNORE_PROJECTS='infra-old')
        self.assertTrue(cfg.project_selected('devops'))
        self.assertTrue(cfg.project_selected('infrastructure'))
        self.assertFalse(cfg.project_selected('infra-old'))
        self.assertFalse(cfg.project_selected('proxy.docker.io'))


class TestParsing(unittest.TestCase):

    def test_parse_scan_overview(self):
        overview = parse_scan_overview(make_artifact({'Critical': 2, 'High': 3, 'Negligible': 1}, fixable=4))
        self.assertEqual(overview.status, 'Success')
        self.assertEqual(overview.counts, {'Unknown': 1, 'Low': 0, 'Medium': 0, 'High': 3, 'Critical': 2})
        self.assertEqual(overview.fixable, 4)
        self.assertEqual(overview.end_time, 1792284937.0)

    def test_parse_not_scanned_artifact(self):
        overview = parse_scan_overview(make_artifact())
        self.assertEqual(overview.status, NOT_SCANNED)
        self.assertEqual(overview.counts, {})

    def test_encode_repository(self):
        self.assertEqual(encode_repository('bitnami/nginx'), 'bitnami%252Fnginx')
        self.assertEqual(encode_repository('nginx'), 'nginx')


class TestSummarizeVulnerabilities(unittest.TestCase):

    def setUp(self):
        self.vulnerabilities = [
            make_vulnerability('CVE-1', severity='Critical'),
            make_vulnerability('CVE-2', severity='High', fix_version=''),
            make_vulnerability('CVE-3', severity='Medium'),
            # the same package can be reported multiple times
            make_vulnerability('CVE-1', severity='Critical'),
        ]

    def test_filters_by_severity_and_deduplicates(self):
        rows, descriptions = summarize_vulnerabilities(self.vulnerabilities, make_config())
        self.assertEqual(rows, {
            ('CVE-1', 'openssl', '1.0.0', '1.0.1', 'Critical'),
            ('CVE-2', 'openssl', '1.0.0', '', 'High'),
        })
        self.assertEqual(descriptions, {})

    def test_only_fixable(self):
        rows, _ = summarize_vulnerabilities(self.vulnerabilities, make_config(ONLY_FIXABLE='true', MIN_SEVERITY='low'))
        self.assertEqual({row[0] for row in rows}, {'CVE-1', 'CVE-3'})

    def test_label_subset_collapses_rows(self):
        rows, _ = summarize_vulnerabilities(self.vulnerabilities, make_config(VULNERABILITY_LABELS='package,severity', MIN_SEVERITY='Unknown'))
        self.assertEqual(rows, {('openssl', 'Critical'), ('openssl', 'High'), ('openssl', 'Medium')})

    def test_descriptions(self):
        vulnerabilities = [make_vulnerability('CVE-1', description='Line one.\n\nLine   two.')]
        _, descriptions = summarize_vulnerabilities(vulnerabilities, make_config(INCLUDE_DESCRIPTION='true', DESCRIPTION_MAX_LENGTH='12'))
        self.assertEqual(descriptions, {'CVE-1': 'Line one. Li'})


class TestHarborClient(unittest.TestCase):

    def test_paginate(self):
        client = HarborClient(make_config())
        pages = [[{'name': f'p{i}'} for i in range(100)], [{'name': 'last'}]]
        responses = [MagicMock(status_code=200, json=MagicMock(return_value=page)) for page in pages]
        client.session.get = MagicMock(side_effect=responses)

        self.assertEqual(len(client.projects()), 101)
        self.assertEqual([call.kwargs['params']['page'] for call in client.session.get.call_args_list], [1, 2])
        self.assertEqual(client.requests_snapshot(), {'200': 2})


class FakeClient:
    def __init__(self, projects, artifacts, reports=None):
        self._projects = projects
        self.artifacts = artifacts
        self.reports = reports or {}
        self.failing = set()

    def projects(self):
        return list(self._projects)

    def repositories(self, project):
        if project in self.failing:
            raise requests.exceptions.ConnectionError('boom')
        return self._projects[project]

    def latest_artifact(self, project, repository):
        if f'{project}/{repository}' in self.failing:
            raise requests.exceptions.ConnectionError('boom')
        return self.artifacts.get(f'{project}/{repository}')

    def vulnerabilities(self, artifact):
        return self.reports[artifact['digest']]

    def requests_snapshot(self):
        return {'200': 1}


class TestCrawler(unittest.TestCase):

    def setUp(self):
        self.client = FakeClient(
            projects={'infra': ['infra/app', 'infra/ignored', 'infra/chart', 'infra/empty'], 'proxy': ['proxy/nginx']},
            artifacts={
                'infra/app': make_artifact({'Critical': 1, 'High': 0}, fixable=1, digest='sha256:app'),
                'infra/chart': make_artifact(),
                'proxy/nginx': make_artifact({'Low': 5}, digest='sha256:nginx'),
            },
            reports={'sha256:app': [make_vulnerability('CVE-1', severity='Critical')]},
        )

    def test_crawl(self):
        cfg = make_config(DETAILED_METRICS='true', IGNORE_REPOSITORIES='infra/ignored')
        reports, errors = Crawler(cfg, self.client).crawl()

        self.assertEqual(errors, 0)
        # infra/empty has no artifacts (deleted repository or expired proxy cache)
        self.assertEqual(sorted(reports), [('infra', 'app'), ('infra', 'chart'), ('proxy', 'nginx')])
        self.assertEqual(reports[('infra', 'app')].vulnerabilities, {('CVE-1', 'openssl', '1.0.0', '1.0.1', 'Critical')})
        self.assertEqual(reports[('infra', 'chart')].scan.status, NOT_SCANNED)
        # nginx has only Low vulnerabilities, the report is not downloaded
        self.assertEqual(reports[('proxy', 'nginx')].vulnerabilities, set())

    def test_failed_repository_is_dropped(self):
        crawler = Crawler(make_config(), self.client)
        crawler.crawl()
        self.client.failing.add('infra/app')
        reports, errors = crawler.crawl()

        # stale results are not served for a single repository, the failure is counted instead
        self.assertEqual(errors, 1)
        self.assertEqual(sorted(reports), [('infra', 'chart'), ('proxy', 'nginx')])

    def test_failed_project_is_dropped(self):
        crawler = Crawler(make_config(), self.client)
        crawler.crawl()
        self.client.failing.add('infra')
        reports, errors = crawler.crawl()

        self.assertEqual(errors, 1)
        self.assertEqual(sorted(reports), [('proxy', 'nginx')])


class TestRender(unittest.TestCase):

    def test_render(self):
        cfg = make_config(DETAILED_METRICS='true', INCLUDE_DESCRIPTION='true')
        report = RepositoryReport(
            project='infra', repository='app', digest='sha256:app',
            scan=ScanOverview(status='Success', end_time=100.0, counts={'Unknown': 0, 'Low': 0, 'Medium': 0, 'High': 1, 'Critical': 2}, fixable=2),
            vulnerabilities={('CVE-1', 'openssl', '1.0.0', '1.0.1', 'Critical')},
            descriptions={'CVE-1': 'Buffer "overflow"'},
        )
        not_scanned = RepositoryReport(project='infra', repository='chart')
        exporter = Exporter(cfg, client=FakeClient({}, {}))
        snapshot = render({('infra', 'app'): report, ('infra', 'chart'): not_scanned}, exporter.stats, cfg)
        lines = samples(snapshot.body)

        self.assertIn('harbor_image_vulnerabilities_total{project="infra",repository="app",severity="Critical"} 2.0', lines)
        self.assertIn('harbor_image_vulnerabilities_fixable{project="infra",repository="app"} 2.0', lines)
        self.assertIn('harbor_image_scan_status{project="infra",repository="chart",status="not_scanned"} 1.0', lines)
        self.assertIn('harbor_image_vulnerability{fix_version="1.0.1",id="CVE-1",package="openssl",project="infra",repository="app",severity="Critical",version="1.0.0"} 1.0', lines)
        self.assertIn('harbor_vulnerability_info{description="Buffer \\"overflow\\"",id="CVE-1"} 1.0', lines)
        # not scanned repositories have no counts
        self.assertFalse([line for line in lines if 'repository="chart"' in line and 'vulnerabilities_total' in line])
        self.assertEqual(gzip.decompress(snapshot.gzipped), snapshot.body)

    def test_detailed_metrics_are_disabled_by_default(self):
        cfg = make_config()
        exporter = Exporter(cfg, client=FakeClient({}, {}))
        body = render({}, exporter.stats, cfg).body.decode()
        self.assertNotIn('harbor_image_vulnerability ', body)
        self.assertNotIn('harbor_vulnerability_info', body)
        self.assertIn('harbor_exporter_collect_errors_total 0.0', body)


class TestExporter(unittest.TestCase):

    def test_refresh_failure_keeps_previous_results(self):
        client = FakeClient({'infra': ['infra/app']}, {'infra/app': make_artifact({'High': 1})})
        exporter = Exporter(make_config(), client=client)
        exporter.refresh()
        last_success = exporter.stats.last_success

        client.projects = MagicMock(side_effect=requests.exceptions.ConnectionError('harbor is down'))
        exporter.refresh()

        self.assertEqual(exporter.stats.last_success, last_success)
        self.assertEqual(exporter.stats.errors_total, 1)
        self.assertIn(b'repository="app"', exporter.snapshot.body)


class TestHttpHandler(unittest.TestCase):

    def setUp(self):
        self.exporter = Exporter(make_config(), client=FakeClient({'infra': ['infra/app']}, {'infra/app': make_artifact({'High': 1})}))
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(self.exporter))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def get(self, path, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        connection.request('GET', path, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.getheader('Content-Encoding'), response.read()

    def test_not_ready_before_first_collection(self):
        self.assertEqual(self.get('/healthz')[0], 200)
        self.assertEqual(self.get('/ready')[0], 503)
        self.assertEqual(self.get('/metrics')[0], 503)

    def test_metrics(self):
        self.exporter.refresh()
        self.assertEqual(self.get('/ready')[0], 200)

        status, encoding, body = self.get('/metrics')
        self.assertEqual((status, encoding), (200, None))
        self.assertIn(b'harbor_image_vulnerabilities_total{project="infra",repository="app",severity="High"} 1.0', body)

        status, encoding, gzipped = self.get('/metrics', {'Accept-Encoding': 'gzip'})
        self.assertEqual((status, encoding), (200, 'gzip'))
        self.assertEqual(gzip.decompress(gzipped), body)


if __name__ == '__main__':
    unittest.main()
