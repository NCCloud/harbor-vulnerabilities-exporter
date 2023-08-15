import unittest
from unittest.mock import patch
from exporter import CustomCollector


class TestCustomCollector(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.collector = CustomCollector()
        cls.repository = "my_project/my_repository"
        cls.artifact = {
            "addition_links": {
                "vulnerabilities": {"href": "/api/v2.0/vulnerabilities"}
            }
        }
        cls.vulnerabilities = {
            "application/vnd.security.vulnerability.report; version=1.1": {
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-5678",
                        "package": "test_package",
                        "version": "1.0.0",
                        "fix_version": "1.0.1",
                        "severity": "High",
                        "description": "Description of vulnerability"
                    }
                ]
            }
        }

    # Mocking the requests.get method to simulate vulnerabilities data parsing
    @patch('requests.get')
    def test_process_artifact(self, mock_get):
        # Configure the mock response
        mock_get.return_value.json.return_value = self.vulnerabilities
        self.collector.process_artifact(self.artifact, self.repository)

        # Get metrics to compare labels with expected_labels
        metrics = self.collector.metrics
        first_metric_labels = metrics[0].samples[0].labels
        expected_labels = {
            'id': 'CVE-2021-5678',
            'package': 'test_package',
            'version': '1.0.0',
            'fix_version': '1.0.1',
            'severity': 'High',
            'description': 'Description of vulnerability',
            'project': 'my_project',
            'repository': 'my_repository'
        }

        self.assertEqual(first_metric_labels, expected_labels)
        self.assertEqual(len(metrics), 1)

    # Mocking the requests.get method to simulate an exception and test if process_artifact raises an exception
    @patch('requests.get', side_effect=Exception('Test exception'))
    def test_process_artifact_exception(self, mock_get):
        with self.assertRaises(Exception):
            self.collector.process_artifact(self.artifact, self.repository)


if __name__ == '__main__':
    unittest.main()
