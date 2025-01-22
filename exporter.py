#!/usr/bin/env python3

import os
import sys
import time
import logging
import requests
import concurrent.futures
import threading

from prometheus_client.core import REGISTRY, GaugeMetricFamily
from prometheus_client import start_http_server

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the base URL of your Harbor instance for example: 'http://harbor-harbor-harbor-core.harbor/api/v2.0'
HARBOR_API_URL = os.environ.get('HARBOR_API_URL')
HARBOR_USERNAME = os.environ.get('HARBOR_USERNAME')
HARBOR_PASSWORD = os.environ.get('HARBOR_PASSWORD')
# number of parallel threads to use in API requests, default value is 5
THREADS = int(os.environ.get('THREADS', 5))
URL_PARAMS = {"page": 1, "page_size": 0}
# comma separated list of project/repositories to ignore (won't create a metric in prometheus), for example: 'project/repo1,project/repo2'
IGNORE_REPOSITORIES = [repo.strip() for repo in os.environ.get('IGNORE_REPOSITORIES', "").split(',') if repo.strip()]


if not HARBOR_API_URL:
    logging.error('harbor api url was not specified. You have to set HARBOR_API_URL env variable.')
    # HARBOR_API_URL variable is a must, exitting script
    sys.exit(2)

# Optional: Add basic authentication if the HARBOR_USERNAME and HARBOR_PASSWORD are available
AUTH = None
if HARBOR_USERNAME and HARBOR_PASSWORD:
    AUTH = (HARBOR_USERNAME, HARBOR_PASSWORD)


class CustomCollector:
    def __init__(self):
        self.metrics = []
        self.lock = threading.Lock()

    def parse_vulnerabilities(self, vulnerabilities, repository):
        """
        Parse the vulnerabilities data and create a Prometheus metric for each vulnerability.

        Args:
            vulnerabilities (list): List of vulnerabilities.
            repository (str): Name of the repository with project name. Like: my_project/my_repository

        Returns:
            GaugeMetricFamily: Prometheus metric for vulnerabilities.

        """
        try:
            project, repository = repository.split("/", maxsplit=1)
            metric_name = 'harbor_image_vulnerabilities'
            metric_description = 'Vulnerabilities found in the latest pushed images into every repository'
            metric_labels = ['id', 'package', 'version', 'fix_version', 'severity', 'description', 'project', 'repository']
            metric = GaugeMetricFamily(metric_name, metric_description, labels=metric_labels)

            for vulnerability in vulnerabilities:
                label_values = [
                    vulnerability['id'],
                    vulnerability['package'],
                    vulnerability['version'],
                    vulnerability['fix_version'],
                    vulnerability['severity'],
                    vulnerability['description'],
                    project,
                    repository
                ]

                metric.add_metric(
                    labels=label_values,
                    value=1
                )

        except Exception:
            logging.exception('Error parsing vulnerabilities')
            raise

        return metric

    def process_artifact(self, artifact, repository):
        """
        Process an artifact to retrieve the vulnerabilities and create Prometheus metrics.

        Args:
            artifact (dict): Harbor artifact details.
            repository (str): Name of the repository.

        """
        try:
            vulnerabilities_url = artifact['addition_links']['vulnerabilities']['href']
            vulnerabilities_url = vulnerabilities_url.replace("/api/v2.0", "")

            response = requests.get(HARBOR_API_URL + vulnerabilities_url, auth=AUTH)
            response.raise_for_status()
            vulnerabilities_data = response.json()
            # iterating over vulnerabilities_data and get "vulnerabilities" key
            vulnerabilities = next(iter(vulnerabilities_data.values()))['vulnerabilities']
            # Checking if vulnerabilities were detected or not
            if vulnerabilities:
                logging.info(f'Found vulnerabilities for repository {repository}')
                metric = self.parse_vulnerabilities(vulnerabilities, repository)
                # Add metric to the list
                self.metrics.append(metric)
            else:
                logging.info(f'No vulnerabilities found for repository {repository}')

        except requests.exceptions.RequestException as e:
            logging.error(f'Error processing artifact: {str(e)}')

    def process_repo(self, repo):
        """
        Process a repository to retrieve the latest artifact and process it for vulnerabilities.

        Args:
            repo (dict): Repository details

        """
        try:
            # Check if the repository is in the ignore list
            if f"{repo['name']}" in IGNORE_REPOSITORIES:
                logging.info(f"Repository {repo['name']} is in the ignore list. Skipping.")
                return

            project, repository = repo['name'].split("/", maxsplit=1)
            repository = repository.replace("/library", "")
            # this is needed for getting repos like proxy.docker.io/bitnami/nginx
            repository_patched = requests.utils.quote(repository, safe="")
            repository_patched = requests.utils.quote(repository_patched, safe="")
            url = f'{HARBOR_API_URL}/projects/{project}/repositories/{repository_patched}/artifacts'
            response = requests.get(url, params=URL_PARAMS, auth=AUTH)
            response.raise_for_status()
            artifacts = response.json()
            # if you have proxy cache repos and cache is expired - there will be no artifacts
            if artifacts:
                latest_artifact = max(artifacts, key=lambda x: x['push_time'])
                logging.info(f'Found latest artifact for repository {repo["name"]}:')
                self.process_artifact(latest_artifact, repo['name'])
            else:
                logging.info(f'No artifacts found for repository {repo["name"]}')

        except requests.exceptions.RequestException as e:
            logging.error(f'Error processing repository {repo["name"]}: {str(e)}')

    def process_project(self, project):
        """
        Process all projects to get repository details

        Args:
            project (dict): Project details

        """
        try:
            url = f'{HARBOR_API_URL}/projects/{project["name"]}/repositories'
            response = requests.get(url, params=URL_PARAMS, auth=AUTH)
            response.raise_for_status()
            repos = response.json()

            # Use ThreadPoolExecutor for parallel requests
            with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
                # Submit the requests for each repo
                futures = [executor.submit(self.process_repo, repo) for repo in repos]
                # Wait for all the requests to complete
                concurrent.futures.wait(futures)

        except requests.exceptions.RequestException as e:
            logging.error(f'Error processing project {project["name"]}: {str(e)}')

    def collect(self):
        """
        Collect vulnerabilities for latest pushed images in all projects and repositories in Harbor
        Then making Prometheus metrics with project_repository in the name and vulnerabilities details in labels

        Returns:
            metrics: List of Prometheus metrics.

        """
        with self.lock:
            try:
                self.metrics = []
                url = f'{HARBOR_API_URL}/projects'
                response = requests.get(url, params=URL_PARAMS, auth=AUTH)
                response.raise_for_status()
                projects = response.json()

                # Use ThreadPoolExecutor for parallel requests
                with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
                    # Submit the requests for each project
                    futures = [executor.submit(self.process_project, project) for project in projects]
                    # Wait for all the requests to complete
                    concurrent.futures.wait(futures)

            except requests.exceptions.RequestException as e:
                logging.error(f'Error retrieving projects: {str(e)}')

            return self.metrics


if __name__ == '__main__':
    # default exporter listening port is 8000
    EXPORTER_PORT = int(os.environ.get('EXPORTER_PORT', 8000))

    REGISTRY.register(CustomCollector())
    start_http_server(EXPORTER_PORT)

    while True:
        time.sleep(1)
