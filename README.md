# Harbor Vulnerabilities Exporter

The Harbor Vulnerabilities Prometheus Exporter is a Python script that collects vulnerability information for the latest pushed images in Harbor repositories and generates Prometheus metrics based on the collected data.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Versioning](#versioning)
- [Contributing](#contributing)
- [License](#license)

## Introduction

Harbor is a container image registry that allows you to store, manage, and secure container images. The Harbor Vulnerabilities Exporter helps you gather vulnerability information for images stored in Harbor repositories and exposes this data as Prometheus metrics, making it easier to monitor security aspects of your images.

## Features

- Collects vulnerability information for the latest pushed images in Harbor repositories.
- Exposes vulnerability metrics in Prometheus format.
- Supports parallel processing for improved performance.
- Easily configurable through environment variables.

## Installation

Clone the repository:

   ```bash
   git clone https://github.com/NCCloud/harbor-vulnerabilities-exporter.git
   cd harbor-vulnerabilities-exporter
   ```

Install the required Python packages:

   ```bash
   pip install -r requirements.txt
   ```
Set up your environment variables as described in the [Configuration] section.

Alternatively you can build a docker image for the harbor-vulnerabilities-exporter using the provided Dockerfile in the root of this repository:
   ```bash
   docker build -t my-image-tag .
   ```

## Configuration

You can configure the exporter using environment variables:

- **HARBOR_API_URL**: API URL of your Harbor instance, for example: 'http://harbor-harbor-harbor-core.harbor/api/v2.0'
- **HARBOR_USERNAME**: Your Harbor username (optional).
- **HARBOR_PASSWORD**: Your Harbor password (optional).
- **THREADS**: Number of parallel threads for API requests (default is 5).
- **EXPORTER_PORT**: Port for the Prometheus metrics exporter (default is 8000).

## Usage

Run the exporter using the following command:

   ```bash
   export HARBOR_API_URL='http://your-harbor-endpoint'
   python3 exporter.py
   ```

or using container image:

   ```bash
   docker run -e HARBOR_API_URL='http://your-harbor-endpoint' -p 8000:8000 my-image-tag
   ```

### Helm chart

Variables:

| Configuration        | Description                                                       | Default Value                                            |
|----------------------|-------------------------------------------------------------------|----------------------------------------------------------|
| replicas             | Number of replicas for the exporter deployment.                   | 1                                                        |
| harborApiUrl         | The API URL of your Harbor instance.                              | http://harbor-harbor-harbor-core.harbor/api/v2.0         |
| exporterPort         | Port for the Prometheus metrics exporter.                         | 8000                                                     |
| threadCount          | Number of parallel threads for API requests.                      | 5                                                        |
| harborUsername       | Your Harbor username (leave empty if not required).               |                                                          |
| harborPassword       | Your Harbor password (leave empty if not required).               |                                                          |
| scrapeTimeout        | Timeout for Prometheus scraping.                                  | "30s"                                                    |
| scrapeInterval       | Interval for Prometheus scraping.                                 | "300s"                                                   |
| image.repository     | Repository for the exporter Docker image.                         | ghcr.io/nccloud/harbor-vulnerabilities-exporter          |
| image.tag            | Tag for the exporter Docker image.                                | latest                                                   |
| image.imagePullPolicy| Image pull policy for Kubernetes.                                 | Always                                                   |

Install helm chart:

   ```bash
   cd charts/harbor-vulnerabilities-exporter
   helm install harbor-vulnerabilities-exporter .
   ```

## Versioning

We use [SemVer](http://semver.org/) for versioning.
To see the available versions, check [tags in this repository](https://github.com/NCCloud/harbor-vulnerabilities-exporter/tags).

Once you are ready to make a new release, perform the following steps:
1. Open a pull request and assign the `release` label to it.
2. Merge the PR. This will trigger the pipeline which will build and publish the container image to the ghcr.

## Contribution

We welcome contributions, issues, and feature requests!
Also, please refer to our [contribution guidelines](https://github.com/NCCloud/harbor-vulnerabilities-exporter/blob/main/CONTRIBUTING.md) for details.


## License
All functionalities are in beta and is subject to change. The code is provided as-is with no warranties.<br>
[Apache 2.0 License](./LICENSE)<br>
<br><br>
<img alt="logo" width="75" src="https://avatars.githubusercontent.com/u/7532706" /><br>
Made with <span style="color: #e25555;">&hearts;</span> by [Namecheap Cloud Team](https://github.com/NCCloud)
