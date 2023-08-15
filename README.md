# Harbor Vulnerabilities Exporter
<p float="left">
  <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/3/38/Prometheus_software_logo.svg/2066px-Prometheus_software_logo.svg.png" width="200" height="200" />
  <img src="https://goharbor.io/img/logos/harbor-icon-color.png" width="200" height="200"  />
</p>

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

[Helm](https://helm.sh) must be installed to use the charts.  Please refer to Helm's [documentation](https://helm.sh/docs) to get started.

Once Helm has been set up correctly, add the repo as follows:

  ```bash
  helm repo add nccloud https://nccloud.github.io/charts
  ```

If you had already added this repo earlier, run `helm repo update` to retrieve the latest versions of the packages.
You can then run `helm search repo nccloud` to see the charts.

To install the exporter chart:

  ```bash
  helm install harbor-vulnerabilities-exporter nccloud/harbor-vulnerabilities-exporter
  ```

See [values](https://github.com/NCCloud/charts/blob/main/charts/harbor-vulnerabilities-exporter) for details.

## Versioning

We use [SemVer](http://semver.org/) for versioning.
To see the available versions, check [tags in this repository](https://github.com/NCCloud/harbor-vulnerabilities-exporter/tags).

## Contributing

We welcome contributions, issues, and feature requests!
Also, please refer to our [contribution guidelines](https://github.com/NCCloud/harbor-vulnerabilities-exporter/blob/main/CONTRIBUTING.md) for details.


## License
All functionalities are in beta and is subject to change. The code is provided as-is with no warranties.<br>
[Apache 2.0 License](./LICENSE)<br>
<br><br>
<img alt="logo" width="75" src="https://avatars.githubusercontent.com/u/7532706" /><br>
Made with <span style="color: #e25555;">&hearts;</span> by [Namecheap Cloud Team](https://github.com/NCCloud)
