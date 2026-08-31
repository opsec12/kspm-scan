FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY kspm ./kspm

RUN pip install --no-cache-dir .

# Mount manifests at /manifests and/or a kubeconfig at /root/.kube/config, e.g.:
#   docker run --rm -v $(pwd):/manifests kspm-scanner manifests /manifests
#   docker run --rm -v ~/.kube/config:/root/.kube/config:ro kspm-scanner live
ENTRYPOINT ["kspm"]
CMD ["--help"]
