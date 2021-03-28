## OpenTelemetry Datadog Sandbox

This Repository allows users to deploy a sandbox distributed tracing application instrumented with OpenTelemetry SDKs, which emit traces to OpenTelemetry Collectors, and export Telemetry data to Datadog via the Datadog Exporter. It also demonstrates how to manually inject datadog formatted trace and span ids in an Application instrumented with OpenTelemetry SDKs in Ruby, Python, and Node.

To learn more about OpenTelemetry, please review the [Datadog Documentation](https://docs.datadoghq.com/tracing/setup_overview/open_standards/#opentelemetry-collector-datadog-exporter)

### Kubernetes

This test environment is useful for testing Kubernetes-specific behavior of the exporter.
It defines an agent-collector setup within Kubernetes which deployes opentelemetry collectors as a daemonset, which forwards to a standalone opentelemetry-collector service. It generates trafffic at a rate of 1 request per second for 15 minutes.

To use it you need to [install `minikube`](https://minikube.sigs.k8s.io/docs/start/).

1. Replace <YOUR_API_KEY> with your API key in `k8s-collector.yml` manifest.
  - If you also wish to enable log collection, Replace <YOUR_API_KEY> with your API key in the `value` of the `FLUENT_DATADOG_API_KEY` env var within the `fluent-bit` `DaemonSet`.
  - If you also wish to enable export to the datadog-agent, Replace <YOUR_API_KEY> with your API key in the `values.yaml` file.
2. Following [the documentation here](https://docs.datadoghq.com/agent/kubernetes/apm/?tab=helm#pagetitle), deploy the datadog-agent with the following `helm` command, replacing `<YOUR_API_KEY>` with your api key:
	- `helm install datadog-agent -f values.yaml  --set datadog.apiKey=<YOUR_API_KEY> datadog/datadog --set targetSystem=linux`
3. `$ sh ./build.sh`
4. `$ sh ./run.sh start`

Some sample requests should be generated automatically. To make individual requests to the sandbox:

1. After starting the cluster, create a tunnell to the `python-microservice` service:
  
  ```
  minikube service python-microservice --url
  ```

2. visit the url returned by the command above in your browser or via `curl`

### Example Output

![example_1](https://user-images.githubusercontent.com/14250318/108424500-443b3300-7207-11eb-9b6b-9551cc21dd02.png)
![example_2](https://user-images.githubusercontent.com/14250318/108424526-4b624100-7207-11eb-89c4-fb8f7f57da37.png)


