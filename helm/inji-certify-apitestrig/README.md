# inji-certify-apitestrig

Helm chart to deploy APITESTRIG (API test rig) for INJI `inji-certify` as a Kubernetes CronJob.

This chart was previously consumed from `mosip/apitestrig` (mosip-functional-tests) and is now maintained in this repository.

## Install
```console
$ cd ../../deploy/inji-certify-apitestrig
$ ./install.sh
```

Or directly from the published chart repository:
```console
$ helm repo add inji https://inji.github.io/helm
$ helm -n inji-certify install inji-certify-apitestrig inji/inji-certify-apitestrig --version 1.0.0-rc.2-develop -f deploy/inji-certify-apitestrig/values.yaml
```

For local development (unpublished chart changes), install from this directory instead:
```console
$ helm dependency update helm/inji-certify-apitestrig
$ helm -n inji-certify install inji-certify-apitestrig helm/inji-certify-apitestrig -f deploy/inji-certify-apitestrig/values.yaml
```

## Key values
| Parameter | Description | Default |
|---|---|---|
| `modules.injicertify.image.repository` | apitest-inji-certify image | `injistack/apitest-inji-certify` |
| `modules.injicertify.image.tag` | apitest-inji-certify image tag | `1.0.0-alpha.1` |
| `crontime` | Cron schedule | `0 3 * * *` |
| `apitestrig.configmaps.apitestrig.*` | Values for the `apitestrig` configmap (ENV_USER, ENV_ENDPOINT, ENV_TESTLEVEL, eSignetDeployed, ...) | |
| `apitestrig.variables.push_reports_to_s3` | Push reports to S3 (`yes`) or to an NFS-backed PVC (`no`) | `yes` |
| `enable_insecure` | Add init container that trusts the server's self-signed certificate | `false` |
| `cacertsMountPath` | Where the generated cacerts is mounted when `enable_insecure` is true | `/usr/lib/jvm/java-21-openjdk-amd64/lib/security/cacerts` |
