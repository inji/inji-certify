# APITESTRIG

## Introduction
ApiTestRig will test the working of APIs of the MOSIP modules.

## Helm chart
* The `inji-certify-apitestrig` helm chart is maintained in this repository at [helm/inji-certify-apitestrig](../../helm/inji-certify-apitestrig) (earlier it was consumed from `mosip/apitestrig` in `mosip-functional-tests`).
* The chart is published to the `inji` helm repository (https://inji.github.io/helm) by the `chart-lint-publish` workflow; `install.sh` installs `inji/inji-certify-apitestrig` (version `CHART_VERSION`) as the helm release `inji-certify-apitestrig`.
* To test unpublished chart changes, run `helm dependency update ../../helm/inji-certify-apitestrig` and replace `inji/inji-certify-apitestrig --version $CHART_VERSION` in `install.sh` with `../../helm/inji-certify-apitestrig`.

## Install
* Review `values.yaml` (overrides) and [chart values](../../helm/inji-certify-apitestrig/values.yaml).
* Install
```sh
./install.sh
```
* During the execution of the `install.sh` script, a prompt appears requesting information regarding the presence of a public domain and a valid SSL certificate on the server.
* If the server lacks a public domain and a valid SSL certificate, it is advisable to select the `n` option. Opting it will enable the `init-container` with an `emptyDir` volume and include it in the deployment process.
* The init-container will proceed to download the server's self-signed SSL certificate and mount it to the specified location within the container's Java keystore (i.e., `cacerts`) file.
* This particular functionality caters to scenarios where the script needs to be employed on a server utilizing self-signed SSL certificates.

## Uninstall
* To uninstall ApiTestRig, run `delete.sh` script.
```sh
./delete.sh 
```

## Run apitestrig manually

#### Rancher UI
* Run apitestrig manually via Rancher UI.
  ![apitestrig-2.png](../../docs/images/apitestrig-2.png)
* There are two modes of apitestrig `smoke` & `smokeAndRegression`.
* By default, apitestrig will execute with `smokeAndRegression`. <br>
  If you want to run apitestrig with only `smoke`. <br>
  You have to update the `apitestrig` configmap and rerun the specific apitestrig job.

#### CLI
* Download Kubernetes cluster `kubeconfig` file from `rancher dashboard` to your local.
  ![apitestrig-1.png](../../docs/images/apitestrig-1.png)
* Install `kubectl` package to your local machine.
* Run apitestrig manually via CLI by creating a new job from an existing k8s cronjob.
  ```
  kubectl --kubeconfig=<k8s-config-file> -n inji-certify create job --from=cronjob/<cronjob-name> <job-name>
  ```
  example:
  ```
  kubectl --kubeconfig=/home/xxx/Downloads/qa4.config -n inji-certify create job --from=cronjob/cronjob-inji-certify-apitestrig-injicertify cronjob-inji-certify-apitestrig-injicertify-manual
  ```