# Secretgen Controller Package

Secretgen-controller provides CRDs to specify what secrets need to be on cluster (generated or not).

Features:

* supports generating certificates, passwords, RSA keys and SSH keys
* supports exporting and importing secrets across namespaces

## Components

* secretgen-controller

## Configuration

The following configuration values can be set to customize the secretgen-controller installation.

### Secret Gen Controller Configuration

| Value | Required/Optional | Description |
|-------|-------------------|-------------|
| `namespace` | Optional | The namespace in which to deploy secretgen-controller. |
| `create_namespace` | Optional | A boolean that indicates whether to create the namespace specified. Default value is `true`. |
| `deployment.updateStrategy` | Optional | Update strategy of deployments, either 'RollingUpdate' or empty (use default strategy). |
| `deployment.rollingUpdate.maxUnavailable` | Optional | The maxUnavailable of rollingUpdate. Applied only if RollingUpdate is used as updateStrategy. |
| `deployment.rollingUpdate.maxSurge` | Optional | The maxSurge of rollingUpdate. Applied only if RollingUpdate is used as updateStrategy. |
| `deployment.nodeSelector` | Optional | NodeSelector configuration applied to all the deployments. |


## Usage Example

To learn more about how to use secretgen-controller refer to [secretgen-controller website](https://github.com/vmware-tanzu/carvel-secretgen-controller)
