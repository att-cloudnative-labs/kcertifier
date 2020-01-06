# Kcertifier

---

<p align="center">
  <a href="https://goreportcard.com/report/github.com/att-cloudnative-labs/kcertifier" alt="Go Report Card">
    <img src="https://goreportcard.com/badge/github.com/att-cloudnative-labs/kcertifier">
  </a>
</p>
<p align="center">
    <a href="https://github.com/att-cloudnative-labs/kcertifier/graphs/contributors" alt="Contributors">
		<img src="https://img.shields.io/github/contributors/att-cloudnative-labs/kcertifier.svg">
	</a>
	<a href="https://github.com/att-cloudnative-labs/kcertifier/commits/master" alt="Commits">
		<img src="https://img.shields.io/github/commit-activity/m/att-cloudnative-labs/kcertifier.svg">
	</a>
	<a href="https://github.com/att-cloudnative-labs/kcertifier/pulls" alt="Open pull requests">
		<img src="https://img.shields.io/github/issues-pr-raw/att-cloudnative-labs/kcertifier.svg">
	</a>
	<a href="https://github.com/att-cloudnative-labs/kcertifier/pulls" alt="Closed pull requests">
    	<img src="https://img.shields.io/github/issues-pr-closed-raw/att-cloudnative-labs/kcertifier.svg">
	</a>
	<a href="https://github.com/att-cloudnative-labs/kcertifier/issues" alt="Issues">
		<img src="https://img.shields.io/github/issues-raw/att-cloudnative-labs/kcertifier.svg">
	</a>
	</p>
<p align="center">
	<a href="https://github.com/att-cloudnative-labs/kcertifier/stargazers" alt="Stars">
		<img src="https://img.shields.io/github/stars/att-cloudnative-labs/kcertifier.svg?style=social">
	</a>
	<a href="https://github.com/att-cloudnative-labs/kcertifier/watchers" alt="Watchers">
		<img src="https://img.shields.io/github/watchers/att-cloudnative-labs/kcertifier.svg?style=social">
	</a>
	<a href="https://github.com/att-cloudnative-labs/kcertifier/network/members" alt="Forks">
		<img src="https://img.shields.io/github/forks/att-cloudnative-labs/kcertifier.svg?style=social">
	</a>
</p>

----

Kcertifier is a custom controller for a custom resource, Kcertifier, that defines a desired TLS certificate to be provisioned by the cluster CA as well as the type of packaging (PEM, PKCS12, and JKS), which the controller will then reconcile into a Kubernetes secret.

A Kcertifier resource has fields to indicate key length, subject information (common-name, country, org, locality,...), alternate names, format of the certificate file(s) or keystore (package), and any associated password secrets. It also allows you to indicate that you would like to add any arbitrary key/values from another secret. An example of this use could be if you had an existing secret containing a truststore, you could indicate that you want to add that key value to the certificate secret that the controller will create so that the keystore and truststore could be in  a single secret. There is also a field for indicating an a secret from which to extract the keystore password (for keystore types of packages).

One note about the 'none' package type. This type can be used for an import-only package (no certificate, key or keystore is put into package). If there are no packages other than 'none' in the kcertifier, no rsa key or csr will be created. The motivation behind this package type is to allow kcertifier to handle creation of any ancillary secrets related to SSL certificates such as a root certificates that exists in another secret. 

When a Kcertifier resource is created or modified, a RSA key will be created and used to create a CSR according to the specs defined in the Kcertifier resource. The controller will then approve then certificate and create a secret with the resulting key and certificate in the format or formats (multiple outputs per Kcertifier allowed) specified.

The kcertifier controller also allows you to annotate a namespace with the namespace/name of an existing Kcertifier resource from another namespace to copy and add to the annotated namespace. This allows you to easily copy a particular Kcertifier resource that has a format that will be used widely in many namespaces. The namespace can be annotated with an additional annotation that allows you to override the common-name in the imported Kcertifier resource.

----

### Security

The premise of Kcertifier controller is to facility automated creation of TLS certificates to some specification with support for keystore formats. Anyone with the permissions to create/update Kcertifier resources can effectively sign certificates in the name of the cluster CA. Therefore RBAC permissions for Kcertifiers must be considered and configured appropriately. The inspiration for this project was in a opinionated platform where service accounts for platform-related automation tooling and platform admins had permissions to create Kcertifier resources.

The import of secrets into the packages defined in Kcertifiers could be a potential security risk in certain scenarios. First note that, by default, you can't import data from namespaces outside of that of the Kcertifier resource. There is a controller wide setting that allows imports from other namespaces. Proceed with caution when enabling this. Also note that the secret with the data being imported must be annotated to signify that it is allowing Kcertifiers to import its data.

The namespace annotation feature must also be enabled using the controller settings and the Kcertifier resource that would be copied into the namespace must also be annotated.

----

### Kcertifier Resource Spec

```yaml
keyLength: "RSA key length (Default: 2048)"
subject:
  commonName: "server name *required (ex: server.example.com) - wildcard name is allowed (ex: *.example.com)"
  country: "country"
  stateOrProvince: "state or province"
  locality: "locality"
  organization: "organization"
  organizationalUnit: "organizational unit"
sans: "[] list of alternate server names"
packages: "[] list of output secrets"
  - type: "cert/key or keystore format. valid values are 'pem', 'pkcs12', 'jks', and 'none'"
    secretName: "name of the output secret"
    labels: "[map] key/value pairs of labels to put in output secret metadata"
    annotations: "[map] key/value pairs of annotations to put in output secret metadata. **some controller specific annotations will also be added to the output secret"
    options: "[map] key/value pairs of settings specific to the 'type' of output secret"
    imports: "[] list of data entries to copy from another secret and add to this package"
      - namespace: "source secret namespace"
        secretName: "source secret name"
        sourceKey: "key of the source data inside the source secret to import"
        targetKey: "key inside the output secret that you want the import data to go in as"
```

----

#### Package Options

Each package type has specific options that must be set:

##### PEM

```yaml
options:
  certDataKey: "(default: cert) key inside the secret data for the certificate pem data"
  keyDataKey: "(default: key) key inside the secret data for the rsa key pem data"
```

##### PKCS12/JKS

```yaml
options:
  keystoreDataKey: "(default: keystore) key inside the secret data for the pkcs12 data"
  alias: "(default: 1) keystore alias"
  passwordSecretNamespaceName: "(optional) namespace and name of the secret containing password used to encrypt the keystore in the format namespace/name. if not set, default password 'changeit' is used"
  passwordSecretKey: "(optional) key inside the secret named by passwordSecretNamespaceName option that has the password data. If passwordSecretNamespaceName is set and this is not, it is expected that there is only one key in the secret otherwise it is an error"
```

----

#### Controller Settings

These are command line arguments to the controller

```yaml
--metrics-addr: "(default: :8080) The address the metric endpoint binds to"
--enable-leader-election: "(default: false) Enable leader election for controller manager"
--allow-global-imports: "(default: false) Allow the import of secret data from external namespaces"
--allow-global-password-secret: "(default false) Allow keystore passwords to come from external namespaces"
--allow-namespace-auto-import: "(default false) Allow annotated namespaces to automatically import kcertifier from another namespace"
```

----

#### Annotations

```yaml
"kcertifier.atteg.com/allow-global-import": "true - this indicates that the secret annotated with this can be used as a source for importing data into the kcertifier output package secret"
"kcertifier.atteg.com/global-password-secret": "true - this indicates that the secret annotated with such can be used by kcertifiers named in other namespaces (still requires controller settings to allow this)"

"kcertifier.atteg.com/import-kcertifier": "namespace/name - this identifies the kcertifier to copy into the namespace annotated with such"
"kcertifier.atteg.com/override-common-name": "this sets the common name in the kcertifier copied using the import-kcertifier annotation on the namespace"
"kcertifier.atteg.com/override-sans": "this sets the sans (comma-separated) in the kcertifier copied using the import-kcertifier annotation on the namespace"
```

**There are some annotations used internally by the controller on resources it creates and modifies (csr, secrets). These should not be modified/removed manually.

----

### Example Kcertifiers

#### Single Pem Package, No Imports

```yaml
apiVersion: kcertifier.atteg.com/v1alpha1
kind: Kcertifier
metadata:
  namespace: my-namespace
  name: my-kcertifier
spec:
  keyLength: 2048
  subject:
    commonName: "myapp.example.com"
    country: "US"
    stateOrProvince: "CA"
    locality: "Los Angeles"
    organization: "MyCompany"
    organizationalUnit: "MyUnit"
  packages:
    - type: "pem"
      secretName: "mycert"
      options:
        certDataKey: "cert"
        keyDataKey: "key"
```

#### Pem and Pkcs12 with imports

```yaml
apiVersion: kcertifier.atteg.com/v1alpha1
kind: Kcertifier
metadata:
  namespace: my-namespace
  name: my-kcertifier
spec:
  keyLength: 2048
  subject:
    commonName: mykcjkscert.atteg.com
    country: US
    locality: El Segundo
    organization: AT&T
    organizationalUnit: Mobility & Entertainment
    stateOrProvince: CA
  sans:
  - "alt1.example.com"
  - "alt2.myapp.example.com"
  packages:
  - type: "pem"
    secretName: "mycert"
    options:
      certDataKey: "cert"
      keyDataKey: "key"
  - type: pkcs12
    secretName: myp12
    options:
      keystoreDataKey: keystore
      passwordSecretNamespaceName: some-namespace/some-secret
      passwordSecretKey: some-key
    imports:
    - namespace: other-namespace
      secretName: other-secret
      sourceKey: other-key
      targetKey: mykey
```

----

## Installation

Run (with kubectl context set to the target cluster):
```shell script
make deploy IMG=docker.io/atteg/kcertifier:v0.10.0-alpha-1
```

----

*Developed using the Kubebuilder Framework, https://github.com/kubernetes-sigs/kubebuilder