---
title: Workload Identity Integration
authors:
    - @sonasingh46
reviewers:
    - @aramase
    - @CecileRobertMichon

creation-date: 2022-11-16
last-updated: N/A
status: implementable
see-also:
    - https://github.com/kubernetes-sigs/cluster-api-provider-azure/issues/2205
---

# Workload Identity Integration

## <a name='TableofContents'></a>Table of Contents

<!-- vscode-markdown-toc -->
* [Table of Contents](#TableofContents)
* [Acronyms](#Acronyms)
* [Summary](#Summary)
* [Motivation](#Motivation)
	* [Goals](#Goals)
	* [Non-Goals / Future Work](#Non-GoalsFutureWork)
* [Proposal](#Proposal)
	* [Implementation Details/Notes/Constraints](#ImplementationDetailsNotesConstraints)
		* [Key Generation](#KeyGeneration)
		* [OIDC URL Setup](#OidcUrlSetup)
		* [Set Service Account Signing Flags](#SetServiceAccountSigningFlags)
		* [Federated Credential](#FederatedCredential)
		* [Distribute Keys To Management Cluster](#DistributeKeys)
	* [Proposed Deployment Configuration Changes](#ProposedConfigurationChanges)
	* [Proposed Controller Changes](#ProposedControllerChanges)
		* [Identity](#Identity)
	* [Open Questions](#OpenQuestions)
		* [1. How to achieve multi-tenancy?](#Howtomultitenancy)
		* [2. How to distribute key pair to management cluster?](#Howtodistributekeys)
		* [3. User Experience](#UserExperience)
	* [Migration Plan](#MigrationPlan)
	* [Test Plan](#TestPlan)
* [Implementation History](#ImplementationHistory)

<!-- vscode-markdown-toc-config
	numbering=false
	autoSave=false
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->

## <a name='Acronyms'></a>Acronyms
| Acronym      | Full Form               |
| ------------ | ------------------------|
| AD           | Active Directory        |
| AAD          | Azure Active Directory  |
| AZWI         | Azure Workload Identity |
| OIDC         | OpenID Connect          |
| JWKS         | JSON Web Key Sets       |

## <a name='Summary'></a>Summary

Workloads deployed in Kubernetes cluster may require Azure Active Directory application credential or managed identities to access azure protected resource e.g. Azure Key Vault, Virtual Machines etc. Azure AD Pod Identity helps access azure resources without the need of a secret management via Azure Managed Identities. Azure AD Pod Identity is now deprecated and Azure AD Workload Identity is the next iteration of the former. This design proposal aims to define the way for AZWI integration into capz for self managed clusters with keeping in mind other factor e.g. User Experience, Multi Tenancy, Backwards Compatibility etc.

For more details about Azure AD Pod Identity please visit this [link](https://github.com/Azure/aad-pod-identity)  

## <a name='Motivation'></a>Motivation

AZWI gives the capability to federate the credentials with external identity providers in a Kubernetes native way. This approach overcomes several limitations of Azure AD Identity as mentioned below.
- Removes scale and performance issues that existed for identity assignment.
- Supports K8s clusters hosted in any cloud or on premise.
- Supports both Linux and Windows workloads and removes the need for CRD and pods that intercept IMDS traffic.

From CAPZ perspective
- The AAD pod identity pod has to be deployed on all the nodes where the capz pod can be potentially scheduled.
- It has a dependency with the CNI and requires modifying iptables on the node.
- AAD pod identity is now deprecated. 

To learn more about AZWI please visit this link https://azure.github.io/azure-workload-identity/docs/introduction.html

### <a name='Goals'></a>Goals

- Enable CAPZ pod to use AZWI on the management cluster to authenticate to Azure to create/update/delete resources as part of workload cluster lifecycle management

## <a name='Proposal'></a>Proposal

In this model, Kubernetes cluster itself becomes the token issuer issuing tokens to Kubernetes service accounts. These service accounts can be configured to be trusted on Azure AD application or user assigned managed identity. Workloads/pods can use this service account token which is projected to it's volume and can exchange the projected service account token for an Azure AD token.

The first step for creating a Kubernetes cluster using capz is creating a bootstrap cluster and then deploying capi, capz and other helper components. On a high level the workflow looks the following to be able to use AZWI and create a management cluster.

**Bootstrap Cluster**

- The operator/admin generates signing key pair or BYO key pair. 

- The bootstrap cluster is configured with appropriate flags on kube-apiserver and kube-controller-manager and the key pairs are mounted on the container path for control plane node. [ToDo: Details on the values of the flag]
	- kube-apiserver flags
		- --service-account-issuer
		- --service-account-signing-key-file
		- --service-account-key-file
	- kube-controller-manager
		- --service-account-private-key-file

- The operator/admin uploads the following two documents in a blob storage container. These documents is accessible publicy on a URL and this URL is commonly referred as issuer URL in this context. More about this [here](https://azure.github.io/azure-workload-identity/docs/installation/self-managed-clusters/oidc-issuer.html)  
  - Generate and upload the Discovery Document.
  - Generate and upload the JWKS Document.
 
- The operator/admin installs the AZWI mutating admission webhook on the bootstrap cluster.

- CAPZ pod can use the client ID of the Azure AD or User Assigned Identity by passing it in AzureClusterIdentity CR. Also, the capz manager service account can be optionally annotated with the Azure AD or User Assigned Client ID for fallback. 

- A federated credential should be created between the identity and the OIDC issuer URL and the service account(subject). More on this [here](https://azure.github.io/azure-workload-identity/docs/topics/federated-identity-credential.html)

- CAPZ pod should use the `azidentity` module from the azure-sdk-for-go to exchange AD token in lieu of the projected service account token.

**Management Cluster**

- Once a K8s cluster is created from the bootstrap cluster, to convert it into a management cluster `clusterctl init` and `clusterctl move` commands are executed.

- After `clusterctl init` command is executed, the control plane node should have the key pairs and then patched to include them in the container path by setting the kube-apiserver and kube-controller-manager flags.

- The capz pod should know what client ID to use. It can again be supplied via AzureClusterIdentity.

### <a name='ImplementationDetailsNotesConstraints'></a>Implementation Details/Notes/Constraints

- AAD pod identity can co exist with AZWI
- Migration plan from AAD pod identity to AZWI for existing cluster. Refer to the `Migration Plan` section at the bottom of the document.
- For AZWI to work the following prerequisites must be met.
  - Key Generation
  - OIDC URL Setup
  - Set Service Account Signing Flags

#### <a name='KeyGeneration'></a>Key Generation

Admin should generate signing key pairs by using a tool such as openssl or bring their own public and private keys. 
These keys will be mounted on a path on the containers running on the control plane node. These keys are required for signing the service account tokens that will be used by the capz pod. 

#### <a name='OidcUrlSetup'></a>OIDC URL Setup

Two documents i.e OIDC and JWKS json documents needs to be generated and published to a public URL. The OIDC document contains the metadata of the issuer. The JSON Web Key Sets (JWKS) document contains the public signing key(s) that allows AAD to verify the authenticity of the service account token.

For more details on how to set up OIDC URL and more details on it, please g through this this [link](https://azure.github.io/azure-workload-identity/docs/installation/self-managed-clusters/oidc-issuer.html)

The steps on a high level to setup is the following
- Create an azure blob storage account.
- Create a storage container.
- Generate the OIDC and JWKS document.
- The document should be accessible on the public accessible URL which will be used later.

#### <a name='SetServiceAccountSigningFlags'></a>Set Service Account Signing Flags

Setup the flags on the kind cluster. An example is shown below

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
      # path on node where the public key exists
    - hostPath: ${SERVICE_ACCOUNT_KEY_FILE}
      containerPath: /etc/kubernetes/pki/sa.pub
      # path on node where the private key exists
    - hostPath: ${SERVICE_ACCOUNT_SIGNING_KEY_FILE}
      containerPath: /etc/kubernetes/pki/sa.key
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        # the oidc url after it has been set up
        service-account-issuer: ${SERVICE_ACCOUNT_ISSUER}
        service-account-key-file: /etc/kubernetes/pki/sa.pub
        service-account-signing-key-file: /etc/kubernetes/pki/sa.key
    controllerManager:
      extraArgs:
        service-account-private-key-file: /etc/kubernetes/pki/sa.key
```

#### <a name='FederatedCredential'></a>Federated Credential

The service account that the capz pod will use should be annotated with the client ID of the AAD application or User Assigned Identity and a federated identity should be created by associating the Service Accont as a subject.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  annotations:
    azure.workload.identity/client-id: ${APPLICATION_CLIENT_ID:-$USER_ASSIGNED_IDENTITY_CLIENT_ID}
  labels:
    azure.workload.identity/use: "true"
  name: ${SERVICE_ACCOUNT_NAME}
  namespace: ${SERVICE_ACCOUNT_NAMESPACE}
```

Also, a federated identity should be created using the azure cli ( or via the azure portal).

```bash
az identity federated-credential create \
  --name "kubernetes-federated-credential" \
  --identity-name "${USER_ASSIGNED_IDENTITY_NAME}" \
  --resource-group "${RESOURCE_GROUP}" \
  --issuer "${SERVICE_ACCOUNT_ISSUER}" \
  --subject "system:serviceaccount:${SERVICE_ACCOUNT_NAMESPACE}:${SERVICE_ACCOUNT_NAME}"
```

This means there are two approaches to associate the correct service account to the capz deployment.

- Deploy the capz with the usual configuration YAML and then patch the service account with the client ID.

- Or create the service account prior to capz deployment which uses the same service account.


#### <a name='DistributeKeys'></a>Distribute Keys To Management Cluster

Setting up credentials for management cluster which is created from the bootstrap cluster is key activity. This requires storing the keys on control plane node. One approach to do so can be the following:

- A reular `clusterctl init` is done.
- Once the cluster is up and running, the keys can be distributed on the control plane node via scp.
- After distributing the key, the appropriate flags as it was set up for the bootstrap cluster can be setup.
- The service account should be annotated with the client ID.
- At this stage, `clusterctl move` can be executed.

Above activities can be automated via clusterctl subcommands that is specific to azure infrastructre.

### <a name='ProposedConfigurationChanges'></a>Proposed Deployment Configuration Changes

- Azure Workload Identity mutating webhook should be deployed as part of capz deployment.

- The capz deployment configuration should have a environment variable configuration that is used to enable/disable the use of AZWI. By default it will be disabled.


### <a name='ProposedControllerChanges'></a>Proposed Controller Changes

The identity code workflow in capz should use `azidentity` module to exchange token from AAD as displayed in the next section.


#### <a name='Identity'></a>Identity

Following is a sample code that should be made into capz identity workflow. 

```go
		if AZWIEnabled == "true" {
			// Azure AD Workload Identity webhook will inject the 
			// following env vars

			// AZURE_CLIENT_ID with the clientID set in the service 
			// account annotation

			// AZURE_TENANT_ID with the tenantID set in the service 
			// account annotation. If not defined, then
			// the tenantID provided via azure-wi-webhook-config for the 
			// webhook will be used.

			// AZURE_FEDERATED_TOKEN_FILE is the service account token 
			// path

			// AZURE_AUTHORITY_HOST is the AAD authority hostname
			clientID := os.Getenv("AZURE_CLIENT_ID")
			tenantID := os.Getenv("AZURE_TENANT_ID")
			tokenFilePath := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
			// see the next code section for details on this function
			cred, err := newWorkloadIdentityCredential(tenantID, clientID, tokenFilePath, wiCredOptions)
			if err != nil {
				return nil, errors.Wrap(err, "failed to setup workload identity")
			}

			client := subscriptions.NewClient()

			// setCredentialsForWorkloadIdentity just setups the 
			// PublicCloud env URLs 
			params.AzureClients.setCredentialsForWorkloadIdentity(ctx, params.AzureCluster.Spec.SubscriptionID, params.AzureCluster.Spec.AzureEnvironment)
			client.Authorizer = azidext.NewTokenCredentialAdapter(cred, []string{"https://management.azure.com//.default"})
			params.AzureClients.Authorizer = client.Authorizer

		}
```

**NOTE:**
`azidext.NewTokenCredentialAdapter` is used to get a authoriser in order to add to the existing code workflow to adapt an azcore.TokenCredential type to an autorest.Authorizer type.

Also a go file e.g `workload_identity.go` in the `identity` package dealing with AZWI functionality.

```go

type workloadIdentityCredential struct {
	assertion string
	file      string
	cred      *azidentity.ClientAssertionCredential
	lastRead  time.Time
}

type workloadIdentityCredentialOptions struct {
	azcore.ClientOptions
}

func newWorkloadIdentityCredential(tenantID, clientID, file string, options *workloadIdentityCredentialOptions) (*workloadIdentityCredential, error) {
	w := &workloadIdentityCredential{file: file}
	cred, err := azidentity.NewClientAssertionCredential(tenantID, clientID, w.getAssertion, &azidentity.ClientAssertionCredentialOptions{ClientOptions: options.ClientOptions})
	if err != nil {
		return nil, err
	}
	w.cred = cred
	return w, nil
}

func (w *workloadIdentityCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return w.cred.GetToken(ctx, opts)
}

func (w *workloadIdentityCredential) getAssertion(context.Context) (string, error) {
	if now := time.Now(); w.lastRead.Add(5 * time.Minute).Before(now) {
		content, err := os.ReadFile(w.file)
		if err != nil {
			return "", err
		}
		w.assertion = string(content)
		w.lastRead = now
	}
	return w.assertion, nil
}

```


### <a name='OpenQuestions'></a>Open Questions

#### <a name='Howtomultitenancy'></a>1. How to achieve multi-tenancy?

The identity is tied to service account via the client ID annotation present in the service account. Service account has one to one mapping with the pod. To have a many-to-one relationship between multiple identities and a service account, multiple federated identity credentials can be created that references the same service account.

`azure.workload.identity/client-id` annotations contains the client ID of the identity that will be used.

To use a different client ID, the client ID should be updated but the limitation is that at a time only one identity can be used. 


#### <a name='Howtodistributekeys'></a>2. How to distribute key pair to management cluster?

This an open question to discuss to find a better way to distribute keys to the control plane node for the management cluster.


#### <a name='UserExperience'></a>3. User Experience

Though AZWI has a lot of advantages as compared to AZWI, setting up AZWI involves couple of manual step and it can impact the user experience. 

### <a name='MigrationPlan'></a>Migration Plan

Management clusters using AAD pod identity should have a seamless migration process which is well documented.

As part of upgrade that supports AZWI, the env variable can be set to true to use AZWI. 
But if capz uses AZWI, it can use only one identity at a time and it can pose challenges to migration if the management cluster is using different identity simultaneously from the AAD pod identity. 

### <a name='TestPlan'></a>Test Plan

* Unit tests to validate newer workload identity functions and helper functions.  
* Using AZWI for existing e2e tests for create, upgrade, scale down/up, and delete.

## <a name='ImplementationHistory'></a>Implementation History
TBD