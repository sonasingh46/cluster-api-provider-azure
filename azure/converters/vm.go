/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package converters

import (
	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2021-04-01/compute"
	"github.com/Azure/go-autorest/autorest/to"
	corev1 "k8s.io/api/core/v1"
	infrav1 "sigs.k8s.io/cluster-api-provider-azure/api/v1beta1"
)

// VM describes an Azure virtual machine.
type VM struct {
	ID               string `json:"id,omitempty"`
	Name             string `json:"name,omitempty"`
	AvailabilityZone string `json:"availabilityZone,omitempty"`
	// Hardware profile
	VMSize string `json:"vmSize,omitempty"`
	// Storage profile
	Image         infrav1.Image  `json:"image,omitempty"`
	OSDisk        infrav1.OSDisk `json:"osDisk,omitempty"`
	StartupScript string         `json:"startupScript,omitempty"`
	// State - The provisioning state, which only appears in the response.
	State    infrav1.ProvisioningState `json:"vmState,omitempty"`
	Identity infrav1.VMIdentity        `json:"identity,omitempty"`
	Tags     infrav1.Tags              `json:"tags,omitempty"`

	// Addresses contains the addresses associated with the Azure VM.
	Addresses []corev1.NodeAddress `json:"addresses,omitempty"`
}

// SDKToVM converts an Azure SDK VirtualMachine to the CAPZ VM type.
func SDKToVM(v compute.VirtualMachine) *VM {
	vm := &VM{
		ID:    to.String(v.ID),
		Name:  to.String(v.Name),
		State: infrav1.ProvisioningState(to.String(v.ProvisioningState)),
	}

	if v.VirtualMachineProperties != nil && v.VirtualMachineProperties.HardwareProfile != nil {
		vm.VMSize = string(v.VirtualMachineProperties.HardwareProfile.VMSize)
	}

	if v.Zones != nil && len(*v.Zones) > 0 {
		vm.AvailabilityZone = to.StringSlice(v.Zones)[0]
	}

	if len(v.Tags) > 0 {
		vm.Tags = MapToTags(v.Tags)
	}

	return vm
}
