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

package roleassignments

import (
	"context"
	"fmt"

	"sigs.k8s.io/cluster-api-provider-azure/util/reconciler"

	"sigs.k8s.io/cluster-api-provider-azure/azure/services/async"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2021-04-01/compute"
	"github.com/pkg/errors"

	"sigs.k8s.io/cluster-api-provider-azure/azure"
	"sigs.k8s.io/cluster-api-provider-azure/azure/services/scalesets"
	"sigs.k8s.io/cluster-api-provider-azure/azure/services/virtualmachines"
	"sigs.k8s.io/cluster-api-provider-azure/util/tele"
)

const azureBuiltInContributorID = "b24988ac-6180-42a0-ab88-20f7382dd24c"
const serviceName = "roleassignments"

// RoleAssignmentScope defines the scope interface for a role assignment service.
type RoleAssignmentScope interface {
	azure.ClusterDescriber
	azure.AsyncStatusUpdater
	RoleAssignmentSpecs() []azure.ResourceSpecGetter
}

// Service provides operations on Azure resources.
type Service struct {
	Scope RoleAssignmentScope
	client
	async.Reconciler
	virtualMachinesClient        virtualmachines.Client
	virtualMachineScaleSetClient scalesets.Client
}

// New creates a new service.
func New(scope RoleAssignmentScope) *Service {
	client := newClient(scope)
	return &Service{
		Scope:                        scope,
		client:                       client,
		virtualMachinesClient:        virtualmachines.NewClient(scope),
		virtualMachineScaleSetClient: scalesets.NewClient(scope),
		Reconciler:                   async.New(scope, client, client),
	}
}

// Reconcile creates a role assignment.
func (s *Service) Reconcile(ctx context.Context) error {
	ctx, _, done := tele.StartSpanWithLogger(ctx, "roleassignments.Service.Reconcile")
	defer done()
	ctx, cancel := context.WithTimeout(ctx, reconciler.DefaultAzureServiceReconcileTimeout)
	defer cancel()

	for _, roleSpec := range s.Scope.RoleAssignmentSpecs() {
		rs := roleSpec.(*RoleAssignmentSpec)
		scope := fmt.Sprintf("/subscriptions/%s/", s.Scope.SubscriptionID())
		rs.Scope = scope
		contributorRoleDefinitionID := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", s.Scope.SubscriptionID(), azureBuiltInContributorID)
		rs.RoleDefinitionID = contributorRoleDefinitionID
		switch rs.ResourceType {
		case azure.VirtualMachine:
			return s.reconcileVM(ctx, rs)
		case azure.VirtualMachineScaleSet:
			return s.reconcileVMSS(ctx, rs)
		default:
			return errors.Errorf("unexpected resource type %q. Expected one of [%s, %s]", rs.ResourceType,
				azure.VirtualMachine, azure.VirtualMachineScaleSet)
		}
	}
	return nil
}

func (s *Service) reconcileVM(ctx context.Context, roleSpec *RoleAssignmentSpec) error {
	ctx, log, done := tele.StartSpanWithLogger(ctx, "roleassignments.Service.reconcileVM")
	defer done()
	spec := &virtualmachines.VMSpec{
		Name:          roleSpec.MachineName,
		ResourceGroup: s.Scope.ResourceGroup(),
	}

	resultVMIface, err := s.virtualMachinesClient.Get(ctx, spec)
	if err != nil {
		return errors.Wrap(err, "cannot get VM to assign role to system assigned identity")
	}
	resultVM, ok := resultVMIface.(compute.VirtualMachine)
	if !ok {
		return errors.Errorf("%T is not a compute.VirtualMachine", resultVMIface)
	}

	roleSpec.PrincipalID = resultVM.Identity.PrincipalID
	err = s.assignRole(ctx, roleSpec)
	if err != nil {
		return errors.Wrap(err, "cannot assign role to VM system assigned identity")
	}

	log.V(2).Info("successfully created role assignment for generated Identity for VM", "virtual machine", roleSpec.MachineName)

	return nil
}

func (s *Service) reconcileVMSS(ctx context.Context, roleSpec *RoleAssignmentSpec) error {
	ctx, log, done := tele.StartSpanWithLogger(ctx, "roleassignments.Service.reconcileVMSS")
	defer done()

	resultVMSS, err := s.virtualMachineScaleSetClient.Get(ctx, s.Scope.ResourceGroup(), roleSpec.MachineName)
	if err != nil {
		return errors.Wrap(err, "cannot get VMSS to assign role to system assigned identity")
	}
	roleSpec.PrincipalID = resultVMSS.Identity.PrincipalID
	err = s.assignRole(ctx, roleSpec)
	if err != nil {
		return errors.Wrap(err, "cannot assign role to VMSS system assigned identity")
	}

	log.V(2).Info("successfully created role assignment for generated Identity for VMSS", "virtual machine scale set", roleSpec.MachineName)

	return nil
}

func (s *Service) assignRole(ctx context.Context, roleSpec *RoleAssignmentSpec) error {
	ctx, _, done := tele.StartSpanWithLogger(ctx, "roleassignments.Service.assignRole")
	defer done()
	_, err := s.CreateResource(ctx, roleSpec, serviceName)
	return err
}

// Delete is a no-op as the role assignments get deleted as part of VM deletion.
func (s *Service) Delete(ctx context.Context) error {
	_, _, done := tele.StartSpanWithLogger(ctx, "roleassignments.Service.Delete")
	defer done()
	return nil
}
