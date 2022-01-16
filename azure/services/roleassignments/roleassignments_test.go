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
	"net/http"
	"testing"

	"sigs.k8s.io/cluster-api-provider-azure/azure/services/scalesets/mock_scalesets"

	"github.com/Azure/go-autorest/autorest"

	"github.com/Azure/go-autorest/autorest/to"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2021-04-01/compute"

	"sigs.k8s.io/cluster-api-provider-azure/azure/services/virtualmachines/mock_virtualmachines"

	"sigs.k8s.io/cluster-api-provider-azure/azure"

	gomockinternal "sigs.k8s.io/cluster-api-provider-azure/internal/test/matchers/gomock"

	"sigs.k8s.io/cluster-api-provider-azure/azure/services/async/mock_async"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/cluster-api-provider-azure/azure/services/roleassignments/mock_roleassignments"
	"sigs.k8s.io/cluster-api-provider-azure/azure/services/virtualmachines"
)

var (
	fakeVMSpec = virtualmachines.VMSpec{
		Name:          "test-vm",
		ResourceGroup: "my-rg",
	}

	fakeRoleAssignment1 = RoleAssignmentSpec{
		MachineName:   "test-vm",
		ResourceGroup: "my-rg",
		ResourceType:  azure.VirtualMachine,
	}
	fakeRoleAssignment2 = RoleAssignmentSpec{
		MachineName:   "test-vmss",
		ResourceGroup: "my-rg",
		ResourceType:  azure.VirtualMachineScaleSet,
	}
	fakeRoleAssignmentSpecs = []azure.ResourceSpecGetter{&fakeRoleAssignment1, &fakeRoleAssignment2}
)

func TestReconcileRoleAssignmentsVM(t *testing.T) {
	testcases := []struct {
		name   string
		expect func(s *mock_roleassignments.MockRoleAssignmentScopeMockRecorder, r *mock_async.MockReconcilerMockRecorder,
			mvm *mock_virtualmachines.MockClientMockRecorder)
		expectedError string
	}{
		{
			name:          "create a role assignment",
			expectedError: "",
			expect: func(s *mock_roleassignments.MockRoleAssignmentScopeMockRecorder,
				r *mock_async.MockReconcilerMockRecorder,
				mvm *mock_virtualmachines.MockClientMockRecorder) {
				s.RoleAssignmentSpecs().Return(fakeRoleAssignmentSpecs[:1])
				s.SubscriptionID().AnyTimes().Return("fake-id")
				s.ResourceGroup().Return("my-rg")
				mvm.Get(gomockinternal.AContext(), &fakeVMSpec).Return(compute.VirtualMachine{
					Identity: &compute.VirtualMachineIdentity{
						PrincipalID: to.StringPtr("000"),
					},
				}, nil)
				r.CreateResource(gomockinternal.AContext(), &fakeRoleAssignment1, serviceName).Return(&fakeRoleAssignment1, nil)
			},
		},
		{
			name:          "error getting VM",
			expectedError: "cannot get VM to assign role to system assigned identity: #: Internal Server Error: StatusCode=500",
			expect: func(s *mock_roleassignments.MockRoleAssignmentScopeMockRecorder,
				r *mock_async.MockReconcilerMockRecorder,
				mvm *mock_virtualmachines.MockClientMockRecorder) {
				s.SubscriptionID().AnyTimes().Return("fake-id")
				s.ResourceGroup().Return("my-rg")
				s.RoleAssignmentSpecs().Return(fakeRoleAssignmentSpecs[:1])
				mvm.Get(gomockinternal.AContext(), &fakeVMSpec).Return(compute.VirtualMachine{},
					autorest.NewErrorWithResponse("", "", &http.Response{StatusCode: 500}, "Internal Server Error"))
			},
		},
		{
			name:          "return error when creating a role assignment",
			expectedError: "cannot assign role to VM system assigned identity: #: Internal Server Error: StatusCode=500",
			expect: func(s *mock_roleassignments.MockRoleAssignmentScopeMockRecorder,
				r *mock_async.MockReconcilerMockRecorder,
				mvm *mock_virtualmachines.MockClientMockRecorder) {
				s.SubscriptionID().AnyTimes().Return("fake-id")
				s.ResourceGroup().Return("my-rg")
				s.RoleAssignmentSpecs().Return(fakeRoleAssignmentSpecs[:1])
				mvm.Get(gomockinternal.AContext(), &fakeVMSpec).Return(compute.VirtualMachine{
					Identity: &compute.VirtualMachineIdentity{
						PrincipalID: to.StringPtr("000"),
					},
				}, nil)
				r.CreateResource(gomockinternal.AContext(), &fakeRoleAssignment1, serviceName).Return(&RoleAssignmentSpec{},
					autorest.NewErrorWithResponse("", "", &http.Response{StatusCode: 500}, "Internal Server Error"))
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			t.Parallel()
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			scopeMock := mock_roleassignments.NewMockRoleAssignmentScope(mockCtrl)
			asyncMock := mock_async.NewMockReconciler(mockCtrl)
			vmMock := mock_virtualmachines.NewMockClient(mockCtrl)

			tc.expect(scopeMock.EXPECT(), asyncMock.EXPECT(), vmMock.EXPECT())

			s := &Service{
				Scope:                 scopeMock,
				Reconciler:            asyncMock,
				virtualMachinesClient: vmMock,
			}

			err := s.Reconcile(context.TODO())
			if tc.expectedError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err).To(MatchError(tc.expectedError))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
			}
		})
	}
}

func TestReconcileRoleAssignmentsVMSS(t *testing.T) {
	testcases := []struct {
		name   string
		expect func(s *mock_roleassignments.MockRoleAssignmentScopeMockRecorder, r *mock_async.MockReconcilerMockRecorder,
			mvmss *mock_scalesets.MockClientMockRecorder)
		expectedError string
	}{
		{
			name:          "create a role assignment",
			expectedError: "",
			expect: func(s *mock_roleassignments.MockRoleAssignmentScopeMockRecorder,
				r *mock_async.MockReconcilerMockRecorder,
				mvmss *mock_scalesets.MockClientMockRecorder) {
				s.SubscriptionID().AnyTimes().Return("fake-id")
				s.ResourceGroup().Return("my-rg")
				s.RoleAssignmentSpecs().Return(fakeRoleAssignmentSpecs[1:2])
				mvmss.Get(gomockinternal.AContext(), "my-rg", "test-vmss").Return(compute.VirtualMachineScaleSet{
					Identity: &compute.VirtualMachineScaleSetIdentity{
						PrincipalID: to.StringPtr("000"),
					},
				}, nil)
				r.CreateResource(gomockinternal.AContext(), &fakeRoleAssignment2, serviceName).Return(&fakeRoleAssignment2, nil)
			},
		},
		{
			name:          "error getting VMSS",
			expectedError: "cannot get VMSS to assign role to system assigned identity: #: Internal Server Error: StatusCode=500",
			expect: func(s *mock_roleassignments.MockRoleAssignmentScopeMockRecorder,
				r *mock_async.MockReconcilerMockRecorder,
				mvmss *mock_scalesets.MockClientMockRecorder) {
				s.SubscriptionID().AnyTimes().Return("fake-id")
				s.ResourceGroup().Return("my-rg")
				s.RoleAssignmentSpecs().Return(fakeRoleAssignmentSpecs[1:2])
				mvmss.Get(gomockinternal.AContext(), "my-rg", "test-vmss").Return(compute.VirtualMachineScaleSet{},
					autorest.NewErrorWithResponse("", "", &http.Response{StatusCode: 500}, "Internal Server Error"))
			},
		},
		{
			name:          "return error when creating a role assignment",
			expectedError: "cannot assign role to VMSS system assigned identity: #: Internal Server Error: StatusCode=500",
			expect: func(s *mock_roleassignments.MockRoleAssignmentScopeMockRecorder,
				r *mock_async.MockReconcilerMockRecorder,
				mvmss *mock_scalesets.MockClientMockRecorder) {
				s.SubscriptionID().AnyTimes().Return("fake-id")
				s.ResourceGroup().Return("my-rg")
				s.RoleAssignmentSpecs().Return(fakeRoleAssignmentSpecs[1:2])
				mvmss.Get(gomockinternal.AContext(), "my-rg", "test-vmss").Return(compute.VirtualMachineScaleSet{
					Identity: &compute.VirtualMachineScaleSetIdentity{
						PrincipalID: to.StringPtr("000"),
					},
				}, nil)
				r.CreateResource(gomockinternal.AContext(), &fakeRoleAssignment2, serviceName).Return(&RoleAssignmentSpec{},
					autorest.NewErrorWithResponse("", "", &http.Response{StatusCode: 500}, "Internal Server Error"))
			},
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			t.Parallel()
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()
			scopeMock := mock_roleassignments.NewMockRoleAssignmentScope(mockCtrl)
			asyncMock := mock_async.NewMockReconciler(mockCtrl)
			vmMock := mock_scalesets.NewMockClient(mockCtrl)

			tc.expect(scopeMock.EXPECT(), asyncMock.EXPECT(), vmMock.EXPECT())

			s := &Service{
				Scope:                        scopeMock,
				Reconciler:                   asyncMock,
				virtualMachineScaleSetClient: vmMock,
			}

			err := s.Reconcile(context.TODO())
			if tc.expectedError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err).To(MatchError(tc.expectedError))
			} else {
				g.Expect(err).NotTo(HaveOccurred())
			}
		})
	}
}
