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
	"fmt"

	"github.com/Azure/azure-sdk-for-go/profiles/2019-03-01/authorization/mgmt/authorization"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/pkg/errors"
)

// RoleAssignmentSpec defines the specification for a Role Assignment.
type RoleAssignmentSpec struct {
	RoleAssignmentName string
	ResourceGroup      string
	MachineName        string
	Name               string
	ResourceType       string
	SubscriptionID     string
	PrincipalID        *string
	RoleDefinitionID   string
	Scope              string
}

// ResourceName returns the name of the role assignment.
func (s *RoleAssignmentSpec) ResourceName() string {
	return s.RoleAssignmentName
}

// ResourceGroupName returns the name of the resource group.
func (s *RoleAssignmentSpec) ResourceGroupName() string {
	return s.ResourceGroup
}

// OwnerResourceName is a no-op for role assignment.
func (s *RoleAssignmentSpec) OwnerResourceName() string {
	return ""
}

// Parameters returns the parameters for the RoleAssignmentSpec.
func (s *RoleAssignmentSpec) Parameters(existing interface{}) (interface{}, error) {
	if existing != nil {
		if _, ok := existing.(authorization.RoleAssignment); !ok {
			return nil, errors.Errorf("%T is not a authorization.RoleAssignment", existing)
		}
		// RoleAssignmentSpec already exists
		return nil, nil
	}
	scope := fmt.Sprintf("/subscriptions/%s/", s.SubscriptionID)
	// Azure built-in roles https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
	contributorRoleDefinitionID := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions/%s", s.SubscriptionID, azureBuiltInContributorID)
	return &authorization.RoleAssignmentPropertiesWithScope{
		Scope:            to.StringPtr(scope),
		RoleDefinitionID: to.StringPtr(contributorRoleDefinitionID),
		PrincipalID:      s.PrincipalID,
	}, nil
}
