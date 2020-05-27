package uam2.policy

## Headers is added to pass any additional data as part of entitlement query within the input node
headers := input.headers

default allow = false

allow {

	data.uam2.entitlements["user2EntitlementIds"][input.user][_] == data.uam2.entitlements["entitlement2Id"][input.resource]

# data.uam2.entitlements["entGroup2LdapGroups"][data.uam2.entitlements["resource2EntGroup"]["com.anz.csp.partyservice.read"][_]][_] == data.uam2.groups["user2LdapGroups"]["sbosadmin"][_]
}
