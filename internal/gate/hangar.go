package gate

// Hangar vocabulary the gate's behaviour depends on, in one place for R-5 (which makes it configuration):

// DefaultOutsideGroups is the baseline's outside group: a Backstage group ref for the platform admins.
var DefaultOutsideGroups = []string{"group:default/admins"}

// DefaultOwnerFallback stands in as the owner group when neither the check nor Owners names one and the policy
// has no outside group (dispatch.register_change).
const DefaultOwnerFallback = "group:default/admins"
