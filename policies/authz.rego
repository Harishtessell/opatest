package authz

default allow := false

allow if {
  input.payload.user == "admin"
  input.payload.action == "withdraw"
}
