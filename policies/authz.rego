package authz

default allow := false

allow if {
  input.user == "admin"
  input.action == "withdraw"
}
