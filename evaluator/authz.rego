package authz

default allow := false

allow if {
  input.user == "admin"
}
