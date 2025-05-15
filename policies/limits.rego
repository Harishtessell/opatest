package limits

default allow := false

allow if {
  input.amount == 100
}
