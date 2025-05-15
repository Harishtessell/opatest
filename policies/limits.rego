package limits

default allow := false

allow if {
  input.amount == data.limits.value
}
