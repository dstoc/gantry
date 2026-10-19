package sandbox.main

default decision := {
  "allow": false,
  "filesystem": null,
  "baffle_session": null,
}

decision := {
  "allow": true,
  "filesystem": null,
  "baffle_session": null,
} if {
  command_allowed
  env_allowed
}

command_allowed if {
  data.sandbox[input.command].allow
}

env_allowed if {
  count(object.keys(input.env)) == 0
}

env_allowed if {
  data.sandbox[input.command].allow_env
}
