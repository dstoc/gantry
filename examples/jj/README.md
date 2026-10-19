# jj policy example

This example returns a structured decision with `filesystem` and
`baffle_session` set to `null`. It requires the explicit Direct backend:

```sh
GANTRY_POLICY_DIR=/path/to/examples/jj/policy gantry --backend direct
```

Direct execution uses Gantry's host filesystem and network access. The example
does not provide Bubblewrap filesystem isolation. For Bubblewrap, create an
administrator-managed profile in the sibling `filesystems/` directory and
change allowed decisions to select that profile. See the filesystem profile
and structured decision examples in the main [README](../../README.md).
