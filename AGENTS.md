When GitHub authentication or publishing fails inside the sandbox, retry outside the sandbox before reporting a blocker.
When BuildBuddy access fails inside the sandbox, retry `bb` outside the sandbox before treating authentication as unavailable.
Use `bb login -check` to verify authentication and `bb view <invocation-url>` to inspect CI logs; ask the user to run `bb login` when needed.
For physical-device provisioning and acceptance tests, inspect host resources outside the sandbox—including /dev, provisioning files, and configured tooling—requesting escalation when required.
Firmware logs go to the USB-Serial-JTAG CDC node (esp-println `jtag-serial`), so browse them by reading the board's `/dev/ttyACM*` directly — never `espflash monitor`, which uploads a flash stub and latches ROM download mode.
