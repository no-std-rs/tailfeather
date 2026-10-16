import {
  workflow, configuration, event, repo, packages, checks, jobs,
  OperationRef, OperationRequest, RegistryPublishRequest, WriteResult,
} from "runnerless/v1";

const program = workflow().releasePlease();
const crates = ["wirefeather", "tailfeather", "tailfeather-gateway"];

export function configure(): void {
  program.configure();
  configuration.workflow("crate-publishing", ["workflow_run", "runnerless_completion"]);
}

export function run(): void {
  program.run();
  const details = event.details();
  const name = details.get("event").string();
  if (name == "runnerless_completion") {
    for (let i = 0; i < crates.length; i++) {
      const crate = crates[i];
      const result = jobs.lookup<WriteResult>(new OperationRef<WriteResult>("op:publish-" + crate));
      if (!result.ok) continue;
      const value = result.value;
      checks.report("crates-" + crate,
        value.get("status").string() == "succeeded"
          && value.get("value").get("failed").json == "false",
        "crates.io publication: " + value.get("status").string()
          + " " + value.get("value").get("error").string());
    }
    return;
  }
  if (name != "workflow_run"
    || details.get("action").string() != "completed"
    || details.get("workflowPath").string() != ".github/workflows/release.yml"
    || details.get("conclusion").string() != "success") return;
  const tag = details.get("headRef").string();
  for (let i = 0; i < crates.length; i++) {
    const crate = crates[i];
    if (!tag.startsWith(crate + "-v")) continue;
    // "head" is the completed build's immutable revision, never a moving main.
    const version = repo.readText("crates/" + crate + "/version.txt", "head").trim();
    if (tag != crate + "-v" + version || !packages.releasePublished(tag, version)) return;
    packages.crates(new OperationRequest("publish-" + crate),
      new RegistryPublishRequest(tag, version).add(crate, crate + "-" + version + ".cargo-upload"));
    return;
  }
}
