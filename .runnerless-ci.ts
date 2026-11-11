import {
  workflow, configuration, event, repo, packages, checks, jobs,
  OperationRequest, RegistryPublishRequest, ReleaseTrack,
} from "runnerless/v1";

// Every published crate is one release track: crates/<name>/{version.txt,CHANGELOG.md},
// tags <name>-vX.Y.Z, pre-1.0 bumps. See docs/releases.md.
const CRATES = ["wirefeather", "tailfeather", "tailfeather-gateway"];

function crate(name: string): ReleaseTrack {
  return ReleaseTrack.directory(name, "crates/" + name).bumpMinorPreMajor();
}

const program = workflow().releasePlease([
  crate("wirefeather"),
  // The browser, firmware and harness adapters ship with the core crate.
  crate("tailfeather").paths(["web/**", "firmware/**", "harness/**"]),
  // Never released on its own before; plan its first release from the shared floor.
  crate("tailfeather-gateway").bootstrap("tailfeather-v0.0.1", "0.0.1"),
]);

export function configure(): void {
  configuration.titlePolicy();
  program.configure();
  configuration.workflow("crate-publishing", ["workflow_run", "runnerless_completion"]);
}

export function run(): void {
  program.run();
  const delivery = event.delivery();
  if (delivery.isCompletion()) {
    for (let i = 0; i < CRATES.length; i++) {
      const job = jobs.find("publish-" + CRATES[i]);
      if (job.found) checks.report("crates-" + CRATES[i], job.succeeded(), "crates.io publication: " + job.describe());
    }
    return;
  }
  // release.yml packages a published GitHub Release and attaches the .cargo-upload.
  if (!delivery.workflowRunSucceeded(".github/workflows/release.yml")) return;
  const tag = delivery.headRef;
  for (let i = 0; i < CRATES.length; i++) {
    const name = CRATES[i];
    if (!tag.startsWith(name + "-v")) continue;
    // "head" is the completed build's immutable revision, never a moving main.
    const version = repo.readText("crates/" + name + "/version.txt", "head").trim();
    if (tag != name + "-v" + version || !packages.releasePublished(tag, version)) return;
    packages.crates(new OperationRequest("publish-" + name),
      new RegistryPublishRequest(tag, version).add(name, name + "-" + version + ".cargo-upload"));
    return;
  }
}
