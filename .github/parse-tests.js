const readline = require("readline");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

const summary = { fail: [], pass: [], skip: [] };

rl.on("line", (line) => {
  const output = JSON.parse(line);
  if (
    output.Action === "pass" ||
    output.Action === "skip" ||
    output.Action === "fail"
  ) {
    if (output.Test) {
      summary[output.Action].push(output);
    }
  }
});


rl.on("close", () => {
  console.log("## Summary");
  console.log("| | # of Tests |");
  console.log("|--|--|");
  console.log(
    "| ✅ Passed | %d |",
    summary.pass.length
  );
  console.log(
    "| ❌ Failed | %d |",
    summary.fail.length
  );
  console.log(
    "| 🚧 Skipped | %d |",
    summary.skip.length
  );

  if (summary.fail.length > 0) {
    console.log("\n## ❌ Failures\n");
  }

  summary.fail.forEach((test) => {
    console.log("* `%s` (%s)", test.Test, test.Package);
  });

  // also display skipped tests.
  if (summary.skip.length > 0) {
    console.log("\n## 🚧 Skipped\n");
  }

  summary.skip.forEach((test) => {
    console.log("* `%s` (%s)", test.Test, test.Package);
  });

});

