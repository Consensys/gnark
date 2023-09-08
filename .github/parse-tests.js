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

function totalTime(entries) {
  return entries.reduce((total, l) => total + l.Elapsed, 0);
}

rl.on("close", () => {
  console.log("## Summary");
  console.log("| | # of Tests | Total Time |");
  console.log("|--|--|--|");
  console.log(
    "| Passed | %d | %fs |",
    summary.pass.length,
    totalTime(summary.pass)
  );
  console.log(
    "| Failed | %d | %fs |",
    summary.fail.length,
    totalTime(summary.fail)
  );
  console.log(
    "| Skipped | %d | %fs |",
    summary.skip.length,
    totalTime(summary.skip)
  );

  if (summary.fail.length > 0) {
    console.log("\n## Failures\n");
  }

  summary.fail.forEach((test) => {
    console.log("* %s (%s) %fs", test.Test, test.Package, test.Elapsed);
  });
});

