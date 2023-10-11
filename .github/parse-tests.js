const readline = require('readline');

// Create readline interface
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

let content = '';

// Read stdin content
rl.on('line', (line) => {
  content += line + '\n';
});

rl.on('close', () => {
  // Escape special characters
  const escapedContent = content.replace(/`/g, '\\`').replace(/"/g, '\\"').replace(/\n/g, '\\n');

  // Convert the JSON object to a string
  // const jsonStr = JSON.stringify(escapedContent);

  console.log(escapedContent);
});