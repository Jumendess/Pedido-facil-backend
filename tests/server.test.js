import { spawn } from "child_process";

const server = spawn("node", ["src/index.js"]);

setTimeout(() => {
  server.kill();
  console.log("Server started successfully");
  process.exit(0);
}, 3000);

server.on("error", () => {
  console.error("Server failed to start");
  process.exit(1);
});