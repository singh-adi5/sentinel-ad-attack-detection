#!/usr/bin/env node
// Parse and analyse every detections/*/query.kql with Microsoft's Kusto language
// service. Fails on any syntax error or any reference to a column that is not in
// scripts/securityevent.schema. It does not run the query against a workspace.
"use strict";
require("@kusto/language-service-next/bridge.min.js");
require("@kusto/language-service-next/Kusto.Language.Bridge.min.js");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const columns = fs
  .readFileSync(path.join(__dirname, "securityevent.schema"), "utf8")
  .split("\n")
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith("#"));

const symbols = Kusto.Language.Symbols;
const table = new symbols.TableSymbol.$ctor7("SecurityEvent", `(${columns.join(", ")})`, null);
const database = new symbols.DatabaseSymbol.$ctor3("workspace", null, [table], false);
const globals = Kusto.Language.GlobalState.Default.WithDatabase(database);

const files = process.argv.slice(2);
if (files.length === 0) {
  const base = path.join(root, "detections");
  for (const dir of fs.readdirSync(base).sort()) {
    const candidate = path.join(base, dir, "query.kql");
    if (fs.existsSync(candidate)) files.push(candidate);
  }
}
if (files.length === 0) {
  console.error("FAIL no query.kql files found");
  process.exit(1);
}

let failures = 0;
for (const file of files) {
  const text = fs.readFileSync(file, "utf8");
  const diagnostics = Kusto.Language.KustoCode.ParseAndAnalyze(text, globals).GetDiagnostics();
  const label = path.relative(root, file);
  if (diagnostics.Count === 0) {
    console.log(`PASS ${label}`);
    continue;
  }
  failures += 1;
  console.log(`FAIL ${label}`);
  for (let i = 0; i < diagnostics.Count; i += 1) {
    const item = diagnostics.getItem(i);
    const line = text.slice(0, item.Start).split("\n").length;
    console.log(`  line ${line}: ${item.Message}`);
  }
}
process.exit(failures ? 1 : 0);
