#!/bin/bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd "$script_dir/../.." && pwd)"
temporary_dir="$(mktemp -d /tmp/latra-e2e.XXXXXX)"
fixture_cache="/tmp/latra/cache/fixture-sdk"
mock_pid=""

cleanup() {
  if [[ -n "$mock_pid" ]]; then
    kill "$mock_pid" 2>/dev/null || true
    wait "$mock_pid" 2>/dev/null || true
  fi
  rm -rf -- "$temporary_dir" "$fixture_cache"
}

finish() {
  status=$?
  trap - EXIT
  if [[ $status -ne 0 && -f "$temporary_dir/mock-store.log" ]]; then
    printf '\nMock SDK Store log:\n' >&2
    sed 's/^/  /' "$temporary_dir/mock-store.log" >&2
  fi
  cleanup
  exit "$status"
}

trap finish EXIT
trap 'exit 130' INT TERM

cd "$project_root"

if find testdata/e2e -type f -name '*.sdk' -print -quit | grep -q .; then
  echo "generated .sdk archives must not be stored under testdata/e2e" >&2
  exit 1
fi

rm -rf -- "$fixture_cache"
mkdir -p build
go build -trimpath -o build/latra ./cmd/latra

python3 testdata/e2e/mock_store.py \
  --port 0 \
  --ready-file "$temporary_dir/ready.json" \
  >"$temporary_dir/mock-store.log" 2>&1 &
mock_pid=$!

for _ in $(seq 1 100); do
  if [[ -s "$temporary_dir/ready.json" ]]; then
    break
  fi
  if ! kill -0 "$mock_pid" 2>/dev/null; then
    echo "mock SDK Store exited before becoming ready" >&2
    exit 1
  fi
  sleep 0.05
done

if [[ ! -s "$temporary_dir/ready.json" ]]; then
  echo "timed out waiting for mock SDK Store" >&2
  exit 1
fi

store_url="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["url"])' "$temporary_dir/ready.json")"
if [[ "$store_url" != http://127.0.0.1:* ]]; then
  echo "mock SDK Store URL is not loopback-only: $store_url" >&2
  exit 1
fi

python3 - "$store_url" <<'PY'
import json
import sys
import time
import urllib.request

url = sys.argv[1] + "/healthz"
for _ in range(100):
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            if response.status == 200 and json.load(response) == {"status": "ok"}:
                break
    except OSError:
        time.sleep(0.05)
else:
    raise SystemExit("mock SDK Store health check timed out")
PY

export SDK_STORE_URL="$store_url"
export NO_PROXY="127.0.0.1,localhost${NO_PROXY:+,$NO_PROXY}"
export no_proxy="$NO_PROXY"

./build/latra scan testdata/e2e/project \
  --format json \
  --verbose \
  --output "$temporary_dir/report.json"

python3 - "$temporary_dir/report.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as report_file:
    report = json.load(report_file)

assert report["schemaVersion"] == "4"
assert report["findingDatabase"]["schemaVersion"] == "4"
assert report["findingDatabase"]["contentVersion"] == "2026.11.11.4"
assert report["findingDatabase"]["source"] == "embedded-default"
assert report["input"]["kind"] == "project"
assert report["summary"]["sdks"] == {
    "count": 1,
    "sdkNames": {"resolved": ["fixture-sdk"], "unresolved": []},
    "resolved": 1,
    "unresolved": 0,
}
assert report["summary"]["unknownCommands"]["count"] == 0
assert report["summary"]["files"]["contentSkipped"] == 0
assert all(item["contentSkipped"] == 0 for item in report["summary"]["files"]["bySdk"])
assert report["summary"]["diagnostics"]["count"] == 0
assert report["summary"]["findings"]["count"] > 0
assessment = report["assessment"]
assert assessment["classification"] in {
    "expected-and-controlled",
    "powerful-but-controlled",
    "weakly-controlled",
    "high-priority-review",
    "insufficient-evidence",
}
assert 0 <= assessment["reviewPriority"]["score"] <= 100
assert 0 <= assessment["risk"]["score"] <= 100
assert 0 <= assessment["assurance"]["score"] <= 100
assert 0 <= assessment["coverage"]["score"] <= 100
assert assessment["coverage"]["files"]["contentSkipped"] == 0
assert len(assessment["bySdk"]) == 1
assert assessment["bySdk"][0]["sdk"] == "fixture-sdk"
assert "keyRisks" in assessment
assert "keyRisks" in assessment["bySdk"][0]
for highlight in assessment["keyRisks"]:
    assert highlight["id"].startswith("risk.")
    assert highlight["occurrences"] > 0
    assert 0 <= highlight["score"] <= 100
    assert highlight["scopes"]

assert len(report["sdks"]) == 1
sdk = report["sdks"][0]
assert sdk["name"] == "fixture-sdk"
assert sdk["source"] == "store"
assert sdk["state"] == "Resolved"
assert sdk["channel"] == "latest/stable"
assert sdk["metadata"]["version"] == "1.0"
assert sdk["findings"]
assert all(finding["evidence"] for finding in sdk["findings"])
assert sorted(hook["name"] for hook in sdk["hooks"]) == ["check-health", "setup-base"]
for hook in sdk["hooks"]:
    assert "relations" in hook
    pending_operations = list(hook["operations"])
    operation_ids = set()
    while pending_operations:
        operation = pending_operations.pop()
        operation_ids.add(operation["id"])
        pending_operations.extend(operation.get("children", []))
    for relation in hook["relations"]:
        assert relation["fromOperationId"] in operation_ids
        assert relation["toOperationId"] in operation_ids

capabilities = {
    capability["kind"]
    for hook in sdk["hooks"]
    for capability in hook["capabilities"]
}
assert {"network-access", "network-download", "privilege-modification"} <= capabilities

files = {item["path"]: item for item in sdk["files"]}
assert files["meta/sdk.yaml"]["contentEncoding"] == "utf-8"
assert files["meta/sdk.yaml"]["contentStatus"] == "analyzed"
assert "name: fixture-sdk" in files["meta/sdk.yaml"]["content"]
assert files["share/config.json"]["contentEncoding"] == "utf-8"
assert files["share/config.json"]["contentStatus"] == "analyzed"
assert report["diagnostics"] == []
PY

./build/latra hook fixture-sdk setup-base \
  --project testdata/e2e/project \
  >"$temporary_dir/setup-base"
grep -F 'curl -fsSL https://example.invalid/tool' "$temporary_dir/setup-base" >/dev/null

./build/latra file fixture-sdk meta/sdk.yaml \
  --project testdata/e2e/project \
  >"$temporary_dir/sdk.yaml"
grep -F 'name: fixture-sdk' "$temporary_dir/sdk.yaml" >/dev/null

./build/latra scan testdata/e2e/project \
  --format json \
  --output "$temporary_dir/second-report.json"

python3 - "$store_url" <<'PY'
import json
import sys
import urllib.request

with urllib.request.urlopen(sys.argv[1] + "/stats", timeout=2) as response:
    stats = json.load(response)

assert stats == {"resolveRequests": 2, "downloadRequests": 1}, stats
print(
    "mock SDK Store requests: "
    f"resolve={stats['resolveRequests']} download={stats['downloadRequests']}"
)
PY

echo "Latra SDK Store E2E passed"
