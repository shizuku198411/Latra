# SDK Store E2E fixtures

`mock_store.py` implements the SDK Store endpoints required by Latra's end-to-end tests. It generates a deterministic Zstandard-compressed `.sdk` archive from `store-sdk/` each time it starts; no generated archive is stored in the repository.

The server binds only to a loopback address. With `--port 0`, the operating system selects an available port and the selected URL is written to `--ready-file`.

```bash
python3 testdata/e2e/mock_store.py \
  --port 0 \
  --ready-file /tmp/latra-e2e-ready.json
```

Set `SDK_STORE_URL` to the `url` value in the ready file before scanning `testdata/e2e/project`.

Run the complete black-box test through the Workshop action:

```bash
workshop run dev -- e2e
```

The action builds `build/latra`, starts the mock Store, validates a verbose JSON report, exercises `hook` and `file`, and confirms that a second scan resolves twice but downloads the archive only once.

Available endpoints:

- `GET /healthz`
- `GET /stats`
- `POST /v2/revisions/resolve`
- `GET /api/v1/sdks/download/latra-e2e-fixture_42.sdk`
