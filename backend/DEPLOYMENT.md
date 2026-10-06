# Deployment notes

## Client IP resolution (task 001)

Click Shield creates Google Ads IP exclusions for the client IP it records, so that IP must not be spoofable.

- **`TRUSTED_PROXY_CIDRS`** — comma-separated CIDRs of *our own* reverse proxies / load balancers, e.g. `10.0.0.0/8` or the provider's published LB ranges.
  - Empty (the default) means trust nobody: `X-Forwarded-For` is ignored and the socket peer address is used. This is correct when uvicorn is reached directly (local development).
  - When the direct peer is inside one of these networks, the client IP is the **rightmost** `X-Forwarded-For` entry that is not itself a trusted proxy.
  - An invalid CIDR stops the app at startup.
- **Run uvicorn with `--no-proxy-headers`.** Uvicorn's own proxy-header handling is on by default and trusts `127.0.0.1`. It would rewrite the client address from `X-Forwarded-For` before Click Shield sees the request, which bypasses `TRUSTED_PROXY_CIDRS`:

  ```bash
  uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-proxy-headers
  ```

- **Before enabling protection behind a new proxy:** check that `sessions.ip_address` shows many distinct values, not only the proxy's IP. A wrong trusted list makes every visitor look like one IP, and velocity/reputation rules will spike.
