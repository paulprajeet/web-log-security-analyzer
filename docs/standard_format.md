# Standard Normalized Log Format 📋

**ALL input formats get converted to this structure:**

## NormalizedLogEntry Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `ip` | str | Client IP address | `192.168.0.40` |
| `timestamp` | str | ISO 8601 format | `2021-06-25T23:24:01.000Z` |
| `method` | str | HTTP method | `GET`, `POST` |
| `path` | str | Request path | `/`, `/login`, `/api/factory/status` |
| `status_code` | int | HTTP status | `401`, `200` |
| `status_text` | str | Status description | `UNAUTHORIZED`, `SUCCESS` |
| `user_id` | str/null | Authorized user | `52Mr1nEo2VAXZ8zMtzdTK6` or `null` |

## Sample Normalized Output
