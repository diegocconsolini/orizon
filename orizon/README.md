# Orizon - Module Structure

This directory contains all Orizon-specific code extensions to LiteLLM.

## Directory Structure

```
orizon/
├── auth/               # Authentication & Authorization
│   ├── middleware.py   # Request middleware (oauth2-proxy integration)
│   ├── utils.py        # Helper functions (header extraction)
│   ├── sessions.py     # Session management
│   ├── email.py        # Email service (magic link)
│   ├── oauth.py        # GitHub OAuth integration
│   └── routes.py       # Auth API endpoints
│
├── hierarchy/          # Department Tier (4th level)
│   ├── departments.py  # Department CRUD APIs
│   └── teams.py        # Extended team creation
│
├── budgets/            # Budget System Extensions
│   ├── alerts.py       # Soft/hard limit alerts
│   ├── overage.py      # Overage allowance logic
│   └── enforcement.py  # Configurable enforcement
│
├── analytics/          # Analytics & Privacy
│   ├── privacy.py      # Privacy level configuration
│   ├── archival.py     # Cold storage (local/Azure Blob)
│   └── attribution.py  # Multi-dimensional attribution
│
├── portal/             # Portal Integration
│   ├── websocket.py    # Real-time updates
│   └── integration.py  # Portal API
│
└── sdk/                # JavaScript SDK
    └── javascript/     # TypeScript SDK source
```

## Design Principles

1. **Extend, Don't Replace:** Orizon extends LiteLLM, doesn't replace it
2. **Hybrid Schema:** New features = new tables, extensions = modify existing
3. **Environment-Driven:** All configuration via environment variables
4. **Test Coverage:** 80%+ coverage required for all Orizon code

## Development

All Orizon modules are mounted read-only into the Docker container during development:

```yaml
volumes:
  - ./orizon:/app/orizon:ro
```

Changes to code require container restart to take effect.

## Testing

Tests are located in `/tests/orizon/` mirroring this structure:

```bash
# Run all Orizon tests
docker-compose -f docker-compose.test.yml up

# Run specific module tests
pytest tests/orizon/auth/
```

## Phase Status

- **Phase 0:** Foundation ✅
- **Phase 1:** Authentication (in progress)
- **Phase 2-9:** Pending
