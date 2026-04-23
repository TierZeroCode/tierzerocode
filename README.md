![Tier Zero C.O.D.E Logo](https://hersheys.tierzerocode.com/static/login_app/img/Tier%20Zero%20CO.D.E-logos_black.png)
# Tier Zero C.O.D.E (Tier Zero Correlation of Distributed Endpoints)

Tier Zero C.O.D.E is an enterprise security dashboard that correlates endpoint and identity data from multiple distributed security platforms into a unified compliance view. It aggregates users, devices, authentication posture, password policies, and security controls across your entire vendor stack — giving IT and security teams a single pane of glass for daily operations and executive reporting.

## Key Features

- **Unified Device Inventory** — Correlate device records from up to 8 security vendors into a single master list with compliance status per OS platform
- **Identity & Authentication Posture** — Track MFA capability, passwordless adoption, SSPR, and authentication method coverage across all Entra ID users
- **Active Directory Integration** — Sync on-premises AD users and Fine-Grained Password Policies (FGPP) via LDAPS; correlates with Entra ID hybrid accounts
- **Password Policy Management** — Unified view of password policies from both Microsoft Entra ID (per verified domain) and on-prem Active Directory FGPP
- **Security Controls** — Define, evaluate, and track security controls against configurable targets; supports automated evaluators and manual overrides
- **Conditional Access Visibility** — Sync and display all Entra ID Conditional Access policies with grant/session control details
- **Sign-In Analytics** — CA+MFA coverage analysis from Entra ID sign-in logs
- **Persona-Based User Grouping** — Map users to business personas via Entra ID group membership for targeted reporting
- **Compliance Scoring** — Per-OS compliance evaluation against configurable thresholds for each security vendor
- **Audit Logging** — Full audit trail of all sync operations and administrative actions

## Repository Stats

<a href="https://github.com/andrewixl/tierzerocode/blob/master/LICENSE"><img alt="GitHub license" src="https://img.shields.io/github/license/andrewixl/tierzerocode"></a>
<img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/andrewixl/tierzerocode">
<a href="https://github.com/andrewixl/tierzerocode/issues"><img alt="GitHub issues" src="https://img.shields.io/github/issues/andrewixl/tierzerocode"></a>
<a href="https://hub.docker.com/r/andrewixl/tierzerocode"><img alt="Docker pulls" src="https://img.shields.io/docker/pulls/andrewixl/tierzerocode"></a>

## Repository Technologies

<img alt="Python" src="https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white"> <img alt="Django" src="https://img.shields.io/badge/Django-6.0-green?logo=django&logoColor=white"> <img alt="PostgreSQL" src="https://img.shields.io/badge/PostgreSQL-17-blue?logo=postgresql&logoColor=white"> <img alt="Redis" src="https://img.shields.io/badge/Redis-7-red?logo=redis&logoColor=white"> <img alt="Docker" src="https://img.shields.io/badge/Docker-Alpine-blue?logo=docker&logoColor=white">

## Minimum Requirements
- 2 CPU Cores
- 4 GB RAM
- 32 GB SSD

## Recommended Requirements
- 4 CPU Cores
- 8 GB RAM
- 64 GB SSD

## Prerequisites

Before you begin, ensure you have the following installed:
- **Docker** (version 20.10 or later)
- **Docker Compose** (version 2.0 or later)
- Network access to your security platform APIs (Microsoft Entra ID, CrowdStrike, etc.)

---

## Getting Started

Docker Install: Latest
```bash
andrewixl/tierzerocode:latest
```

Docker Install: Dev
```bash
andrewixl/tierzerocode:latest-dev
```

## Production Deployment with Docker Compose

### Full Stack (Web + Worker + Database + Redis)

1. Create a `docker-compose.yml` file:
```yaml
services:
  web:
    image: docker.io/andrewixl/tierzerocode:latest
    ports:
      - "${WEB_PORT:-8000}:8000"
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - DEBUG=${DEBUG:-False}
      - DJANGO_ALLOWED_HOSTS=${DJANGO_ALLOWED_HOSTS:-localhost,127.0.0.1}
      - DATABASE_HOST=db
      - DATABASE_NAME=${DATABASE_NAME:-dockerdjango}
      - DATABASE_USER=${DATABASE_USER:-dbuser}
      - DATABASE_PASSWORD=${DATABASE_PASSWORD:-dbpassword}
      - DATABASE_PORT=${DATABASE_PORT:-5432}
      - DATABASE_ENGINE=${DATABASE_ENGINE:-postgresql_psycopg2}
      - REDIS_HOST=redis
      - REDIS_PORT=${REDIS_PORT:-6379}
      - REDIS_DB=${REDIS_DB:-0}
    depends_on:
      - db
      - redis
    restart: unless-stopped
    command: python -m gunicorn --bind 0.0.0.0:8000 --workers ${GUNICORN_WORKERS:-3} tierzerocode.wsgi:application

  worker:
    image: docker.io/andrewixl/tierzerocode:latest
    environment:
      - SECRET_KEY=${SECRET_KEY}
      - DEBUG=${DEBUG:-False}
      - DJANGO_ALLOWED_HOSTS=${DJANGO_ALLOWED_HOSTS:-localhost,127.0.0.1}
      - DATABASE_HOST=db
      - DATABASE_NAME=${DATABASE_NAME:-dockerdjango}
      - DATABASE_USER=${DATABASE_USER:-dbuser}
      - DATABASE_PASSWORD=${DATABASE_PASSWORD:-dbpassword}
      - DATABASE_PORT=${DATABASE_PORT:-5432}
      - DATABASE_ENGINE=${DATABASE_ENGINE:-postgresql_psycopg2}
      - REDIS_HOST=redis
      - REDIS_PORT=${REDIS_PORT:-6379}
      - REDIS_DB=${REDIS_DB:-0}
    depends_on:
      - db
      - redis
    restart: unless-stopped
    command: python manage.py rqworker default --job-class django_tasks_rq.Job --with-scheduler

  db:
    image: postgres:17-bookworm
    environment:
      - POSTGRES_DB=${DATABASE_NAME:-dockerdjango}
      - POSTGRES_USER=${DATABASE_USER:-dbuser}
      - POSTGRES_PASSWORD=${DATABASE_PASSWORD:-dbpassword}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes

volumes:
  postgres_data:
  redis_data:
```

2. Create a `.env` file:
```bash
SECRET_KEY=your-secret-key-here   # Generate: openssl rand -base64 32
DEBUG=False
DJANGO_ALLOWED_HOSTS=ipaddress,yourdomain.com
DATABASE_NAME=dockerdjango
DATABASE_USER=dbuser
DATABASE_PASSWORD=dbpassword
GUNICORN_WORKERS=3
WEB_PORT=8000
USE_HTTPS=False
```

3. Pull and start:
```bash
sudo docker compose pull
sudo docker compose up -d
```

4. Run migrations:
```bash
sudo docker compose exec web python manage.py migrate
```

5. Create a superuser (first run):
```bash
sudo docker compose exec web python manage.py createsuperuser
```

6. Open `http://ipaddress:8000` and log in.

### Environment Variables

#### Django
| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | — | Django secret key (required) |
| `DEBUG` | `False` | Enable debug mode |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1` | Comma-separated allowed hosts |
| `USE_HTTPS` | `False` | Set `True` behind an SSL-terminating proxy |

#### Database
| Variable | Default | Description |
|---|---|---|
| `DATABASE_HOST` | `db` | PostgreSQL host |
| `DATABASE_NAME` | `dockerdjango` | Database name |
| `DATABASE_USER` | `dbuser` | Database user |
| `DATABASE_PASSWORD` | `dbpassword` | Database password |
| `DATABASE_PORT` | `5432` | Database port |

#### Redis
| Variable | Default | Description |
|---|---|---|
| `REDIS_HOST` | `redis` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_DB` | `0` | Redis database index |

#### Performance
| Variable | Default | Description |
|---|---|---|
| `GUNICORN_WORKERS` | `3` | Gunicorn worker count |
| `WEB_PORT` | `8000` | Exposed web port |

### Managing Services

```bash
sudo docker compose logs -f web       # Web logs
sudo docker compose logs -f worker    # Worker logs
sudo docker compose down              # Stop all services
sudo docker compose restart web       # Restart web
```

---

## Supported Integrations

### Device Integrations
| Integration | Data Collected |
|---|---|
| Microsoft Entra ID | Device inventory, compliance state, join type |
| Microsoft Intune | MDM enrollment, compliance policy status |
| Microsoft Defender for Endpoint | Sensor health, onboarding status |
| CrowdStrike Falcon | Agent version, prevention policy, sensor status |
| Sophos Central | Endpoint protection, tamper status |
| Qualys | Vulnerability scan assets (up to 1,000 devices) |
| Cloudflare Zero Trust | WARP client enrollment, device posture |
| Tailscale | Node enrollment, key expiry, connection status |

### User / Identity Integrations
| Integration | Data Collected |
|---|---|
| Microsoft Entra ID | Users, auth methods, MFA/SSPR posture, CA policies, sign-in logs, password policy, tenant security config |
| Active Directory (on-prem) | User accounts, password last set, Fine-Grained Password Policies (FGPP) |

---

## Required Permissions per Integration

### Microsoft Entra ID — User Integration
App registration with the following **Application** permissions on Microsoft Graph:

| Permission | Purpose |
|---|---|
| `User.Read.All` | User list and profile data |
| `UserAuthenticationMethod.Read.All` | MFA and auth method registration per user |
| `AuditLog.Read.All` | Sign-in logs for CA+MFA coverage analysis |
| `Policy.Read.All` | Conditional Access policies, auth methods policy, SSPR config |
| `Directory.Read.All` | Tenant details, organization info, directory settings, password protection config |
| `Domain.Read.All` | Password policy per verified domain (validity period, notification window) |

### Microsoft Entra ID — Device Integration
| Permission | Purpose |
|---|---|
| `Device.Read.All` | Entra ID device inventory |

### Microsoft Intune — Device Integration
| Permission | Purpose |
|---|---|
| `DeviceManagementManagedDevices.Read.All` | MDM-enrolled device list and compliance state |

### Microsoft Defender for Endpoint — Device Integration
| Permission | Purpose |
|---|---|
| `Machine.Read.All` (WindowsDefenderATP) | Device inventory and sensor health |

### CrowdStrike Falcon — Device Integration
| Permission | Purpose |
|---|---|
| Hosts — Read | Device inventory and agent state |

### Sophos Central — Device Integration
| Permission | Purpose |
|---|---|
| Service Principal — Partner/Service Management Role | Endpoint inventory and protection status |

### Qualys — Device Integration
| Permission | Purpose |
|---|---|
| API user with asset read access | Asset inventory (Host List API) |

### Cloudflare Zero Trust — Device Integration
| Permission | Purpose |
|---|---|
| API Token — Zero Trust Read | WARP-enrolled device list and posture |

### Tailscale — Device Integration
| Permission | Purpose |
|---|---|
| API access key (read-only, tailnet scoped) | Node list and connection status |

### Active Directory — User Integration (on-premises)

Requires a **dedicated service account** with the following rights:

#### Service Account Setup
- Create a standard domain user account (e.g. `svc_tierzerocode`)
- The account does **not** need Domain Admin or any elevated role
- All sync operations are **read-only** — no write permissions are granted or used

#### Required Permissions
| Object | Permission | Purpose |
|---|---|---|
| Domain root (and subtree) | Read, List Contents | Enumerate users and their attributes |
| `CN=Password Settings Container,CN=System,DC=...,DC=...` | Read, List Contents | Read Fine-Grained Password Policies (FGPP) |

#### Granting PSO Container Access (PowerShell — run on a DC)
```powershell
$serviceAccount = "DOMAIN\svc_tierzerocode"
$psContainer    = "CN=Password Settings Container,CN=System,DC=yourdomain,DC=com"

# Grant Read on the container and all child PSO objects
dsacls $psContainer /G "$($serviceAccount):GR" /I:T
```

Or via ADUC (GUI):
1. **View → Advanced Features**
2. Browse to `System → Password Settings Container`
3. Right-click → **Properties → Security**
4. Add the service account → grant **Read** and **List Contents**

#### Connection Settings
| Field | Value |
|---|---|
| LDAP Server | IP or FQDN of a domain controller |
| Port | `636` (LDAPS, recommended) or `389` (LDAP) |
| Use SSL | `True` for LDAPS (port 636) |
| Base DN | `DC=yourdomain,DC=com` |
| Service Account DN | `svc_tierzerocode@yourdomain.com` (UPN) or full DN |
| Service Account Password | Account password |

> **Note:** The service account DN must be in UPN format (`user@domain.com`), down-level format (`DOMAIN\user`), or full distinguished name (`CN=user,OU=...,DC=...`). Bare sAMAccountName (`username` only) is not supported with LDAP simple bind.

---

## Troubleshooting

### Common Issues

**Database connection errors:**
- Ensure PostgreSQL is running: `sudo docker compose ps`
- Check credentials in `.env`
- Verify network connectivity between containers

**Redis connection errors:**
- Ensure Redis is running: `sudo docker compose ps`
- Check Redis config in `.env`

**Static files not loading:**
```bash
sudo docker compose exec web python manage.py collectstatic --noinput
```

**Worker not processing jobs:**
- Check worker logs: `sudo docker compose logs -f worker`
- Ensure Redis is reachable from the worker container

**Port already in use:**
- Change `WEB_PORT` in `.env` to an available port

**Active Directory sync — LDAP bind failed (invalidCredentials):**
- Ensure the Service Account DN is in UPN (`user@domain.com`) or full DN format, not bare username
- Re-enter the password in the integration modal and save

**Active Directory sync — PSOs synced: 0:**
- The service account likely lacks read access to `CN=Password Settings Container,CN=System,DC=...,DC=...`
- Grant Read/List Contents using the `dsacls` command above

**Microsoft Entra ID sync — permission errors:**
- Verify all required Application permissions are granted and admin-consented in the app registration
- `Domain.Read.All` is required for password policy sync; `Policy.Read.All` for CA policies and SSPR

### Getting Help

1. Check [GitHub Issues](https://github.com/andrewixl/tierzerocode/issues) for similar problems
2. Review container logs: `sudo docker compose logs -f [service-name]`
3. Open a new issue with: description, steps to reproduce, relevant log output, and environment details

---

## Roadmap
- [ ] Qualys Vulnerability Management (all devices, beyond 1,000 limit)
- [ ] JAMF Pro (Under Development)
- [ ] Tenable (Under Development)
- [ ] Active Directory Default Domain Password Policy (default policy, separate from FGPP)

## Security Considerations

- **Change default credentials** — Always change default database and application credentials before going live
- **Use a strong SECRET_KEY** — Generate with `openssl rand -base64 32`
- **HTTPS in production** — Use a reverse proxy (nginx, Traefik) with SSL/TLS in front of the app
- **Network security** — Restrict access to the application and database to trusted networks
- **Regular updates** — Keep Docker images and dependencies updated
- **Backup strategy** — Implement regular PostgreSQL volume backups
- **API credentials** — Store integration credentials securely; consider a secrets manager for production
- **Service accounts** — Use dedicated, minimal-permission service accounts for each integration; never use personal or admin accounts

## Support
Submit issues via the [GitHub Issues](https://github.com/andrewixl/tierzerocode/issues) section.

## Contribute
If you love the project or want to show your appreciation, consider supporting on Patreon:
https://www.patreon.com/tierzerocode

## License
Distributed under the Apache License Version 2.0. See [LICENSE](LICENSE) for more information.
