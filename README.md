![Tier Zero C.O.D.E Logo](https://hersheys.tierzerocode.com/static/login_app/img/Tier%20Zero%20CO.D.E-logos_black.png)
# Tier Zero C.O.D.E (Tier Zero Correlation of Distributed Endpoints)

Tier Zero C.O.D.E is an enterprise-level security dashboard designed to correlate and manage endpoint data from multiple distributed security tools and platforms. It provides a unified view of your organization's endpoints, users, and security posture by integrating with leading security solutions including Microsoft Entra ID, CrowdStrike Falcon, Microsoft Defender for Endpoint, Microsoft Intune, Sophos Central, and Qualys.

## Key Features

- **Unified Endpoint Management**: Centralize endpoint data from multiple security platforms into a single dashboard
- **User and Device Correlation**: Track and correlate user and device information across your security ecosystem
- **Multi-Platform Integration**: Seamlessly integrate with major security vendors and platforms
- **Real-time Monitoring**: Monitor endpoint compliance, security status, and user activity in real-time
- **Enterprise-Ready**: Built with Django and designed for enterprise-scale deployments

## Repository Stats

<a href="https://github.com/andrewixl/tierzerocode/blob/master/LICENSE"><img alt="GitHub license" src="https://img.shields.io/github/license/andrewixl/tierzerocode"></a>
<img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/andrewixl/tierzerocode">
<a href="https://github.com/andrewixl/tierzerocode/issues"><img alt="GitHub issues" src="https://img.shields.io/github/issues/andrewixl/tierzerocode"></a>
<a href="https://hub.docker.com/r/andrewixl/tierzerocode"><img alt="Docker pulls" src="https://img.shields.io/docker/pulls/andrewixl/tierzerocode"></a>

## Repository Technologies

<img alt="Python" src="https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white"> <img alt="Django" src="https://img.shields.io/badge/Django-6.0.1-green?logo=django&logoColor=white"> <img alt="PostgreSQL" src="https://img.shields.io/badge/PostgreSQL-17-blue?logo=postgresql&logoColor=white"> <img alt="Redis" src="https://img.shields.io/badge/Redis-7-red?logo=redis&logoColor=white"> <img alt="Docker" src="https://img.shields.io/badge/Docker-Alpine-blue?logo=docker&logoColor=white">

## Minimum Requirements
- [ ] 2 CPU Cores
- [ ] 4 GB RAM
- [ ] 32 GB SSD

## Recommended Requirements
- [ ] 4 CPU Cores
- [ ] 8 GB RAM
- [ ] 64 GB SSD

## Prerequisites

Before you begin, ensure you have the following installed:
- **Docker** (version 20.10 or later)
- **Docker Compose** (version 2.0 or later)
- Network access to your security platform APIs (Microsoft Entra ID, CrowdStrike, etc.)

## Getting started

Docker Install: Latest
```bash
andrewixl/tierzerocode:latest
```

Docker Install: Latest - Dev
```bash
andrewixl/tierzerocode:latest-dev
```

## Production Deployment with Docker Compose

### Full Stack (Web + Worker + Database + Redis)

This setup runs everything in Docker Compose, including PostgreSQL and Redis:

1. Create a `docker-compose.yml` file:
```bash
services:
  web:
    image: docker.io/andrewixl/tierzerocode:latest
    ports:
      - "${WEB_PORT:-8000}:8000"
    environment:
      # Django settings
      - SECRET_KEY=${SECRET_KEY}
      - DEBUG=${DEBUG:-False}
      - DJANGO_ALLOWED_HOSTS=${DJANGO_ALLOWED_HOSTS:-localhost,127.0.0.1}
      # Database settings
      - DATABASE_HOST=db
      - DATABASE_NAME=${DATABASE_NAME:-dockerdjango}
      - DATABASE_USER=${DATABASE_USER:-dbuser}
      - DATABASE_PASSWORD=${DATABASE_PASSWORD:-dbpassword}
      - DATABASE_PORT=${DATABASE_PORT:-5432}
      - DATABASE_ENGINE=${DATABASE_ENGINE:-postgresql_psycopg2}
      # Redis settings
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
      # Django settings
      - SECRET_KEY=${SECRET_KEY}
      - DEBUG=${DEBUG:-False}
      - DJANGO_ALLOWED_HOSTS=${DJANGO_ALLOWED_HOSTS:-localhost,127.0.0.1}
      # Database settings
      - DATABASE_HOST=db
      - DATABASE_NAME=${DATABASE_NAME:-dockerdjango}
      - DATABASE_USER=${DATABASE_USER:-dbuser}
      - DATABASE_PASSWORD=${DATABASE_PASSWORD:-dbpassword}
      - DATABASE_PORT=${DATABASE_PORT:-5432}
      - DATABASE_ENGINE=${DATABASE_ENGINE:-postgresql_psycopg2}
      # Redis settings
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

2. Create a `.env` file with your configuration:
```bash
SECRET_KEY=your-secret-key-here # Generate with: openssl rand -base64 32
DEBUG=False
DJANGO_ALLOWED_HOSTS=ipaddress,yourdomain.com,
DATABASE_NAME=dockerdjango
DATABASE_USER=dbuser
DATABASE_PASSWORD=dbpassword
GUNICORN_WORKERS=3
WEB_PORT=8000
USE_HTTPS=False
```

2. Pull and start all services:
```bash
sudo docker compose pull
sudo docker compose up -d
```

3. Run migrations:
```bash
sudo docker compose exec web python manage.py migrate
```

4. OPTIONAL Create superuser (if needed):
```bash
sudo docker compose exec web python manage.py createsuperuser
```

5. Access the application:
   - Open your browser and navigate to `http://ipaddress:8000` (or your configured `WEB_PORT`)
   - Create Administrator Account (or Log in with the superuser credentials you created)

### Configuration

The following environment variables can be configured in your `.env` file:

#### Django Settings
- `SECRET_KEY` - Django secret key (required for production) Generate with: openssl rand -base64 32
- `DEBUG` - Enable debug mode (default: `False`)
- `DJANGO_ALLOWED_HOSTS` - Comma-separated list of allowed hostnames
- `USE_HTTPS=False` - True / False

#### Database Settings
- `DATABASE_HOST` - PostgreSQL host (default: `db` for Docker Compose)
- `DATABASE_NAME` - Database name (default: `dockerdjango`)
- `DATABASE_USER` - Database user (default: `dbuser`)
- `DATABASE_PASSWORD` - Database password (default: `dbpassword`)
- `DATABASE_PORT` - Database port (default: `5432`)
- `DATABASE_ENGINE` - Database engine (default: `postgresql_psycopg2`)

#### Redis Settings
- `REDIS_HOST` - Redis host (default: `redis` for Docker Compose)
- `REDIS_PORT` - Redis port (default: `6379`)
- `REDIS_DB` - Redis database number (default: `0`)

#### Performance Settings
- `GUNICORN_WORKERS` - Number of Gunicorn worker processes (default: `3`)
- `WEB_PORT` - Port to expose the web service (default: `8000`)

### Managing Services

- View logs: `sudo docker compose logs -f web` or `docker compose logs -f worker`
- Stop services: `sudo docker compose down`
- Restart a service: `sudo docker compose restart web`
- Scale workers: Edit `docker-compose.yml` and use `sudo docker compose up -d --scale worker=3`

### Image Tags

The docker compose files use `docker.io/andrewixl/tierzerocode:latest` by default. To use a specific version:
```yaml
image: docker.io/andrewixl/tierzerocode:latest-dev
image: docker.io/andrewixl/tierzerocode:v1.0.0 (legacy to be updated)
```

## Required Permissions per Integration    
- Microsoft Entra ID (User)
    - Microsoft Graph - Directory.Read.All - Application Permissions
      - Populates Dashboard Tenant Name, Tenant ID, Primary Domain, # of Groups, and # of Apps
    - Microsoft Graph - User.Read.All - Application Permissions
    - Microsoft Graph - UserAuthenticationMethod.Read.All - Application Permissions
- CrowdStrike Falcon (Device)
    - Hosts - Read
- Microsoft Defender for Endpoint (Device)
    - WindowsDefenderATP - Machine.Read.All - Application Permissions
- Microsoft Entra ID (Device)
    - Microsoft Graph - Device.Read.All - Application Permissions
    - Microsoft Graph - AuditLog.Read.All - Application Permissions
- Microsoft Intune (Device)
    - Microsoft Graph - DeviceManagementManagedDevices.Read.All - Application Permissions
- Sophos Central (Device)
    - API Credential - Service Principal Management Role

## Integrate with your tools

- [ ] Microsoft Entra ID (Devices and Users Data)
- [ ] Cloudflare Zero Trust
- [ ] CrowdStrike Falcon
- [ ] Microsoft Defender for Endpoint
- [ ] Microsoft Intune
- [ ] Sophos Central
- [ ] Qualys Vulnerability Management (Limited to First 1000 Devices)

## Roadmap
- [ ] Qualys Vulnerability Management (All Devices)
- [ ] JAMF Pro (Under Development)
- [ ] Tenable (Under Development)

## Troubleshooting

### Common Issues

**Database connection errors:**
- Ensure PostgreSQL container is running: `sudo docker compose ps`
- Check database credentials in `.env` file
- Verify network connectivity between containers

**Redis connection errors:**
- Ensure Redis container is running: `sudo docker compose ps`
- Check Redis configuration in `.env` file

**Static files not loading:**
- Run collectstatic: `sudo docker compose exec web python manage.py collectstatic --noinput`

**Worker not processing jobs:**
- Check worker logs: `sudo docker compose logs -f worker`
- Ensure Redis is accessible from worker container

**Port already in use:**
- Change `WEB_PORT` in `.env` file to an available port
- Or stop the service using port 8000

### Getting Help

If you encounter issues not covered here:
1. Check the [GitHub Issues](https://github.com/andrewixl/tierzerocode/issues) for similar problems
2. Review container logs: `sudo docker compose logs -f [service-name]`
3. Create a new issue with:
   - Description of the problem
   - Steps to reproduce
   - Relevant log output
   - Your environment (Docker version, OS, etc.)

## Security Considerations

- **Change default credentials**: Always change default database and application credentials
- **Use strong SECRET_KEY**: Generate a secure Django secret key for production
- **HTTPS in production**: Use a reverse proxy (nginx, Traefik) with SSL/TLS certificates
- **Network security**: Restrict access to the application and database containers
- **Regular updates**: Keep Docker images and dependencies updated
- **Backup strategy**: Implement regular backups of PostgreSQL data volumes
- **API credentials**: Store integration API keys securely (consider using secrets management)

## Support
Please submit any issues into the issues section within this GitHub

## Contribute
If you are feeling generous, love the project, or just want to show your appreciation please donated at the Patreon Link Below!
https://www.patreon.com/tierzerocode

## License

Distributed under the Apache License Version 2.0. See [LICENSE](LICENSE) for more information.

<!-- ## Collaborate with your team

- [ ] [Invite team members and collaborators](https://docs.gitlab.com/ee/user/project/members/)
- [ ] [Create a new merge request](https://docs.gitlab.com/ee/user/project/merge_requests/creating_merge_requests.html)
- [ ] [Automatically close issues from merge requests](https://docs.gitlab.com/ee/user/project/issues/managing_issues.html#closing-issues-automatically)
- [ ] [Enable merge request approvals](https://docs.gitlab.com/ee/user/project/merge_requests/approvals/)
- [ ] [Set auto-merge](https://docs.gitlab.com/ee/user/project/merge_requests/merge_when_pipeline_succeeds.html)

## Test and Deploy

Use the built-in continuous integration in GitLab.

- [ ] [Get started with GitLab CI/CD](https://docs.gitlab.com/ee/ci/quick_start/index.html)
- [ ] [Analyze your code for known vulnerabilities with Static Application Security Testing (SAST)](https://docs.gitlab.com/ee/user/application_security/sast/)
- [ ] [Deploy to Kubernetes, Amazon EC2, or Amazon ECS using Auto Deploy](https://docs.gitlab.com/ee/topics/autodevops/requirements.html)
- [ ] [Use pull-based deployments for improved Kubernetes management](https://docs.gitlab.com/ee/user/clusters/agent/)
- [ ] [Set up protected environments](https://docs.gitlab.com/ee/ci/environments/protected_environments.html)

***

# Editing this README

When you're ready to make this README your own, just edit this file and use the handy template below (or feel free to structure it however you want - this is just a starting point!). Thanks to [makeareadme.com](https://www.makeareadme.com/) for this template.

## Suggestions for a good README

Every project is different, so consider which of these sections apply to yours. The sections used in the template are suggestions for most open source projects. Also keep in mind that while a README can be too long and detailed, too long is better than too short. If you think your README is too long, consider utilizing another form of documentation rather than cutting out information.

## Name
Choose a self-explaining name for your project.

## Description
Let people know what your project can do specifically. Provide context and add a link to any reference visitors might be unfamiliar with. A list of Features or a Background subsection can also be added here. If there are alternatives to your project, this is a good place to list differentiating factors.

## Badges
On some READMEs, you may see small images that convey metadata, such as whether or not all the tests are passing for the project. You can use Shields to add some to your README. Many services also have instructions for adding a badge.

## Visuals
Depending on what you are making, it can be a good idea to include screenshots or even a video (you'll frequently see GIFs rather than actual videos). Tools like ttygif can help, but check out Asciinema for a more sophisticated method.

## Installation
Within a particular ecosystem, there may be a common way of installing things, such as using Yarn, NuGet, or Homebrew. However, consider the possibility that whoever is reading your README is a novice and would like more guidance. Listing specific steps helps remove ambiguity and gets people to using your project as quickly as possible. If it only runs in a specific context like a particular programming language version or operating system or has dependencies that have to be installed manually, also add a Requirements subsection.

## Usage
Use examples liberally, and show the expected output if you can. It's helpful to have inline the smallest example of usage that you can demonstrate, while providing links to more sophisticated examples if they are too long to reasonably include in the README.

## Support
Tell people where they can go to for help. It can be any combination of an issue tracker, a chat room, an email address, etc.

## Roadmap
If you have ideas for releases in the future, it is a good idea to list them in the README.

## Contributing
State if you are open to contributions and what your requirements are for accepting them.

For people who want to make changes to your project, it's helpful to have some documentation on how to get started. Perhaps there is a script that they should run or some environment variables that they need to set. Make these steps explicit. These instructions could also be useful to your future self.

You can also document commands to lint the code or run tests. These steps help to ensure high code quality and reduce the likelihood that the changes inadvertently break something. Having instructions for running tests is especially helpful if it requires external setup, such as starting a Selenium server for testing in a browser.

## Authors and acknowledgment
Show your appreciation to those who have contributed to the project.

## License
For open source projects, say how it is licensed.

## Project status
If you have run out of energy or time for your project, put a note at the top of the README saying that development has slowed down or stopped completely. Someone may choose to fork your project or volunteer to step in as a maintainer or owner, allowing your project to keep going. You can also make an explicit request for maintainers. -->
