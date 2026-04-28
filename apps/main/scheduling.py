"""
Cron-driven sync scheduling service.

UI lets operators put any sync task on a cron schedule. Schedules are persisted
in `IntegrationSchedule` (per integration × task) and registered with
rq-scheduler. The worker (running with `--with-scheduler`) ticks every minute,
and when a cron fires it enqueues `run_scheduled_sync(schedule_id)` on the
default queue. That function applies a Redis lock for skip-if-running, looks
up the right sync function from the registry, and runs it.

Time zone: cron expressions are interpreted in UTC. Local-TZ rendering is the
template's job.
"""
import logging
from datetime import datetime, timezone as dt_timezone

import croniter
import django_rq
from django.utils import timezone
from django.utils.text import slugify

logger = logging.getLogger(__name__)


# ── Task registry ─────────────────────────────────────────────────────────────
# Per (integration_type, integration_context) → list of (task_key, label) tuples.
# Order matters — defines display order in the modal.

INTEGRATION_TASKS = {
    ('Microsoft Entra ID', 'User'): [
        ('users',         'Users (directory + auth methods + persona memberships)'),
        ('signins',       'Sign-in logs (last 30 days)'),
        ('ca_policies',   'Conditional Access policies'),
        ('tenant_config', 'Tenant security configuration'),
        ('auth_methods',  'Authentication methods + SSPR policy'),
        ('password',      'Password policy'),
    ],
    ('Microsoft Entra ID', 'Device'):       [('devices', 'Devices')],
    ('Microsoft Intune', 'Device'):         [('devices', 'Devices')],
    ('Microsoft Defender for Endpoint', 'Device'): [('devices', 'Devices')],
    ('CrowdStrike Falcon', 'Device'):       [('devices', 'Devices')],
    ('Tailscale', 'Device'):                [('devices', 'Devices')],
    ('Cloudflare Zero Trust', 'Device'):    [('devices', 'Devices')],
    ('Qualys', 'Device'):                   [('devices', 'Devices')],
    ('Sophos Central', 'Device'):           [('devices', 'Devices')],
    ('Active Directory', 'User'):           [('users', 'Users')],
}


def get_tasks_for(integration):
    """Return list of (task_key, label) tuples for an Integration row."""
    return INTEGRATION_TASKS.get(
        (integration.integration_type, integration.integration_context),
        [],
    )


# ── Cron presets ──────────────────────────────────────────────────────────────
# (preset_key, cron_expression, label) — None means "Custom" placeholder.

CRON_PRESETS = [
    ('hourly',  '0 * * * *',   'Hourly (top of hour)'),
    ('every6h', '0 */6 * * *', 'Every 6 hours'),
    ('daily',   '0 3 * * *',   'Daily at 3am UTC'),
    ('weekly',  '0 3 * * 0',   'Weekly Sunday 3am UTC'),
    ('custom',  None,          'Custom (cron expression)'),
]


def preset_for_cron(cron_expression):
    """Return the preset key matching a cron expression, or 'custom'."""
    if not cron_expression:
        return None
    for key, expr, _ in CRON_PRESETS:
        if expr and expr == cron_expression:
            return key
    return 'custom'


# ── Cron validation / preview ─────────────────────────────────────────────────

def validate_cron(expression):
    """Return (is_valid, error_message). Empty string is valid (means unscheduled)."""
    if not expression:
        return True, ''
    try:
        croniter.croniter(expression, datetime.now(dt_timezone.utc))
        return True, ''
    except (ValueError, KeyError) as e:
        return False, str(e)


def next_run(expression, after=None):
    """Return next datetime the cron expression fires, in UTC. None on invalid."""
    if not expression:
        return None
    try:
        base = after or datetime.now(dt_timezone.utc)
        return croniter.croniter(expression, base).get_next(datetime)
    except (ValueError, KeyError):
        return None


# ── rq-scheduler integration ──────────────────────────────────────────────────

def _get_scheduler():
    """Return the rq-scheduler instance for the default queue."""
    return django_rq.get_scheduler('default')


def _job_id_for(schedule):
    """Stable rq-scheduler job id keyed on the schedule pk."""
    return f'integration_schedule:{schedule.pk}'


def register_schedule(schedule):
    """Register or replace the rq-scheduler job for a schedule.

    Idempotent: cancels any prior job with our id before scheduling fresh.
    No-op when disabled or cron is empty (caller should ensure those rows
    are unregistered separately).
    """
    if not schedule.enabled or not schedule.cron_expression:
        return unregister_schedule(schedule)

    is_valid, _ = validate_cron(schedule.cron_expression)
    if not is_valid:
        logger.warning('Refusing to register schedule %s: invalid cron %r',
                       schedule.pk, schedule.cron_expression)
        return None

    scheduler = _get_scheduler()
    job_id = _job_id_for(schedule)

    # Cancel any prior version of this job before re-creating.
    try:
        scheduler.cancel(job_id)
    except Exception:
        pass

    job = scheduler.cron(
        schedule.cron_expression,
        func='apps.main.scheduling.run_scheduled_sync',
        args=[schedule.pk],
        queue_name='default',
        id=job_id,
        timeout=7200,
        repeat=None,
        use_local_timezone=False,
    )

    next_run_dt = next_run(schedule.cron_expression)
    schedule.rq_job_id = job_id
    schedule.next_run_at = next_run_dt
    schedule.save(update_fields=['rq_job_id', 'next_run_at', 'updated_at'])
    return job


def unregister_schedule(schedule):
    """Cancel the rq-scheduler job for a schedule and clear bookkeeping."""
    job_id = schedule.rq_job_id or _job_id_for(schedule)
    try:
        _get_scheduler().cancel(job_id)
    except Exception:
        pass
    if schedule.rq_job_id or schedule.next_run_at:
        schedule.rq_job_id = None
        schedule.next_run_at = None
        schedule.save(update_fields=['rq_job_id', 'next_run_at', 'updated_at'])


# ── Skip-if-running guard + dispatch ─────────────────────────────────────────

_LOCK_TTL_SECS = 8100  # job timeout (7200) + 15 min buffer


def _redis_lock(schedule_id):
    """SETNX-style lock keyed on schedule. Returns (got_lock, redis_conn).

    Caller is responsible for releasing on success and on failure paths.
    The TTL acts as a deadman switch in case of crashes.
    """
    redis = _get_scheduler().connection
    key = f'integration_schedule_lock:{schedule_id}'
    got = redis.set(key, '1', ex=_LOCK_TTL_SECS, nx=True)
    return bool(got), redis, key


def run_scheduled_sync(schedule_id):
    """Top-level entry point for scheduled syncs. Called by rq-scheduler.

    Acquires a Redis lock keyed on the schedule, dispatches to the integration's
    sync function, then releases. If the lock is already held (a previous run
    is still going), logs and skips this tick.
    """
    from apps.main.models import IntegrationSchedule

    try:
        schedule = IntegrationSchedule.objects.select_related('integration').get(pk=schedule_id)
    except IntegrationSchedule.DoesNotExist:
        logger.info('Scheduled sync %s: schedule deleted, skipping', schedule_id)
        return

    if not schedule.enabled:
        logger.info('Scheduled sync %s: disabled, skipping', schedule_id)
        return

    got_lock, redis, lock_key = _redis_lock(schedule_id)
    if not got_lock:
        logger.warning('Scheduled sync %s: previous run still active, skipping',
                       schedule_id)
        return

    try:
        schedule.last_run_at = timezone.now()
        schedule.save(update_fields=['last_run_at', 'updated_at'])
        _dispatch_sync(schedule)
    except Exception:
        logger.exception('Scheduled sync %s failed', schedule_id)
    finally:
        try:
            redis.delete(lock_key)
        except Exception:
            pass
        # Recompute next_run regardless of success — the cron is still ticking.
        try:
            schedule.refresh_from_db()
            schedule.next_run_at = next_run(schedule.cron_expression) if schedule.enabled else None
            schedule.save(update_fields=['next_run_at', 'updated_at'])
        except Exception:
            pass


# Per-context, per-task runner functions. Each takes the Integration row so it
# can pick the right credentials / sync target.

def _run_entra_users(integration):
    from apps.main.integrations.user_integrations.MicrosoftEntraID import syncEntraUsers
    syncEntraUsers()


def _run_entra_signins(integration):
    from apps.main.integrations.user_integrations.MicrosoftEntraID import syncEntraSignIns
    syncEntraSignIns()


def _run_entra_ca_policies(integration):
    from apps.main.integrations.user_integrations.MicrosoftEntraID import syncEntraCaPolicies
    syncEntraCaPolicies()


def _run_entra_tenant_config(integration):
    from apps.main.integrations.user_integrations.MicrosoftEntraID import syncEntraTenantConfig
    syncEntraTenantConfig()


def _run_entra_auth_methods(integration):
    from apps.main.integrations.user_integrations.MicrosoftEntraID import syncEntraAuthMethodsPolicy
    syncEntraAuthMethodsPolicy()


def _run_entra_password(integration):
    from apps.main.integrations.user_integrations.MicrosoftEntraID import syncEntraPasswordPolicy
    syncEntraPasswordPolicy()


def _run_active_directory_users(integration):
    from apps.main.integrations.user_integrations.ActiveDirectory import syncActiveDirectoryUsers
    syncActiveDirectoryUsers()


def _run_devices(integration):
    """Dispatch a device sync by integration slug (matches DEVICE_SYNC_MAP)."""
    from apps.main.tasks import DEVICE_SYNC_MAP
    slug = slugify(integration.integration_type)
    sync_fn = DEVICE_SYNC_MAP.get(slug)
    if sync_fn is None:
        logger.error('No DEVICE_SYNC_MAP entry for slug %r', slug)
        return
    sync_fn()


_RUNNERS = {
    ('User',   'users'):         _run_entra_users,
    ('User',   'signins'):       _run_entra_signins,
    ('User',   'ca_policies'):   _run_entra_ca_policies,
    ('User',   'tenant_config'): _run_entra_tenant_config,
    ('User',   'auth_methods'):  _run_entra_auth_methods,
    ('User',   'password'):      _run_entra_password,
    ('Device', 'devices'):       _run_devices,
}

def _dispatch_sync(schedule):
    """Look up the right sync function and run it inline.

    Each scheduled run is its own RQ job, so the sync runs in the worker
    process — no need to enqueue another job. Both Entra ID User and
    Active Directory User use the 'users' task key, so we disambiguate
    by integration_type before falling back to the generic runner map.
    """
    integration = schedule.integration
    if integration.integration_type == 'Active Directory' and schedule.task_key == 'users':
        return _run_active_directory_users(integration)
    runner = _RUNNERS.get((integration.integration_context, schedule.task_key))
    if runner is None:
        logger.error('No runner registered for %s / %s',
                     integration.integration_type, schedule.task_key)
        return
    runner(integration)
