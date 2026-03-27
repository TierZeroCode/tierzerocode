import logging
from django.utils import timezone
from user_agents import parse
from .models import Log

audit_logger = logging.getLogger('tierzerocode_audit')

def _parse_user_agent(user_agent_string, max_length=250):
    """Parse browser and OS from user agent string. Returns (browser, operating_system)."""
    if not user_agent_string or not user_agent_string.strip():
        return 'Unknown', 'Unknown'
    try:
        ua = parse(user_agent_string)
        browser = ua.browser.family or 'Unknown'
        if ua.browser.version_string:
            browser = f"{browser} {ua.browser.version_string}"
        os_name = ua.os.family or 'Unknown'
        if ua.os.version_string:
            os_name = f"{os_name} {ua.os.version_string}"
        return browser[:max_length], os_name[:max_length]
    except Exception:
        return 'Unknown', 'Unknown'

def get_client_ip(request):
    """Get client IP from request, respecting X-Forwarded-For when behind a proxy."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')

def createLog(request, event_code, event_type, event_group, user_level, privileged, action, outcome, **kwargs):
    """
    Hybrid Logging:
    - Technical data (IP, Browser) -> extracted from 'request'
    - Business data (Event Code, Group) -> passed explicitly
    """
    try:
        # --- 1. AUTOMATED EXTRACTION (From Request) ---
        # Handle user_id safely (authenticated vs anonymous)
        if request.user.is_authenticated:
            user_id = str(request.user.id)
            # If you want the username/email instead, change to request.user.email
        else:
            user_id = "Anonymous"

        ip_address = get_client_ip(request)

        # Get User Agent (and truncate to max length if needed)
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:255]
        
        # Get Session ID safely
        if not request.session.session_key:
            request.session.save() # Force a session if one doesn't exist
        session_id = request.session.session_key

        # Parse browser and OS from user_agent; kwargs can override
        parsed_browser, parsed_os = _parse_user_agent(user_agent)
        browser = kwargs.get('browser', parsed_browser)
        operating_system = kwargs.get('operating_system', parsed_os)
        additional_data = kwargs.get('additional_data', '')

        # --- 2. DATABASE WRITE ---
        Log.objects.create(
            session_id=session_id,
            event_code=event_code,
            event_type=event_type,
            event_group=event_group,
            user_level=user_level,
            privileged=privileged,
            action=action,
            outcome=outcome,
            additional_data=additional_data,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            browser=browser,
            operating_system=operating_system
        )

        # --- 3. FILE LOGGING ---
        current_time = timezone.now().strftime('%Y-%m-%dT%H:%M:%SZ')
        
        # Construct the log string using the explicit arguments
        log_message = (
            f"SessionID={session_id} "
            f"EventCode={event_code} "
            f"EventType={event_type} "
            f"EventGroup={event_group} "
            f"UserLevel={user_level} "
            f"Privileged={privileged} "
            f"Action={action} "
            f"Outcome={outcome} "
            f"AdditionalData={additional_data}"
            f"UserID={user_id} "
            f"IPAddress={ip_address} "
            f"UserAgent={user_agent} "
            f"Browser={browser} "
            f"OperatingSystem={operating_system} "
            f"EventTime={current_time} " 
        )
        
        audit_logger.info(log_message)

    except Exception as e:
        # Fallback so the user experience doesn't break
        print(f"CRITICAL: Logging failed: {e}")