from django.db import models

# Create your models here.
class Log(models.Model):
    """
    Log model to store event logs with details such as event code, type, group, user level, privilege, action, outcome, additional data, user ID, and creation timestamp.
    """
    session_id = models.CharField(max_length=100, null=True, blank=True)
    event_code = models.CharField(max_length=4)
    event_type = models.CharField(max_length=50)
    event_group = models.CharField(max_length=50)
    user_level = models.CharField(max_length=50)
    privileged = models.BooleanField(default=True)
    action = models.CharField(max_length=100)
    outcome = models.CharField(max_length=20)
    additional_data = models.TextField(default='', blank=True)
    user_id = models.CharField(max_length=50, null=True, blank=True)
    ip_address = models.CharField(max_length=50, null=True, blank=True)
    user_agent = models.CharField(max_length=250, null=True, blank=True)
    browser = models.CharField(max_length=250, null=True, blank=True)
    operating_system = models.CharField(max_length=250, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.event_code} {self.action}"