from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin

from .models import Log


class LogResource(resources.ModelResource):
    class Meta:
        model = Log
        fields = (
            "id",
            "session_id",
            "event_code",
            "event_type",
            "event_group",
            "user_level",
            "privileged",
            "action",
            "outcome",
            "additional_data",
            "user_id",
            "ip_address",
            "user_agent",
            "browser",
            "operating_system",
            "created_at",
        )


@admin.register(Log)
class LogAdmin(ImportExportModelAdmin):
    resource_class = LogResource
    list_display = ('id', 'event_code', 'event_type', 'event_group', 'user_level', 'privileged', 'action', 'outcome', 'additional_data', 'created_at', 'user_id')
    search_fields = ('event_code', 'event_type', 'event_group', 'action', 'user_id')
    list_filter = ('event_type', 'event_group', 'user_level', 'privileged', 'outcome', 'created_at')
    ordering = ('-created_at',)
