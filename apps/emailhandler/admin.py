from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin

from .models import EmailIntegration


class EmailIntegrationResource(resources.ModelResource):
    class Meta:
        model = EmailIntegration
        # client_id and client_secret are intentionally omitted.
        fields = (
            "id",
            "enabled",
            "integration_type",
            "image_navbar_path",
            "image_integration_path",
            "tenant_id",
            "tenant_domain",
            "last_synced_at",
            "created_at",
            "updated_at",
        )


@admin.register(EmailIntegration)
class EmailIntegrationAdmin(ImportExportModelAdmin):
    resource_class = EmailIntegrationResource
