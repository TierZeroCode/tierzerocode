from django.contrib import admin
from import_export import resources
from import_export.admin import ImportExportModelAdmin

from .models import SSOIntegration


class SSOIntegrationResource(resources.ModelResource):
    class Meta:
        model = SSOIntegration
        fields = (
            "id",
            "enabled",
            "integration_type",
            "integration_type_short",
            "image_navbar_path",
            "image_integration_path",
            "client_id",
            "client_secret",
            "tenant_id",
            "tenant_domain",
            "last_synced_at",
            "created_at",
            "updated_at",
        )


@admin.register(SSOIntegration)
class SSOIntegrationAdmin(ImportExportModelAdmin):
    resource_class = SSOIntegrationResource
