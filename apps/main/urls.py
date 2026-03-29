from . import views
from django.urls import path

urlpatterns = [
    # ============================================================================
    # Dashboard & Index Pages
    # ============================================================================
    path('', views.index, name='index'),
    path('', views.index, name='admin-dashboard'),  # Alias for index
    path('device-dashboard', views.indexDevice, name='device-dashboard'),
    path('user-dashboard', views.indexUser, name='user-dashboard'),
    path('user-dashboard/<int:persona_id>', views.personaMetrics, name='persona-metrics'),
    
    # ============================================================================
    # Device Management
    # ============================================================================
    path('endpoints/master-list', views.masterList, name='master-list'),
    path('endpoints/<str:integration>', views.endpointList, name='endpoint-list'),
    path('device/<int:id>', views.deviceData, name='device-data'),
    
    # ============================================================================
    # User Management
    # ============================================================================
    path('users/master-list', views.userMasterList, name='user-master-list'),
    
    # ============================================================================
    # Integration Management
    # ============================================================================
    path('integrations', views.integrations, name='integrations'),
    path('enable-integration/<int:id>', views.enableIntegration, name='enable-integration'),
    path('disable-integration/<int:id>', views.disableIntegration, name='disable-integration'),
    path('update-integration/<int:id>', views.updateIntegration, name='update-integration'),
    path('sync-<str:integration>-devices', views.syncDevices, name='sync-devices'),
    path('sync-<str:integration>-users', views.syncUsers, name='sync-users'),
    path('test-connection/<int:id>', views.testConnection, name='test-connection'),
    
    # ============================================================================
    # Compliance & Settings
    # ============================================================================
    path('identity/general-settings', views.generalSettings, name='general-settings'),
    path('update_compliance/<int:id>', views.update_compliance, name='update_compliance'),
    
    # ============================================================================
    # Notification Management
    # ============================================================================
    path('delete-notification/<int:id>', views.delete_notification, name='delete_notification'),
    
    # ============================================================================
    # Persona Group Management
    # ============================================================================
    path('add-persona-group', views.add_persona_group, name='add_persona_group'),
    path('delete-persona-group/<int:id>', views.delete_persona_group, name='delete_persona_group'),
    
    # ============================================================================
    # Persona Management
    # ============================================================================
    path('add-persona', views.add_persona, name='add_persona'),
    path('delete-persona/<int:id>', views.delete_persona, name='delete_persona'),
    
    # ============================================================================
    # API Endpoints
    # ============================================================================
    # Device Master List API
    path('api/device-master-list', views.device_master_list_api, name='device_master_list_api'),

    # User Master List APIs
    path('api/user-master-list', views.user_master_list_api, name='user_master_list_api'),
    path('api/user-master-list-export', views.user_master_list_export_api, name='user_master_list_export_api'),
    
    # Compliance Settings APIs
    path('api/compliance-summary', views.compliance_summary_api, name='compliance_summary_api'),
    path('api/compliance-report', views.compliance_report_api, name='compliance_report_api'),
    path('api/bulk-update-compliance', views.bulk_update_compliance_api, name='bulk_update_compliance_api'),
    path('api/reset-compliance-settings', views.reset_compliance_settings_api, name='reset_compliance_settings_api'),
    
    # ============================================================================
    # Utility & Admin Routes
    # ============================================================================
    # path('initial-setup/', views.initialSetup, name='initial-setup'),
    path('error500', views.error500, name='error500'),
]