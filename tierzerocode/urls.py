import os
from django.contrib import admin
from django.urls import path, include

handler404 = 'apps.main.views.custom_404'
handler403 = 'apps.main.views.custom_403'

urlpatterns = [
    *([path('admin/django_rq/', include('django_rq.urls'))] if not os.environ.get('DJANGO_DEV') else []),  # django-rq admin URLs (must be before admin.site.urls)
    path('admin/', admin.site.urls),
    path('accounts/', include('allauth.urls')),
    path('identity/', include('apps.login_app.urls')),
    path('identity/', include('apps.authhandler.urls')),
    path('', include('apps.main.urls')),
]