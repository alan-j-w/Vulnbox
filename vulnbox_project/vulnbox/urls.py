from django.contrib import admin
from django.urls import path, include

# These imports are necessary for serving files in development
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('authapp.urls', namespace='authapp')),
    path('', include('core.urls', namespace='core')),
]

# This configuration is for DEVELOPMENT ONLY.
# It tells Django's development server how to find and serve two types of files:
# 1. Your project's own assets like CSS and JS (STATIC files).
# 2. User-uploaded content like profile pictures (MEDIA files).
if settings.DEBUG:
    # This line handles your project's static files (e.g., CSS).
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    # This line handles user-uploaded media files (e.g., profile pictures).
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

