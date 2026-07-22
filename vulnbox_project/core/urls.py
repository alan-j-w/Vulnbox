from django.urls import path
from django.views.generic import TemplateView
from .views import (
    # Main
    home, dashboard, profile_view, delete_account_view, leaderboard_view, health_check,
    # Labs
    submit_flag_view,
    course_sql, login_bypass, sql_injection,
    course_bruteforce, brute_force_lab,
    course_cryptography, crypto_lab,
    course_xss, xss_lab,
    course_csrf, csrf_lab,
    course_nosql, nosql_lab,
    course_ssti, ssti_lab,
    course_command_injection, command_injection_lab,
    course_prompt_injection, prompt_injection_lab,
    course_data_poisoning, data_poisoning_lab,
    course_model_theft, model_theft_lab,
    # Community
    community_hub, channel_detail, send_message, fetch_messages,
    # Exams
    exam_list_view, start_exam_view, submit_exam_view, verify_certificate_view,
    # Static Pages
    privacy_policy, disclaimer, tos, aup, ethics, about_developer,
    # AI
    ask_ai_view,
    # Errors
    error_404, error_500,
)

app_name = 'core'

urlpatterns = [
    path('health/', health_check, name='health_check'),
    path('', home, name='home'),
    path('dashboard/', dashboard, name='dashboard'),
    path('leaderboard/', leaderboard_view, name='leaderboard'),
    path('profile/', profile_view, name='profile'),
    path('profile/delete/', delete_account_view, name='delete_account'),

    path('submit-flag/', submit_flag_view, name='submit_flag'),
    path('exams/', exam_list_view, name='exam_list'),
    path('exam/start/', start_exam_view, name='start_exam'),
    path('exam/submit/', submit_exam_view, name='submit_exam'),

    path('community/', community_hub, name='community_hub'),
    path('community/<int:channel_id>/', channel_detail, name='channel_detail'),
    path('community/<int:channel_id>/send/', send_message, name='send_message'),
    path('community/<int:channel_id>/fetch/', fetch_messages, name='fetch_messages'),

    path('course/sql/', course_sql, name='course_sql'),
    path('login-bypass/', login_bypass, name='login_bypass'),
    path('sql/', sql_injection, name='sql_injection'),

    path('course/brute-force/', course_bruteforce, name='course_brute_force'),
    path('lab/brute-force/', brute_force_lab, name='brute_force_lab'),

    path('course/cryptography/', course_cryptography, name='course_cryptography'),
    path('lab/crypto/', crypto_lab, name='crypto_lab'),

    path('course/xss/', course_xss, name='course_xss'),
    path('lab/xss/', xss_lab, name='xss_lab'),

    path('course/csrf/', course_csrf, name='course_csrf'),
    path('lab/csrf/', csrf_lab, name='csrf_lab'),

    path('course/nosql/', course_nosql, name='course_nosql'),
    path('lab/nosql/', nosql_lab, name='nosql_lab'),

    path('course/ssti/', course_ssti, name='course_ssti'),
    path('lab/ssti/', ssti_lab, name='ssti_lab'),

    path('course/command-injection/', course_command_injection, name='course_command_injection'),
    path('lab/command-injection/', command_injection_lab, name='command_injection_lab'),

    path('course/prompt-injection/', course_prompt_injection, name='course_prompt_injection'),
    path('lab/prompt-injection/', prompt_injection_lab, name='prompt_injection_lab'),

    path('course/data-poisoning/', course_data_poisoning, name='course_data_poisoning'),
    path('lab/data-poisoning/', data_poisoning_lab, name='data_poisoning_lab'),

    path('course/model-theft/', course_model_theft, name='course_model_theft'),
    path('lab/model-theft/', model_theft_lab, name='model_theft_lab'),

    # Utility Pages
    path('privacy-policy/', privacy_policy, name='privacy_policy'),
    path('disclaimer/', disclaimer, name='disclaimer'),
    path('tos/', tos, name='tos'),
    path('aup/', aup, name='aup'),
    path('ethics/', ethics, name='ethics'),
    path('about/', about_developer, name='about_developer'),

    # AI Assistant
    path('ask_ai/', ask_ai_view, name='ask_ai'),

    # Certification Verification
    path('verify/<uuid:cert_id>/', verify_certificate_view, name='verify_certificate'),

    # SEO Routes
    path('robots.txt', TemplateView.as_view(template_name="robots.txt", content_type="text/plain")),
    path('sitemap.xml', TemplateView.as_view(template_name="sitemap.xml", content_type="application/xml")),
]
