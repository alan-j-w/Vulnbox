from django.urls import path
from . import views

app_name = 'core'

urlpatterns = [
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('leaderboard/', views.leaderboard_view, name='leaderboard'),
    path('profile/', views.profile_view, name='profile'),
    path('profile/delete/', views.delete_account_view, name='delete_account'),

    path('submit-flag/', views.submit_flag_view, name='submit_flag'),
    path('exams/', views.exam_list_view, name='exam_list'),
    path('exam/start/', views.start_exam_view, name='start_exam'),
    path('exam/submit/', views.submit_exam_view, name='submit_exam'),


    path('community/', views.community_hub, name='community_hub'),
    path('community/<int:channel_id>/', views.channel_detail, name='channel_detail'),
    path('community/<int:channel_id>/send/', views.send_message, name='send_message'),
    path('community/<int:channel_id>/fetch/', views.fetch_messages, name='fetch_messages'),


    path('course/sql/', views.course_sql, name='course_sql'),
    path('login-bypass/', views.login_bypass, name='login_bypass'),
    path('sql/', views.sql_injection, name='sql_injection'),

    path('course/brute-force/', views.course_bruteforce, name='course_brute_force'),
    path('lab/brute-force/', views.brute_force_lab, name='brute_force_lab'),

    path('course/cryptography/', views.course_cryptography, name='course_cryptography'),
    path('lab/crypto/', views.crypto_lab, name='crypto_lab'),

    path('course/xss/', views.course_xss, name='course_xss'),
    path('lab/xss/', views.xss_lab, name='xss_lab'),

    path('course/csrf/', views.course_csrf, name='course_csrf'),
    path('lab/csrf/', views.csrf_lab, name='csrf_lab'),

    path('course/nosql/', views.course_nosql, name='course_nosql'),
    path('lab/nosql/', views.nosql_lab, name='nosql_lab'),

    path('course/ssti/', views.course_ssti, name='course_ssti'),
    path('lab/ssti/', views.ssti_lab, name='ssti_lab'),

    path('course/command-injection/', views.course_command_injection, name='course_command_injection'),
    path('lab/command-injection/', views.command_injection_lab, name='command_injection_lab'),

    path('course/prompt-injection/', views.course_prompt_injection, name='course_prompt_injection'),
    path('lab/prompt-injection/', views.prompt_injection_lab, name='prompt_injection_lab'),

    path('course/data-poisoning/', views.course_data_poisoning, name='course_data_poisoning'),
    path('lab/data-poisoning/', views.data_poisoning_lab, name='data_poisoning_lab'),

    path('course/model-theft/', views.course_model_theft, name='course_model_theft'),
    path('lab/model-theft/', views.model_theft_lab, name='model_theft_lab'),

    path('privacy-policy/', views.privacy_policy, name='privacy_policy'),
    path('disclaimer/', views.disclaimer, name='disclaimer'),

    # AI Assistant URL
    path('ask_ai/', views.ask_ai_view, name='ask_ai'),
]
