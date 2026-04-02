import json
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.template import Template, Context, TemplateSyntaxError
from django_ratelimit.decorators import ratelimit

# Flag Database
FLAG_DATABASE = {
    'FLAG{auth_bypass_achieved_d9a3}':    {'name': 'Login Bypass',       'points': 10},
    'FLAG{sql_injection_success_e4b1}':   {'name': 'SQL Injection',       'points': 15},
    'flag{w3ak_p4ssw0rds_l34d_t0_d00m}': {'name': 'Brute-Force',         'points': 20},
    'flag{caesars_salad_is_not_encrypted}': {'name': 'Cryptography',      'points': 10},
    'flag{xss_sCripT_k1dd1e_alert}':      {'name': 'XSS',                'points': 25},
    'flag{csrf_f0rg3d_r3qu3st_succ3ss}':  {'name': 'CSRF',               'points': 20},
    'flag{n0sql_1nj3ct10n_byp4ss}':       {'name': 'NoSQL Injection',     'points': 30},
    'flag{t3mpl4t3s_c4n_b3_tr41t0rs}':    {'name': 'SSTI',               'points': 35},
    'flag{sh3ll_c0mm4nd_ma5t3r}':         {'name': 'Command Injection',   'points': 40},
    'flag{pr0mpt_h4ck_m45t3r}':           {'name': 'Prompt Injection',    'points': 50},
    'flag{tr41n1ng_d4t4_c0rrupt3d}':      {'name': 'Data Poisoning',      'points': 60},
    'flag{m0d3l_p4r4m3t3r_3xtr4ct3d}':   {'name': 'Model Theft',         'points': 65},
}

@ratelimit(key='user', rate='15/m', block=False)
@login_required
def submit_flag_view(request):
    if getattr(request, 'limited', False):
        messages.error(request, 'Too many flag submissions. Please wait a minute.')
        return redirect('core:submit_flag')
    if request.method == 'POST':
        submitted_flag = request.POST.get('flag', '').strip()
        if submitted_flag in FLAG_DATABASE:
            challenge = FLAG_DATABASE[submitted_flag]
            challenge_name = challenge['name']
            if challenge_name not in request.user.completed_challenges:
                request.user.score += challenge['points']
                request.user.completed_challenges.append(challenge_name)
                request.user.save()
                messages.success(request, f"Correct! You earned {challenge['points']} points for the '{challenge_name}' challenge.")
            else:
                messages.error(request, 'You have already submitted the flag for this challenge.')
        else:
            messages.error(request, 'Incorrect flag. Please try again.')
        return redirect('core:submit_flag')
    return render(request, 'submit_flag.html')

# --- COURSE VIEWS (Theory) ---
@login_required
def course_sql(request): return render(request, 'course_sql.html')
@login_required
def course_bruteforce(request): return render(request, 'course_bruteforce.html')
@login_required
def course_cryptography(request): return render(request, 'course_cryptography.html')
@login_required
def course_xss(request): return render(request, 'course_xss.html')
@login_required
def course_csrf(request): return render(request, 'course_csrf.html')
@login_required
def course_nosql(request): return render(request, 'course_nosql.html')
@login_required
def course_ssti(request): return render(request, 'course_ssti.html')
@login_required
def course_command_injection(request): return render(request, 'course_command_injection.html')
@login_required
def course_prompt_injection(request): return render(request, 'course_prompt_injection.html')
@login_required
def course_data_poisoning(request): return render(request, 'course_data_poisoning.html')
@login_required
def course_model_theft(request): return render(request, 'course_model_theft.html')

# --- LAB VIEWS (Practical) ---
@csrf_exempt
@login_required
def login_bypass(request):
    challenge_path = 'challenges/login_bypass.html'
    if request.method == 'POST':
        password = request.POST.get('password', '')
        if "' OR '1'='1" in password:
            context = {
                'flag': 'FLAG{auth_bypass_achieved_d9a3}',
                'vulnerability_explanation': "The form was vulnerable because it built the SQL query by directly combining strings...",
                'remediation_explanation': "The correct way to prevent this is by using Parameterized Queries...",
                'return_url_name': 'core:course_sql',
                'line_1_message': '> AUTHENTICATION BYPASSED...',
            }
            return render(request, 'flag.html', context)
        return render(request, challenge_path, {'error': 'ACCESS DENIED: Incorrect payload.'})
    return render(request, challenge_path)

@csrf_exempt
@login_required
def sql_injection(request):
    challenge_path = 'challenges/sql_injection.html'
    if request.method == 'POST':
        query = request.POST.get('query', '')
        if 'UNION' in query.upper() and 'SELECT' in query.upper():
            context = {
                'flag': 'FLAG{sql_injection_success_e4b1}',
                'vulnerability_explanation': "The search feature was vulnerable because it directly inserted your search term into its SQL query...",
                'remediation_explanation': "As with the login bypass, the solution is to use Parameterized Queries...",
                'return_url_name': 'core:course_sql',
                'line_1_message': '> DATABASE COMPROMISED...',
            }
            return render(request, 'flag.html', context)
        return render(request, challenge_path, { 'message': 'QUERY FAILED: No data returned.', 'message_class': 'error' })
    return render(request, challenge_path)

@login_required
def brute_force_lab(request):
    correct_username = 'admin'
    correct_password = 'admin123'
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username == correct_username and password == correct_password:
            context = { 'flag': 'flag{w3ak_p4ssw0rds_l34d_t0_d00m}', 'vulnerability_explanation': 'The system was vulnerable because it did not implement any form of rate limiting or account lockout...', 'remediation_explanation': 'To fix this, the application should implement rate limiting and an account lockout policy...', 'return_url_name': 'core:course_brute_force', 'line_1_message': '> ACCESS GRANTED...', }
            return render(request, 'flag.html', context)
        else:
            return render(request, 'challenges/brute_force_lab.html', {'error': 'Error: Invalid Credentials. Access Denied.'})
    return render(request, 'challenges/brute_force_lab.html')

@login_required
def crypto_lab(request):
    correct_flag = 'flag{caesars_salad_is_not_encrypted}'
    if request.method == 'POST':
        submitted_flag = request.POST.get('flag', '').lower()
        if submitted_flag == correct_flag:
            context = { 'flag': correct_flag, 'vulnerability_explanation': 'The Caesar cipher is insecure because it has a tiny keyspace...', 'remediation_explanation': 'Modern encryption uses complex algorithms (like AES)...', 'return_url_name': 'core:course_cryptography' }
            return render(request, 'flag.html', context)
        else:
            return render(request, 'challenges/crypto_lab.html', {'error': 'Incorrect flag. Keep trying!'})
    return render(request, 'challenges/crypto_lab.html')

@login_required
def xss_lab(request):
    comments = request.session.get('xss_comments', [])
    if request.method == 'POST':
        comment = request.POST.get('comment', '')
        comments.append(comment)
        request.session['xss_comments'] = comments
        if '<script>' in comment.lower():
            request.session['xss_comments'] = []
            context = { 'flag': 'flag{xss_sCripT_k1dd1e_alert}', 'vulnerability_explanation': 'The application was vulnerable because it rendered user-supplied input without proper sanitization...', 'remediation_explanation': 'The best way to prevent Stored XSS is to always sanitize user input...', 'return_url_name': 'core:course_xss' }
            return render(request, 'flag.html', context)
    return render(request, 'challenges/xss_lab.html', {'comments': comments})

@login_required
def nosql_lab(request):
    admin_user = {"username": "admin", "password": "a_very_secret_password"}
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username == admin_user['username'] and '"$ne"' in password:
            context = { 'flag': 'flag{n0sql_1nj3ct10n_byp4ss}', 'vulnerability_explanation': 'The application was vulnerable because it did not properly sanitize user input...', 'remediation_explanation': 'To prevent this, the application must perform strict type checking...', 'return_url_name': 'core:course_nosql' }
            return render(request, 'flag.html', context)
        return render(request, 'challenges/nosql_lab.html', {'error': 'Authentication Failed.'})
    return render(request, 'challenges/nosql_lab.html')

@login_required
@csrf_exempt
def csrf_lab(request):
    user_email = request.session.get('csrf_lab_email', 'user@vulnbox.com')
    success_message, flag = None, None
    if request.method == 'POST':
        new_email = request.POST.get('email')
        if new_email:
            user_email = new_email
            request.session['csrf_lab_email'] = user_email
            success_message = f"Success! Your email has been changed to {user_email}"
            flag = 'flag{csrf_f0rg3d_r3qu3st_succ3ss}'
    return render(request, 'challenges/csrf_lab.html', {'user_email': user_email, 'success_message': success_message, 'flag': flag})

@login_required
def ssti_lab(request):
    context = {}
    if request.method == 'POST':
        user_input = request.POST.get('name', '')
        try:
            template = Template(f'Hello, {user_input}!')
            rendered_output = template.render(Context({'user': request.user}))
            context['rendered_template'] = rendered_output
            if "49" in rendered_output:
                flag_context = { 'flag': 'flag{t3mpl4t3s_c4n_b3_tr41t0rs}', 'vulnerability_explanation': "The application was vulnerable because it concatenated user input directly into a template string...", 'remediation_explanation': "Never build templates from strings containing user input...", 'return_url_name': 'core:course_ssti' }
                return render(request, 'flag.html', flag_context)
        except TemplateSyntaxError as e:
            context['error'] = f"Template Syntax Error: {e}"
    return render(request, 'challenges/ssti_lab.html', context)

@login_required
def command_injection_lab(request):
    context = {}
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address', '')
        if (';' in ip_address or '&' in ip_address) and ('whoami' in ip_address.lower() or 'id' in ip_address.lower()):
            flag_context = { 'flag': 'flag{sh3ll_c0mm4nd_ma5t3r}', 'vulnerability_explanation': "The application was vulnerable because it built an OS command by formatting user input into a string...", 'remediation_explanation': "Never build command strings with user input...", 'return_url_name': 'core:course_command_injection' }
            return render(request, 'flag.html', flag_context)
        elif ip_address:
            output = f"Pinging {ip_address}...\n[Simulated Output]"
            if ';' in ip_address or '&' in ip_address: output += "\n\n[INJECTION DETECTED...]"
            context['command_output'] = output
        else:
            context['error'] = "Please enter an IP address."
    return render(request, 'challenges/command_injection_lab.html', context)
