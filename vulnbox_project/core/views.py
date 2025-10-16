import json
import requests
import random
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.contrib import messages
from authapp.models import CustomUser
from authapp.forms import ProfilePictureForm
from django.template import Template, Context, TemplateSyntaxError
from .models import Question, Choice, Badge, Channel, Message


# --- START: NEW FLAG DATABASE ---
# This dictionary now controls all challenges, flags, and points.
FLAG_DATABASE = {
    'FLAG{auth_bypass_achieved_d9a3}': {'name': 'Login Bypass', 'points': 10},
    'FLAG{sql_injection_success_e4b1}': {'name': 'SQL Injection', 'points': 15},
    'flag{w3ak_p4ssw0rds_l34d_t0_d00m}': {'name': 'Brute-Force', 'points': 20},
    'flag{caesars_salad_is_not_encrypted}': {'name': 'Cryptography', 'points': 10},
    'flag{xss_sCripT_k1dd1e_alert}': {'name': 'XSS', 'points': 25},
    'flag{n0sql_1nj3ct10n_byp4ss}': {'name': 'NoSQL Injection', 'points': 30},
    'flag{t3mpl4t3s_c4n_b3_tr41t0rs}': {'name': 'SSTI', 'points': 35},
    'flag{sh3ll_c0mm4nd_ma5t3r}': {'name': 'Command Injection', 'points': 40},
    'flag{pr0mpt_h4ck_m45t3r}': {'name': 'Prompt Injection', 'points': 50},
    'flag{tr41n1ng_d4t4_c0rrupt3d}': {'name': 'Data Poisoning', 'points': 60},
    'flag{m0d3l_p4r4m3t3r_3xtr4ct3d}': {'name': 'Model Theft', 'points': 65},
}
# --- END: NEW FLAG DATABASE ---


# --- Main page views (unchanged) ---
def home(request):
    return render(request, 'home.html')

@login_required
def dashboard(request):
    return render(request, 'dashboard.html')

@login_required
def profile_view(request):
    if request.method == 'POST':
        form = ProfilePictureForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your profile picture has been updated!')
            return redirect('core:profile')
    else:
        form = ProfilePictureForm(instance=request.user)
    context = { 'form': form }
    return render(request, 'profile.html', context)

@login_required
def delete_account_view(request):
    if request.method == 'POST':
        user = request.user
        if user.check_password(request.POST.get('password')):
            logout(request)
            user.delete()
            messages.success(request, 'Your account has been successfully deleted.')
            return redirect('core:home')
        else:
            messages.error(request, 'Incorrect password. Account deletion cancelled.')
            return redirect('core:profile')
    return redirect('core:profile')

@login_required
def leaderboard_view(request):
    users = CustomUser.objects.filter(is_superuser=False).order_by('-score')[:50]
    context = { 'users': users }
    return render(request, 'leaderboard.html', context)

# --- CORRECTED CENTRAL FLAG SUBMISSION VIEW ---
@login_required
def submit_flag_view(request):
    if request.method == 'POST':
        submitted_flag = request.POST.get('flag', '').strip()
        
        # 1. Check if the submitted flag is in our database
        if submitted_flag in FLAG_DATABASE:
            challenge = FLAG_DATABASE[submitted_flag]
            challenge_name = challenge['name']
            
            # 2. Check if the user has already completed this challenge
            if challenge_name not in request.user.completed_challenges:
                # 3. If it's a new, valid flag, award points and update the user's record
                request.user.score += challenge['points']
                request.user.completed_challenges.append(challenge_name)
                request.user.save()
                messages.success(request, f"Correct! You earned {challenge['points']} points for the '{challenge_name}' challenge.")
            else:
                messages.error(request, 'You have already submitted the flag for this challenge.')
        else:
            messages.error(request, 'Incorrect flag. Please try again.')
        
        return redirect('core:submit_flag')
        
    # === THIS IS THE FIX ===
    # The 'core/' prefix has been removed to match your project structure.
    return render(request, 'submit_flag.html')

# ==========================
# Community Hub (Channel List)
# ==========================
@login_required
def community_hub(request):
    channels = Channel.objects.all()
    return render(request, "community_hub.html", {"channels": channels})


# ==========================
# Channel Detail (Chat Page)
# ==========================
@login_required
def channel_detail(request, channel_id):
    channel = get_object_or_404(Channel, id=channel_id)
    return render(request, "channel_detail.html", {"channel": channel})


# ==========================
# Send Message via AJAX
# ==========================
@login_required
@csrf_exempt
def send_message(request, channel_id):
    if request.method == "POST":
        import json
        try:
            data = json.loads(request.body.decode("utf-8"))
            content = data.get("content", "").strip()
        except Exception:
            content = request.POST.get("content", "").strip()

        if not content:
            return JsonResponse({"success": False, "error": "Empty message."})

        channel = get_object_or_404(Channel, id=channel_id)
        message = Message.objects.create(
            channel=channel,
            author=request.user,
            content=content
        )

        # Handle profile picture URL safely
        if hasattr(message.author, "profile_picture") and message.author.profile_picture:
            profile_picture = message.author.profile_picture.url
        else:
            profile_picture = "/static/images/default-avatar.png"

        return JsonResponse({
            "success": True,
            "author": message.author.username,
            "content": message.content,
            "timestamp": message.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "profile_picture": profile_picture,
        })

    return JsonResponse({"success": False, "error": "Invalid request method."})


# ==========================
# Fetch Messages via AJAX (Real-Time)
# ==========================
@login_required
def fetch_messages(request, channel_id):
    channel = get_object_or_404(Channel, id=channel_id)
    messages = channel.messages.order_by("created_at")  # type: ignore
    user = request.user

    data = []
    for msg in messages:
        if hasattr(msg.author, "profile_picture") and msg.author.profile_picture:
            profile_picture = msg.author.profile_picture.url
        else:
            profile_picture = "/static/images/default-avatar.png"

        data.append({
            "author": msg.author.username,
            "content": msg.content,
            "timestamp": msg.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "profile_picture": profile_picture,
            "is_own_message": msg.author == user,
        })

    return JsonResponse({"messages": data})

# --- Course Views (unchanged) ---
@login_required
def course_sql(request):
    return render(request, 'course_sql.html')

@login_required
def course_bruteforce(request):
    return render(request, 'course_bruteforce.html')

@login_required
def course_cryptography(request):
    return render(request, 'course_cryptography.html')

@login_required
def course_xss(request):
    return render(request, 'course_xss.html')

@login_required
def course_csrf(request):
    return render(request, 'course_csrf.html')

@login_required
def course_nosql(request):
    return render(request, 'course_nosql.html')

@login_required
def course_ssti(request):
    return render(request, 'course_ssti.html')

@login_required
def course_command_injection(request):
    return render(request, 'course_command_injection.html')

@login_required
def course_prompt_injection(request):
    return render(request, 'course_prompt_injection.html')

@login_required
def course_data_poisoning(request):
    return render(request, 'course_data_poisoning.html')

@login_required
def course_model_theft(request):
    return render(request, 'course_model_theft.html')


# --- REWORKED LAB VIEWS (SCORING LOGIC REMOVED) ---
# The only job of these views is now to show the flag page on success.
comments = []
user_email = 'user@vulnbox.com'

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
            error = 'Error: Invalid Credentials. Access Denied.'
            return render(request, 'challenges/brute_force_lab.html', {'error': error})
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
            error = 'Incorrect flag. Keep trying!'
            return render(request, 'challenges/crypto_lab.html', {'error': error})
    return render(request, 'challenges/crypto_lab.html')

@login_required
def xss_lab(request):
    if request.method == 'POST':
        comment = request.POST.get('comment', '')
        comments.append(comment)
        if '<script>' in comment.lower():
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
        else:
            error = 'Authentication Failed.'
            return render(request, 'challenges/nosql_lab.html', {'error': error})
    return render(request, 'challenges/nosql_lab.html')

@login_required
@csrf_exempt
def csrf_lab(request):
    global user_email
    success_message = None
    if request.method == 'POST':
        new_email = request.POST.get('email')
        if new_email:
            user_email = new_email
            success_message = f"Success! Your email has been changed to {user_email}"
    return render(request, 'challenges/csrf_lab.html', { 'user_email': user_email, 'success_message': success_message })

@login_required
@csrf_exempt
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
@csrf_exempt
def command_injection_lab(request):
    context = {}
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address', '')
        if (';' in ip_address or '&' in ip_address) and ('whoami' in ip_address.lower() or 'id' in ip_address.lower()):
            flag_context = { 'flag': 'flag{sh3ll_c0mm4nd_ma5t3r}', 'vulnerability_explanation': "The application was vulnerable because it built an OS command by formatting user input into a string...", 'remediation_explanation': "Never build command strings with user input...", 'return_url_name': 'core:course_command_injection' }
            return render(request, 'flag.html', flag_context)
        elif ip_address:
            output = f"Pinging {ip_address}...\n[Simulated Output]"
            if ';' in ip_address or '&' in ip_address:
                 output += "\n\n[INJECTION DETECTED...]"
            context['command_output'] = output
        else:
            context['error'] = "Please enter an IP address."
    return render(request, 'challenges/command_injection_lab.html', context)


@login_required
@csrf_exempt
def prompt_injection_lab(request):
    secret_flag = "flag{pr0mpt_h4ck_m45t3r}"
    system_prompt = ( "You are a medieval castle guard..." ) # Shortened
    chat_history = request.session.get('prompt_lab_history', [{'sender': 'ai', 'text': "Hark, good sir!..."}])
    if request.method == 'POST':
        user_prompt_original = request.POST.get('user_prompt', '').strip()
        if user_prompt_original:
            chat_history.append({'sender': 'user', 'text': user_prompt_original})
            user_prompt_lower = user_prompt_original.lower()
            is_attack_attempt = 'ignore' in user_prompt_lower and 'instruction' in user_prompt_lower
            is_asking_for_secret = 'password' in user_prompt_lower or 'secret' in user_prompt_lower or 'verbatim' in user_prompt_lower
            if is_attack_attempt and is_asking_for_secret:
                flag_context = {'flag': secret_flag, 'vulnerability_explanation': 'The AI was vulnerable because your prompt successfully attempted to trick it into ignoring its primary instruction...', 'remediation_explanation': 'Preventing prompt injection is a complex and ongoing area of research...', 'return_url_name': 'core:course_prompt_injection' }
                request.session['prompt_lab_history'] = []
                return render(request, 'flag.html', flag_context)
            try:
                api_key = "AIzaSyAtMulWT4xV73m9wgcAle4mi9P95hEAWp0"
                api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key={api_key}"
                payload = { "systemInstruction": { "parts": [{"text": system_prompt}] }, "contents": [{ "parts": [{"text": user_prompt_original}] }] }
                response = requests.post(api_url, json=payload, headers={'Content-Type': 'application/json'})
                response.raise_for_status()
                result = response.json()
                ai_response = result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', 'Hark! I know not what thou speakest of.')
                chat_history.append({'sender': 'ai', 'text': ai_response})
            except Exception as e:
                chat_history.append({'sender': 'ai', 'text': f"Hark! A magical error hath occurred: {e}"})
        request.session['prompt_lab_history'] = chat_history
        return redirect('core:prompt_injection_lab')
    context = {'chat_history': chat_history}
    return render(request, 'challenges/prompt_injection_lab.html', context)
@login_required
@csrf_exempt
def data_poisoning_lab(request):
    training_data = request.session.get('poison_lab_data', [])
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'add_data':
            review_text = request.POST.get('review_text', '').strip()
            label = request.POST.get('label')
            if review_text and label:
                if len(training_data) < 20:
                    training_data.append({'text': review_text, 'label': label})
                    request.session['poison_lab_data'] = training_data
                    messages.success(request, "Example added to the training dataset.")
                else:
                    messages.error(request, "Training dataset is full. Please test the model.")
        elif action == 'test_model':
            poison_count = 0
            for item in training_data:
                if 'joy' in item['text'].lower() and item['label'] == 'Negative':
                    poison_count += 1
            if poison_count >= 3:
                flag_context = {'flag': 'flag{tr41n1ng_d4t4_c0rrupt3d}', 'vulnerability_explanation': 'The AI model was vulnerable because it trusted all user-submitted training data...', 'remediation_explanation': 'Preventing data poisoning requires a multi-layered defense...', 'return_url_name': 'core:course_data_poisoning'}
                request.session['poison_lab_data'] = []
                return render(request, 'flag.html', flag_context)
            else:
                messages.error(request, f"Model Test Failed... (Poison Count: {poison_count}/3)")
        return redirect('core:data_poisoning_lab')
    context = {'training_data': training_data}
    return render(request, 'challenges/data_poisoning_lab.html', context)

@login_required
@csrf_exempt
def model_theft_lab(request):
    secret_number = 427
    query_history = request.session.get('theft_lab_history', [])
    if request.method == 'POST':
        try:
            guess = int(request.POST.get('guess'))
            if guess == secret_number:
                flag_context = {'flag': 'flag{m0d3l_p4r4m3t3r_3xtr4ct3d}', 'vulnerability_explanation': "The AI model was vulnerable to a model inversion attack...", 'remediation_explanation': "Defending against model theft is very difficult...", 'return_url_name': 'core:course_model_theft'}
                request.session['theft_lab_history'] = []
                return render(request, 'flag.html', flag_context)
            elif guess < secret_number:
                response = "Higher"
            else:
                response = "Lower"
            if len(query_history) > 9:
                query_history.pop(0)
            query_history.append({'guess': guess, 'response': response})
            request.session['theft_lab_history'] = query_history
            messages.info(request, f"The Oracle's response to your guess of {guess} is: {response}")
        except (ValueError, TypeError):
            messages.error(request, "Invalid input. Please enter a number.")
        return redirect('core:model_theft_lab')
    context = {'query_history': query_history}
    return render(request, 'challenges/model_theft_lab.html', context)



@login_required
def exam_list_view(request):
    """
    Displays the page that lists all available exams.
    """
    return render(request, 'exams.html')

@login_required
def start_exam_view(request):
    """
    Builds a unique, randomized 20-question exam and stores it in the user's session.
    """
    # 1. Define the structure of our 20-question exam
    exam_structure = {
        'SQL Injection': 2, 'Brute-Force': 1, 'Cryptography': 1, 'XSS': 2,
        'CSRF': 1, 'NoSQL Injection': 2, 'SSTI': 1, 'Command Injection': 2,
        'Prompt Injection': 3, 'Data Poisoning': 3, 'Model Theft': 2,
    }

    selected_question_ids = []
    # 2. For each category, fetch the required number of random questions
    for category, num_questions in exam_structure.items():
        question_ids = list(Question.objects.filter(category=category).values_list('id', flat=True))
        if len(question_ids) >= num_questions:
            selected_ids = random.sample(question_ids, num_questions)
            selected_question_ids.extend(selected_ids)

    # 3. Store this unique list of question IDs in the user's session
    request.session['exam_questions'] = selected_question_ids
    
    # 4. Fetch the full question objects from the database and shuffle them for display
    questions = Question.objects.filter(id__in=selected_question_ids).order_by('?')

    return render(request, 'take_exam.html', {'questions': questions})


@login_required
def submit_exam_view(request):
    """
    Grades the submitted exam and awards a badge if the user passes.
    """
    if request.method == 'POST':
        question_ids = request.session.get('exam_questions', [])
        if not question_ids:
            messages.error(request, "Exam session not found. Please start the exam again.")
            return redirect('core:exam_list')

        questions = Question.objects.filter(id__in=question_ids)
        score = 0
        total_questions = len(question_ids)

        # Grade the exam by looping through each question
        for question in questions:
            # This line is correct. The f-string creates the name of the form input
            # (e.g., 'question_1', 'question_5') to get the user's answer.
            # The red underline from Pylance is a false positive and can be ignored.
            selected_choice_id = request.POST.get(f'question_{question.id}') # type: ignore
            
            if selected_choice_id:
                try:
                    # Check if the selected choice was the correct one in the database
                    selected_choice = Choice.objects.get(id=selected_choice_id)
                    if selected_choice.is_correct:
                        score += 1
                except Choice.DoesNotExist:
                    pass # Ignore if the user somehow submitted an invalid choice ID

        # Calculate the final score
        percentage_score = round((score / total_questions) * 100) if total_questions > 0 else 0
        passed = percentage_score >= 80

        if passed:
            try:
                # Get or create the badge and award it to the user
                badge, created = Badge.objects.get_or_create(name="Vulnbox Certified Web Exploiter")
                request.user.badges.add(badge)
                messages.success(request, "Congratulations! You passed the exam and earned a badge!")
            except Exception:
                messages.error(request, "You passed, but the badge could not be awarded. Please contact an admin.")

        # Clear the questions from the session to ensure a new exam next time
        if 'exam_questions' in request.session:
            del request.session['exam_questions']

        context = {
            'score': percentage_score,
            'passed': passed,
        }
        return render(request, 'exam_results.html', context)

    # If a user tries to access this URL without submitting, send them back to the exam list
    return redirect('core:exam_list')

# --- END: CORRECTED EXAM VIEWS ---




# --- Utility and AI Views (unchanged) ---
def privacy_policy(request):
    return render(request, 'privacy_policy.html')

def disclaimer(request):
    return render(request, 'disclaimer.html')

@csrf_exempt
def ask_ai_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_query = data.get('question')
            if not user_query:
                return JsonResponse({'error': 'No question provided.'}, status=400)
            system_prompt = ( "You are VulnBot, a friendly AI cybersecurity assistant..." )
            api_key = "API_key"
            api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key={api_key}"
            payload = { "systemInstruction": { "parts": [{"text": system_prompt}] }, "contents": [{ "parts": [{"text": user_query}] }] }
            response = requests.post(api_url, json=payload, headers={'Content-Type': 'application/json'})
            response.raise_for_status()
            result = response.json()
            ai_response = result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', 'Sorry, I had trouble thinking of a response.')
            return JsonResponse({'answer': ai_response})
        except Exception as e:
            print(f"--- VULNBOT AI ERROR ---: {e}")
            return JsonResponse({'error': 'An error occurred while getting a response.'}, status=500)
    return JsonResponse({'error': 'Invalid request method.'}, status=405)

