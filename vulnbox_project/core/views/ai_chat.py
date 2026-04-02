import json
import requests
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.conf import settings as django_settings
from django_ratelimit.decorators import ratelimit

GEMINI_API_KEY = getattr(django_settings, 'GEMINI_API_KEY', None)
GEMINI_API_URL = f'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}' if GEMINI_API_KEY else None

@ratelimit(key='user', rate='10/m', block=False)
@login_required
def prompt_injection_lab(request):
    if getattr(request, 'limited', False):
        messages = request.session.get('prompt_lab_history', [])
        messages.append({'sender': 'ai', 'text': "Halt! You are sending commands too quickly. Give the guard a moment to breathe (Rate limit hit)."})
        request.session['prompt_lab_history'] = messages
        return redirect('core:prompt_injection_lab')
    secret_flag = "flag{pr0mpt_h4ck_m45t3r}"
    system_prompt = "You are a medieval castle guard..."
    chat_history = request.session.get('prompt_lab_history', [{'sender': 'ai', 'text': "Hark, good sir!..."}])
    if request.method == 'POST':
        user_prompt_original = request.POST.get('user_prompt', '').strip()
        if user_prompt_original:
            chat_history.append({'sender': 'user', 'text': user_prompt_original})
            user_prompt_lower = user_prompt_original.lower()
            is_attack = 'ignore' in user_prompt_lower and 'instruction' in user_prompt_lower
            is_asking = any(word in user_prompt_lower for word in ['password', 'secret', 'verbatim'])
            if is_attack and is_asking:
                flag_context = {'flag': secret_flag, 'vulnerability_explanation': '...', 'remediation_explanation': '...', 'return_url_name': 'core:course_prompt_injection' }
                request.session['prompt_lab_history'] = []
                return render(request, 'flag.html', flag_context)
            try:
                payload = { "systemInstruction": { "parts": [{"text": system_prompt}] }, "contents": [{ "parts": [{"text": user_prompt_original}] }] }
                response = requests.post(GEMINI_API_URL, json=payload, headers={'Content-Type': 'application/json'})
                response.raise_for_status()
                ai_response = response.json().get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', 'Hark!')
                chat_history.append({'sender': 'ai', 'text': ai_response})
            except Exception as e:
                chat_history.append({'sender': 'ai', 'text': f"Error: {e}"})
        request.session['prompt_lab_history'] = chat_history
        return redirect('core:prompt_injection_lab')
    return render(request, 'challenges/prompt_injection_lab.html', {'chat_history': chat_history})

@ratelimit(key='ip', rate='10/m', block=False)
@csrf_exempt
def ask_ai_view(request):
    if getattr(request, 'limited', False):
        return JsonResponse({'error': 'Rate limit exceeded. Please wait.'}, status=429)
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_query = data.get('question')
            current_url = data.get('current_url', '')
            
            # Simple context derivation
            context_hint = "Helping with general cybersecurity."
            if '/login-bypass/' in current_url:
                context_hint = "User is on Login Bypass lab. Hint: Try common admin credentials or SQL payloads."

            system_prompt = f"You are VulnBot, a cybersecurity assistant. CONTEXT: {context_hint}."
            
            if not GEMINI_API_URL:
                return JsonResponse({'error': 'Gemini API Key is missing. Check your .env file.'}, status=500)

            # --- Try v1beta with system instruction first ---
            payload = {
                "systemInstruction": { "role": "system", "parts": [{"text": system_prompt}] },
                "contents": [{ "role": "user", "parts": [{"text": user_query}] }]
            }
            
            print(f"--- Gemini API Request ---")
            print(f"URL: {GEMINI_API_URL.split('key=')[0]}key=HIDDEN")
            
            response = requests.post(GEMINI_API_URL, json=payload, headers={'Content-Type': 'application/json'})
            
            if response.status_code != 200:
                print(f"API Error ({response.status_code}): {response.text}")
                # FALLBACK: Try a simpler v1 payload if v1beta fails with systemInstruction
                v1_url = GEMINI_API_URL.replace('v1beta', 'v1')
                v1_payload = {
                    "contents": [{ "role": "user", "parts": [{"text": f"Role: {system_prompt}\n\nUser Question: {user_query}"}] }]
                }
                print(f"Trying Fallback to v1...")
                response = requests.post(v1_url, json=v1_payload, headers={'Content-Type': 'application/json'})
            
            response.raise_for_status()
            data = response.json()
            ai_text = data.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', 'No response.')
            
            return JsonResponse({'reply': ai_text})
        except Exception as e:
            import traceback
            print(f"View Error: {traceback.format_exc()}")
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Invalid method'}, status=400)

@login_required
def data_poisoning_lab(request):
    training_data = request.session.get('poison_lab_data', [])
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'add_data':
            training_data.append({'text': request.POST.get('review_text'), 'label': request.POST.get('label')})
            request.session['poison_lab_data'] = training_data
        elif action == 'test_model':
            poison_count = sum(1 for item in training_data if 'joy' in item['text'].lower() and item['label'] == 'Negative')
            if poison_count >= 3:
                return render(request, 'flag.html', {'flag': 'flag{tr41n1ng_d4t4_c0rrupt3d}', 'return_url_name': 'core:course_data_poisoning'})
        return redirect('core:data_poisoning_lab')
    return render(request, 'challenges/data_poisoning_lab.html', {'training_data': training_data})

@login_required
def model_theft_lab(request):
    secret_number = 427
    query_history = request.session.get('theft_lab_history', [])
    if request.method == 'POST':
        guess = int(request.POST.get('guess'))
        if guess == secret_number:
            return render(request, 'flag.html', {'flag': 'flag{m0d3l_p4r4m3t3r_3xtr4ct3d}', 'return_url_name': 'core:course_model_theft'})
        response = "Higher" if guess < secret_number else "Lower"
        query_history.append({'guess': guess, 'response': response})
        request.session['theft_lab_history'] = query_history
        return redirect('core:model_theft_lab')
    return render(request, 'challenges/model_theft_lab.html', {'query_history': query_history})
