import random
from datetime import timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from django_ratelimit.decorators import ratelimit
from core.models import Question, Choice, Badge
from certification.models import ExamAttempt, Certificate

@login_required
def exam_list_view(request):
    return render(request, 'exams.html')

@ratelimit(key='user', rate='5/m', block=False)
@login_required
def start_exam_view(request):
    if getattr(request, 'limited', False):
        messages.error(request, 'You are starting exams too quickly.')
        return redirect('core:exam_list')
        
    latest_attempt = ExamAttempt.objects.filter(user=request.user).order_by('-timestamp').first()
    if latest_attempt and latest_attempt.cooldown_until and latest_attempt.cooldown_until > timezone.now():
        cooldown_remaining = latest_attempt.cooldown_until - timezone.now()
        minutes = int(cooldown_remaining.total_seconds() / 60) + 1
        messages.error(request, f"Cooldown: Try again in {minutes} minutes.")
        return redirect('core:exam_list')

    exam_structure = {
        'SQL Injection': 2, 'Brute-Force': 1, 'Cryptography': 1, 'XSS': 2,
        'CSRF': 1, 'NoSQL Injection': 2, 'SSTI': 1, 'Command Injection': 2,
        'Prompt Injection': 3, 'Data Poisoning': 3, 'Model Theft': 2,
    }

    selected_question_ids = []
    for category, num_questions in exam_structure.items():
        question_ids = list(Question.objects.filter(category=category).values_list('id', flat=True))
        if len(question_ids) >= num_questions:
            selected_question_ids.extend(random.sample(question_ids, num_questions))

    request.session['exam_questions'] = selected_question_ids
    questions = Question.objects.filter(id__in=selected_question_ids).order_by('?')
    return render(request, 'take_exam.html', {'questions': questions})

@login_required
def submit_exam_view(request):
    if request.method == 'POST':
        question_ids = request.session.get('exam_questions', [])
        if not question_ids: return redirect('core:exam_list')

        questions = Question.objects.filter(id__in=question_ids)
        score = 0
        total_questions = len(question_ids)

        for question in questions:
            selected_choice_id = request.POST.get(f'question_{question.id}')
            if selected_choice_id:
                try:
                    if Choice.objects.get(id=selected_choice_id).is_correct:
                        score += 1
                except Choice.DoesNotExist: pass

        percentage_score = round((score / total_questions) * 100) if total_questions > 0 else 0
        passed = percentage_score >= 80
        attempt_number = ExamAttempt.objects.filter(user=request.user).count() + 1
        cooldown = timezone.now() + timedelta(hours=1) if not passed else None
        
        ExamAttempt.objects.create(user=request.user, score=percentage_score, passed=passed, attempt_number=attempt_number, cooldown_until=cooldown)

        if passed:
            cert, created = Certificate.objects.get_or_create(user=request.user, status='Valid')
            badge, b_created = Badge.objects.get_or_create(name="Vulnbox Certified Web Exploiter")
            request.user.badges.add(badge)
            messages.success(request, f"Congratulations! You passed! Certificate ID: {cert.certificate_id}")

        if 'exam_questions' in request.session: del request.session['exam_questions']
        return render(request, 'exam_results.html', {'score': percentage_score, 'passed': passed})
    return redirect('core:exam_list')

@login_required
def verify_certificate_view(request, cert_id):
    certificate = get_object_or_404(Certificate, certificate_id=cert_id)
    return render(request, 'verify_certificate.html', {'certificate': certificate})
