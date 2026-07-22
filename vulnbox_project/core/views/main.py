from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.contrib import messages
from authapp.models import CustomUser
from authapp.forms import ProfilePictureForm
from curriculum.models import Module, LabCompletion

def health_check(request):
    return HttpResponse("OK", status=200)

def home(request):
    return render(request, 'home.html')

@login_required
def dashboard(request):
    modules = Module.objects.prefetch_related('labs').all()
    completions = LabCompletion.objects.filter(user=request.user).select_related('lab')
    completed_lab_slugs = [c.lab.slug for c in completions]
    
    course_to_labs_map = {
        'theory-brute-force': ['brute-force'],
        'theory-sql-injection': ['login-bypass', 'sql-injection-union'],
        'theory-nosql-injection': ['nosql-injection'],
        'theory-command-injection': ['command-injection'],
        'theory-ssti': ['ssti'],
        'theory-xss': ['stored-xss'],
        'theory-csrf': ['csrf'],
        'theory-cryptography': ['cryptography-caesar'],
        'theory-ai-security': ['ai-prompt-injection'],
        'theory-data-poisoning': ['ml-data-poisoning'],
        'theory-model-theft': ['ml-model-theft'],
    }

    module_progress = []
    for mod in modules:
        dashboard_items = mod.labs.filter(content_type='theory').order_by('order')
        practical_labs = mod.labs.filter(content_type='lab')
        total_practical = practical_labs.count()
        completed_practical = sum(1 for lab in practical_labs if lab.slug in completed_lab_slugs)
        mod_percentage = int((completed_practical / total_practical) * 100) if total_practical > 0 else 0
        
        items_with_status = []
        for item in dashboard_items:
            required_slugs = course_to_labs_map.get(item.slug, [])
            is_completed = all(slug in completed_lab_slugs for slug in required_slugs) if required_slugs else False
            items_with_status.append({
                'lab': item,
                'is_completed': is_completed
            })

        module_progress.append({
            'module': mod,
            'percentage': mod_percentage,
            'entries': items_with_status,
        })
    
    return render(request, 'dashboard.html', {
        'module_progress': module_progress,
    })

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
    
    recent_completions = LabCompletion.objects.filter(user=request.user).order_by('-completed_at')[:5]
    total_completions = LabCompletion.objects.filter(user=request.user).count()
    context = { 'form': form, 'recent_completions': recent_completions, 'total_completions': total_completions }
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

