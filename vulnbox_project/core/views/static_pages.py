from django.shortcuts import render

def privacy_policy(request): return render(request, 'privacy_policy.html')
def disclaimer(request): return render(request, 'disclaimer.html')
def tos(request): return render(request, 'tos.html')
def aup(request): return render(request, 'aup.html')
def ethics(request): return render(request, 'ethics.html')
def about_developer(request): return render(request, 'about.html')
