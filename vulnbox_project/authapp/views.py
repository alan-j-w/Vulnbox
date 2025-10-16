from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.forms import AuthenticationForm
# Import our new custom form
from .forms import CustomUserCreationForm

def signup_view(request):
    if request.method == 'POST':
        # Use our new custom form instead of the default UserCreationForm
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            if request.POST.get('privacy_policy') == 'on':
                user = form.save()
                login(request, user)
                return redirect('core:dashboard')
            else:
                form.add_error(None, "You must agree to the Privacy Policy to create an account.")
    else:
        form = CustomUserCreationForm()

    return render(request, 'auth/signup.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        # No changes needed here, AuthenticationForm handles custom user models automatically
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('core:dashboard')
    else:
        form = AuthenticationForm()
    
    return render(request, 'auth/login.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('core:home')
