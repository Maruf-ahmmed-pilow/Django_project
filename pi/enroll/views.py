from django.shortcuts import render, HttpResponseRedirect
from .forms import SignUpForm,EditUserForm,EditAdminForm
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm, SetPasswordForm
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.models import User

#SignupForm
def sign_up(request):
    if request.method == 'POST':
        fm = SignUpForm(request.POST)
        if fm.is_valid():
            messages.success(request, 'Account Created Successfully !!')
            fm.save()

    else:
        fm = SignUpForm()
    return render(request, 'enroll/signup.html', {'form':fm})

#loginForm
def user_login(request):
    if not request.user.is_authenticated:
        if request.method =='POST':
            fm = AuthenticationForm(request=request, data = request.POST)
            if fm.is_valid():
                uname = fm.cleaned_data['username']
                upass = fm.cleaned_data['password']
                user = authenticate(username=uname, password=upass)
                if user is not None:
                    login(request, user)
                    messages.success(request, 'Login successfully !!')
                    return HttpResponseRedirect('/profile/')
        else:
            if request.user.is_superuser == True:
                fm = EditAdminForm(instance=request.user)
            else:
                fm = AuthenticationForm()
        return render(request, 'enroll/login.html',{'name':request.user.username, 'form':fm})
    else:
        return HttpResponseRedirect('/profile/')


#Profile
def user_profile(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            if request.user.is_superuser == True:
                fm = EditAdminForm(request.POST, instance=request.user)
                users = User.objects.all()
            else:
                fm = EditUserForm(request.POST, instance=request.user)
                
            if fm.is_valid():
                messages.success(request,'Update profile sucessfully!!')
                fm.save()
        else:
            if request.user.is_superuser == True:
                fm = EditAdminForm(instance=request.user)
                users = User.objects.all()
            else:
                fm = EditUserForm(instance = request.user)
                user = None
        return render(request, 'enroll/profile.html',{'name':request.user.username, 'form':fm, 'users':users})
    else:
        return HttpResponseRedirect('/login/')

#logout
def user_logout(request):
    logout(request)
    return HttpResponseRedirect('/login/')

#change password
def user_change_pass(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            fm = PasswordChangeForm(user=request.user, data=user.POST)
            if fm.is_valid():
                fm.save()
                update_session_auth_hash(request, fm.user)
                messages.success(request, 'Password Changed Successfully!!')
                return HttpResponseRedirect('/profile/')
        else:    
            fm = PasswordChangeForm(user=request.user)
        return render(request, 'enroll/changepass.html', {'form':fm})
    else:
        return render(request, '/profile/')


#setpassword
def user_change_pass1(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            fm = SetPasswordForm(user=request.user, data=user.POST)
            if fm.is_valid():
                fm.save()
                update_session_auth_hash(request, fm.user)
                messages.success(request, 'Password Changed Successfully!!')
                return HttpResponseRedirect('/profile/')
        else:    
            fm = SetPasswordForm(user=request.user)
        return render(request, 'enroll/changepass1.html', {'form':fm})
    else:
        return render(request, '/profile/')
    

def user_detail(request, id):
    if request.user.is_authenticated:
        pi = User.objects.get(pk=id)
        fm = EditAdminForm(instance = pi)
        return render(request, 'enroll/userdetail.html',{'form':fm})
    else:
        return HttpResponseRedirect('/login/')