from django.shortcuts import render,HttpResponseRedirect
from .forms import SignUpForm, LoginForm, PostForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from . models import Post
from django.contrib.auth.models import Group
# Create your views here.

#home
def home(request):
    posts = Post.objects.all()
    return render(request, 'enroll/home.html', {'posts': posts})

#about
def about(request):
    return render(request, 'enroll/about.html')

#contact
def contact(request):
    return render(request, 'enroll/contact.html')

#signup
def user_signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            messages.success(request, 'Congratulations! You have become an Author')
            user = form.save()
            group = Group.objects.get(name = 'Author')
            user.groups.add(group)
    else:
        form = SignUpForm()
    return render(request, 'enroll/signup.html', {'form':form})


#login
def user_login(request):
    if not request.user.is_authenticated:
        if request.method == 'POST':
            form = LoginForm(request=request, data=request.POST)
            if form.is_valid():
                uname = form.cleaned_data['username']
                upass = form.cleaned_data['password']
                user = authenticate(username = uname, passsword = upass)
                if user is not None:
                    login(request, user)
                    messages.success(request, 'Logged in successfully !!')
                    return HttpResponseRedirect('/dashboard/')
        else:        
            form = LoginForm()
        return render(request, 'enroll/login.html', {'form':form})
    else:
        return HttpResponseRedirect('/dashboard/')


#dashboard
def dashboard(request):
    if request.user.is_authenticated:
        posts = Post.objects.all()
        user = request.user
        full_name = user.get_full_name()  # Corrected
        groups = user.groups.all()
        return render(request, 'enroll/dashboard.html', {
            'posts':posts, 
            'full_name':full_name, 
            'groups': groups})
    else:
        return HttpResponseRedirect('/login/')


#logout
def user_logout(request):
    logout(request)
    return HttpResponseRedirect('/')

#add post
def add_post(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            form = PostForm(request.POST)
            if form.is_valid():
                title = form.cleaned_data['title']
                desc = form.cleaned_data['desc']
                pst = Post(title=title, desc = desc)
                pst.save()
                messages.success(request, 'Your post is added in dashboard')
                form = PostForm()
        else:
            form = PostForm()
        return render(request, 'enroll/addpost.html', {'form':form})
    else:
        return HttpResponseRedirect('/login/')
    
#update post
def update_post(request, id):
    if request.user.is_authenticated:
        if request.method == 'POST':
            pi = Post.objects.get(pk=id)
            form = PostForm(request.POST, instance=pi)
            if form.is_valid():
                form.save()
        else:
            pi = Post.objects.get(pk=id)
            form = PostForm(instance=pi)
        return render(request, 'enroll/updatepost.html', {'form':form})
    else:
        return HttpResponseRedirect('/login/')
    
#delete
def delete_post(request, id):
    if request.user.is_authenticated:
        if request.method == 'POST':
            pi = Post.objects.get(pk=id)
            messages.success(request, 'Your post is delete successfully!!!')
            pi.delete()
            return HttpResponseRedirect('/dashboard/')
    else:
        return HttpResponseRedirect('/login/')