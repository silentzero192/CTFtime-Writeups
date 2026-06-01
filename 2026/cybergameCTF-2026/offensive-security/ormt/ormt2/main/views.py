from django.shortcuts import render
from django.http import HttpResponse, HttpResponseServerError, HttpResponseBadRequest
from main.models import SiteUser
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt

def sanitize(param):
    while param.find('__') != -1:
        param = param.replace('__', '_')
    return param

@csrf_exempt
def siteuser_login(request):
    if request.method == 'GET':
        return render(request, 'login.html')
    elif request.method == 'POST':
        params = {}
        for param in request.POST:
            params[sanitize(param)] = request.POST[param]
        if {'password', 'username'}.intersection(params.keys()) != {'password', 'username'}:
            return HttpResponseServerError('Password and username required')
        try:
            user = SiteUser.objects.get(**params)
        except SiteUser.DoesNotExist:
            return render(request, 'error.html', {'message': 'Login failed'})
        except Exception as e:
            return HttpResponseServerError(f'Query error {e}')
        if user.role == 'admin':
            return render(request, 'error.html', {'message': 'SK-CERT{fake_flag}'})
        return render(request, 'error.html', {'message': 'Welcome back! More features coming soon!'})

@csrf_exempt
def siteuser_signup(request):
    if request.method == 'GET':
        return render(request, 'signup.html')
    if request.method == 'POST':
        try:
            username = request.POST['username']
            password = request.POST['password']
        except Exception:
            return HttpResponseBadRequest('Missing parameters')
        try:
            SiteUser.objects.create(username=username, password=password, role='customer')
        except Exception:
            return render(request, 'error.html', {'message': 'Username taken'})
        return render(request, 'error.html', {'message': 'User created'})