from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, HttpResponseBadRequest
from main.models import Review, Book, SiteUser
from django.db.models import Min, Max, Avg, Count, Sum
from django.db import connection, reset_queries
from django.db.models.fields import TextField, DecimalField
from django.db.models import Field
from main.functions import Convert
from functools import wraps
import base64
import secrets

AGGREGATES = {'Min': Min, 'Max': Max, 'Avg': Avg, 'Count': Count, 'Sum': Sum, 'Convert': Convert}
VALID_FIELDS = [f.name for f in Book._meta.get_fields() if isinstance(f, Field) and not f.is_relation]

def siteuser_basic_auth(required_role=None, realm="Restricted"):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            auth = request.META.get("HTTP_AUTHORIZATION", "")
            if auth.startswith("Basic "):
                try:
                    b64 = auth.split(" ", 1)[1].strip()
                    decoded = base64.b64decode(b64).decode("utf-8")
                    username, password = decoded.split(":", 1)

                    user = SiteUser.objects.filter(username=username).first()
                    if user and secrets.compare_digest(user.password, password):
                        if required_role is None or user.role == required_role:
                            request.site_user = user
                            return view_func(request, *args, **kwargs)
                except Exception:
                    pass
            resp = HttpResponse("Authentication required", status=401)
            resp["WWW-Authenticate"] = f'Basic realm="{realm}", charset="UTF-8"'
            return resp
        return _wrapped
    return decorator

@csrf_exempt
def book_filtering(request):
    if request.method == 'GET':
        if len(request.GET) == 0:
            return render(request, 'repository.html')
        params = {}
        filters = {}
        for param in request.GET:
            if param.find('__') != -1:
                if len(param.split('__')) > 2:
                    return HttpResponseBadRequest('Traversing relations is forbidden')
                if param.split('__')[0] not in VALID_FIELDS:
                    return HttpResponseBadRequest('Filter contains an invalid field')
                filters[param] = request.GET[param]
            else:
                if param in ['template', 'function']:
                    return HttpResponseBadRequest("Forbidden param")
                params[param] = request.GET[param]
        try:
            aggregate_function = params.pop('aggregate')
            target_field = params.pop('field')
        except Exception:
            result = Book.objects.filter(**filters).values(*VALID_FIELDS)
            return render(request, 'repository.html', {'result': result, 'columns': VALID_FIELDS})
        if target_field not in VALID_FIELDS:
            return HttpResponseBadRequest('Invalid field')
        if aggregate_function not in AGGREGATES.keys():
            return HttpResponseBadRequest('Invalid aggregate function')
        aggregate_function_callable = AGGREGATES[aggregate_function]
        result = Book.objects.filter(**filters).aggregate(res=aggregate_function_callable(target_field ,**params))
        print(result)
        return render(request, 'repository.html', {'aggregate': result['res'], 'aggregate_name': 'res'})
    
def details(request):
    id = request.GET.get('id', None)
    if id is None:
        return redirect('/')
    book = Book.objects.filter(id=id).first()
    if book is None:
        return redirect('/')
    reviews = Review.objects.filter(for_book=book).all()
    return render(request, 'details.html', {'book': book, 'reviews': reviews})

def index(request):
    books = Book.objects.all()
    return render(request, 'index.html', {'books': books})

@siteuser_basic_auth(required_role="admin", realm="Admin Area")
def admin(request):
    return HttpResponse('SK-CERT{fake_flag}')