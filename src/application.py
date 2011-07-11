import web
import web.contrib.template
import mongoengine
import hashlib
import beaker.middleware

# routing
urls = (
   '^/$', 'Home',
   '^/private$', 'Private',
   '^/login$', 'Login',
   '^/logout$', 'Logout',
   '^/register$', 'Register'
)

app = web.application(urls, globals())

# mongodb connection
mongoengine.connect('wmbm')


# models
class BaseUser(object):
    def is_authenticated(self):
        return NotImplementedError
    
    def is_anonymous(self):
        return NotImplementedError
    
    
class AnonymousUser(BaseUser):
    def is_authenticated(self):
        return False
    
    def is_anonymous(self):
        return True
    

class User(mongoengine.Document, BaseUser):
    username = mongoengine.StringField(required=True, unique=True)
    password = mongoengine.StringField(required=True)
    
    def set_password(self, raw_password):
        self.password = hashlib.sha256(raw_password).hexdigest()
        
    def is_authenticated(self):
        return True
    
    def is_anonymous(self):
        return False
    
    @classmethod
    def create(cls, username, raw_password):
        user = User(username=username)
        user.set_password(raw_password)
        user.save()
        return user
        

# forms
LoginForm = web.form.Form(
    web.form.Textbox('username', web.form.notnull, description='Username'),
    web.form.Password('password', web.form.notnull, description='Password'),
    web.form.Button('login', type='submit', html='Login')
)

RegistrationForm = web.form.Form(
    web.form.Textbox('username',
                    web.form.regexp(r'\w{3,20}$', 'must be between 3 and ' +
                                    '20 characters'),
                    description='Username'),
    web.form.Password('password', web.form.notnull, description='Password'),
    web.form.Password('password2', web.form.notnull, description='Retype ' +
                      'Password'),
    web.form.Button('register', type='submit', html='Register'),
    validators = [web.form.Validator("Passwords did't match",
                                     lambda i: i.password == i.password2)
    ]
)


# helpers
render = web.contrib.template.render_mako(directories=['templates'],
                                          input_encoding='utf-8',
                                          output_encoding='utf-8')

def authenticate(username, password):
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return False
    if user.password == hashlib.sha256(password).hexdigest():
        return True
    return False

def session_middleware(app):
    return beaker.middleware.SessionMiddleware(app, environ_key='session',
                                               key='session.id')

def get_session():
    return web.ctx.env['session']

def cache_middleware(app):
    return beaker.middleware.CacheMiddleware(app, environ_key='cache')

def get_cache():
    return web.ctx.env['cache']

def auth_middleware(app):
    return AuthMiddleware(app)

def get_user():
    return web.ctx.env['user']

# decorators
def login_required(method):
    def wrapper(self, *args, **kwargs):
        print 'wrapper begins'
        user = get_user()
        print user
        if not user.is_authenticated():
            return web.redirect('/login')
        print user.username
        return method(self, *args, **kwargs)
    return wrapper


# middlewares
class AuthMiddleware(object):
    def __init__(self, app):
        self.app = app
        
    def __call__(self, environ, start_response):
        session = environ['session']
        cache = environ['cache']
        
        try:
            uid = session['uid']
        except KeyError:
            uid = None
            
        if uid is None:
            environ['user'] = AnonymousUser()
        else:
            user_cache_ns = cache.get_cache('user' + str(uid))
            try:
                user = user_cache_ns.get('user')
                print 'cached user'
            except KeyError:
                try:
                    user = User.objects.with_id(uid)
                    user_cache_ns.put('user', user)
                    print 'fresh user stored in cache'
                except User.DoesNotExist:
                    user = AnonymousUser()
            environ['user'] = user
        return self.app(environ, start_response)
        
# controllers
class Home(object):
    def GET(self):
        return render.home(user=get_user())

class Login(object):
    def GET(self):
        form = LoginForm()
        return render.login(form=form)

    def POST(self):
        form = LoginForm()
        if form.validates():
            errors = []
            if authenticate(form['username'].value, form['password'].value):
                session = get_session()
                session['uid'] = User.objects.get(username=form['username'].
                                                  value).id
                session.save()
                return web.redirect('/')
            else:
                errors.append('Login failed')
                return render.login(form=form, errors=errors)
        else:
            return render.login(form=form)


class Logout(object):
    def GET(self):
        get_session().delete()
        return web.redirect('/')


class Register(object):
    def GET(self):
        form = RegistrationForm()
        return render.register(form=form)

    def POST(self):
        form = RegistrationForm()
        if form.validates():
            errors =[]
            try:
                User.create(username=form['username'].value,
                            raw_password=form['password'].value)
            except:
                errors.append('User already exists')
                return render.register(form=form, errors=errors)
            return web.redirect('/')
        else:
            return render.register(form=form)


class Private(object):
    @login_required
    def GET(self):
        return render.private()


if __name__ == "__main__":
    app.run(auth_middleware, cache_middleware, session_middleware)