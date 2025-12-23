from django.contrib.auth.decorators import login_required
from .forms import SignupForm, PasswordSetForm, LoginForm
from django.template.loader import render_to_string
from django.http import HttpResponse, JsonResponse
# VERCEL NO SOPORTA CELERY, SOPORTE DESACTIVADO
#from .tasks import no_reply_sender, creador_datos
from django.shortcuts import render, redirect
from asgiref.sync import sync_to_async
from django.contrib.auth.models import User
from django.contrib import auth
from django.views import View
from bs4 import BeautifulSoup
from django.core.mail import EmailMessage
from django.utils import timezone
from . import models
import requests, secrets, random, asyncio, json
import dateutil.relativedelta


###############################################################################################################
############################################ FUNCIONES ########################################################
###############################################################################################################

def calculador_cantidad_true(lista:list):
    index = 0
    for i in lista:
        if i:
            index += 1
    return index

def index(request):
    return render(request, "user_mngmnt/index.html")

# convierte tiempo de utc a un tz
def utc_to_tz(time, from_utc):
    # offset delta de las hs ingresadas como parametro
    timezone_offset = timezone.timedelta(hours=abs(from_utc))
    # si el tz esta por delante del utc
    if from_utc > 0:
        # se suma al utc el delta
        return time + timezone_offset
    # si el tz esta por atras del delta
    elif from_utc < 0:
        # se resta al utc el delta
        return time - timezone_offset

# convierte a utc
def tz_to_utc(time, from_utc):
    # offset del tz
    timezone_offset = timezone.timedelta(hours=abs(from_utc))
    # si el tz esta por delante de utc
    if from_utc > 0:
        # se convierte a utc restando
        return time - timezone_offset
    # si el tz esta por detras de utc
    elif from_utc < 0:
        # se convierte a utc sumando
        return time + timezone_offset
    

# sender de mails, tomado de celery tasks
def no_reply_sender(email, subject, html_message):
    mail = EmailMessage(subject, html_message, to=[email])
    mail.content_subtype = 'html' # aclaracion de tipo de contenido
    mail.send()

###############################################################################################################
################################################ SIGNUP #######################################################
###############################################################################################################

# registro
class Signup(View):
    # si se rellena un login
    def post(self, request):     
        # consigo el form con los datos posteados
        form = SignupForm(request.POST)

        offset = float(request.POST["tz_offset"])

        # si el formulario es valido
        if form.is_valid():
            # tomo los datos
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            email = form.cleaned_data['email']
            username = form.cleaned_data['username']
            password1 = form.cleaned_data['password1']
            password2 = form.cleaned_data['password2']

            # creo el usuario
            User.objects.create_user(email=email, 
                                        username=username, 
                                        password=password1, 
                                        first_name= first_name, 
                                        last_name = last_name)
            # lo autentico y logueo
            user = auth.authenticate(username=username, password = password1)
            auth.login(request, user)
            # genero token de confirmacion de registro
            token = secrets.token_urlsafe(32)
            # lo guardo en la base de datos
            models.UsersTokens(user=user, signup_token=token).save()
            # genero offline user y
            # deshabilito al usuario hasta que verifique por mail
            models.isOnline(user=user, is_online = False).save()
            models.Timezone(user=user, timezone_offset=offset).save()
            user.is_active = False
            user.save()

            context = {"first_name": user.first_name, "username": user.username, "mail": user.email, "url": f"{request.build_absolute_uri('/')}user/signup-verification/{token}", "base": request.build_absolute_uri('/')}
            # mando mail
            no_reply_sender(email = user.email, subject='¡Confirmá tu registro!', html_message=render_to_string("user_mngmnt/auth/confirmacion_signup.html", context))

            # redirijo a pestaña a continuación
            return render(request, 'user_mngmnt/auth/signup-verification.html')
    
            
        # si el form no es válido
        else:
            # codigo de error
            try:
                # intento encontrar mensaje de error
                error = form.errors.as_data()['__all__'][0].message
            # si no lo encuentro
            except:
                # hago diccionario de errores
                errors = form.errors.as_data()
                # para cada error
                for i in errors:
                    # busco el ultimo mensaje
                    error = errors[i][0].message
                # si el mensaje es el mencionado abajo
                if error == 'This field is required.':
                    # devuelvo error
                    error = 'Caracteres no validos'

            # retorno con codigo de error
            return render(request, 'user_mngmnt/auth/signup.html', {'form': form, 'error': error})
            
        
    # si entro a la web con un GET
    def get(self, request, *args, **kwargs):
        # armo template
        form = SignupForm()
        return render(request, 'user_mngmnt/auth/signup.html', {'form': form})


# verificacion de registro
class SignupVerification(View):
    def get(self, request, token):
        # busco en la tabla de tokens un token igual al ingresado
        data = models.UsersTokens.objects.filter(signup_token=token)
        # si el token esta entre los tokens guardados
        if data and token in data[0].signup_token:
            user = data[0].user
            # activo al usuario
            user.is_active = True
            user.save()
            # borro el token
            models.UsersTokens.objects.filter(signup_token = token).delete()
            # aviso por mail que el usuario se ha verificado
            no_reply_sender(email=user.email, subject="¡Tu cuenta se ha verificado!", html_message=f"""
¡Felicidades, {user.first_name}! El usuario de Solar Link {user.username} se ha verificado. ¡Ya podés acceder a la plataforma!""")
            # devuelvo que el usuario se registro adecuadamente
            return render(request, 'user_mngmnt/auth/signup-verification.html')
        # si no hay token o es invalido, devuelvo signup
        else:
            return redirect('signup')

###############################################################################################################
########################################### PASSWORD RESET ####################################################
###############################################################################################################

# Password reset
class PasswordReset(View):
    # vista del password reset
    def get(self, request):
        return render(request, "user_mngmnt/auth/password-reset.html")
    
    # posteo de form para resetear contrasenia
    def post(self, request):
        # tomo mail
        email = request.POST['email']
        # busco usuarios con ese mail
        users = User.objects.filter(email=email)
        # si hay usuarios
        if users:
            # para cada usuario
            for user in users:
                # genero token
                token = secrets.token_urlsafe(32)
                # guardo token a usuario
                models.UsersTokens(user=user, password_reset_token=token).save()

                context = {"first_name": user.first_name, "username": user.username, "mail": user.email, "url": f"{request.build_absolute_uri('/')}user/password-set/{token}", "base": request.build_absolute_uri('/')}
                # mando mail
                no_reply_sender(email = user.email, subject='Cambio de contraseña', html_message=render_to_string("user_mngmnt/auth/confirmacion_password.html", context))
        # devuelvo vista con booleano para avisar que ya se envió mail
        return render(request, 'user_mngmnt/auth/password-reset-done.html')
    
# Cambio de contrasenia, genera token
class PasswordSet(View):

    # vista de cambio de contrasenia
    def get(self, request, token):
        # busco si hay pedidos de cambio de contraseña con ese token
        data = models.UsersTokens.objects.filter(password_reset_token = token)
        # si hay, y el token es valido
        if data and token in data[0].password_reset_token:
            # armo form
            form = PasswordSetForm()
            # devuelvo form con el token en ctx para postear
            return render(request, 'user_mngmnt/auth/password-set.html', {"form":form, "token":token})
        else:
            # si no, redirijo a index
            return redirect('login')
        

    # post del form para cambio de contrasenia
    def post(self, request, token):
        # armo form con parametros posteados
        form = PasswordSetForm(request.POST)
        # si el form es valido
        if form.is_valid():
            # tomo nueva contraseña
            new_password = form.cleaned_data['password1']
            # busco los datos del token ingresado
            data = models.UsersTokens.objects.filter(password_reset_token = token)
            # tomo el usuario de ese token
            user = data[0].user
            # le cambio la contraseña y guardo
            user.set_password(new_password)
            user.save()
            # borro token
            models.UsersTokens.objects.filter(password_reset_token = token).delete()
            # devuelvo vista con booleano para la vista de success
            return render(request, 'user_mngmnt/auth/password-set-done.html')
        # si el form no es valido
        else:
            # devuelvo mensaje de error
            error = form.errors.as_data()['__all__'][0].message
            # se carga vista, se vuelve a mandar token para seguir pudiendo postear aun con intentos fallidos!!
            return render(request, 'user_mngmnt/auth/password-set.html', {'form':form, 'error': error, "token": token})
            

###############################################################################################################
################################################ LOGIN ########################################################
###############################################################################################################

# pagina de login /user/login/
class Login(View):

    def get(self, request):
        form = LoginForm()
        return render(request, "user_mngmnt/auth/login.html", {"form":form})
    
    def post(self, request):
        form = LoginForm(request.POST)

        # si el form es valido
        if form.is_valid():
            #obtengo user y pass
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            # autentico si existe usuario
            user = auth.authenticate(username=username, password = password)
            # logueo
            auth.login(request, user)
            # redirijo a index
            return redirect('userpage')
        # si el form no es valido
        else:
            # codigo de error
            try:
                # intento encontrar mensaje de error
                error = form.errors.as_data()['__all__'][0].message
            # si no lo encuentro
            except:
                # hago diccionario de errores
                errors = form.errors.as_data()
                # para cada error
                for i in errors:
                    # busco el ultimo mensaje
                    error = errors[i][0].message
                # si el mensaje es el mencionado abajo
                if error == 'This field is required.':
                    # devuelvo error
                    error = 'Caracteres no validos'
                
            return render(request, 'user_mngmnt/auth/login.html', {"form": form, 'error': error})


# logout
@login_required
def logout(request):
    auth.logout(request)
    return redirect('index')

###############################################################################################################
################################################ DATOS ########################################################
###############################################################################################################

# pagina de usuario /user/datos/
class UserPage(View):
    def get(self, request):
        # usuario
        user = request.user
        # offset de timezone
        tz_offset = user.timezone.timezone_offset
        # ahora en UTC
        now = timezone.now()
        # tiempo actual, pero con +3 hs de offset para tomar solo datos en el TZ del usuario
        now_for_filter = tz_to_utc(now, tz_offset)
        # ahora en el tz del usuario
        now_on_tz = utc_to_tz(now, tz_offset)
        # comienzo del dia en el que el usuario esta ahora
        today_start_tz = tz_to_utc(timezone.datetime(now_on_tz.year, now_on_tz.month, now_on_tz.day, 0, 0, 0), tz_offset)

        # filtro los datos entre el comienzo del dia del usuario, y ahora
        today_data = models.DatosHora.objects.filter(user = user, time__range = [today_start_tz, now_for_filter])

        ###################### HOY ######################
        # variables
        total_proveedor_semana = 0
        total_solar_semana = 0
        dict_hoy = []
        # para cada hora del dia, creo un dato
        for i in range(0, 24):
            dict_hoy.append({"hora": i,
                            "consumo_l1_proveedor": 0,
                            "consumo_l2_proveedor": 0,
                            "consumo_l1_solar": 0,
                            "consumo_l2_solar": 0})
        
        # para cada dato del dia de hoy, sobreescribo el dato creado por el de la db, si lo hay
        for data in today_data:
            dict_hoy[utc_to_tz(data.time, tz_offset).hour] = {"hora": utc_to_tz(data.time, tz_offset).hour,
                             "consumo_l1_proveedor": data.consumo_l1_proveedor,
                             "consumo_l2_proveedor":data.consumo_l2_proveedor,
                             "consumo_l1_solar": data.consumo_l1_solar,
                             "consumo_l2_solar": data.consumo_l2_solar}
            total_proveedor_semana += data.consumo_hora_red
            total_solar_semana += data.consumo_hora_solar

        # listas para pasar ctx al frontend
        consumo_l1_solar = []
        consumo_l2_solar = []
        consumo_l1_proveedor = []
        consumo_l2_proveedor = []
        
        # apendo en lista para contexto
        for i in dict_hoy:
            consumo_l1_solar.append(i["consumo_l1_solar"])
            consumo_l2_solar.append(i["consumo_l2_solar"])
            consumo_l1_proveedor.append(i["consumo_l1_proveedor"])
            consumo_l2_proveedor.append(i["consumo_l2_proveedor"])

        # contexto
        context = {}
        if today_data:
            context["datos_hoy"] = True
            context["consumo_l1_solar"] = consumo_l1_solar
            context["consumo_l2_solar"] = consumo_l2_solar
            context["consumo_l1_prov"] = consumo_l1_proveedor
            context["consumo_l2_prov"] = consumo_l2_proveedor

        else:
            context["datos_hoy"] = False

        ###################### SEMANA ######################


        # tiempo de hace una semana, pero adaptado a timezone para filtrar en la database
        a_week_ago_for_filter = today_start_tz - timezone.timedelta(days=7)
        # datos de toda la semana entre el timezone del usuario
        week_data = models.DatosHora.objects.filter(user = user, time__range=[a_week_ago_for_filter, now_for_filter])

        # variables para ctx
        consumo_semanasolar = []
        consumo_semanaproveedor = []
        consumo_diasolar = 0
        consumo_diaproveedor = 0
        dias = []

        # inicio del dia
        day_start = a_week_ago_for_filter

        # para cada dia desde hoy hasta hace una semana
        for i in range(1, 8):
            # final del dia
            day_end = a_week_ago_for_filter + timezone.timedelta(days=i)
            # filtro entre el inicio y el final del dia
            day_data = week_data.filter(time__range=[day_start, day_end])
            # dia y mes en formato DD/MM string, pasado al timezone del usuario
            dias.append(f"{utc_to_tz(day_start, tz_offset).day}/{utc_to_tz(day_start, tz_offset).month}")
            # calculo consumo del proveedor y solar
            for data in day_data:
                consumo_diaproveedor += data.consumo_hora_red
                consumo_diasolar += data.consumo_hora_solar
            

            # apendo para ctx
            consumo_semanaproveedor.append(consumo_diaproveedor)
            consumo_semanasolar.append(consumo_diasolar)
            consumo_diaproveedor = 0
            consumo_diasolar = 0
            
            # start en este dia para filtrar el siguiente
            day_start = day_end
        
        # contexto
        if week_data:
            context["datos_7dias"] = True
            context["semanasolar"] = consumo_semanasolar
            context["semanaprov"] = consumo_semanaproveedor
            context["porcentaje_ahorro"] = round(sum(consumo_semanasolar)/sum(consumo_semanaproveedor) * 100, 2)
            context["dias"] = dias
            context["total_semanasolar"] = int(sum(consumo_semanasolar))
            context["total_semanaprov"] = int(sum(consumo_semanaproveedor))
        else:
            context["datos_7dias"] = False

        ####################### AGNO #######################

        # inicio del agno en el timezone del usuario
        year_start = tz_to_utc(timezone.datetime(year = now_for_filter.year, month = 1, day = 1), tz_offset)
        # final del agno en el timezone del usuario
        year_end = year_start + dateutil.relativedelta.relativedelta(years=1)
        
        # datos de todos el agno
        year_data = models.DatosHora.objects.filter(user = user, time__range=[year_start, year_end])

        # variables
        consumo_messolar = 0
        consumo_mesproveedor = 0
        consumo_ahorrado_meses = []
        consumo_prov_meses = []
        month_start = year_start

        # para cada mes del agno
        for i in range(1, 13):
            # un mes dsps del inicio
            month_end = month_start + dateutil.relativedelta.relativedelta(months=1)

            # datos del mes
            month_data = year_data.filter(time__range = [month_start, month_end])

            # para cada dato del mes, sumo a la variable mensual
            for data in month_data:
                consumo_mesproveedor += data.consumo_l1_proveedor + data.consumo_l2_proveedor
                consumo_messolar += data.consumo_l1_solar + data.consumo_l2_solar

            # guardo datos en lista de los meses, paso a kW/h
            consumo_prov_meses.append(consumo_mesproveedor / 1000)
            consumo_ahorrado_meses.append(consumo_messolar / 1000)

            # reinicio variables
            consumo_mesproveedor = 0
            consumo_messolar = 0

            # nuevo mes de inicio
            month_start = month_end

        # contexto
        if year_data:
            context["datos_anual"] = True
            context["consumo_ahorrado_meses"] = consumo_ahorrado_meses
            context["consumo_prov_meses"] = consumo_prov_meses
        else:
            context["datos_anual"] = False


        return render(request, "user_mngmnt/index.html", context)

        
###############################################################################################################
################################################# API #########################################################
###############################################################################################################

# API para pedir a la db datos del tablero del usuario
class APIData(View):
    def get(self, request):
        # usuario
        user = request.user
        # offset de timezone en db
        tz_offset = user.timezone.timezone_offset
        # ahora en UTC
        now = timezone.now()

        # tiempo actual en el tz del usuario
        now_on_tz = utc_to_tz(now, tz_offset)


        ###################### HOY ######################

        # comienzo del dia del tz que el usuario esta ahora, en utc
        today_start_tz = tz_to_utc(timezone.datetime(now_on_tz.year, now_on_tz.month, now_on_tz.day, 0, 0, 0), tz_offset)


        # filtro los datos entre el comienzo del dia en el tz del usuario, y ahora
        today_data = models.DatosHora.objects.filter(user = user, time__range = [today_start_tz, today_start_tz + dateutil.relativedelta.relativedelta(hours=24)])

        
        # contexto a enviar
        context = {}


        data_day = []
        # para cada hora del dia, creo un dato
        for i in range(0, 24):
            data_day.append({"hora": i,
                            "consumo_l1_proveedor": 0,
                            "consumo_l2_proveedor": 0,
                            "consumo_l1_solar": 0,
                            "consumo_l2_solar": 0})
        
        # para cada dato del dia de hoy, sobreescribo el dato creado por el de la db, si lo hay
        for data in today_data:
            data_day[utc_to_tz(data.time, tz_offset).hour] = {"hora": utc_to_tz(data.time, tz_offset).hour,
                             "consumo_l1_proveedor": data.consumo_l1_proveedor,
                             "consumo_l2_proveedor":data.consumo_l2_proveedor,
                             "consumo_l1_solar": data.consumo_l1_solar,
                             "consumo_l2_solar": data.consumo_l2_solar}


        # seccion hoy
        context["today"] = {}
        if today_data:
            context["today"]["is_data"] = True
            context["today"]["data"] = data_day

        else:
            context["today"]["is_data"] = False

        ###################### SEMANA ######################


        # tiempo de hace una semana, pero adaptado a timezone para filtrar en la database
        a_week_ago_tz = today_start_tz - timezone.timedelta(days=7)
        # datos de toda la semana entre el timezone del usuario
        week_data = models.DatosHora.objects.filter(user = user, time__range=[a_week_ago_tz, today_start_tz])
 
        # datos semanales finales
        data_week = []
        # para cada dia desde hoy hasta hace una semana
        for i in range(1, 8):
            # vars
            consumo_dia_solar = 0
            consumo_dia_proveedor = 0

            # inicio del dia a ver
            day_start = a_week_ago_tz + timezone.timedelta(days=i-1)
            # final del dia a ver
            day_end = a_week_ago_tz + timezone.timedelta(days=i)
            # filtro entre el inicio y el final del dia
            day_data = week_data.filter(time__range=[day_start, day_end])
            # dia y mes en formato DD/MM string, en el tz del usuario
            dia = f"{utc_to_tz(day_start, tz_offset).day}/{utc_to_tz(day_start, tz_offset).month}"
            # calculo consumo del proveedor y solar del dia, sumando el de cada hora
            for data in day_data:
                consumo_dia_proveedor += data.consumo_hora_red
                consumo_dia_solar += data.consumo_hora_solar
            
            # apendo un dict del dia a la lista
            data_week.append({"dia": dia, "consumo_dia_proveedor": consumo_dia_proveedor, 
                            "consumo_dia_solar": consumo_dia_solar})
            
            
        
        context["week"] = {}
        # contexto
        if week_data:
            context["week"]["is_data"] = True
            context["week"]["data"] = data_week
        else:
            context["week"]["is_data"] = False

        ####################### AGNO #######################

        # inicio del agno en el timezone del usuario
        year_start = tz_to_utc(timezone.datetime(year = now_on_tz.year, month = 1, day = 1), tz_offset)
        # final del agno en el timezone del usuario
        year_end = year_start + dateutil.relativedelta.relativedelta(years=1)
        
        # datos de todos el agno
        year_data = models.DatosHora.objects.filter(user = user, time__range=[year_start, year_end])

        data_year = []

        # para cada mes del agno
        for i in range(1, 13):
            # vars
            consumo_mes_solar = 0
            consumo_mes_proveedor = 0

            # inicio de cada mes
            month_start = year_start + dateutil.relativedelta.relativedelta(months=i-1)
            # un mes dsps del inicio
            month_end = year_start + dateutil.relativedelta.relativedelta(months=i)

            # datos del mes
            month_data = year_data.filter(time__range = [month_start, month_end])

            # para cada dato del mes, sumo a la variable mensual
            for data in month_data:
                consumo_mes_proveedor += data.consumo_l1_proveedor + data.consumo_l2_proveedor
                consumo_mes_solar += data.consumo_l1_solar + data.consumo_l2_solar

            # guardo datos en lista de los meses, paso a kW/h
            data_year.append({"month": i, "consumo_mes_proveedor": consumo_mes_proveedor / 1000, 
                              "consumo_mes_solar": consumo_mes_solar / 1000})

        context["year"] = {}
        # contexto
        if year_data:
            context["year"]["is_data"] = True
            context["year"]["data"] = data_year
        else:
            context["year"]["is_data"] = False

        print(timezone.now())
        return JsonResponse(context)
    
# API para actualizar status offline-online de un usuario
class OnlineUsersUpdate(View):
    # pone usuario offline
    def post(self, request):
        # usuario
        user = request.user
        # offline
        user.isonline.is_online = False
        # guardo
        user.isonline.save()
        # borro los datos recibidos desde el solar link en tiempo real
        models.TiempoReal.objects.filter(user=user).delete()

        return JsonResponse({"response":True})

    # pone usuario online
    def get(self, request):
        # usuario
        user = request.user
        # seteo online
        user.isonline.is_online = True
        # guardo
        user.isonline.save()

        return JsonResponse({"response":True})

# API para retornar si el usuario esta o no conectado
class shouldPost(View):
    def get(self, request):
        # si el contenido esta en post
        if request.GET:
            # usuario posteado
            data = request.GET
        # si el contenido esta en body
        if request.body and not request.GET:
            data = json.loads(request.body)

        username = data["username"]
        password = data["password"]

        # autentico
        user = auth.authenticate(username=username, password=password)

        # si el usuario esta logueado, mando True
        return JsonResponse({"response": user.isonline.is_online})

# API para subir datos hora a nombre del usuario
class LoadData(View):

    def post(self, request):
        # si el contenido esta en post
        if request.POST:
            # usuario posteado
            self.data = request.POST
            
        # si el contenido esta en body
        if request.body and not request.POST:
            data = json.loads(request.body)

        # usuario y contrasenia
        username = data["username"]
        password = data["password"]

        # autentico
        user = auth.authenticate(username=username, password=password)
        # si existe el usuario
        if user:
            # guardo datos
            models.DatosHora(
                user = user,
                voltaje_hora_red = data["voltaje_hora_red"],
                consumo_hora_solar = data["consumo_hora_solar"],
                consumo_hora_red = data["consumo_hora_red"],
                consumo_l1_solar = data["consumo_l1_solar"],
                consumo_l2_solar = data["consumo_l2_solar"],
                consumo_l1_proveedor = data["consumo_l1_proveedor"],
                consumo_l2_proveedor = data["consumo_l2_proveedor"],
                time = timezone.now(),
                solar_ahora = data["solar_ahora"]).save()      

        return JsonResponse({"status": True})



# API para ver dato del tablero en tiempo real o subirlos
class DataNow(View):
    # retorna ultimo dato en tiempo real
    def get(self, request):
        # user
        user = request.user
        # datos en tiempo real del usuario
        data = models.TiempoReal.objects.filter(user=user)
        # si hay datos
        if data:
            # se toma el ultimo
            for d in data:
                now = d
            # se devuelven datos actuales
            response = {"voltaje": now.voltaje,
                        "consumo_l1": now.consumo_l1,
                        "consumo_l2": now.consumo_l2,
                        "solar": (now.solar_l1 or now.solar_l2)}
            # retorno datos
            return JsonResponse(response)
        # si no hay datos, devuelvo false
        else:
            return JsonResponse({"response": False})
        
    # sube dato en tiempo real a la db
    def post(self, request):
        # si el contenido esta en post
        if request.POST:
            # usuario posteado
            data = request.POST
            
        # si el contenido esta en body
        if request.body and not request.POST:
            data = json.loads(request.body)
        
        data = dict(data)

        username = data["username"]
        password = data["password"]
        voltaje = data["voltaje"]
        consumo_l1 = data["consumo_l1"]
        consumo_l2 = data["consumo_l2"]
        solar_l1 = data["solar_l1"]
        solar_l2 = data["solar_l2"]
        
        user = auth.authenticate(username = username, password=password)

        models.TiempoReal(user=user,
                          voltaje=voltaje,
                          consumo_l1 = consumo_l1,
                          consumo_l2 = consumo_l2,
                          solar_l1 = solar_l1,
                          solar_l2 = solar_l2).save()
        
        return JsonResponse({"status": True})

# API para validacion de usuarios
class APILogin(View):
    async def post(self, request):
        # si el contenido esta en post
        if request.POST:
            # usuario posteado
            username = request.POST["username"]
            password = request.POST["password"]
        # si el contenido esta en body
        if request.body and not request.POST:
            async_json_loads = sync_to_async(json.loads, thread_sensitive=False)
            username = (await async_json_loads(request.body))["username"]
            password = (await async_json_loads(request.body))["password"]

        # autentico
        async_auth = sync_to_async(auth.authenticate, thread_sensitive=False)
        user = await async_auth(username=username, password=password)

        # si existe el usuario, respondo aprobación
        if user:
            response = {"login": True}
        else:
            response = {"login": False}
        
        return JsonResponse(response)
    

###############################################################################################################
################################################ CRONS ########################################################
###############################################################################################################

# ADAPTACION DE CRON JOBS A VIEWS YA QUE VERCEL NO SOPORTA CELERY

def token_clean(request):
    # todos los tokens activos
    data = models.UsersTokens.objects.all()
    # hora en timezone
    actual = timezone.now()
    # para cada dato
    for d in data:
        # si el tiempo entre que el token fue creado y el actual es mayor a 1h
        if (actual - d.time) > timezone.timedelta(hours=1):
            # borro el token
            d.delete()


###############################################################################################################
################################################ TOOLS ########################################################
###############################################################################################################

def creador(request):
    user = request.user
    
    models.DatosHora(user = user,
                     voltaje_hora_red = 200,
                     consumo_hora_solar = 400,
                     consumo_hora_red = 500,
                     consumo_l1_solar = 300,
                     consumo_l1_proveedor = 300,
                     consumo_l2_solar = 400,
                     consumo_l2_proveedor = 500,
                     time = timezone.datetime(2024, 10, 2, 12, tzinfo=timezone.utc)).save()

    models.DatosHora(user = user,
                     voltaje_hora_red = 200,
                     consumo_hora_solar = 400,
                     consumo_hora_red = 500,
                     consumo_l1_solar = 300,
                     consumo_l1_proveedor = 300,
                     consumo_l2_solar = 400,
                     consumo_l2_proveedor = 500,
                     time = timezone.datetime(2024, 10, 2, 2)).save()
    
    models.DatosHora(user = user,
                     voltaje_hora_red = 200,
                     consumo_hora_solar = 400,
                     consumo_hora_red = 500,
                     consumo_l1_solar = 300,
                     consumo_l1_proveedor = 300,
                     consumo_l2_solar = 400,
                     consumo_l2_proveedor = 500,
                     time = timezone.datetime(2024, 10, 2, 4)).save()
    models.DatosHora(user = user,
                     voltaje_hora_red = 200,
                     consumo_hora_solar = 400,
                     consumo_hora_red = 500,
                     consumo_l1_solar = 300,
                     consumo_l1_proveedor = 300,
                     consumo_l2_solar = 400,
                     consumo_l2_proveedor = 500,
                     time = timezone.datetime(2024, 10, 2, 3)).save()

                
def sender(request):
    no_reply_sender('ivanchicago70@gmail.com', 'nashe', 'nashe')
    #mail = EmailMessage('Hola', 'hola', to=['ivanchicago70@gmail.com'])
    #mail.content_subtype = 'html' # aclaracion de tipo de contenido
    #mail.send()

