
import requests
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import redirect
from django.template.loader import render_to_string

from usuarios.models import ProductoVenta, Productos, Soporte, UserProfile, TransaccionWebpay, Venta
from .serializers import GoogleRegisterSerializer, SoporteSerializer,LoginSerializer, VentaConProductosSerializer, VentaEstadoSerializer, VentaSerializer, TransaccionWebpaySerializer,ProductoSerializer, UserSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer,UserReadOnlySerializer
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.utils.encoding import force_bytes
from django.core.mail import send_mail

from django.conf import settings
from django.views import View
from django.http import JsonResponse
import json
from django.middleware.csrf import get_token
from django.utils.decorators import method_decorator
from django.db import transaction
import uuid
from base64 import b64encode

from rest_framework.generics import ListAPIView

import logging
from rest_framework.viewsets import ModelViewSet
from rest_framework.decorators import action

logger = logging.getLogger(__name__)
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.decorators.csrf import csrf_exempt


class RegistroUsuario(generics.CreateAPIView):
    """
    Vista para registrar un nuevo usuario.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer

class LoginView(APIView):
    """
    Vista de inicio de sesión. Valida las credenciales y genera tokens de autenticación.
    """
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        tokens = serializer.validated_data  # Tokens devueltos por el serializador en caso de éxito
        return Response(tokens, status=status.HTTP_200_OK)

def activate_account(request, uidb64, token):
    """
    Activa la cuenta del usuario utilizando el uidb64 y token.
    """
    try:
        # Decodifica el UID y busca al usuario
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    # Verifica el token y activa la cuenta
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        # Redirige al cliente Angular con un parámetro indicando éxito
        return redirect('http://localhost:4200/autenticacion?status=success')
    else:
        # Redirige al cliente Angular con un parámetro indicando fallo
        return redirect('http://localhost:4200/autenticacion?status=error')

class UserProfileView(APIView):
    """
    Vista para obtener el perfil del usuario autenticado.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user  # Instancia del usuario autenticado
        serializer = UserSerializer(user)  # Serializa los datos del usuario
        user_data = serializer.data
        user_data["is_admin"] = user.is_superuser  # Verifica si el usuario es administrador
        return Response(user_data, status=status.HTTP_200_OK)
    
class PasswordResetView(APIView):
    """
    Vista para solicitar la recuperación de contraseña.
    """
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Obtén el email validado
        email = serializer.validated_data['email']
        try:
            # Verificar que el usuario existe
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"error": "No hay ningún usuario registrado con este correo."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Generar token y UID
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))  # Ahora uid es un string
        print(f"UID generado: {uid}")

        # Generar el enlace de recuperación
        reset_link = f"http://localhost:4200/password-reset-confirm/{uid}/{token}"
        print(f"Enlace generado: {reset_link}")

        html_message = f"""
            <html>
            <body style="font-family: Arial, sans-serif; text-align: center; background-color: #f9f9f9; padding: 20px;">
                <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1); padding: 20px;">
                    <img src="https://i.ibb.co/FzPs1mR/logo.png" width="80">
                    <h2 style="color: #333;">Restauración de Contraseña</h2>
                    <p style="color: #555;">Hola,</p>
                    <p style="color: #555;">Hemos recibido una solicitud para restaurar tu contraseña. Si no realizaste esta solicitud, ignora este correo.</p>
                    <p style="color: #555;">Haz clic en el botón de abajo para restaurar tu contraseña:</p>
                    <a href="{reset_link}" 
                    style="display: inline-block; background-color: #007bff; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin-top: 20px; font-weight: bold;">
                    Restaurar Contraseña
                    </a>
                    <p style="margin-top: 20px; color: #555;">Este enlace es válido por 24 horas.</p>
                    <p style="color: #555;">Si el botón no funciona, copia y pega el siguiente enlace en tu navegador:</p>
                    <p style="color: #007bff; word-wrap: break-word;">{reset_link}</p>
                    <p style="margin-top: 20px; color: #333;"><strong>Saludos,<br>Bermellona Accesorios</strong></p>
                </div>
            </body>
            </html>
            """
        try:
            # Enviar correo
            send_mail(
                subject="Restauración de contraseña",
                message="",
                from_email="noreply@example.com",
                recipient_list=[email],
                html_message=html_message,
                fail_silently=False,
            )
        except Exception as e:
            print(f"Error al enviar correo: {e}")
            return Response(
                {"error": "Ocurrió un error al enviar el correo."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response(
            {"message": "Se ha enviado un enlace de recuperación a tu correo."},
            status=status.HTTP_200_OK
        )

class PasswordResetConfirmView(APIView):
    """
    Vista para confirmar el cambio de contraseña.
    """
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"message": "Contraseña actualizada con éxito."}, status=status.HTTP_200_OK)

class IniciarPagoView(View):
    def post(self, request):
        try:
            logger.debug(f"Cookies recibidas: {request.COOKIES}")
            logger.debug(f"Encabezados recibidos: {request.headers}")
            csrf_cookie = request.COOKIES.get('csrftoken')
            csrf_header = request.headers.get('X-CSRFToken')
            print(f"Token en la cookie: {csrf_cookie}")
            print(f"Token en el encabezado: {csrf_header}")

            if csrf_cookie != csrf_header:
                logger.error("El token CSRF en la cookie no coincide con el encabezado")
                return JsonResponse({'error': 'CSRF token mismatch'}, status=403)

            payload = json.loads(request.body)
            buy_order = payload.get('buy_order')
            session_id = payload.get('session_id')
            amount = payload.get('amount')
            return_url = payload.get('return_url')

            # Validar los datos recibidos
            if not all([buy_order, session_id, amount, return_url]):
                return JsonResponse({'error': 'Datos incompletos'}, status=400)

            # Realizar la solicitud a Webpay
            url = 'https://webpay3gint.transbank.cl/rswebpaytransaction/api/webpay/v1.2/transactions'
            headers = {
                'Tbk-Api-Key-Id': settings.TBK_API_KEY_ID,
                'Tbk-Api-Key-Secret': settings.TBK_API_KEY_SECRET,
                'Content-Type': 'application/json',
            }
            payload = {
                'buy_order': buy_order,
                'session_id': session_id,
                'amount': amount,
                'return_url': return_url,
            }
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                data = response.json()
                return JsonResponse({'url': data['url'], 'token': data['token']})
            else:
                return JsonResponse({'error': 'Error al iniciar pago', 'details': response.text}, status=response.status_code)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Formato de datos inválido'}, status=400)

class ConfirmarPagoView(View):
    def put(self, request, token):
        # Endpoint de Transbank para confirmar transacciones
        url = f'https://webpay3gint.transbank.cl/rswebpaytransaction/api/webpay/v1.2/transactions/{token}'

        # Cabeceras requeridas por Transbank
        headers = {
            'Tbk-Api-Key-Id': settings.TBK_API_KEY_ID,  # Clave pública
            'Tbk-Api-Key-Secret': settings.TBK_API_KEY_SECRET,  # Clave privada
            'Content-Type': 'application/json',
        }

        # Realizar la solicitud PUT a Transbank
        response = requests.put(url, headers=headers)

        if response.status_code == 200:
            # Éxito: La transacción fue confirmada
            data = response.json()
            return JsonResponse({'status': 'success', 'data': data})
        elif response.status_code == 402:
            # Error de autorización de la transacción
            return JsonResponse({'status': 'error', 'message': 'Transacción no autorizada.'}, status=402)
        elif response.status_code == 409:
            # Error por estado inconsistente
            return JsonResponse({'status': 'error', 'message': 'Estado inconsistente de la transacción.'}, status=409)
        else:
            # Otros errores
            return JsonResponse({'status': 'error', 'message': response.text}, status=response.status_code)
        
def csrf_view(request):
    csrf_token = get_token(request)
    return JsonResponse({'csrftoken': csrf_token})

class ProductoViewSet(ModelViewSet):

    """
    ViewSet para manejar los productos.
    """
    queryset = Productos.objects.all()
    serializer_class = ProductoSerializer

    def perform_create(self, serializer):
        # Personaliza la lógica al crear un producto
        serializer.save()

    def perform_update(self, serializer):
        # Personaliza la lógica al actualizar un producto
        serializer.save()

    def perform_destroy(self, instance):
        # Personaliza la lógica al eliminar un producto
        instance.delete()

    @action(detail=False, methods=['get'], url_path='destacados')
    def destacados(self, request):
        """
        Obtiene los productos destacados.
        """
        destacados = self.queryset.filter(destacado=True)
        serializer = self.get_serializer(destacados, many=True)
        return Response(serializer.data)
    
class UserListView(ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserReadOnlySerializer

class ToggleUserStatusView(APIView):
    def post(self, request, *args, **kwargs):
        # Obtener el ID del usuario y la acción (activar/desactivar) desde la solicitud
        user_id = request.data.get('id')
        action = request.data.get('action')  # "activar" o "desactivar"

        if not user_id or not action:
            return Response(
                {'error': 'ID de usuario y acción son requeridos'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Buscar al usuario por ID
            user = User.objects.get(id=user_id)

            if action == 'activar':
                user.is_active = True
                user.save()
                return Response(
                    {'message': f'El usuario {user.username} ha sido activado correctamente'},
                    status=status.HTTP_200_OK
                )
            elif action == 'desactivar':
                user.is_active = False
                user.save()
                return Response(
                    {'message': f'El usuario {user.username} ha sido desactivado correctamente'},
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {'error': 'Acción no válida. Usa "activar" o "desactivar"'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except User.DoesNotExist:
            return Response({'error': 'Usuario no encontrado'}, status=status.HTTP_404_NOT_FOUND)


class PasswordResetRequestView(APIView):
    """
    Endpoint para solicitar un correo de restauración de contraseña.
    """
    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({"error": "El correo electrónico es obligatorio."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "No existe un usuario registrado con este correo."}, status=status.HTTP_404_NOT_FOUND)

        # Generar token y UID
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Generar enlace de restauración
        reset_link = f"http://localhost:4200/password-reset-confirm/{uid}/{token}"

        # Enviar el correo

        html_message = f"""
            <html>
            <body style="font-family: Arial, sans-serif; text-align: center; background-color: #f9f9f9; padding: 20px;">
                <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1); padding: 20px;">
                    <img src="https://i.ibb.co/FzPs1mR/logo.png" width="80">
                    <h2 style="color: #333;">Restauración de Contraseña</h2>
                    <p style="color: #555;">Hola,</p>
                    <p style="color: #555;">Hemos recibido una solicitud para restaurar tu contraseña. Si no realizaste esta solicitud, ignora este correo.</p>
                    <p style="color: #555;">Haz clic en el botón de abajo para restaurar tu contraseña:</p>
                    <a href="{reset_link}" 
                    style="display: inline-block; background-color: #007bff; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin-top: 20px; font-weight: bold;">
                    Restaurar Contraseña
                    </a>
                    <p style="margin-top: 20px; color: #555;">Este enlace es válido por 24 horas.</p>
                    <p style="color: #555;">Si el botón no funciona, copia y pega el siguiente enlace en tu navegador:</p>
                    <p style="color: #007bff; word-wrap: break-word;">{reset_link}</p>
                    <p style="margin-top: 20px; color: #333;"><strong>Saludos,<br>Bermellona Accesorios</strong></p>
                </div>
            </body>
            </html>
            """
        try:
            # Enviar correo
            send_mail(
                subject="Restauración de contraseña",
                message="",
                from_email="noreply@example.com",
                recipient_list=[email],
                html_message=html_message,
                fail_silently=False,
            )
        except Exception as e:
            return Response({"error": "Error al enviar el correo."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "Se ha enviado un enlace de restauración a tu correo."}, status=status.HTTP_200_OK)


class GoogleAuthView(APIView):
    """
    Autentica usuarios con Google.
    Si no existen, los registra automáticamente y genera tokens JWT.
    """
    def post(self, request):
        email = request.data.get('email')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')

        if not email:
            return Response({'error': 'El correo es requerido'}, status=status.HTTP_400_BAD_REQUEST)

        # Crear usuario si no existe
        user, created = User.objects.get_or_create(email=email, defaults={
            'first_name': first_name,
            'last_name': last_name,
            'username': email
        })

        # Generar tokens JWT
        refresh = RefreshToken.for_user(user)
        tokens = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

        # Serializar datos del usuario
        user_data = UserSerializer(user).data
        user_data['tokens'] = tokens
        return Response(user_data, status=status.HTTP_200_OK)


class SoporteViewSet(ModelViewSet):
    """
    ViewSet para manejar soporte
    """
    queryset = Soporte.objects.all()
    serializer_class = SoporteSerializer

    def perform_create(self, serializer):
        # Guarda la instancia del soporte
        soporte = serializer.save()

        # HTML para el correo del administrador
        admin_html_message = f"""
        <html>
        <body style="font-family: Arial, sans-serif; text-align: center; background-color: #f9f9f9; padding: 20px;">
            <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1); padding: 20px;">
                <img src="https://i.ibb.co/FzPs1mR/logo.png" width="80">
                <h2 style="color: #333;">Nuevo Requerimiento de Soporte</h2>
                <p style="color: #555;">Un nuevo requerimiento de soporte ha sido enviado con los siguientes detalles:</p>
                <div style="text-align: left; margin-top: 20px;">
                    <p><strong>N° Ticket:</strong> {soporte.codigo}</p>
                    <p><strong>Nombre:</strong> {soporte.nombre}</p>
                    <p><strong>Correo:</strong> {soporte.correo_electronico}</p>
                    <p><strong>Motivo:</strong> {soporte.motivo}</p>
                    <p><strong>Mensaje:</strong></p>
                    <p style="background-color: #f1f1f1; padding: 10px; border-radius: 4px;">{soporte.mensaje}</p>
                </div>
            </div>
        </body>
        </html>
        """

        # Enviar correo al administrador
        send_mail(
            subject='Nuevo requerimiento de soporte',
            message='',  # Se deja vacío porque usamos html_message
            from_email='cri.jimenez21@gmail.com',  # Correo desde el que se enviará
            recipient_list=['cri.jimenez24@gmail.com'],  # Correo del administrador
            html_message=admin_html_message,
            fail_silently=False,
        )

        # HTML para el correo del usuario
        user_html_message = f"""
        <html>
        <body style="font-family: Arial, sans-serif; text-align: center; background-color: #f9f9f9; padding: 20px;">
            <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1); padding: 20px;">
                <img src="https://i.ibb.co/FzPs1mR/logo.png" width="80">
                <h2 style="color: #333;">Confirmación de Recepción de Soporte</h2>
                <p style="color: #555;">Hola {soporte.nombre},</p>
                <p style="color: #555;">Hemos recibido tu solicitud de soporte con el siguiente detalle:</p>
                <div style="text-align: left; margin-top: 20px;">
                    <p><strong>N° Ticket:</strong> {soporte.codigo}</p>
                    <p><strong>Motivo:</strong> {soporte.motivo}</p>
                    <p><strong>Mensaje:</strong></p>
                    <p style="background-color: #f1f1f1; padding: 10px; border-radius: 4px;">{soporte.mensaje}</p>
                </div>
                <p style="margin-top: 20px; color: #555;">Pronto nos pondremos en contacto contigo. Gracias.</p>
                <p style="color: #333;"><strong>Saludos cordiales,<br>Bermellona Accesorios</strong></p>
            </div>
        </body>
        </html>
        """

        # Enviar correo al usuario que llenó el formulario
        send_mail(
            subject='Confirmación de recepción de soporte',
            message='',  # Se deja vacío porque usamos html_message
            from_email='tu_correo@gmail.com',  # Correo desde el que se enviará
            recipient_list=[soporte.correo_electronico],  # Correo del solicitante
            html_message=user_html_message,
            fail_silently=False,
        )


class UserProfileDetailView(APIView):
    """
    Vista para obtener el perfil del usuario basado en el identificador pasado.
    """

    def get(self, request, user_id):
        try:
            # Obtén el usuario basado en el ID proporcionado
            user = User.objects.get(id=user_id)
            # Serializa los datos del usuario
            serializer = UserReadOnlySerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "Usuario no encontrado."}, status=status.HTTP_404_NOT_FOUND)


class TransaccionWebpayViewSet(ModelViewSet):
    queryset = TransaccionWebpay.objects.all()
    serializer_class = TransaccionWebpaySerializer

@method_decorator(csrf_exempt, name='dispatch')
class GuardarVentaView(View):
    def post(self, request, *args, **kwargs):
        try:
            # Parsear los datos del cuerpo de la solicitud
            body = json.loads(request.body)

            # Extraer datos principales
            usuario_id = body.get('usuario')
            usuario = User.objects.get(id=usuario_id) if usuario_id else None  # Manejar caso de usuario=None

            # Crear la venta
            with transaction.atomic():
                venta = Venta.objects.create(
                    codigo = f"VENTA-{uuid.uuid4().hex[:8].upper()}",
                    rut_cliente=body.get('rut_cliente'),
                    nombre_cliente=body.get('nombre_cliente'),
                    apellido_cliente=body.get('apellido_cliente'),
                    email_cliente=body.get('email_cliente'),
                    opcion_entrega=body.get('opcion_entrega'),
                    region=body.get('region'),
                    comuna=body.get('comuna'),
                    calle=body.get('calle'),
                    celular=body.get('celular'),
                    descuento=body.get('descuento', 0.0),
                    valor_total=body.get('valor_total'),
                    estado=body.get('estado', 'pendiente'),
                    usuario=usuario,  # Será None si no se envía
                    tokenWebpay=body.get('tokenWebpay'),
                    metodo_pago=body.get('forma_pago'),
                )
                productos_guardados = []
                # Guardar los productos asociados a la venta
                for producto_data in body.get('productos', []):
                    producto = Productos.objects.get(id=producto_data['id'])

                    # Validar stock
                    if producto.cantidad < producto_data['cantidad']:
                        raise ValueError(f"Stock insuficiente para el producto {producto.nombre}.")

                    # Crear relación ProductoVenta
                    producto_venta = ProductoVenta.objects.create(
                        venta=venta,
                        producto=producto,
                        cantidad=producto_data['cantidad']
                    )
                    productos_guardados.append(producto_venta)

                    # Actualizar el stock del producto
                    producto.cantidad -= producto_data['cantidad']
                    producto.save()
                       # Enviar correo con el resumen de la venta

                enviar_resumen_venta(venta, productos_guardados)
            return JsonResponse({"status": "success", "venta_id": venta.id, "mensaje": "Venta guardada exitosamente."}, status=201)

        except Productos.DoesNotExist:
            return JsonResponse({"status": "error", "mensaje": "Producto no encontrado."}, status=404)
        except ValueError as e:
            return JsonResponse({"status": "error", "mensaje": str(e)}, status=400)
        except Exception as e:
            return JsonResponse({"status": "error", "mensaje": f"Error al procesar la venta: {str(e)}"}, status=500)

def obtener_url_absoluta_sin_request(ruta_relativa):
    """
    Construye una URL absoluta sin necesidad del objeto `request`.
    """
    base_url = getattr(settings, 'SITE_URL', 'http://127.0.0.1:8000')
    if not ruta_relativa.startswith('/'):
        ruta_relativa = '/' + ruta_relativa
    return base_url + ruta_relativa

def enviar_resumen_venta(venta, productos):
    """
    Envía un correo con el resumen de la venta al cliente.
    :param venta: Objeto de la venta
    :param productos: Lista de productos asociados
    """

    info_transferencia = ""
    if venta.metodo_pago == "transferencia":
        info_transferencia = f"""
        <h3>Información cuenta para transferir</h3>
        <p>Recordar transferir el monto total, a la siguiente cuenta, para que podamos procesar tu solicitud.</p>
        <p><strong>Banco:</strong>  Banco de Chile</p>
        <p><strong>Tipo:</strong>Cuenta corriente</p>
        <p><strong>Cuenta:</strong>123456789</p>
        <p><strong>Rut:</strong>12.345.678-9</p>
        <p><strong>Correo:</strong>pagos@bermellona.cl</p>
        <p style="color: red"><strong>*IMPORTANTE: Recordar incluir el código de venta en los comentarios de la transferencia. </strong></p>
        """

    # HTML para el correo
    correo_html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; text-align: center; background-color: #f9f9f9; padding: 20px;">
        <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1); padding: 20px;">
            <img src="https://i.ibb.co/FzPs1mR/logo.png" width="80">
            <h2 style="color: #333;">Resumen de tu Compra</h2>
            <p style="color: #555;">¡Gracias por tu compra, {venta.nombre_cliente}!</p>
            <div style="text-align: left; margin-top: 20px;">
                <p><strong>Código de Venta:</strong> {venta.codigo}</p>
                <p><strong>Fecha:</strong> {venta.fecha.strftime('%d-%m-%Y %H:%M')}</p>
                <p><strong>Método de pago:</strong> {venta.metodo_pago}</p>
                <p><strong>Estado:</strong> EN PROCESO DE COMPROBACIÓN</p>
                <p><strong>Total Pagado:</strong> ${venta.valor_total}</p>
                {info_transferencia}
                <h3 style="color: #333;">Productos:</h3>
                <ul style="list-style: none; padding: 0;">
    """

    # Agregar los productos al correo
    for producto in productos:

        correo_html += f"""
        <li style="margin-bottom: 10px; padding: 10px; background-color: #f1f1f1; border-radius: 4px;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <img src="https://i.ibb.co/XY3cY4J/image11.jpg" alt="{producto.producto.nombre}" width="60">
                <div>
                    <p><strong>{producto.producto.nombre}</strong></p>
                    <p>Precio Unitario: ${producto.producto.precio}</p>
                    <p>Cantidad: {producto.cantidad}</p>
                    <p><strong>Total: ${producto.cantidad * producto.producto.precio}</strong></p>
                </div>
            </div>
        </li>
        <hr>
        """


    # Cerrar el HTML
    correo_html += """
                </ul>
            </div>
            <p style="margin-top: 20px; color: #555;">Recibirás más actualizaciones como este cuando el estado de tu compra cambie.</p>
            <p style="margin-top: 20px; color: #555;">Gracias por confiar en nosotros.</p>
        </div>
    </body>
    </html>
    """

    # Enviar el correo
    try:
        send_mail(
            subject=f'Resumen de tu compra - {venta.codigo}',
            message='',  # Se deja vacío porque usamos html_message
            from_email='tomi.latin.99@gmail.com',  # Cambiar al correo configurado
            recipient_list=[venta.email_cliente],
            html_message=correo_html,
            fail_silently=False,
        )
        print("Correo enviado exitosamente.")
    except Exception as e:
        print(f"Error al enviar el correo: {e}")


class VentaListView(ListAPIView):
    queryset = Venta.objects.all()
    serializer_class = VentaSerializer


class VentaEstadoUpdateView(APIView):
    def patch(self, request, pk):
        try:
            venta = Venta.objects.get(pk=pk)
            serializer = VentaEstadoSerializer(venta, data=request.data, partial=True)

            if serializer.is_valid():
                serializer.save()

                # Enviar correo
                productos = ProductoVenta.objects.filter(venta=venta)
                enviar_cambia_estado(venta, productos)

                return Response({'message': 'Estado actualizado y correo enviado.'}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Venta.DoesNotExist:
            return Response({'error': 'Venta no encontrada.'}, status=status.HTTP_404_NOT_FOUND)

        
def enviar_cambia_estado(venta, productos):
    # Información adicional si el estado es "En despacho"
    envio_info = ""
    if venta.estado == "En despacho" and venta.numero_envio and venta.despachador:
        envio_info = f"""
        <h3>Información del Envío</h3>
        <p><strong>Número de Envío:</strong> {venta.numero_envio}</p>
        <p><strong>Despachador:</strong> {venta.despachador}</p>
        <p>Recuerde verificar el estado de su envio y el cobro por recibirlo, en la pagina de seguimiento del despachador.</p>
        """


    correo_html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; text-align: center; background-color: #f9f9f9; padding: 20px;">
        <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1); padding: 20px;">
            <img src="https://i.ibb.co/FzPs1mR/logo.png" width="80">
            <h2 style="color: #333;">Estado actualizado de tu compra</h2>
            <p style="color: #555;">¡Hola, {venta.nombre_cliente}!</p>
            <p>Tu estado de compra ha cambiado a: <strong>{venta.estado}</strong></p>
            <p><strong>Código de Venta:</strong> {venta.codigo}</p>
            <p><strong>Total Pagado:</strong> ${venta.valor_total}</p>
            {envio_info}
            <h3 style="color: #333;">Productos:</h3>
            <ul style="list-style: none; padding: 0;">
    """

    for producto in productos:
        correo_html += f"""
        <li style="margin-bottom: 10px; padding: 10px; background-color: #f1f1f1; border-radius: 4px;">
            <div style="text-align: left;">
                <p><strong>{producto.producto.nombre}</strong></p>
                <p>Precio Unitario: ${producto.producto.precio}</p>
                <p>Cantidad: {producto.cantidad}</p>
                <p><strong>Total: ${producto.cantidad * producto.producto.precio}</strong></p>
            </div>
        </li>
        <hr>
        """

    correo_html += """
                </ul>
                <p style="margin-top: 20px; color: #555;">Recibirás más actualizaciones cuando el estado de tu compra cambie.</p>
                <p style="margin-top: 20px; color: #555;">Gracias por confiar en nosotros.</p>
            </div>
        </div>
    </body>
    </html>
    """

    send_mail(
        subject=f'Actualización de tu compra - {venta.codigo}',
        message='',  # Se deja vacío porque usamos html_message
        from_email='tomi.latin.99@gmail.com',  # Cambiar al correo configurado
        recipient_list=[venta.email_cliente],
        html_message=correo_html,
        fail_silently=False,
    )

class VentasPorClienteView(APIView):
    """
    Devuelve las ventas asociadas a un cliente junto con los productos de cada venta.
    """

    def get(self, request, cliente_id):
        try:
            # Filtrar ventas por usuario asociado
            ventas = Venta.objects.filter(usuario_id=cliente_id)

            if not ventas.exists():
                return Response(
                    {"message": "No se encontraron ventas para este cliente."},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Serializar los datos incluyendo productos
            serializer = VentaConProductosSerializer(ventas, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class SoporteEstadoUpdateView(APIView):
    def patch(self, request, pk):
        try:
            soporte = Soporte.objects.get(pk=pk)
            nuevo_estado = request.data.get('estado')
            mensaje_resolucion = request.data.get('mensaje_resolucion')

            if not nuevo_estado or not mensaje_resolucion:
                return Response(
                    {'error': 'Debe proporcionar el estado y el mensaje de resolución.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Actualizar estado
            soporte.estado = nuevo_estado
            soporte.save()

            # HTML para el correo al cliente
            cliente_html_message = f"""
            <html>
            <body style="font-family: Arial, sans-serif; text-align: center; background-color: #f9f9f9; padding: 20px;">
                <div style="max-width: 600px; margin: auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1); padding: 20px;">
                    <img src="https://i.ibb.co/FzPs1mR/logo.png" width="80">
                    <h2 style="color: #333;">Actualización de Soporte</h2>
                    <p style="color: #555;">El estado de su ticket de soporte ha sido actualizado:</p>
                    <div style="text-align: left; margin-top: 20px;">
                        <p><strong>N° Ticket:</strong> {soporte.codigo}</p>
                        <p><strong>Estado:</strong> {soporte.estado}</p>
                        <p><strong>Mensaje de Resolución:</strong></p>
                        <p style="background-color: #f1f1f1; padding: 10px; border-radius: 4px;">{mensaje_resolucion}</p>
                    </div>
                </div>
            </body>
            </html>
            """

            # Enviar correo al cliente
            send_mail(
                subject=f'Actualización de Soporte - Ticket {soporte.codigo}',
                message='',  # Se deja vacío porque usamos html_message
                from_email='cri.jimenez21@gmail.com',  # Correo desde el que se enviará
                recipient_list=[soporte.correo_electronico],
                html_message=cliente_html_message,
                fail_silently=False,
            )

            return Response({'message': 'Estado actualizado y correo enviado al cliente.'}, status=status.HTTP_200_OK)

        except Soporte.DoesNotExist:
            return Response({'error': 'Soporte no encontrado.'}, status=status.HTTP_404_NOT_FOUND)