
import requests
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import redirect

from usuarios.models import Productos
from .serializers import LoginSerializer, ProductoSerializer, UserSerializer, PasswordResetSerializer, PasswordResetConfirmSerializer
from rest_framework.permissions import IsAuthenticated
from django.utils.encoding import force_bytes
from django.core.mail import send_mail

from django.conf import settings
from django.views import View
from django.http import JsonResponse
import json
from django.middleware.csrf import get_token

import logging
from rest_framework.viewsets import ModelViewSet
from rest_framework.decorators import action

logger = logging.getLogger(__name__)


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
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
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

        # Enviar el correo
        try:
            send_mail(
                subject='Recuperación de contraseña',
                message=(
                    f'Hola, {user.first_name}. '
                    f'Haz clic en el siguiente enlace para recuperar tu contraseña: {reset_link}'
                ),
                from_email='noreply@example.com',
                recipient_list=[email],
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