from django.contrib.auth.models import User
from .models import Productos, TerminosYCondiciones
from rest_framework import serializers
from django.core.mail import send_mail

from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User

from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken


class UserSerializer(serializers.ModelSerializer):
    # Campo adicional para aceptar términos y condiciones, solo para escritura (no se devuelve en la respuesta)
    acepto_terminos = serializers.BooleanField(write_only=True)

    class Meta:
        # Especifica que el serializer está basado en el modelo User
        model = User
        # Define los campos que se incluirán al serializar y deserializar los datos
        fields = ['username', 'password', 'email', 'first_name', 'last_name', 'acepto_terminos']
        # Configura el campo password para que solo sea de escritura y no se muestre en las respuestas
        extra_kwargs = {'password': {'write_only': True}}

    def validate_email(self, value):
        # Verifica si el correo electrónico ya está registrado en la base de datos
        if User.objects.filter(email=value).exists():
            # Lanza un error si el correo ya existe, evitando registros duplicados
            raise serializers.ValidationError("Este correo electrónico ya está registrado.")
        # Devuelve el valor si no hay errores
        return value

    def create(self, validated_data):
        # Extrae el valor de acepto_terminos y lo elimina de validated_data
        acepto_terminos = validated_data.pop('acepto_terminos', False)
        
        # Crea una nueva instancia del modelo User con los datos proporcionados
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            is_active=False  # Define el usuario como inactivo hasta que se confirme el registro
        )

        # Encripta la contraseña antes de guardarla en la base de datos
        user.set_password(validated_data['password'])
        # Guarda el nuevo usuario en la base de datos
        user.save()

        # Si acepto_terminos es True, crea un registro en el modelo TerminosYCondiciones
        if acepto_terminos:
            TerminosYCondiciones.objects.create(
                acepto_terminos=True,  # Registra que el usuario aceptó los términos
                id_usuario=user.email  # Usa el email del usuario como ID en el registro de términos
            )


        # Generar el token y el ID seguro para el enlace de activación
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        activation_link = f"http://localhost:8000{reverse('activate_account', kwargs={'uidb64': uid, 'token': token})}"


        # Enviar el correo de confirmación
        send_mail(
                'Confirma tu cuenta en Bermellona',
                f'Hola, {user.first_name}. Por favor, confirma tu cuenta haciendo clic en el siguiente enlace: {activation_link}',
                'tomi.latin.99@gmail.com',
                [user.email],
                fail_silently=False,
        )

        # Devuelve el usuario creado para su uso posterior
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        # Intenta obtener el usuario por email antes de autenticar
        try:
            user = User.objects.get(email=email)
            if not user.is_active:
                raise serializers.ValidationError("Esta cuenta está inactiva. Revise su email registrado.")
        except User.DoesNotExist:
            # Si el usuario no existe, se gestionará con el mensaje de "Credenciales incorrectas"
            pass

        # Autentica al usuario
        user = authenticate(username=email, password=password)
        if user is None:
            raise serializers.ValidationError("Credenciales incorrectas.")

        # Genera los tokens de acceso
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        # Verifica si existe un usuario con este email
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No hay un usuario registrado con este correo.")
        return value
    
class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    uidb64 = serializers.CharField()
    new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        try:
            uid = urlsafe_base64_decode(data['uidb64']).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError("El enlace de recuperación es inválido o ha expirado.")

        if not default_token_generator.check_token(user, data['token']):
            raise serializers.ValidationError("El token de recuperación no es válido.")

        return data

    def save(self):
        # Establece la nueva contraseña para el usuario
        uid = urlsafe_base64_decode(self.validated_data['uidb64']).decode()
        user = User.objects.get(pk=uid)
        user.set_password(self.validated_data['new_password'])
        user.save()

class ProductoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Productos
        fields = '__all__'
