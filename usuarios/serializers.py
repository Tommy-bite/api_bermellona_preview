from django.contrib.auth.models import User
from .models import ProductoVenta, Productos, TerminosYCondiciones, UserProfile, Soporte, TransaccionWebpay, Venta
from rest_framework import serializers
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken


class UserSerializer(serializers.ModelSerializer):
    is_admin = serializers.SerializerMethodField()
    acepto_terminos = serializers.BooleanField(write_only=True)

    class Meta:
        model = User
        fields = ['id','username', 'password', 'email', 'first_name', 'last_name', 'is_admin', 'acepto_terminos']
        extra_kwargs = {'password': {'write_only': True}}

    def get_is_admin(self, obj):
        return obj.is_superuser

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Este correo electrónico ya está registrado.")
        return value

    def create(self, validated_data):
        acepto_terminos = validated_data.pop('acepto_terminos', False)
        user = User(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            is_active=False
        )
        user.set_password(validated_data['password'])
        user.save()

        if acepto_terminos:
            TerminosYCondiciones.objects.create(
                acepto_terminos=True,
                id_usuario=user.email
            )

        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        activation_link = f"http://localhost:8000{reverse('activate_account', kwargs={'uidb64': uid, 'token': token})}"

        send_mail(
            'Confirma tu cuenta en Bermellona',
            f'Hola, {user.first_name}. Por favor, confirma tu cuenta haciendo clic en el siguiente enlace: {activation_link}',
            'tomi.latin.99@gmail.com',
            [user.email],
            fail_silently=False,
        )

        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        try:
            user = User.objects.get(email=email)
            if not user.is_active:
                raise serializers.ValidationError("Esta cuenta está inactiva. Revise su email registrado.")
        except User.DoesNotExist:
            raise serializers.ValidationError("Credenciales incorrectas.")

        user = authenticate(username=email, password=password)
        if user is None:
            raise serializers.ValidationError("Credenciales incorrectas.")

        refresh = RefreshToken.for_user(user)
        tokens = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

        user_data = UserSerializer(user).data
        user_data['tokens'] = tokens
        return user_data


class GoogleRegisterSerializer(serializers.ModelSerializer):
    is_admin = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'username', 'is_admin']

    def get_is_admin(self, obj):
        return obj.is_superuser

    def create(self, validated_data):
        if 'username' not in validated_data:
            validated_data['username'] = validated_data['email'].split('@')[0]
        return super().create(validated_data)


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
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
        uid = urlsafe_base64_decode(self.validated_data['uidb64']).decode()
        user = User.objects.get(pk=uid)
        user.set_password(self.validated_data['new_password'])
        user.save()


class ProductoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Productos
        fields = '__all__'

class ProductoVentaSerializer(serializers.ModelSerializer):
    producto = ProductoSerializer()  # Anida información del producto

    class Meta:
        model = ProductoVenta
        fields = ['producto', 'cantidad']  # Incluye el producto y la cantidad


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = '__all__'

class VentaConProductosSerializer(serializers.ModelSerializer):
    productos = ProductoVentaSerializer(source='productoventa_set', many=True)  # Relación inversa

    class Meta:
        model = Venta
        fields = ['id', 'codigo', 'fecha', 'rut_cliente', 'nombre_cliente', 'apellido_cliente',
                  'email_cliente', 'opcion_entrega', 'region', 'comuna', 'calle', 'celular',
                  'valor_total', 'estado', 'productos']


class UserReadOnlySerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(read_only=True)  # Sin `source`

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_superuser', 'is_active', 'profile']


class SoporteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Soporte
        fields = '__all__'

class TransaccionWebpaySerializer(serializers.ModelSerializer):
    class Meta:
        model = TransaccionWebpay
        fields = '__all__'


class VentaSerializer(serializers.ModelSerializer):

    productos = serializers.SerializerMethodField()
    class Meta:
        model = Venta
        fields = [
            'id',
            'codigo',
            'fecha',
            'rut_cliente',
            'nombre_cliente',
            'apellido_cliente',
            'email_cliente',
            'opcion_entrega',
            'region',
            'comuna',
            'calle',
            'celular',
            'descuento',
            'valor_total',
            'estado',
            'metodo_pago',
            'productos',
        ]

    def get_productos(self, obj):
        productos = ProductoVenta.objects.filter(venta=obj)
        return ProductoVentaSerializer(productos, many=True).data


class VentaEstadoSerializer(serializers.ModelSerializer):
    numero_envio = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    despachador = serializers.CharField(required=False, allow_null=True, allow_blank=True)

    class Meta:
        model = Venta
        fields = ['estado', 'numero_envio', 'despachador']
