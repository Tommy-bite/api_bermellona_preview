from django.urls import include, path
from .views import ConfirmarPagoView, IniciarPagoView, ProductoViewSet, RegistroUsuario, activate_account, LoginView, UserProfileView, PasswordResetView, PasswordResetConfirmView, csrf_view
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'productos', ProductoViewSet, basename='producto')

urlpatterns = [
    path('', include(router.urls)),
    path('registro/', RegistroUsuario.as_view(), name='registro'),
    path('login/', LoginView.as_view(), name='login'),
    path('activate/<uidb64>/<token>/', activate_account, name='activate_account'),
    path('user-profile/', UserProfileView.as_view(), name='user-profile'),
    path('password-reset/', PasswordResetView.as_view(), name='password_reset'),
    path('password-reset-confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('webpay/iniciar-pago/', IniciarPagoView.as_view(), name='iniciar_pago'),
    path('webpay/confirmar-pago/<str:token>/', ConfirmarPagoView.as_view(), name='confirmar-pago'),
    path('csrf/', csrf_view, name='csrf'),
]