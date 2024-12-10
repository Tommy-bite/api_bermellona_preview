from django.urls import include, path
from .views import ConfirmarPagoView, GoogleAuthView, UserProfileDetailView, GuardarVentaView,TransaccionWebpayViewSet,SoporteViewSet,IniciarPagoView, PasswordResetRequestView, ProductoViewSet, RegistroUsuario, ToggleUserStatusView, UserListView, activate_account, LoginView, UserProfileView, PasswordResetView, PasswordResetConfirmView, csrf_view
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register(r'productos', ProductoViewSet, basename='producto')
router.register(r'soporte', SoporteViewSet, basename='soporte')
router.register(r'transaccion-webpay', TransaccionWebpayViewSet, basename='transaccion')

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
    path('lista-usuarios/', UserListView.as_view(), name='user-list'),
    path('toggle-user-status/', ToggleUserStatusView.as_view(), name='toggle-user-status'),
    path('password-reset-request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('auth/google/', GoogleAuthView.as_view(), name='google-auth'),
    path('user-profile/<int:user_id>/', UserProfileDetailView.as_view(), name='user-profile-detail'),
    path('guardar-venta/', GuardarVentaView.as_view(), name='guardar-eventa'),

]