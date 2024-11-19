from django.db import models
from django.contrib.auth.models import User
# Create your models here.
class TerminosYCondiciones(models.Model):
    acepto_terminos = models.BooleanField(default=False)
    fecha_aceptacion = models.DateTimeField(auto_now_add=True)
    id_usuario = models.CharField(max_length=255)

    class Meta:
        db_table = 'terminos_condiciones'

    def __str__(self):
        return f"El usuario de ID: {self.id_usuario}, ha leido y aceptado las condiciones el día {self.fecha_aceptacion}"
    

class Productos(models.Model):
    nombre = models.CharField(max_length=255, verbose_name="Nombre del producto")
    imagen = models.ImageField(upload_to='productos', blank=True, null=True, verbose_name="Imagen del producto")
    descripcion = models.TextField(blank=True, null=True, verbose_name="Descripción")
    cantidad = models.PositiveIntegerField(verbose_name="Cantidad disponible")
    precio = models.IntegerField(verbose_name="Precio del producto")
    fecha_creacion = models.DateTimeField(auto_now_add=True, verbose_name="Fecha de creación")
    fecha_actualizacion = models.DateTimeField(auto_now=True, verbose_name="Última actualización")
    destacado = models.BooleanField(blank=True, null=False, default=False)

    class Meta:
        db_table = 'productos'
        verbose_name = 'Producto'
        verbose_name_plural = 'Productos'
        ordering = ['-fecha_creacion']  # Orden por fecha de creación descendente

    def __str__(self):
        return f"{self.nombre} - ${self.precio:.2f}"
    
class Venta(models.Model):
    codigo = models.CharField(max_length=255, unique=True, verbose_name="Código de la venta")
    fecha = models.DateTimeField(auto_now_add=True, verbose_name="Fecha de la venta")
    rut_cliente = models.CharField(max_length=25, verbose_name="RUT del cliente")
    nombre_cliente = models.CharField(max_length=255, verbose_name="Nombre del cliente")
    apellido_cliente = models.CharField(max_length=255, verbose_name="Apellido del cliente")
    email_cliente = models.EmailField(max_length=255, verbose_name="Email del cliente")
    email_cliente = models.EmailField(max_length=255, verbose_name="Email del cliente")
    descuento = models.DecimalField(max_digits=10, decimal_places=2, default=0.00, verbose_name="Descuento aplicado")
    valor_total = models.DecimalField(max_digits=10, decimal_places=2, verbose_name="Valor total de la venta")
    estado = models.CharField(default='Pendiente', max_length=255)

    usuario = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, verbose_name="Usuario asociado")

    class Meta:
        db_table = 'ventas'
        verbose_name = 'Venta'
        verbose_name_plural = 'Ventas'
        ordering = ['-fecha']  # Orden por fecha de venta descendente

    def __str__(self):
        return f"{self.codigo} - ${self.valor_total:.2f}"


class ProductoVenta(models.Model):
    venta = models.ForeignKey(Venta, on_delete=models.CASCADE, verbose_name="Código de venta")
    producto = models.ForeignKey(Productos, on_delete=models.CASCADE, verbose_name="Producto")
    cantidad = models.PositiveIntegerField(default=1, verbose_name="Cantidad")

    class Meta:
        db_table = 'productos_venta'
        verbose_name = 'Producto en Venta'
        verbose_name_plural = 'Productos en Venta'

    def __str__(self):
        return f"{self.producto.nombre} x{self.cantidad} - Venta {self.venta.codigo}"


class TransaccionWebpay(models.Model):
    venta = models.OneToOneField(Venta, on_delete=models.CASCADE, verbose_name="Venta asociada")
    token = models.CharField(max_length=255, verbose_name="Token de la transacción")
    fecha_transaccion = models.DateTimeField(auto_now_add=True, verbose_name="Fecha de la transacción")
    estado = models.CharField(
        max_length=50,
        choices=[('aprobada', 'Aprobada'), ('rechazada', 'Rechazada')],
        default='aprobada',
        verbose_name="Estado de la transacción"
    )
    monto = models.DecimalField(max_digits=10, decimal_places=2, verbose_name="Monto de la transacción")

    class Meta:
        db_table = 'transacciones_webpay'
        verbose_name = 'Transacción Webpay'
        verbose_name_plural = 'Transacciones Webpay'

    def __str__(self):
        return f"Transacción {self.token} - {self.estado}"