# Sistema de Agencia de Viajes

![commits](https://badgen.net/github/commits/clubdecomputacion/lpa1-taller-requerimientos?icon=github) 
![last_commit](https://img.shields.io/github/last-commit/clubdecomputacion/lpa1-taller-requerimientos)

- ver [badgen](https://badgen.net/) o [shields](https://shields.io/) para otros tipos de _badges_

## Autor

- [Jhon Sebastian Lema Montoya](https://github.com/Sebastianl1232/lpa2-taller-requerimientos.git)

## Descripción del Proyecto

El presente proyecto tiene como objetivo desarrollar un sistema de reservas de hoteles que permita gestionar de manera eficiente la información relacionada con hoteles, habitaciones, clientes y reservas. Este sistema busca optimizar los procesos administrativos y mejorar la experiencia del usuario al realizar búsquedas y reservas en línea.

* La plataforma ofrecerá funcionalidades como:

* Registro y administración de hoteles con información detallada, servicios y promociones.

* Gestión de habitaciones con precios dinámicos, calendarios de disponibilidad y estados de actividad.

* Registro de clientes y manejo de sus datos personales de forma segura.

* Procesos de reserva y pago integrados, con políticas de cancelación y reembolsos configurables.

* Sistema de calificaciones y comentarios para evaluar la calidad del servicio.

El sistema se diseñará con un enfoque en usabilidad, seguridad y eficiencia, garantizando una interfaz intuitiva tanto para administradores como para clientes. Su implementación contribuirá a la digitalización del sector hotelero, facilitando la gestión operativa y mejorando la satisfacción del cliente.

## Documentación

Revisar la documentación en [`./docs`](./docs)

### Requerimientos

- **R1 REGRISTO DE HOTELES**: El sistema debe permitir registrar un hotel proporcionando nombre, direccion, telefono, correo electronico, ubicacion geografica, descripcion de servicios ( restaurante, piscina, gimnasio, etc...) y fotos.
- **R2 OFERTAS Y PROMOCIONES**: El sistema debe permitir registrar promociones o paquetes especiales por temporada baja, ofrecer servicios adicionales en estos paquetes (Estacionamiento, areas de coworking, etc..)
- **R3 REGISTRO DE HABITACIONES**: El sistema debe permitir registrar habitaciones con los siguientes atributos: tipo, descripcion, precio, servicios incluidos, capacidad maxima y fotos.
- **R4 POLITICAS DE PAGO Y CANCELACION**: El sistema debe de permitir configurar politicas de pago (adelantado o al llegar) y cancelacion con (reembolso total, parcial o penalidad por alguna temporada y tipo de habitacion).
- **R5 GESTION DE REEMBOLSOS**: El sistema debe de procesar reembolsos de acuerdo con la politica de cancelacion definida por cada hotel.
- **R6 GESTION DE ESTADO DE HOTELES Y HABITACIONES**: El sistema debe permitir marcar hoteles y habitacion como activos e inactivos. El hotel por razones de reformas y las habitaciones por mantenimiento, remodelacion o por limpieza a fondo.
- **R7 GESTION DE PRECIOS**: El sistema debe de calcular precios de habitaicones segun la temporada (alta/baja) y numero de huespedes, sin exceder la capacidad maxima definida.
- **R8 CALENDARIO DE DISPONIBILIDAD**: El sistema debe de permitir que cada habitaicon tenga un calendario que muestre las fechas reservadas y disponibles, se debe actualizar automaticamente este calendario al confirmar una reserva.
- **R9 CALIFICACIONES Y COMENTARIOS**: El sistema debe permitir a los clientes evaluar su estancia y dejar comentarios, se calculara una calificacion promedio por habitacion y una calificacion general por hotel.
- **R10 REGISTRO DE CLIENTES**: El sistema debe permitir registrar clientes solicitando nombre completo, numero de telefono, correo electronico y direccion.
- **R11 BUSQUEDA DE HABITACIONES**: El sistema debe permitir a los clientes buscar habitaciones filtrando fecha, ubicacion, precio y calificacion, pudiendo combinar varios criterios de busqueda.
- **R12 DISPONIBILIDAD DE INFORMACION**: El sistema debe mostrar unicamente hoteles y habitaciones activas en las busquedas y resultados.
- **R13 VISUALIZACION DE DETALLES DE HABITACIONES**: El sistema debe mostrar al cliente la descripcion, servicios inlcuidos, fotos, calificacion promedio y comentarios de huespedes anteriores.
- **R14 PROCESO DE RESERVA**: El sistema debe permitir al cliente seleccionar una habitacion, confirmar la reserva y realizar el pago, la reserva quedara formalizada solo tras la confirmacion del pago.
- **R15 SEGURIDAD DE DATOS**: El sistema debe de garantizar la proteccion de datos personales y transaccionales de pago mediante cifrado y autenticacion segura.
<br>...<br>
- **Rn**: El sistema debe ...
- **Rm**: El sistema debe ...

## Diseño

### Diagrama de Clases

![Diagrama de Clases](./docs/Clase%20UML.png)


### Tárifas

|destino|pasajes|silver|gold|platinum|
|:---|---:|---:|---:|---:|
|Aruba|418|134|167|191|
|Bahamas|423|112|183|202|
|Cancún|350|105|142|187|
|Hawaii|858|210|247|291|
|Jamaica|380|115|134|161|
|Madrid|496|190|230|270|
|Miami|334|122|151|183|
|Moscu|634|131|153|167|
|NewYork|495|104|112|210|
|Panamá|315|119|138|175|
|Paris|512|210|260|290|
|Rome|478|184|220|250|
|Seul|967|205|245|265|
|Sidney|1045|170|199|230|
|Taipei|912|220|245|298|
|Tokio|989|189|231|255|

## Instalación

Para ejecutar el proyecto del sistema de reservas de hoteles en tu entorno local, sigue los pasos detallados a continuación:

1. Clonar el proyecto

    ```bash
    git clone https://github.com/clubdecomputacion/lpa1-taller-requerimientos.git
    ```

2. Crear y activar entorno virtual

    ```bash
    cd lpa1-taller-requerimientos
    python3 -m venv venv
    source venv/bin/activate
    ```

3. Instalar librerías y dependencias

    ```bash
    pip install -r requirements.txt
    ```
    
## Ejecución

Una vez instalado el proyecto y configurado el entorno virtual, puedes ejecutar el sistema siguiendo estos pasos:

1. Ejecutar el proyecto

    ```bash
    cd lpa1-taller-requerimientos
    python3 app.py
    ```

