from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import threading
import webbrowser
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta
from math import ceil
from pathlib import Path
from typing import Dict, List, Optional
from uuid import uuid4

from flask import Flask, render_template, request


# ================= VALIDACIONES BÁSICAS =================
PATRON_EMAIL = re.compile(r"^[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}$")
PATRON_TELEFONO = re.compile(r"^[+]?\d[\d\s\-]{6,}$")
FORMATO_FECHA = "%Y-%m-%d"


# ================= SEGURIDAD (R15) =================
def hash_contrasena(password: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
    return digest.hex()


def verificar_contraseña(password: str, sal_hex: str, hash_esperado: str) -> bool:
    salt = bytes.fromhex(sal_hex)
    computed = hash_contrasena(password, salt)
    return hmac.compare_digest(computed, hash_esperado)


def _bytes_clave_secreta() -> bytes:
    raw = os.getenv("APP_SECRET", "lpa2-demo-secret")
    return hashlib.sha256(raw.encode("utf-8")).digest()


def encriptar_texto(texto_plano: str) -> str:
    key = _bytes_clave_secreta()
    data = texto_plano.encode("utf-8")
    cipher = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return base64.urlsafe_b64encode(cipher).decode("utf-8")


def desencriptar_texto(texto_cifrado: str) -> str:
    key = _bytes_clave_secreta()
    data = base64.urlsafe_b64decode(texto_cifrado.encode("utf-8"))
    plain = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return plain.decode("utf-8")


# ================= MODELOS =================
# R1
@dataclass
class Hotel:
    id: str
    nombre: str
    direccion: str
    telefono: str
    correo_encriptado: str
    ubicacion_geografica: str
    descripcion_servicios: List[str]
    fotos: List[str]
    activo: bool
    politica_pago: str
    politica_cancelacion: Dict


# R2
@dataclass
class Promocion:
    id: str
    hotel_id: str
    nombre: str
    descripcion: str
    temporada: str
    porcentaje_descuento: float
    servicios_adicionales: List[str]
    fecha_inicio: str
    fecha_fin: str
    activa: bool


# R3
@dataclass
class Habitación:
    id: str
    hotel_id: str
    tipo: str
    descripcion: str
    precio_base: float
    servicios_incluidos: List[str]
    capacidad_maxima: int
    fotos: List[str]
    activo: bool


# R10
@dataclass
class Cliente:
    id: str
    nombre_completo: str
    telefono: str
    correo_encriptado: str
    direccion: str


# R14 / R5
@dataclass
class Reserva:
    id: str
    cliente_id: str
    hotel_id: str
    habitación_id: str
    fecha_inicio: str
    fecha_fin: str
    huespedes: int
    temporada: str
    precio_calculado: float
    estado: str
    pago_estado: str
    metodo_pago: str
    token_pago_encriptado: str
    monto_reembolso: float
    creado_en: str


# R9
@dataclass
class Comentario:
    id: str
    cliente_id: str
    hotel_id: str
    habitación_id: str
    puntaje: int
    comentario: str
    fecha: str


# R15
@dataclass
class Usuario:
    nombre_usuario: str
    hash_contrasena: str
    sal_hex: str
    rol: str


class ErrorNegocio(ValueError):
    pass


# ================= PERSISTENCIA =================
class AlmacenJson:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def read(self) -> Dict:
        if not self.db_path.exists():
            return self._default_schema()

        try:
            raw = self.db_path.read_text(encoding="utf-8").strip()
            if not raw:
                return self._default_schema()
            data = json.loads(raw)
            return self._merge_defaults(data)
        except (json.JSONDecodeError, OSError):
            return self._default_schema()

    def write(self, data: Dict) -> None:
        self.db_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def _default_schema(self) -> Dict:
        return {
            "hoteles": [],
            "promociónes": [],
            "habitaciónes": [],
            "clientes": [],
            "reservas": [],
            "comentarios": [],
            "usuarios": [],
        }

    def _merge_defaults(self, data: Dict) -> Dict:
        base = self._default_schema()
        base.update(data)
        return base


# ================= SISTEMA PRINCIPAL =================
class SistemaAgenciaViajes:
    def __init__(self, almacen: AlmacenJson) -> None:
        self.almacen = almacen
        self.tokens_activos: Dict[str, str] = {}
        self._asegurar_usuario_admin()

    # -------- Utilidades --------
    def _cargar_todo(self) -> Dict:
        return self.almacen.read()

    def _guardar_todo(self, db: Dict) -> None:
        self.almacen.write(db)

    def _parsear_fecha(self, value: str) -> date:
        try:
            return datetime.strptime(value, FORMATO_FECHA).date()
        except ValueError as exc:
            raise ErrorNegocio(f"Fecha inválida: {value}. Formato esperado YYYY-MM-DD") from exc

    def _temporalidad(self, fecha_inicio: date) -> str:
        if fecha_inicio.month in {6, 7, 8, 12}:
            return "alta"
        return "baja"

    def _se_superpone(self, start_a: date, end_a: date, start_b: date, end_b: date) -> bool:
        return max(start_a, start_b) <= min(end_a, end_b)

    def _buscar_hotel(self, db: Dict, hotel_id: str) -> Hotel:
        for item in db["hoteles"]:
            if item["id"] == hotel_id:
                return Hotel(**item)
        raise ErrorNegocio("Hotel no encontrado")

    def _buscar_habitación(self, db: Dict, habitación_id: str) -> Habitación:
        for item in db["habitaciónes"]:
            if item["id"] == habitación_id:
                return Habitación(**item)
        raise ErrorNegocio("Habitación no encontrada")

    def _buscar_cliente(self, db: Dict, cliente_id: str) -> Cliente:
        for item in db["clientes"]:
            if item["id"] == cliente_id:
                return Cliente(**item)
        raise ErrorNegocio("Cliente no encontrado")

    def _buscar_reserva(self, db: Dict, reserva_id: str) -> Reserva:
        for item in db["reservas"]:
            if item["id"] == reserva_id:
                return Reserva(**item)
        raise ErrorNegocio("Reserva no encontrada")

    def _actualizar_entidad(self, collection: List[Dict], entity_id: str, payload: Dict) -> None:
        for i, item in enumerate(collection):
            if item["id"] == entity_id:
                collection[i] = payload
                return
        raise ErrorNegocio("No se pudo actualizar el registro")

    # -------- Seguridad y autenticacion (R15) --------
    def _asegurar_usuario_admin(self) -> None:
        db = self._cargar_todo()
        if db["usuarios"]:
            return

        salt = secrets.token_bytes(16)
        admin = Usuario(
            nombre_usuario="admin",
            hash_contrasena=hash_contrasena("admin123", salt),
            sal_hex=salt.hex(),
            rol="admin",
        )
        db["usuarios"].append(asdict(admin))
        self._guardar_todo(db)

    def iniciar_sesión(self, nombre_usuario: str, password: str) -> str:
        db = self._cargar_todo()
        usuario = None
        for row in db["usuarios"]:
            if row["nombre_usuario"] == nombre_usuario:
                usuario = Usuario(**row)
                break

        if usuario is None or not verificar_contraseña(password, usuario.sal_hex, usuario.hash_contrasena):
            raise ErrorNegocio("Credenciales inválidas")

        token = secrets.token_urlsafe(24)
        self.tokens_activos[token] = usuario.rol
        return token

    def requerir_admin(self, token: str) -> None:
        if self.tokens_activos.get(token) != "admin":
            raise ErrorNegocio("Acción protegida. Debes iniciar sesión como admin")

    # -------- R1 Registro de hoteles --------
    def registrar_hotel(
        self,
        token: str,
        nombre: str,
        direccion: str,
        telefono: str,
        correo: str,
        ubicacion: str,
        servicios: List[str],
        fotos: List[str],
    ) -> Hotel:
        self.requerir_admin(token)
        if not nombre.strip():
            raise ErrorNegocio("Nombre obligatorio")
        if not direccion.strip():
            raise ErrorNegocio("Dirección obligatoria")
        if not PATRON_TELEFONO.match(telefono.strip()):
            raise ErrorNegocio("Teléfono inválido")
        if not PATRON_EMAIL.match(correo.strip()):
            raise ErrorNegocio("Correo inválido")
        if not ubicacion.strip():
            raise ErrorNegocio("Ubicación obligatoria")
        if not servicios or not all(s.strip() for s in servicios):
            raise ErrorNegocio("Debes agregar al menos un servicio")
        if not fotos or not all(f.strip() for f in fotos):
            raise ErrorNegocio("Debes agregar al menos una foto")

        politica_por_defecto = {
            "tipo_reembolso": "parcial",
            "porcentaje_base": 50,
            "penalidad_temporada": {"alta": 30, "baja": 10},
            "penalidad_tipo_habitación": {},
        }

        hotel = Hotel(
            id=str(uuid4()),
            nombre=nombre.strip(),
            direccion=direccion.strip(),
            telefono=telefono.strip(),
            correo_encriptado=encriptar_texto(correo.strip().lower()),
            ubicacion_geografica=ubicacion.strip(),
            descripcion_servicios=[s.strip() for s in servicios],
            fotos=[f.strip() for f in fotos],
            activo=True,
            politica_pago="llegada",
            politica_cancelacion=politica_por_defecto,
        )

        db = self._cargar_todo()
        db["hoteles"].append(asdict(hotel))
        self._guardar_todo(db)
        return hotel

    # -------- R2 Promociones --------
    def registrar_promoción(
        self,
        token: str,
        hotel_id: str,
        nombre: str,
        descripcion: str,
        temporada: str,
        porcentaje_descuento: float,
        servicios_adicionales: List[str],
        fecha_inicio: str,
        fecha_fin: str,
    ) -> Promocion:
        self.requerir_admin(token)
        db = self._cargar_todo()
        _ = self._buscar_hotel(db, hotel_id)

        temporada = temporada.strip().lower()
        if temporada not in {"alta", "baja"}:
            raise ErrorNegocio("Temporada debe ser alta o baja")
        if not (0 < porcentaje_descuento <= 100):
            raise ErrorNegocio("Descuento debe estar entre 0 y 100")
        if not servicios_adicionales or not all(s.strip() for s in servicios_adicionales):
            raise ErrorNegocio("Debes agregar servicios adicionales")

        start = self._parsear_fecha(fecha_inicio)
        end = self._parsear_fecha(fecha_fin)
        if start > end:
            raise ErrorNegocio("Fecha inicio no puede ser mayor a fecha fin")

        promo = Promocion(
            id=str(uuid4()),
            hotel_id=hotel_id,
            nombre=nombre.strip(),
            descripcion=descripcion.strip(),
            temporada=temporada,
            porcentaje_descuento=float(porcentaje_descuento),
            servicios_adicionales=[s.strip() for s in servicios_adicionales],
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            activa=True,
        )

        db["promociónes"].append(asdict(promo))
        self._guardar_todo(db)
        return promo

    # -------- R3 Habitaciónes --------
    def registrar_habitación(
        self,
        token: str,
        hotel_id: str,
        tipo: str,
        descripcion: str,
        precio_base: float,
        servicios_incluidos: List[str],
        capacidad_maxima: int,
        fotos: List[str],
    ) -> Habitación:
        self.requerir_admin(token)
        db = self._cargar_todo()
        hotel = self._buscar_hotel(db, hotel_id)
        if not hotel.activo:
            raise ErrorNegocio("No se pueden agregar habitaciónes a hoteles inactivos")

        if precio_base <= 0:
            raise ErrorNegocio("Precio base debe ser mayor a 0")
        if capacidad_maxima <= 0:
            raise ErrorNegocio("Capacidad maxima debe ser mayor a 0")
        if not servicios_incluidos or not all(s.strip() for s in servicios_incluidos):
            raise ErrorNegocio("Debes agregar servicios incluidos")
        if not fotos or not all(f.strip() for f in fotos):
            raise ErrorNegocio("Debes agregar al menos una foto")

        habitación = Habitación(
            id=str(uuid4()),
            hotel_id=hotel_id,
            tipo=tipo.strip(),
            descripcion=descripcion.strip(),
            precio_base=float(precio_base),
            servicios_incluidos=[s.strip() for s in servicios_incluidos],
            capacidad_maxima=int(capacidad_maxima),
            fotos=[f.strip() for f in fotos],
            activo=True,
        )

        db["habitaciónes"].append(asdict(habitación))
        self._guardar_todo(db)
        return habitación

    # -------- R4 Políticas de pago y cancelacion --------
    def configurar_politicas(
        self,
        token: str,
        hotel_id: str,
        politica_pago: str,
        tipo_reembolso: str,
        porcentaje_base: float,
        penalidad_alta: float,
        penalidad_baja: float,
        penalidad_por_tipo: Dict[str, float],
    ) -> Hotel:
        self.requerir_admin(token)
        db = self._cargar_todo()
        hotel = self._buscar_hotel(db, hotel_id)

        politica_pago = politica_pago.strip().lower()
        if politica_pago not in {"adelantado", "llegada"}:
            raise ErrorNegocio("Política de pago debe ser adelantado o llegada")

        tipo_reembolso = tipo_reembolso.strip().lower()
        if tipo_reembolso not in {"total", "parcial", "penalidad"}:
            raise ErrorNegocio("Tipo de reembolso inválido")

        if not (0 <= porcentaje_base <= 100):
            raise ErrorNegocio("Porcentaje base fuera de rango")

        hotel.politica_pago = politica_pago
        hotel.politica_cancelacion = {
            "tipo_reembolso": tipo_reembolso,
            "porcentaje_base": float(porcentaje_base),
            "penalidad_temporada": {
                "alta": float(penalidad_alta),
                "baja": float(penalidad_baja),
            },
            "penalidad_tipo_habitación": penalidad_por_tipo,
        }

        self._actualizar_entidad(db["hoteles"], hotel.id, asdict(hotel))
        self._guardar_todo(db)
        return hotel

    # -------- R5 Reembolsos --------
    def cancelar_reserva_y_reembolsar(self, reserva_id: str) -> Reserva:
        db = self._cargar_todo()
        reserva = self._buscar_reserva(db, reserva_id)

        if reserva.estado == "cancelada":
            raise ErrorNegocio("La reserva ya estaba cancelada")
        if reserva.pago_estado != "confirmado":
            raise ErrorNegocio("No hay pago confirmado; no aplica reembolso")

        hotel = self._buscar_hotel(db, reserva.hotel_id)
        habitación = self._buscar_habitación(db, reserva.habitación_id)

        policy = hotel.politica_cancelacion
        tipo = policy.get("tipo_reembolso", "parcial")
        porcentaje = 0.0

        if tipo == "total":
            porcentaje = 100.0
        elif tipo == "parcial":
            porcentaje = float(policy.get("porcentaje_base", 50))
        else:
            pen_temp = float(policy.get("penalidad_temporada", {}).get(reserva.temporada, 0))
            pen_tipo = float(policy.get("penalidad_tipo_habitación", {}).get(habitación.tipo, 0))
            porcentaje = max(0.0, 100.0 - pen_temp - pen_tipo)

        inicio = self._parsear_fecha(reserva.fecha_inicio)
        horas_anticipacion = (datetime.combine(inicio, datetime.min.time()) - datetime.now()).total_seconds() / 3600
        if horas_anticipacion < 24:
            porcentaje = max(0.0, porcentaje - 20)

        reserva.monto_reembolso = round(reserva.precio_calculado * (porcentaje / 100), 2)
        reserva.estado = "cancelada"
        reserva.pago_estado = "reembolsado"

        self._actualizar_entidad(db["reservas"], reserva.id, asdict(reserva))
        self._guardar_todo(db)
        return reserva

    # -------- R6 Estados activos/inactivos --------
    def cambiar_estado_hotel(self, token: str, hotel_id: str, activo: bool) -> Hotel:
        self.requerir_admin(token)
        db = self._cargar_todo()
        hotel = self._buscar_hotel(db, hotel_id)
        hotel.activo = bool(activo)
        self._actualizar_entidad(db["hoteles"], hotel.id, asdict(hotel))
        self._guardar_todo(db)
        return hotel

    def cambiar_estado_habitación(self, token: str, habitación_id: str, activo: bool) -> Habitación:
        self.requerir_admin(token)
        db = self._cargar_todo()
        habitación = self._buscar_habitación(db, habitación_id)
        habitación.activo = bool(activo)
        self._actualizar_entidad(db["habitaciónes"], habitación.id, asdict(habitación))
        self._guardar_todo(db)
        return habitación

    # -------- R7 Gestión de precios --------
    def calcular_precio(self, habitación_id: str, fecha_inicio: str, huespedes: int) -> float:
        db = self._cargar_todo()
        habitación = self._buscar_habitación(db, habitación_id)
        if huespedes > habitación.capacidad_maxima:
            raise ErrorNegocio("Número de huéspedes excede la capacidad máxima")

        inicio = self._parsear_fecha(fecha_inicio)
        temporada = self._temporalidad(inicio)

        season_multiplier = 1.25 if temporada == "alta" else 0.90
        guest_multiplier = 1 + (max(0, huespedes - 1) * 0.10)
        price = habitación.precio_base * season_multiplier * guest_multiplier
        return round(price, 2)

    # -------- R8 Calendario de disponibilidad --------
    def obtener_calendario_disponibilidad(self, habitación_id: str, anio: int, mes: int) -> Dict[str, str]:
        db = self._cargar_todo()
        _ = self._buscar_habitación(db, habitación_id)

        first_day = date(anio, mes, 1)
        next_month = date(anio + (1 if mes == 12 else 0), 1 if mes == 12 else mes + 1, 1)
        last_day = next_month - timedelta(days=1)

        calendario = {}
        current = first_day
        while current <= last_day:
            calendario[current.isoformat()] = "disponible"
            current += timedelta(days=1)

        for row in db["reservas"]:
            reserva = Reserva(**row)
            if reserva.habitación_id != habitación_id or reserva.estado != "confirmada":
                continue

            start = self._parsear_fecha(reserva.fecha_inicio)
            end = self._parsear_fecha(reserva.fecha_fin)
            current = max(start, first_day)
            until = min(end, last_day)
            while current <= until:
                calendario[current.isoformat()] = "reservada"
                current += timedelta(days=1)

        return calendario

    def _esta_habitación_disponible(self, db: Dict, habitación_id: str, inicio: date, fin: date) -> bool:
        for row in db["reservas"]:
            reserva = Reserva(**row)
            if reserva.habitación_id != habitación_id or reserva.estado != "confirmada":
                continue
            r_start = self._parsear_fecha(reserva.fecha_inicio)
            r_end = self._parsear_fecha(reserva.fecha_fin)
            if self._se_superpone(inicio, fin, r_start, r_end):
                return False
        return True

    # -------- R9 Calificaciónes y comentarios --------
    def registrar_comentario(self, cliente_id: str, habitación_id: str, puntaje: int, comentario: str) -> Comentario:
        db = self._cargar_todo()
        _ = self._buscar_cliente(db, cliente_id)
        habitación = self._buscar_habitación(db, habitación_id)

        if puntaje < 1 or puntaje > 5:
            raise ErrorNegocio("Puntaje debe estar entre 1 y 5")

        done_stay = False
        for row in db["reservas"]:
            reserva = Reserva(**row)
            if reserva.cliente_id == cliente_id and reserva.habitación_id == habitación_id and reserva.estado == "confirmada":
                if self._parsear_fecha(reserva.fecha_fin) <= date.today():
                    done_stay = True
                    break
        if not done_stay:
            raise ErrorNegocio("Solo puedes calificar despues de una estancia confirmada y finalizada")

        entry = Comentario(
            id=str(uuid4()),
            cliente_id=cliente_id,
            hotel_id=habitación.hotel_id,
            habitación_id=habitación_id,
            puntaje=int(puntaje),
            comentario=comentario.strip(),
            fecha=date.today().isoformat(),
        )

        db["comentarios"].append(asdict(entry))
        self._guardar_todo(db)
        return entry

    def promedio_habitación(self, habitación_id: str) -> float:
        db = self._cargar_todo()
        points = [c["puntaje"] for c in db["comentarios"] if c["habitación_id"] == habitación_id]
        if not points:
            return 0.0
        return round(sum(points) / len(points), 2)

    def promedio_hotel(self, hotel_id: str) -> float:
        db = self._cargar_todo()
        points = [c["puntaje"] for c in db["comentarios"] if c["hotel_id"] == hotel_id]
        if not points:
            return 0.0
        return round(sum(points) / len(points), 2)

    # -------- R10 Registro de clientes --------
    def registrar_cliente(self, nombre_completo: str, telefono: str, correo: str, direccion: str) -> Cliente:
        if not nombre_completo.strip():
            raise ErrorNegocio("Nombre completo obligatorio")
        if not PATRON_TELEFONO.match(telefono.strip()):
            raise ErrorNegocio("Teléfono inválido")
        if not PATRON_EMAIL.match(correo.strip()):
            raise ErrorNegocio("Correo inválido")
        if not direccion.strip():
            raise ErrorNegocio("Dirección obligatoria")

        cliente_registrado = Cliente(
            id=str(uuid4()),
            nombre_completo=nombre_completo.strip(),
            telefono=telefono.strip(),
            correo_encriptado=encriptar_texto(correo.strip().lower()),
            direccion=direccion.strip(),
        )

        db = self._cargar_todo()
        db["clientes"].append(asdict(cliente_registrado))
        self._guardar_todo(db)
        return cliente_registrado

    # -------- R11 + R12 Búsqueda --------
    def buscar_habitaciónes(
        self,
        fecha_inicio: str,
        fecha_fin: str,
        ubicacion: Optional[str] = None,
        precio_max: Optional[float] = None,
        calificacion_min: Optional[float] = None,
    ) -> List[Dict]:
        db = self._cargar_todo()
        inicio = self._parsear_fecha(fecha_inicio)
        fin = self._parsear_fecha(fecha_fin)
        if inicio > fin:
            raise ErrorNegocio("Fecha inicio no puede ser mayor a fecha fin")

        resultados: List[Dict] = []
        for h_row in db["hoteles"]:
            hotel = Hotel(**h_row)
            # R12: solo hoteles activos
            if not hotel.activo:
                continue
            if ubicacion and ubicacion.strip().lower() not in hotel.ubicacion_geografica.lower():
                continue

            hotel_rating = self.promedio_hotel(hotel.id)

            for r_row in db["habitaciónes"]:
                habitación = Habitación(**r_row)
                if habitación.hotel_id != hotel.id:
                    continue
                # R12: solo habitaciónes activas
                if not habitación.activo:
                    continue
                # R8 + R11: disponibilidad por rango
                if not self._esta_habitación_disponible(db, habitación.id, inicio, fin):
                    continue

                room_rating = self.promedio_habitación(habitación.id)
                if calificacion_min is not None and room_rating < calificacion_min:
                    continue

                sample_price = self.calcular_precio(habitación.id, fecha_inicio, 1)
                if precio_max is not None and sample_price > precio_max:
                    continue

                resultados.append(
                    {
                        "hotel_id": hotel.id,
                        "hotel_nombre": hotel.nombre,
                        "ubicacion": hotel.ubicacion_geografica,
                        "hotel_rating": hotel_rating,
                        "habitación_id": habitación.id,
                        "tipo": habitación.tipo,
                        "precio_estimado": sample_price,
                        "habitación_rating": room_rating,
                    }
                )

        return resultados

    # -------- R13 Detalle de habitación --------
    def detalle_habitación(self, habitación_id: str) -> Dict:
        db = self._cargar_todo()
        habitación = self._buscar_habitación(db, habitación_id)
        hotel = self._buscar_hotel(db, habitación.hotel_id)

        comments = [
            c for c in db["comentarios"] if c["habitación_id"] == habitación_id
        ]

        return {
            "habitación": asdict(habitación),
            "hotel": {
                "id": hotel.id,
                "nombre": hotel.nombre,
                "calificacion_general": self.promedio_hotel(hotel.id),
            },
            "calificacion_promedio_habitación": self.promedio_habitación(habitación_id),
            "comentarios": comments,
        }

    # -------- R14 Reserva y pago --------
    def crear_reserva(
        self,
        cliente_id: str,
        habitación_id: str,
        fecha_inicio: str,
        fecha_fin: str,
        huespedes: int,
        metodo_pago: str,
    ) -> Reserva:
        db = self._cargar_todo()
        _ = self._buscar_cliente(db, cliente_id)
        habitación = self._buscar_habitación(db, habitación_id)
        hotel = self._buscar_hotel(db, habitación.hotel_id)

        if not hotel.activo or not habitación.activo:
            raise ErrorNegocio("Hotel/Habitación inactiva")

        inicio = self._parsear_fecha(fecha_inicio)
        fin = self._parsear_fecha(fecha_fin)
        if inicio > fin:
            raise ErrorNegocio("Rango de fechas inválido")

        if huespedes > habitación.capacidad_maxima:
            raise ErrorNegocio("Huéspedes supera capacidad máxima")

        if not self._esta_habitación_disponible(db, habitación.id, inicio, fin):
            raise ErrorNegocio("Habitación no disponible en ese rango")

        temporada = self._temporalidad(inicio)
        price_per_night = self.calcular_precio(habitación.id, fecha_inicio, huespedes)
        nights = (fin - inicio).days + 1
        total = round(price_per_night * nights, 2)

        token_pago = encriptar_texto(f"{cliente_id}:{total}:{datetime.utcnow().isoformat()}")

        reserva = Reserva(
            id=str(uuid4()),
            cliente_id=cliente_id,
            hotel_id=hotel.id,
            habitación_id=habitación_id,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            huespedes=huespedes,
            temporada=temporada,
            precio_calculado=total,
            estado="pendiente_pago",
            pago_estado="pendiente",
            metodo_pago=metodo_pago.strip().lower(),
            token_pago_encriptado=token_pago,
            monto_reembolso=0.0,
            creado_en=datetime.utcnow().isoformat(),
        )

        db["reservas"].append(asdict(reserva))
        self._guardar_todo(db)
        return reserva

    def confirmar_pago(self, reserva_id: str) -> Reserva:
        db = self._cargar_todo()
        reserva = self._buscar_reserva(db, reserva_id)
        if reserva.estado != "pendiente_pago":
            raise ErrorNegocio("Reserva no está pendiente de pago")

        # R14: la reserva queda formalizada solo tras confirmacion de pago.
        reserva.pago_estado = "confirmado"
        reserva.estado = "confirmada"

        self._actualizar_entidad(db["reservas"], reserva.id, asdict(reserva))
        self._guardar_todo(db)
        return reserva

    # -------- Listados utilitarios --------
    def listar_hoteles(self, solo_activos: bool = False) -> List[Hotel]:
        db = self._cargar_todo()
        hotels = [Hotel(**row) for row in db["hoteles"]]
        if solo_activos:
            hotels = [h for h in hotels if h.activo]
        return hotels

    def listar_habitaciónes_por_hotel(self, hotel_id: str) -> List[Habitación]:
        db = self._cargar_todo()
        return [Habitación(**row) for row in db["habitaciónes"] if row["hotel_id"] == hotel_id]


# ================= CLI =================
def pedir_lista(mensaje: str) -> List[str]:
    print(mensaje)
    print("- Escribe un elemento por línea")
    print("- Presiona Enter vacío para terminar")
    valores: List[str] = []
    while True:
        item = input("> ").strip()
        if not item:
            break
        valores.append(item)
    return valores


def pedir_opcional_float(etiqueta: str) -> Optional[float]:
    value = input(etiqueta).strip()
    if not value:
        return None
    return float(value)


def imprimir_hotel(sistema: SistemaAgenciaViajes, hotel: Hotel) -> None:
    print(f"ID: {hotel.id}")
    print(f"Nombre: {hotel.nombre}")
    print(f"Dirección: {hotel.direccion}")
    print(f"Teléfono: {hotel.telefono}")
    print(f"Correo: {desencriptar_texto(hotel.correo_encriptado)}")
    print(f"Ubicación: {hotel.ubicacion_geografica}")
    print(f"Activo: {hotel.activo}")
    print(f"Servicios: {', '.join(hotel.descripcion_servicios)}")
    print(f"Calificación hotel: {sistema.promedio_hotel(hotel.id)}")


def main() -> None:
    print("Sistema de Agencia de Viajes - Requerimientos R1 a R15")
    print("Credencial inicial admin -> usuario: admin, clave: admin123")

    almacen = AlmacenJson(Path("static/data/database.json"))
    sistema = SistemaAgenciaViajes(almacen)

    token_admin = ""

    while True:
        print("\n===== MENU PRINCIPAL =====")
        print("1. Iniciar sesión admin (R15)")
        print("2. Registrar hotel (R1)")
        print("3. Configurar politicas hotel (R4)")
        print("4. Cambiar estado hotel (R6)")
        print("5. Registrar promoción (R2)")
        print("6. Registrar habitación (R3)")
        print("7. Cambiar estado habitación (R6)")
        print("8. Registrar cliente (R10)")
        print("9. Buscar habitaciónes (R11-R12)")
        print("10. Ver detalle habitación (R13)")
        print("11. Crear reserva (R14 + R7)")
        print("12. Confirmar pago reserva (R14 + R8)")
        print("13. Cancelar reserva y procesar reembolso (R5)")
        print("14. Ver calendario disponibilidad (R8)")
        print("15. Calificar estancia (R9)")
        print("16. Listar hoteles activos (R12)")
        print("17. Salir")

        opcion = input("Selecciona opción: ").strip()

        try:
            if opcion == "1":
                usuario = input("Usuario: ").strip()
                clave = input("Clave: ").strip()
                token_admin = sistema.iniciar_sesión(usuario, clave)
                print("Inicio de sesión exitoso")

            elif opcion == "2":
                servicios = pedir_lista("Servicios del hotel")
                fotos = pedir_lista("Fotos del hotel")
                hotel = sistema.registrar_hotel(
                    token_admin,
                    input("Nombre: "),
                    input("Dirección: "),
                    input("Teléfono: "),
                    input("Correo: "),
                    input("Ubicación geográfica: "),
                    servicios,
                    fotos,
                )
                print(f"Hotel registrado con ID: {hotel.id}")

            elif opcion == "3":
                hotel_id = input("Hotel ID: ").strip()
                politica_pago = input("Política pago (adelantado/llegada): ")
                tipo_reembolso = input("Tipo reembolso (total/parcial/penalidad): ")
                porcentaje_base = float(input("Porcentaje base reembolso (0-100): "))
                pen_alta = float(input("Penalidad temporada alta (0-100): "))
                pen_baja = float(input("Penalidad temporada baja (0-100): "))

                print("Penalidad por tipo de habitación")
                print("Formato: tipo=penalidad. Ej: suite=15")
                print("Presiona Enter vacío para terminar")
                penalidades: Dict[str, float] = {}
                while True:
                    row = input("> ").strip()
                    if not row:
                        break
                    tipo, val = row.split("=", maxsplit=1)
                    penalidades[tipo.strip()] = float(val.strip())

                actualizado = sistema.configurar_politicas(
                    token_admin,
                    hotel_id,
                    politica_pago,
                    tipo_reembolso,
                    porcentaje_base,
                    pen_alta,
                    pen_baja,
                    penalidades,
                )
                print(f"Políticas actualizadas para hotel: {actualizado.nombre}")

            elif opcion == "4":
                hotel_id = input("Hotel ID: ").strip()
                activo = input("Activo? (s/n): ").strip().lower() == "s"
                actualizado = sistema.cambiar_estado_hotel(token_admin, hotel_id, activo)
                print(f"Estado hotel {actualizado.nombre}: {actualizado.activo}")

            elif opcion == "5":
                servicios_extra = pedir_lista("Servicios adicionales de la promoción")
                promo = sistema.registrar_promoción(
                    token_admin,
                    input("Hotel ID: "),
                    input("Nombre promoción: "),
                    input("Descripción: "),
                    input("Temporada (alta/baja): "),
                    float(input("Descuento (0-100): ")),
                    servicios_extra,
                    input("Fecha inicio YYYY-MM-DD: "),
                    input("Fecha fin YYYY-MM-DD: "),
                )
                print(f"Promocion registrada con ID: {promo.id}")

            elif opcion == "6":
                servicios = pedir_lista("Servicios incluidos de la habitación")
                fotos = pedir_lista("Fotos de la habitación")
                habitación = sistema.registrar_habitación(
                    token_admin,
                    input("Hotel ID: "),
                    input("Tipo habitación: "),
                    input("Descripción: "),
                    float(input("Precio base: ")),
                    servicios,
                    int(input("Capacidad maxima: ")),
                    fotos,
                )
                print(f"Habitación registrada con ID: {habitación.id}")

            elif opcion == "7":
                room_id = input("Habitación ID: ").strip()
                activo = input("Activa? (s/n): ").strip().lower() == "s"
                actualizado = sistema.cambiar_estado_habitación(token_admin, room_id, activo)
                print(f"Estado habitación {actualizado.id}: {actualizado.activo}")

            elif opcion == "8":
                cliente_registrado = sistema.registrar_cliente(
                    input("Nombre completo: "),
                    input("Teléfono: "),
                    input("Correo: "),
                    input("Dirección: "),
                )
                print(f"Cliente registrado con ID: {cliente_registrado.id}")

            elif opcion == "9":
                resultados = sistema.buscar_habitaciónes(
                    input("Fecha inicio YYYY-MM-DD: "),
                    input("Fecha fin YYYY-MM-DD: "),
                    input("Ubicacion (opcional): ").strip() or None,
                    pedir_opcional_float("Precio máximo (opcional): "),
                    pedir_opcional_float("Calificación mínima (opcional): "),
                )
                if not resultados:
                    print("Sin resultados")
                else:
                    for idx, item in enumerate(resultados, start=1):
                        print(f"\n{idx}. Hotel: {item['hotel_nombre']} ({item['ubicacion']})")
                        print(f"   Habitación: {item['habitación_id']} - {item['tipo']}")
                        print(f"   Precio estimado: {item['precio_estimado']}")
                        print(f"   Calificación hab/hotel: {item['habitación_rating']} / {item['hotel_rating']}")

            elif opcion == "10":
                detalle = sistema.detalle_habitación(input("Habitación ID: ").strip())
                hab = detalle["habitación"]
                print(f"Habitación: {hab['tipo']} - {hab['id']}")
                print(f"Descripción: {hab['descripcion']}")
                print(f"Servicios: {', '.join(hab['servicios_incluidos'])}")
                print(f"Fotos: {', '.join(hab['fotos'])}")
                print(f"Calificación habitación: {detalle['calificacion_promedio_habitación']}")
                print(f"Hotel: {detalle['hotel']['nombre']} | Calificación general: {detalle['hotel']['calificacion_general']}")
                print("Comentarios:")
                for c in detalle["comentarios"]:
                    print(f"- ({c['puntaje']}/5) {c['comentario']}")

            elif opcion == "11":
                reserva = sistema.crear_reserva(
                    input("Cliente ID: "),
                    input("Habitación ID: "),
                    input("Fecha inicio YYYY-MM-DD: "),
                    input("Fecha fin YYYY-MM-DD: "),
                    int(input("Número de huéspedes: ")),
                    input("Método de pago: "),
                )
                print(f"Reserva creada con ID: {reserva.id}")
                print(f"Estado: {reserva.estado} | Pago: {reserva.pago_estado}")
                print(f"Total: {reserva.precio_calculado}")

            elif opcion == "12":
                reserva = sistema.confirmar_pago(input("Reserva ID: ").strip())
                print(f"Pago confirmado. Reserva formalizada: {reserva.id}")

            elif opcion == "13":
                reserva = sistema.cancelar_reserva_y_reembolsar(input("Reserva ID: ").strip())
                print(f"Reserva cancelada. Reembolso procesado: {reserva.monto_reembolso}")

            elif opcion == "14":
                habitación_id = input("Habitación ID: ").strip()
                anio = int(input("Año: "))
                mes = int(input("Mes (1-12): "))
                calendario = sistema.obtener_calendario_disponibilidad(habitación_id, anio, mes)
                for day, status in calendario.items():
                    print(f"{day}: {status}")

            elif opcion == "15":
                c = sistema.registrar_comentario(
                    input("Cliente ID: "),
                    input("Habitación ID: "),
                    int(input("Puntaje (1-5): ")),
                    input("Comentario: "),
                )
                print(f"Comentario registrado: {c.id}")

            elif opcion == "16":
                activos = sistema.listar_hoteles(solo_activos=True)
                if not activos:
                    print("No hay hoteles activos")
                for h in activos:
                    print("\n---")
                    imprimir_hotel(sistema, h)

            elif opcion == "17":
                print("Hasta luego")
                break

            else:
                print("Opción inválida")

        except ErrorNegocio as exc:
            print(f"Error de negocio: {exc}")
        except Exception as exc:  # noqa: BLE001
            print(f"Error inesperado: {exc}")


def _paginar(items: List[Dict], pagina: int, por_pagina: int) -> tuple[List[Dict], int, int]:
    total_items = len(items)
    total_paginas = max(1, ceil(total_items / por_pagina))
    pagina = max(1, min(pagina, total_paginas))
    inicio = (pagina - 1) * por_pagina
    fin = inicio + por_pagina
    return items[inicio:fin], pagina, total_paginas


TARIFAS = [
    {"destino": "Aruba", "pasajes": 418, "silver": 134, "gold": 167, "platinum": 191},
    {"destino": "Bahamas", "pasajes": 423, "silver": 112, "gold": 183, "platinum": 202},
    {"destino": "Cancún", "pasajes": 350, "silver": 105, "gold": 142, "platinum": 187},
    {"destino": "Hawaii", "pasajes": 858, "silver": 210, "gold": 247, "platinum": 291},
    {"destino": "Jamaica", "pasajes": 380, "silver": 115, "gold": 134, "platinum": 161},
    {"destino": "Madrid", "pasajes": 496, "silver": 190, "gold": 230, "platinum": 270},
    {"destino": "Miami", "pasajes": 334, "silver": 122, "gold": 151, "platinum": 183},
    {"destino": "Moscu", "pasajes": 634, "silver": 131, "gold": 153, "platinum": 167},
    {"destino": "NewYork", "pasajes": 495, "silver": 104, "gold": 112, "platinum": 210},
    {"destino": "Panamá", "pasajes": 315, "silver": 119, "gold": 138, "platinum": 175},
    {"destino": "Paris", "pasajes": 512, "silver": 210, "gold": 260, "platinum": 290},
    {"destino": "Rome", "pasajes": 478, "silver": 184, "gold": 220, "platinum": 250},
    {"destino": "Seul", "pasajes": 967, "silver": 205, "gold": 245, "platinum": 265},
    {"destino": "Sidney", "pasajes": 1045, "silver": 170, "gold": 199, "platinum": 230},
    {"destino": "Taipei", "pasajes": 912, "silver": 220, "gold": 245, "platinum": 298},
    {"destino": "Tokio", "pasajes": 989, "silver": 189, "gold": 231, "platinum": 255},
]


def _imagen_para_ubicacion(ubicacion: str) -> str:
    texto = ubicacion.lower()
    mapa = {
        "aruba": "aruba.png",
        "bahamas": "bahamas.png",
        "canc": "cancun.png",
        "hawai": "hawaii.png",
        "jamaica": "jamaica.png",
        "madrid": "madrid.png",
        "miami": "miami.png",
        "mosc": "moscu.png",
        "newyork": "newyork.png",
        "panam": "panama.png",
        "paris": "paris.png",
        "rome": "rome.png",
        "seul": "seul.png",
        "sidney": "sidney.png",
        "taipei": "taipei.png",
        "tokio": "tokio.png",
    }

    for clave, archivo in mapa.items():
        if clave in texto:
            return f"/static/{archivo}"
    return ""


def crear_app_web() -> Flask:
    app = Flask(__name__, template_folder="templates")
    almacen = AlmacenJson(Path("static/data/database.json"))
    sistema = SistemaAgenciaViajes(almacen)

    @app.get("/")
    def inicio() -> str:
        pagina = request.args.get("pagina", default=1, type=int)
        por_pagina = request.args.get("por_pagina", default=5, type=int)
        por_pagina = max(1, min(por_pagina, 50))

        hoteles = []
        for hotel in sistema.listar_hoteles():
            fila = asdict(hotel)
            fila["imagen_url"] = _imagen_para_ubicacion(hotel.ubicacion_geografica)
            hoteles.append(fila)

        hoteles_pagina, pagina, total_paginas = _paginar(hoteles, pagina, por_pagina)

        return render_template(
            "hoteles.html",
            titulo="Hoteles",
            hoteles=hoteles_pagina,
            pagina=pagina,
            total_paginas=total_paginas,
            por_pagina=por_pagina,
        )

    @app.get("/habitaciones")
    def habitaciones() -> str:
        pagina = request.args.get("pagina", default=1, type=int)
        por_pagina = request.args.get("por_pagina", default=8, type=int)
        por_pagina = max(1, min(por_pagina, 50))

        db = sistema._cargar_todo()
        filas_habitaciones = db.get("habitaciones", db.get("habitaciónes", []))
        hoteles = {h.id: h for h in sistema.listar_hoteles()}

        habitaciones_data: List[Dict] = []
        for fila in filas_habitaciones:
            fila_normalizada = dict(fila)
            if "habitación_id" in fila_normalizada and "habitacion_id" not in fila_normalizada:
                fila_normalizada["habitacion_id"] = fila_normalizada["habitación_id"]
            hotel = hoteles.get(fila_normalizada.get("hotel_id", ""))
            fila_normalizada["hotel_nombre"] = hotel.nombre if hotel else "Hotel no encontrado"
            fila_normalizada["imagen_url"] = _imagen_para_ubicacion(hotel.ubicacion_geografica if hotel else "")
            habitaciones_data.append(fila_normalizada)

        hab_pagina, pagina, total_paginas = _paginar(habitaciones_data, pagina, por_pagina)

        return render_template(
            "habitaciones.html",
            titulo="Habitaciones",
            habitaciones=hab_pagina,
            pagina=pagina,
            total_paginas=total_paginas,
            por_pagina=por_pagina,
        )

    @app.get("/tarifas")
    def tarifas() -> str:
        return render_template("tarifas.html", titulo="Tarifas", tarifas=TARIFAS)

    return app


def ejecutar_web() -> None:
    app = crear_app_web()

    def _instalar_manejadores_salida() -> None:
        def _on_signal(signum, _frame) -> None:
            try:
                nombre = signal.Signals(signum).name
            except ValueError:
                nombre = str(signum)
            print(f"\nSeñal recibida: {nombre}")
            raise KeyboardInterrupt

        for nombre_senal in ("SIGINT", "SIGTERM", "SIGBREAK"):
            if hasattr(signal, nombre_senal):
                signal.signal(getattr(signal, nombre_senal), _on_signal)

    _instalar_manejadores_salida()

    print("Servidor web iniciado")
    print("Abre en navegador:")
    print("- http://127.0.0.1:5000/")
    print("- http://127.0.0.1:5000/habitaciones")
    threading.Timer(1.0, lambda: webbrowser.open("http://127.0.0.1:5000/")).start()
    try:
        app.run(debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("Servidor detenido por usuario o por cierre de terminal.")
    except OSError as exc:
        print(f"No se pudo iniciar o mantener el servidor: {exc}")
        raise
    finally:
        print("Proceso web finalizado.")


if __name__ == "__main__":
    ejecutar_web()








