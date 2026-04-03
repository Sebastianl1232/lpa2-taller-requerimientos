from __future__ import annotations

import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List
from uuid import uuid4


EMAIL_PATTERN = re.compile(r"^[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}$")
PHONE_PATTERN = re.compile(r"^[+]?\d[\d\s\-]{6,}$")


@dataclass
class Hotel:
	id: str
	nombre: str
	direccion: str
	telefono: str
	correo_electronico: str
	ubicacion_geografica: str
	descripcion_servicios: List[str]
	fotos: List[str]


class HotelValidationError(ValueError):
	pass


class HotelRepository:
	def __init__(self, storage_path: Path) -> None:
		self.storage_path = storage_path
		self.storage_path.parent.mkdir(parents=True, exist_ok=True)

	def get_all(self) -> List[Hotel]:
		raw_data = self._read_storage()
		return [Hotel(**item) for item in raw_data]

	def create(self, hotel: Hotel) -> Hotel:
		items = self._read_storage()
		items.append(asdict(hotel))
		self._write_storage(items)
		return hotel

	def _read_storage(self) -> List[dict]:
		if not self.storage_path.exists():
			return []

		try:
			content = self.storage_path.read_text(encoding="utf-8").strip()
			if not content:
				return []
			data = json.loads(content)
			if not isinstance(data, list):
				return []
			return data
		except (json.JSONDecodeError, OSError):
			return []

	def _write_storage(self, items: List[dict]) -> None:
		self.storage_path.write_text(
			json.dumps(items, ensure_ascii=False, indent=2),
			encoding="utf-8",
		)


class HotelService:
	def __init__(self, repository: HotelRepository) -> None:
		self.repository = repository

	def registrar_hotel(
		self,
		nombre: str,
		direccion: str,
		telefono: str,
		correo_electronico: str,
		ubicacion_geografica: str,
		descripcion_servicios: List[str],
		fotos: List[str],
	) -> Hotel:
		self._validar_hotel(
			nombre,
			direccion,
			telefono,
			correo_electronico,
			ubicacion_geografica,
			descripcion_servicios,
			fotos,
		)

		hotel = Hotel(
			id=str(uuid4()),
			nombre=nombre.strip(),
			direccion=direccion.strip(),
			telefono=telefono.strip(),
			correo_electronico=correo_electronico.strip().lower(),
			ubicacion_geografica=ubicacion_geografica.strip(),
			descripcion_servicios=[item.strip() for item in descripcion_servicios],
			fotos=[item.strip() for item in fotos],
		)
		return self.repository.create(hotel)

	def listar_hoteles(self) -> List[Hotel]:
		return self.repository.get_all()

	def _validar_hotel(
		self,
		nombre: str,
		direccion: str,
		telefono: str,
		correo_electronico: str,
		ubicacion_geografica: str,
		descripcion_servicios: List[str],
		fotos: List[str],
	) -> None:
		if not nombre.strip():
			raise HotelValidationError("El nombre del hotel es obligatorio.")
		if not direccion.strip():
			raise HotelValidationError("La direccion del hotel es obligatoria.")
		if not PHONE_PATTERN.match(telefono.strip()):
			raise HotelValidationError("El telefono no tiene un formato valido.")
		if not EMAIL_PATTERN.match(correo_electronico.strip()):
			raise HotelValidationError("El correo electronico no tiene un formato valido.")
		if not ubicacion_geografica.strip():
			raise HotelValidationError("La ubicacion geografica es obligatoria.")
		if not descripcion_servicios:
			raise HotelValidationError("Debe incluir al menos un servicio.")
		if not all(item.strip() for item in descripcion_servicios):
			raise HotelValidationError("Los servicios no pueden estar vacios.")
		if not fotos:
			raise HotelValidationError("Debe incluir al menos una foto.")
		if not all(item.strip() for item in fotos):
			raise HotelValidationError("Las fotos no pueden estar vacias.")


def pedir_lista(mensaje: str) -> List[str]:
	print(mensaje)
	print("- Escribe un elemento por linea.")
	print("- Presiona ENTER en linea vacia para terminar.")
	items: List[str] = []
	while True:
		valor = input("> ").strip()
		if not valor:
			break
		items.append(valor)
	return items


def registrar_hotel_interactivo(service: HotelService) -> None:
	print("\n=== REGISTRO DE HOTEL (R1) ===")
	nombre = input("Nombre: ")
	direccion = input("Direccion: ")
	telefono = input("Telefono: ")
	correo = input("Correo electronico: ")
	ubicacion = input("Ubicacion geografica (ciudad, coordenadas o referencia): ")
	servicios = pedir_lista("Servicios del hotel")
	fotos = pedir_lista("Fotos del hotel (URL o ruta)")

	try:
		hotel = service.registrar_hotel(
			nombre=nombre,
			direccion=direccion,
			telefono=telefono,
			correo_electronico=correo,
			ubicacion_geografica=ubicacion,
			descripcion_servicios=servicios,
			fotos=fotos,
		)
		print("\nHotel registrado correctamente.")
		print(f"ID generado: {hotel.id}")
	except HotelValidationError as exc:
		print(f"\nNo se pudo registrar el hotel: {exc}")


def listar_hoteles_interactivo(service: HotelService) -> None:
	print("\n=== HOTELES REGISTRADOS ===")
	hoteles = service.listar_hoteles()
	if not hoteles:
		print("No hay hoteles registrados.")
		return

	for index, hotel in enumerate(hoteles, start=1):
		print(f"\n{index}. {hotel.nombre}")
		print(f"   ID: {hotel.id}")
		print(f"   Direccion: {hotel.direccion}")
		print(f"   Telefono: {hotel.telefono}")
		print(f"   Correo: {hotel.correo_electronico}")
		print(f"   Ubicacion: {hotel.ubicacion_geografica}")
		print(f"   Servicios: {', '.join(hotel.descripcion_servicios)}")
		print(f"   Fotos: {', '.join(hotel.fotos)}")


def mostrar_menu() -> None:
	print("\n=== SISTEMA DE AGENCIA DE VIAJES ===")
	print("1. Registrar hotel (R1)")
	print("2. Listar hoteles")
	print("3. Salir")


def main() -> None:
	repo = HotelRepository(Path("static/data/hoteles.json"))
	service = HotelService(repo)

	while True:
		mostrar_menu()
		opcion = input("Selecciona una opcion: ").strip()

		if opcion == "1":
			registrar_hotel_interactivo(service)
		elif opcion == "2":
			listar_hoteles_interactivo(service)
		elif opcion == "3":
			print("Hasta luego.")
			break
		else:
			print("Opcion invalida. Intenta de nuevo.")


if __name__ == "__main__":
	main()

