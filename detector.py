import re
import sys
from collections import defaultdict
from datetime import datetime

# Parámetros del detector (se pueden ajustar)
GAP_SEGUNDOS = 30   # si pasan más de 30 s entre fallos, empieza otra ráfaga
UMBRAL_RAFAGA = 5   # nº mínimo de fallos para considerar una ráfaga sospechosa
MITRE = "T1110.001 - Brute Force: Password Guessing"

MESES = {"ene": 1, "feb": 2, "mar": 3, "abr": 4, "may": 5, "jun": 6,
         "jul": 7, "ago": 8, "sep": 9, "oct": 10, "nov": 11, "dic": 12,
         "jan": 1, "apr": 4, "aug": 8, "dec": 12}

PATRON_FECHA = re.compile(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")
PATRON_FALLO = re.compile(r"Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")

def leer_fallos(ruta):
    """Devuelve {ip: [(momento, usuario, usuario_inexistente), ...]}"""
    fallos = defaultdict(list)
    anio = datetime.now().year
    with open(ruta, encoding="utf-8") as f:
        for linea in f:
            fallo = PATRON_FALLO.search(linea)
            fecha = PATRON_FECHA.match(linea)
            if not (fallo and fecha):
                continue
            mes, dia, hora = fecha.groups()
            if mes.lower() not in MESES:
                continue
            momento = datetime.strptime(
                f"{anio} {MESES[mes.lower()]} {dia} {hora}", "%Y %m %d %H:%M:%S")
            inexistente = fallo.group(1) is not None
            fallos[fallo.group(3)].append((momento, fallo.group(2), inexistente))
    return fallos

def agrupar_rafagas(eventos):
    rafagas, actual = [], []
    for ev in sorted(eventos, key=lambda e: e[0]):
        if actual and (ev[0] - actual[-1][0]).total_seconds() > GAP_SEGUNDOS:
            rafagas.append(actual)
            actual = []
        actual.append(ev)
    if actual:
        rafagas.append(actual)
    return rafagas

def severidad(n):
    if n >= 20:
        return "ALTA"
    if n >= 8:
        return "MEDIA"
    return "BAJA"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python v2.py <fichero_log>")
        sys.exit(1)

    fallos = leer_fallos(sys.argv[1])
    encontrado = False

    for ip, eventos in fallos.items():
        for rafaga in agrupar_rafagas(eventos):
            if len(rafaga) < UMBRAL_RAFAGA:
                continue
            encontrado = True
            inicio, fin = rafaga[0][0], rafaga[-1][0]
            usuarios = sorted({e[1] for e in rafaga})
            inexistentes = sum(1 for e in rafaga if e[2])
            print("=" * 55)
            print(f"ALERTA: posible fuerza bruta SSH  [{severidad(len(rafaga))}]")
            print(f"  IP origen        : {ip}")
            print(f"  Intentos fallidos: {len(rafaga)} (a usuarios inexistentes: {inexistentes})")
            print(f"  Usuarios probados: {', '.join(usuarios)}")
            print(f"  Inicio / Fin     : {inicio:%H:%M:%S} / {fin:%H:%M:%S}")
            print(f"  Duración         : {int((fin - inicio).total_seconds())} s")
            print(f"  MITRE ATT&CK     : {MITRE}")
            
    if not encontrado:
        print("No se han detectado ráfagas sospechosas.")
