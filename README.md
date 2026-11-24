# SSH Brute-Force Detector

Detector de ataques de fuerza bruta contra SSH escrito en Python. Analiza los logs de autenticación de un servidor Linux, agrupa los intentos fallidos en ráfagas y genera una alerta clasificada con **MITRE ATT&CK**.

Proyecto surgido de mi laboratorio SOC con **Wazuh** sobre **Proxmox**: quería entender cómo una regla como la 5712 de Wazuh (*brute force trying to get access to the system*) decide que algo es un ataque, y reproducir esa lógica con mi propio código.

## Qué hace

- Lee un log de `sshd` (salida de `journalctl -u ssh`).
- Extrae los intentos fallidos (`Failed password`) con su IP, usuario y hora.
- Agrupa los intentos de cada IP en **ráfagas** (si pasan más de 30 s entre fallos, empieza una nueva).
- Si una ráfaga supera el umbral, emite una alerta con severidad **BAJA / MEDIA / ALTA**.
- Etiqueta la alerta con la técnica **T1110.001 (Brute Force: Password Guessing)**.
- Distingue si el usuario atacado **existe o no** en el sistema.

## Uso

```bash
# 1. Exporta el log del servidor a analizar
sudo journalctl -u ssh --no-pager > ssh-log.txt

# 2. Ejecuta el detector
python detector.py ssh-log.txt
```

Requiere Python 3.8 o superior. No necesita librerías externas.

## Ejemplo de salida

```
=======================================================
ALERTA: posible fuerza bruta SSH [MEDIA]
  IP origen        : 203.0.113.45
  Intentos fallidos: 9 (a usuarios inexistentes: 9)
  Usuarios probados: admin
  Inicio / Fin     : 09:46:46 / 09:47:10
  Duración         : 24 s
  MITRE ATT&CK     : T1110.001 - Brute Force: Password Guessing
```

La IP del ejemplo es una dirección reservada para documentación.

## Parámetros

Al principio de `detector.py`:

| Parámetro | Valor | Significado |
|---|---|---|
| `GAP_SEGUNDOS` | 30 | Tiempo máximo entre fallos para seguir en la misma ráfaga |
| `UMBRAL_RAFAGA` | 5 | Fallos mínimos para considerarla sospechosa |

Para comparar: la regla 5712 de Wazuh salta con 8 fallos en 120 segundos.

## Entorno de pruebas

- Servidor **Proxmox VE** en un HP EliteDesk 800 G5 Mini.
- VM con **Wazuh** (manager, indexer y dashboard) y VM Ubuntu 24.04 con agente.
- Ataque simulado con `ssh` contra un usuario inexistente, comprobado en el dashboard de Wazuh (reglas 5710 y 5712).

## Autor

Javier Aguilar Postigo, Técnico Superior en ASIR, Málaga.
