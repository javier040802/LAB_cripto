from scapy.all import *

def enviar_ping_oculto(mensaje, destino="8.8.8.8"):
    for c in mensaje + "b":  # último carácter 'b' como se solicita
        paquete = IP(dst=destino)/ICMP()/Raw(load=c)
        send(paquete)
        print(f"Enviado carácter: {c}")

if __name__ == "__main__":
    texto = input("Mensaje a enviar: ")
    enviar_ping_oculto(texto)
