#!/usr/bin/env python3
import re
from scapy.all import sniff, ICMP, Raw

# Diccionario de palabras coherentes (puedes ampliarlo)
COHERENT_WORDS = {
    "informacion", "y", "a", "en", "secreta", "mensaje", "datos", "cifrado", "ping", "paquete"
}

def capturar_mensaje(timeout=20):
    """
    Captura paquetes ICMP tipo echo-request (tipo 8) durante 'timeout' segundos.
    Se acumulan todos los caracteres. Si el mensaje termina en 'b', se elimina ese último carácter.
    """
    print("Escuchando paquetes ICMP tipo echo-request (tipo 8) por", timeout, "segundos...")
    paquetes = sniff(filter="icmp and icmp[icmptype] == 8", timeout=timeout)
    mensaje = ""
    for pkt in paquetes:
        print("Paquete capturado:", pkt.summary())
        if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
            try:
                char = pkt[Raw].load.decode('utf-8', errors="ignore")
            except Exception as e:
                print("Error decodificando paquete:", e)
                continue
            print("Contenido del paquete:", repr(char))
            mensaje += char
    # Eliminar marcador 'b' solo si el mensaje tiene más de 1 carácter
    if mensaje.endswith("b") and len(mensaje) > 1:
        mensaje = mensaje[:-1]
    return mensaje

def resaltar_coherentes(texto, dictionary):
    """
    Resalta en verde cada palabra del texto que se encuentre en 'dictionary'.
    1. Se separa el texto por secuencias de caracteres no alfanuméricos (puntuación, espacios).
    2. Se reconstruye el texto con resaltado ANSI para las palabras que coincidan con el diccionario.
    """
    tokens = re.split(r'(\W+)', texto)
    resultado = ""
    for token in tokens:
        # Comparamos el token en minúsculas con el diccionario
        if token.lower() in dictionary:
            resultado += f"\033[92m{token}\033[0m"
        else:
            resultado += token
    return resultado

def contiene_palabra_coherente(texto, dictionary):
    """
    Devuelve True si 'texto' contiene alguna palabra del 'dictionary' como palabra completa.
    - Extrae solo secuencias de letras (a-z, á-ú) y compara con minúsculas.
    - Evita coincidencias parciales de subcadenas (p.ej. 'ping' en 'camping').
    """
    # Extrae todas las 'palabras' alfanuméricas
    palabras = re.findall(r'[a-zA-Zá-úÁ-Ú]+', texto.lower())
    # Verifica si alguna de ellas está en el diccionario
    return any(palabra in dictionary for palabra in palabras)

def descifrar_todos(texto):
    """
    Recorre los 26 posibles desplazamientos del cifrado César y descifra el 'texto'.
    Muestra el resultado resaltando las palabras coherentes.
    Solamente imprime "Posible coincidencia" si encuentra una palabra completa del diccionario.
    """
    encontrado = False
    print("\nResultados del descifrado:")
    for d in range(26):
        descifrado = []
        for c in texto:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                descifrado.append(chr((ord(c) - base - d) % 26 + base))
            else:
                descifrado.append(c)
        descifrado = "".join(descifrado)

        # Resalta palabras en el descifrado
        resaltado = resaltar_coherentes(descifrado, COHERENT_WORDS)
        print(f"Desplazamiento {d}: {resaltado}")

        # Revisa si contiene al menos una palabra del diccionario
        if contiene_palabra_coherente(descifrado, COHERENT_WORDS):
            print(f"\033[92m* Posible coincidencia encontrada en desplazamiento {d}\033[0m")
            encontrado = True

    if not encontrado:
        print("No se encontraron palabras coherentes. Revisa el mensaje o amplía tu diccionario.")

if __name__ == "__main__":
    mensaje_capturado = capturar_mensaje(timeout=20)
    print("\nMensaje capturado:", repr(mensaje_capturado))
    print("\nIntentando descifrar...")
    descifrar_todos(mensaje_capturado)