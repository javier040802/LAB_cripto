def cifrado_cesar(texto, desplazamiento):
    resultado = ""
    for c in texto:
        if c.isalpha():
            mayus = c.isupper()
            base = ord('A') if mayus else ord('a')
            resultado += chr((ord(c) - base + desplazamiento) % 26 + base)
        else:
            resultado += c
    return resultado

if __name__ == "__main__":
    texto = input("Texto a cifrar: ")
    desplazamiento = int(input("Desplazamiento: "))
    cifrado = cifrado_cesar(texto, desplazamiento)
    print("Texto cifrado:", cifrado)
