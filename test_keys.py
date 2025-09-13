"""
test_keys.py

Uso: python test_keys.py [N]
Genera N llaves (por defecto 200) y muestra métricas:
- colisiones
- entropía promedio (bits/símbolo)
- chi-cuadrado (distribución de bytes vs uniforme)
Imprime resultados en consola (útil para incluir en informe).
"""

# Importamos el módulo sys para acceder a los argumentos de línea de comandos.
# Esto nos permite leer cuántas llaves generar si el usuario lo indica.
import sys

# Importamos la función 'evaluar_llaves' desde nuestro módulo 'cifrado'.
# Esta función se encarga de generar llaves, calcular métricas estadísticas,
# y devolver resultados en forma de diccionario.
from cifrado import evaluar_llaves


def main():
    """
    Función principal del script.
    Encargada de:
    - Leer el argumento de línea de comandos (si existe).
    - Generar las llaves y evaluar métricas.
    - Imprimir los resultados en consola de manera legible.
    """

    # Definimos un valor por defecto: número de llaves a generar = 200.
    n = 200

    # Si el usuario proporciona argumentos (ej: python test_keys.py 500),
    # intentamos leer el primer argumento como un entero.
    if len(sys.argv) > 1:
        try:
            # Convertimos el argumento a número entero.
            n = int(sys.argv[1])
        except:
            # Si ocurre un error (ej: argumento no es un número),
            # simplemente ignoramos y dejamos el valor por defecto (200).
            pass

    # Llamamos a la función 'evaluar_llaves' con el número de llaves 'n'.
    # Esto devuelve un diccionario con métricas estadísticas.
    stats = evaluar_llaves(n)

    # Imprimimos un encabezado para diferenciar el bloque de resultados.
    print("---- Evaluación de llaves ----")

    # Cada uno de los siguientes print muestra un valor específico
    # que viene dentro del diccionario 'stats'.
    print(f"Total generadas: {stats['total']}")  # Cantidad total de llaves generadas.
    print(f"Longitud (bytes): {stats['longitud_bytes']}")  # Tamaño de cada llave.
    print(f"Únicas: {stats['unicas']}")  # Número de llaves únicas generadas.
    print(f"Colisiones: {stats['colisiones']}")  # Cuántas veces se repitieron llaves.
    print(
        f"Entropía (bits/símbolo): {stats['entropia_bits_por_simbolo']:.6f} (máx 8)"
    )  # Medida de aleatoriedad (ideal cerca de 8 bits por símbolo).
    print(
        f"Chi-cuadrado uniformidad: {stats['chi2_uniform']:.2f}"
    )  # Test chi-cuadrado para ver qué tan uniforme es la distribución de bytes.

    # Línea final para marcar el cierre de la sección.
    print("------------------------------")


# Este condicional garantiza que 'main()' solo se ejecute cuando el script
# es ejecutado directamente con 'python test_keys.py', y no cuando se importa
# como módulo desde otro archivo.
if __name__ == "__main__":
    main()
