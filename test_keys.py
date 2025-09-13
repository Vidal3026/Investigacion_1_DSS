"""
test_keys.py

Uso: python test_keys.py [N]
Genera N llaves (por defecto 200) y muestra métricas:
- colisiones
- entropía promedio (bits/símbolo)
- chi-cuadrado (distribución de bytes vs uniforme)
Imprime resultados en consola (útil para incluir en informe).
"""

import sys
from cifrado import evaluar_llaves

def main():
    n = 200
    if len(sys.argv) > 1:
        try:
            n = int(sys.argv[1])
        except:
            pass
    stats = evaluar_llaves(n)
    print("---- Evaluación de llaves ----")
    print(f"Total generadas: {stats['total']}")
    print(f"Longitud (bytes): {stats['longitud_bytes']}")
    print(f"Únicas: {stats['unicas']}")
    print(f"Colisiones: {stats['colisiones']}")
    print(f"Entropía (bits/símbolo): {stats['entropia_bits_por_simbolo']:.6f} (máx 8)")
    print(f"Chi-cuadrado uniformidad: {stats['chi2_uniform']:.2f}")
    print("------------------------------")

if __name__ == "__main__":
    main()
