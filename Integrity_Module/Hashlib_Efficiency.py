import hashlib
import time
import os

def benchmark(algorithm_name, data_size_mb=100):
    # Crear datos de prueba
    data = os.urandom(data_size_mb * 1024 * 1024)
    
    # Medir tiempo
    inicio = time.perf_counter()
    h = hashlib.new(algorithm_name)
    h.update(data)
    h.digest()
    fin = time.perf_counter()
    
    return fin - inicio

# Probar cada algoritmo
for algorithm in ['sha256', 'sha512', 'blake2b', 'sha3_256']:
    time_used = benchmark(algorithm, 100)  # Archivo de 100MB
    print(f"{algorithm}: {time_used:.4f} segundos")


#.4f --> .4f es un formato de cadena que se utiliza para formatear números de punto flotante con 4 dígitos después del punto decimal.