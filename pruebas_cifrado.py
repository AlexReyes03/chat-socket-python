import sys

def prueba_cifrado_simetrico():
    """Prueba el modulo de cifrado simetrico"""
    print("="*70)
    print("PRUEBA 1: CIFRADO SIMETRICO (Fernet)")
    print("="*70)
    
    try:
        from cifrado_simetrico import Cifrador
        
        cifrador = Cifrador()
        
        # Prueba 1: Mensaje simple
        print("\n[Test 1.1] Cifrado de mensaje simple")
        mensaje = "Hola mundo!"
        cifrado = cifrador.cifrar_mensaje(mensaje)
        descifrado = cifrador.descifrar_mensaje(cifrado)
        
        print(f"  Original:   {mensaje}")
        print(f"  Cifrado:    {cifrado[:40]}...")
        print(f"  Descifrado: {descifrado}")
        print(f"  Resultado: {'PASS' if mensaje == descifrado else 'FAIL'}")
        
        # Prueba 2: Mensaje largo
        print("\n[Test 1.2] Cifrado de mensaje largo")
        mensaje_largo = "Este es un mensaje mucho mas largo para probar que el cifrado funciona correctamente con textos extensos. " * 3
        cifrado_largo = cifrador.cifrar_mensaje(mensaje_largo)
        descifrado_largo = cifrador.descifrar_mensaje(cifrado_largo)
        print(f"  Longitud original: {len(mensaje_largo)} caracteres")
        print(f"  Resultado: {'PASS' if mensaje_largo == descifrado_largo else 'FAIL'}")
        
        # Prueba 3: Datos de usuario
        print("\n[Test 1.3] Cifrado de datos de usuario")
        nombre, ip, puerto = "TestUser", "192.168.1.100", 12345
        n_c, i_c, p_c = cifrador.cifrar_datos_usuario(nombre, ip, puerto)
        n_d, i_d, p_d = cifrador.descifrar_datos_usuario(n_c, i_c, p_c)
        
        print(f"  Original:   Nombre={nombre}, IP={ip}, Puerto={puerto}")
        print(f"  Descifrado: Nombre={n_d}, IP={i_d}, Puerto={p_d}")
        resultado = nombre == n_d and ip == i_d and puerto == p_d
        print(f"  Resultado: {'PASS' if resultado else 'FAIL'}")
        
        # Prueba 4: Caracteres especiales
        print("\n[Test 1.4] Cifrado con caracteres especiales")
        mensaje_especial = "¡Hola! ¿Cómo estás? ñÑáéíóúÁÉÍÓÚ @#$%"
        cifrado_esp = cifrador.cifrar_mensaje(mensaje_especial)
        descifrado_esp = cifrador.descifrar_mensaje(cifrado_esp)
        print(f"  Original:   {mensaje_especial}")
        print(f"  Descifrado: {descifrado_esp}")
        print(f"  Resultado: {'PASS' if mensaje_especial == descifrado_esp else 'FAIL'}")
        
        print("\n" + "="*70)
        print("CIFRADO SIMETRICO: TODAS LAS PRUEBAS COMPLETADAS")
        print("="*70)
        return True
        
    except ImportError as e:
        print(f"\nERROR: No se pudo importar cifrado_simetrico.py")
        print(f"Detalle: {e}")
        return False
    except Exception as e:
        print(f"\nERROR en pruebas de cifrado simetrico: {e}")
        return False


def prueba_cifrado_asimetrico():
    """Prueba el modulo de cifrado asimetrico"""
    print("\n\n" + "="*70)
    print("PRUEBA 2: CIFRADO ASIMETRICO (RSA)")
    print("="*70)
    
    try:
        from cifrado_asimetrico import Cifrador
        
        # Simular servidor y cliente
        servidor = Cifrador(es_servidor=True)
        cliente = Cifrador(es_servidor=False)
        
        # Prueba 1: Mensaje simple
        print("\n[Test 2.1] Cifrado de mensaje simple")
        mensaje = "Mensaje secreto"
        cifrado = cliente.cifrar_mensaje(mensaje)
        descifrado = servidor.descifrar_mensaje(cifrado)
        
        print(f"  Original:   {mensaje}")
        print(f"  Cifrado:    {cifrado[:40]}...")
        print(f"  Descifrado: {descifrado}")
        print(f"  Resultado: {'PASS' if mensaje == descifrado else 'FAIL'}")
        
        # Prueba 2: Mensaje largo (probando bloques)
        print("\n[Test 2.2] Cifrado de mensaje largo (multiples bloques)")
        mensaje_largo = "Este mensaje es mas largo y se dividira en bloques. " * 5
        cifrado_largo = cliente.cifrar_mensaje(mensaje_largo)
        descifrado_largo = servidor.descifrar_mensaje(cifrado_largo)
        print(f"  Longitud original: {len(mensaje_largo)} caracteres")
        print(f"  Bloques generados: {cifrado_largo.count('|||') + 1}")
        print(f"  Resultado: {'PASS' if mensaje_largo == descifrado_largo else 'FAIL'}")
        
        # Prueba 3: Datos de usuario
        print("\n[Test 2.3] Cifrado de datos de usuario")
        nombre, ip, puerto = "AliceUser", "10.0.0.5", 9999
        n_c, i_c, p_c = cliente.cifrar_datos_usuario(nombre, ip, puerto)
        n_d, i_d, p_d = servidor.descifrar_datos_usuario(n_c, i_c, p_c)
        
        print(f"  Original:   Nombre={nombre}, IP={ip}, Puerto={puerto}")
        print(f"  Descifrado: Nombre={n_d}, IP={i_d}, Puerto={p_d}")
        resultado = nombre == n_d and ip == i_d and puerto == p_d
        print(f"  Resultado: {'PASS' if resultado else 'FAIL'}")
        
        # Prueba 4: Verificar que el cliente NO puede descifrar
        print("\n[Test 2.4] Verificar que el cliente no puede descifrar")
        mensaje_test = "Test de seguridad"
        cifrado_test = cliente.cifrar_mensaje(mensaje_test)
        descifrado_cliente = cliente.descifrar_mensaje(cifrado_test)
        print(f"  Cliente intenta descifrar: {descifrado_cliente}")
        print(f"  Resultado: {'PASS' if descifrado_cliente is None else 'FAIL'}")
        
        # Prueba 5: Caracteres especiales
        print("\n[Test 2.5] Cifrado con caracteres especiales")
        mensaje_especial = "¡Mensaje! ¿RSA? ñÑ áéíóú @#$%"
        cifrado_esp = cliente.cifrar_mensaje(mensaje_especial)
        descifrado_esp = servidor.descifrar_mensaje(cifrado_esp)
        print(f"  Original:   {mensaje_especial}")
        print(f"  Descifrado: {descifrado_esp}")
        print(f"  Resultado: {'PASS' if mensaje_especial == descifrado_esp else 'FAIL'}")
        
        print("\n" + "="*70)
        print("CIFRADO ASIMETRICO: TODAS LAS PRUEBAS COMPLETADAS")
        print("="*70)
        return True
        
    except ImportError as e:
        print(f"\nERROR: No se pudo importar cifrado_asimetrico.py")
        print(f"Detalle: {e}")
        print("\nNOTA: Si es la primera vez que ejecutas esto, primero debes:")
        print("1. Ejecutar: python cifrado_asimetrico.py")
        print("2. Seleccionar opcion 1 para generar claves")
        print("3. Copiar las claves generadas en el archivo cifrado_asimetrico.py")
        return False
    except Exception as e:
        print(f"\nERROR en pruebas de cifrado asimetrico: {e}")
        import traceback
        traceback.print_exc()
        return False


def prueba_integracion():
    """Prueba que ambos modulos pueden coexistir"""
    print("\n\n" + "="*70)
    print("PRUEBA 3: INTEGRACION DE AMBOS MODULOS")
    print("="*70)
    
    try:
        from cifrado_simetrico import Cifrador as CifradorSimetrico
        from cifrado_asimetrico import Cifrador as CifradorAsimetrico
        
        print("\n[Test 3.1] Importar ambos modulos simultaneamente")
        simetrico = CifradorSimetrico()
        servidor_asim = CifradorAsimetrico(es_servidor=True)
        cliente_asim = CifradorAsimetrico(es_servidor=False)
        print("  Resultado: PASS - Ambos modulos pueden coexistir")
        
        print("\n[Test 3.2] Usar ambos cifrados en el mismo mensaje")
        mensaje = "Mensaje de prueba de integracion"
        
        # Cifrar con simetrico
        cifrado_sim = simetrico.cifrar_mensaje(mensaje)
        descifrado_sim = simetrico.descifrar_mensaje(cifrado_sim)
        
        # Cifrar con asimetrico
        cifrado_asim = cliente_asim.cifrar_mensaje(mensaje)
        descifrado_asim = servidor_asim.descifrar_mensaje(cifrado_asim)
        
        print(f"  Original:            {mensaje}")
        print(f"  Descifrado Simetrico: {descifrado_sim}")
        print(f"  Descifrado Asimetrico: {descifrado_asim}")
        
        resultado = mensaje == descifrado_sim and mensaje == descifrado_asim
        print(f"  Resultado: {'PASS' if resultado else 'FAIL'}")
        
        print("\n" + "="*70)
        print("INTEGRACION: TODAS LAS PRUEBAS COMPLETADAS")
        print("="*70)
        return True
        
    except Exception as e:
        print(f"\nERROR en pruebas de integracion: {e}")
        return False


def main():
    """Ejecuta todas las pruebas"""
    print("\n")
    print("#" * 70)
    print("#" + " " * 68 + "#")
    print("#" + " " * 15 + "SUITE DE PRUEBAS DE CIFRADO" + " " * 25 + "#")
    print("#" + " " * 68 + "#")
    print("#" * 70)
    
    resultados = []
    
    # Ejecutar pruebas
    resultados.append(("Cifrado Simetrico", prueba_cifrado_simetrico()))
    resultados.append(("Cifrado Asimetrico", prueba_cifrado_asimetrico()))
    resultados.append(("Integracion", prueba_integracion()))
    
    # Resumen final
    print("\n\n")
    print("#" * 70)
    print("#" + " " * 68 + "#")
    print("#" + " " * 25 + "RESUMEN FINAL" + " " * 30 + "#")
    print("#" + " " * 68 + "#")
    print("#" * 70)
    
    for nombre, resultado in resultados:
        estado = "PASS" if resultado else "FAIL"
        simbolo = "✓" if resultado else "✗"
        print(f"\n  {simbolo} {nombre}: {estado}")
    
    total = len(resultados)
    exitosos = sum(1 for _, r in resultados if r)
    
    print(f"\n\nTotal: {exitosos}/{total} pruebas exitosas")
    
    if exitosos == total:
        print("\n¡EXCELENTE! Todos los modulos funcionan correctamente")
        print("Puedes proceder a integrarlos en el servidor y cliente")
    else:
        print("\nALGUNAS PRUEBAS FALLARON")
        print("Revisa los errores arriba y corrige antes de continuar")
    
    print("\n" + "#" * 70 + "\n")
    
    return exitosos == total


if __name__ == "__main__":
    try:
        exito = main()
        sys.exit(0 if exito else 1)
    except KeyboardInterrupt:
        print("\n\nPruebas interrumpidas por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nERROR CRITICO: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)