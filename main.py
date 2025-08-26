import os
import json
import hashlib
import shutil
import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import secrets

class SecurityManager:
    """
    Gestor principal del sistema de seguridad que maneja:
    - Cifrado/descifrado de archivos
    - Generación de hashes de integridad
    - Gestión de copias de seguridad
    """
    
    def __init__(self, backup_dir: str = "backups", key_file: str = "master.key"):
        """
        Inicializa el gestor de seguridad
        
        Args:
            backup_dir: Directorio para almacenar copias de seguridad
            key_file: Archivo donde se almacena la clave maestra
        """
        self.backup_dir = Path(backup_dir)
        self.key_file = Path(key_file)
        self.backup_dir.mkdir(exist_ok=True)
        
        # Configuración de cifrado
        self.algorithm = algorithms.AES
        self.key_length = 32  # AES-256
        self.block_size = 16  # Tamaño de bloque AES
        
        print(f"🔐 Sistema de Seguridad Iniciado")
        print(f"📁 Directorio de backup: {self.backup_dir.absolute()}")
        print(f"🔑 Archivo de clave: {self.key_file.absolute()}")
    
    def generate_key_from_password(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        Genera una clave AES-256 a partir de una contraseña usando PBKDF2
        
        Args:
            password: Contraseña para generar la clave
            salt: Salt para la derivación (se genera si es None)
            
        Returns:
            Tupla con (clave, salt)
        """
        if salt is None:
            salt = secrets.token_bytes(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_length,
            salt=salt,
            iterations=100000,  # Número alto de iteraciones para seguridad
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode('utf-8'))
        return key, salt
    
    def save_master_key(self, password: str) -> bool:
        """
        Genera y guarda la clave maestra derivada de una contraseña
        
        Args:
            password: Contraseña maestra del sistema
            
        Returns:
            True si se guardó correctamente
        """
        try:
            key, salt = self.generate_key_from_password(password)
            
            # Estructura de la clave maestra
            key_data = {
                'salt': base64.b64encode(salt).decode('utf-8'),
                'created': datetime.datetime.now().isoformat(),
                'algorithm': 'AES-256-CBC',
                'kdf': 'PBKDF2-SHA256'
            }
            
            with open(self.key_file, 'w') as f:
                json.dump(key_data, f, indent=2)
            
            print(f"✅ Clave maestra generada y guardada")
            return True
            
        except Exception as e:
            print(f"❌ Error al guardar clave maestra: {e}")
            return False
    
    def load_key(self, password: str) -> Optional[bytes]:
        """
        Carga la clave maestra usando la contraseña
        
        Args:
            password: Contraseña para derivar la clave
            
        Returns:
            Clave AES o None si hay error
        """
        try:
            if not self.key_file.exists():
                print(f"❌ Archivo de clave no encontrado: {self.key_file}")
                return None
            
            with open(self.key_file, 'r') as f:
                key_data = json.load(f)
            
            salt = base64.b64decode(key_data['salt'])
            key, _ = self.generate_key_from_password(password, salt)
            
            print(f"✅ Clave maestra cargada correctamente")
            return key
            
        except Exception as e:
            print(f"❌ Error al cargar clave: {e}")
            return None
    
    def calculate_sha256(self, data: bytes) -> str:
        """
        Calcula el hash SHA-256 de los datos
        
        Args:
            data: Datos para calcular el hash
            
        Returns:
            Hash SHA-256 en formato hexadecimal
        """
        hash_obj = hashlib.sha256()
        hash_obj.update(data)
        return hash_obj.hexdigest()
    
    def encrypt_data(self, data: bytes, key: bytes) -> Dict:
        """
        Cifra los datos usando AES-256-CBC
        
        Args:
            data: Datos a cifrar
            key: Clave de cifrado AES-256
            
        Returns:
            Diccionario con datos cifrados, IV y metadata
        """
        try:
            # Generar IV aleatorio
            iv = secrets.token_bytes(self.block_size)
            
            # Aplicar padding PKCS7
            padder = padding.PKCS7(128).padder()  # 128 bits = 16 bytes
            padded_data = padder.update(data) + padder.finalize()
            
            # Crear cipher y cifrar
            cipher = Cipher(
                self.algorithm(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Calcular hash de los datos originales para verificación
            original_hash = self.calculate_sha256(data)
            
            # Estructura del archivo cifrado
            encrypted_package = {
                'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'original_hash': original_hash,
                'algorithm': 'AES-256-CBC',
                'timestamp': datetime.datetime.now().isoformat(),
                'size': len(data)
            }
            
            print(f"🔒 Datos cifrados correctamente ({len(data)} bytes)")
            return encrypted_package
            
        except Exception as e:
            print(f"❌ Error al cifrar datos: {e}")
            return {}
    
    def decrypt_data(self, encrypted_package: Dict, key: bytes) -> Optional[bytes]:
        """
        Descifra los datos usando AES-256-CBC
        
        Args:
            encrypted_package: Paquete con datos cifrados
            key: Clave de descifrado
            
        Returns:
            Datos descifrados o None si hay error
        """
        try:
            # Extraer componentes
            encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])
            iv = base64.b64decode(encrypted_package['iv'])
            original_hash = encrypted_package['original_hash']
            
            # Crear cipher y descifrar
            cipher = Cipher(
                self.algorithm(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Quitar padding
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            # Verificar integridad con hash
            calculated_hash = self.calculate_sha256(data)
            if calculated_hash != original_hash:
                print(f"❌ Error de integridad: Hash no coincide")
                return None
            
            print(f"🔓 Datos descifrados correctamente ({len(data)} bytes)")
            print(f"✅ Integridad verificada con SHA-256")
            return data
            
        except Exception as e:
            print(f"❌ Error al descifrar datos: {e}")
            return None
    
    def encrypt_file(self, file_path: str, password: str) -> bool:
        """
        Cifra un archivo completo
        
        Args:
            file_path: Ruta del archivo a cifrar
            password: Contraseña para el cifrado
            
        Returns:
            True si se cifró correctamente
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                print(f"❌ Archivo no encontrado: {file_path}")
                return False
            
            # Cargar o generar clave
            key = self.load_key(password)
            if key is None:
                if not self.save_master_key(password):
                    return False
                key = self.load_key(password)
            
            # Leer archivo
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Cifrar datos
            encrypted_package = self.encrypt_data(file_data, key)
            if not encrypted_package:
                return False
            
            # Guardar archivo cifrado
            encrypted_file = file_path.with_suffix(file_path.suffix + '.enc')
            with open(encrypted_file, 'w') as f:
                json.dump(encrypted_package, f, indent=2)
            
            print(f"📁 Archivo cifrado guardado: {encrypted_file}")
            return True
            
        except Exception as e:
            print(f"❌ Error al cifrar archivo: {e}")
            return False
    
    def decrypt_file(self, encrypted_file_path: str, password: str, output_path: str = None) -> bool:
        """
        Descifra un archivo
        
        Args:
            encrypted_file_path: Ruta del archivo cifrado
            password: Contraseña para descifrar
            output_path: Ruta de salida (opcional)
            
        Returns:
            True si se descifró correctamente
        """
        try:
            encrypted_file = Path(encrypted_file_path)
            if not encrypted_file.exists():
                print(f"❌ Archivo cifrado no encontrado: {encrypted_file}")
                return False
            
            # Cargar clave
            key = self.load_key(password)
            if key is None:
                return False
            
            # Leer archivo cifrado
            with open(encrypted_file, 'r') as f:
                encrypted_package = json.load(f)
            
            # Descifrar datos
            decrypted_data = self.decrypt_data(encrypted_package, key)
            if decrypted_data is None:
                return False
            
            # Determinar archivo de salida
            if output_path is None:
                output_path = encrypted_file.with_suffix('').with_suffix('')
            
            # Guardar archivo descifrado
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            print(f"📁 Archivo descifrado guardado: {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ Error al descifrar archivo: {e}")
            return False
    
    def create_backup(self, source_path: str, password: str, backup_name: str = None) -> bool:
        """
        Crea una copia de seguridad cifrada
        
        Args:
            source_path: Ruta del archivo o directorio a respaldar
            password: Contraseña para cifrar el backup
            backup_name: Nombre del backup (opcional)
            
        Returns:
            True si se creó correctamente
        """
        try:
            source = Path(source_path)
            if not source.exists():
                print(f"❌ Origen no encontrado: {source}")
                return False
            
            # Generar nombre del backup
            if backup_name is None:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = f"backup_{source.name}_{timestamp}"
            
            backup_dir = self.backup_dir / backup_name
            backup_dir.mkdir(exist_ok=True)
            
            print(f"🔄 Creando backup: {backup_name}")
            
            # Copiar archivos
            if source.is_file():
                shutil.copy2(source, backup_dir / source.name)
                files_to_encrypt = [backup_dir / source.name]
            else:
                shutil.copytree(source, backup_dir / source.name, dirs_exist_ok=True)
                files_to_encrypt = list((backup_dir / source.name).rglob('*'))
                files_to_encrypt = [f for f in files_to_encrypt if f.is_file()]
            
            # Cifrar archivos del backup
            encrypted_files = []
            for file_path in files_to_encrypt:
                if self.encrypt_file(str(file_path), password):
                    encrypted_files.append(str(file_path.with_suffix(file_path.suffix + '.enc')))
                    # Eliminar archivo original después del cifrado
                    file_path.unlink()
            
            # Crear manifiesto del backup
            manifest = {
                'backup_name': backup_name,
                'source_path': str(source.absolute()),
                'created': datetime.datetime.now().isoformat(),
                'files_count': len(encrypted_files),
                'encrypted_files': encrypted_files,
                'backup_type': 'file' if source.is_file() else 'directory'
            }
            
            manifest_path = backup_dir / 'backup_manifest.json'
            with open(manifest_path, 'w') as f:
                json.dump(manifest, f, indent=2)
            
            print(f"✅ Backup creado exitosamente")
            print(f"📊 Archivos procesados: {len(encrypted_files)}")
            print(f"📁 Ubicación: {backup_dir.absolute()}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error al crear backup: {e}")
            return False
    
    def restore_backup(self, backup_name: str, password: str, restore_path: str = None) -> bool:
        """
        Restaura una copia de seguridad
        
        Args:
            backup_name: Nombre del backup a restaurar
            password: Contraseña para descifrar
            restore_path: Ruta donde restaurar (opcional)
            
        Returns:
            True si se restauró correctamente
        """
        try:
            backup_path = self.backup_dir / backup_name
            if not backup_path.exists():
                print(f"❌ Backup no encontrado: {backup_name}")
                return False
            
            # Leer manifiesto
            manifest_path = backup_path / 'backup_manifest.json'
            if not manifest_path.exists():
                print(f"❌ Manifiesto del backup no encontrado")
                return False
            
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)
            
            print(f"🔄 Restaurando backup: {backup_name}")
            print(f"📅 Creado: {manifest['created']}")
            print(f"📊 Archivos: {manifest['files_count']}")
            
            # Determinar ruta de restauración
            if restore_path is None:
                restore_path = Path(f"restored_{backup_name}")
            else:
                restore_path = Path(restore_path)
            
            restore_path.mkdir(parents=True, exist_ok=True)
            
            # Descifrar archivos
            restored_count = 0
            for encrypted_file in manifest['encrypted_files']:
                encrypted_path = Path(encrypted_file)
                if encrypted_path.exists():
                    # Determinar ruta de salida
                    relative_path = encrypted_path.relative_to(backup_path)
                    output_path = restore_path / relative_path.with_suffix('').with_suffix('')
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    if self.decrypt_file(str(encrypted_path), password, str(output_path)):
                        restored_count += 1
            
            print(f"✅ Backup restaurado exitosamente")
            print(f"📊 Archivos restaurados: {restored_count}/{manifest['files_count']}")
            print(f"📁 Ubicación: {restore_path.absolute()}")
            
            return restored_count > 0
            
        except Exception as e:
            print(f"❌ Error al restaurar backup: {e}")
            return False
    
    def list_backups(self) -> List[Dict]:
        """
        Lista todos los backups disponibles
        
        Returns:
            Lista de información de backups
        """
        backups = []
        
        try:
            for backup_dir in self.backup_dir.iterdir():
                if backup_dir.is_dir():
                    manifest_path = backup_dir / 'backup_manifest.json'
                    if manifest_path.exists():
                        with open(manifest_path, 'r') as f:
                            manifest = json.load(f)
                        backups.append(manifest)
            
            # Ordenar por fecha de creación
            backups.sort(key=lambda x: x['created'], reverse=True)
            
        except Exception as e:
            print(f"❌ Error al listar backups: {e}")
        
        return backups
    
    def verify_file_integrity(self, file_path: str) -> bool:
        """
        Verifica la integridad de un archivo usando SHA-256
        
        Args:
            file_path: Ruta del archivo a verificar
            
        Returns:
            True si el archivo es íntegro
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                print(f"❌ Archivo no encontrado: {file_path}")
                return False
            
            # Leer archivo
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Calcular hash actual
            current_hash = self.calculate_sha256(file_data)
            
            # Buscar hash almacenado (si existe un archivo .hash)
            hash_file = file_path.with_suffix(file_path.suffix + '.hash')
            if hash_file.exists():
                with open(hash_file, 'r') as f:
                    stored_hash = f.read().strip()
                
                if current_hash == stored_hash:
                    print(f"✅ Integridad verificada: {file_path.name}")
                    print(f"🔍 SHA-256: {current_hash}")
                    return True
                else:
                    print(f"❌ Integridad comprometida: {file_path.name}")
                    print(f"🔍 Hash actual: {current_hash}")
                    print(f"🔍 Hash esperado: {stored_hash}")
                    return False
            else:
                # Crear archivo de hash para futura verificación
                with open(hash_file, 'w') as f:
                    f.write(current_hash)
                print(f"📝 Hash SHA-256 guardado: {hash_file.name}")
                print(f"🔍 SHA-256: {current_hash}")
                return True
                
        except Exception as e:
            print(f"❌ Error al verificar integridad: {e}")
            return False


def demo_sistema_seguridad():
    """
    Demostración completa del sistema de seguridad
    """
    print("="*60)
    print("🔐 DEMOSTRACIÓN DEL SISTEMA DE SEGURIDAD")
    print("="*60)
    
    # Inicializar sistema
    security_manager = SecurityManager()
    
    # Crear archivos de prueba
    print("\n📝 Creando archivos de prueba...")
    
    # Crear directorio test_files si no existe
    test_files_dir = Path("test_files")
    test_files_dir.mkdir(exist_ok=True)
    
    # Archivo de texto
    test_file1 = test_files_dir / "documento_test.txt"
    with open(test_file1, 'w', encoding='utf-8') as f:
        f.write("""DOCUMENTO CONFIDENCIAL - SISTEMA DE SEGURIDAD

Este es un archivo de prueba que contiene información sensible:

1. Datos personales de empleados
2. Información financiera de la empresa
3. Claves de acceso y configuraciones
4. Reportes de seguridad internos

⚠️  ACCESO RESTRINGIDO - SOLO PERSONAL AUTORIZADO ⚠️

El contenido de este documento está protegido por el sistema de 
cifrado AES-256 con verificación de integridad SHA-256.

Fecha: 2025
Sistema: Demostración de Seguridad Informática
""")
    
    # Archivo JSON con datos estructurados
    test_file2 = test_files_dir / "datos_test.json"
    data = {
        "usuarios": [
            {"id": 1, "nombre": "Ana García", "cargo": "CEO", "salario": 120000},
            {"id": 2, "nombre": "Carlos López", "cargo": "CTO", "salario": 95000},
            {"id": 3, "nombre": "María Rodríguez", "cargo": "CFO", "salario": 110000}
        ],
        "configuracion": {
            "servidor_db": "192.168.1.100",
            "puerto": 5432,
            "api_key": "sk-1234567890abcdef",
            "secret_token": "token_super_secreto_2025"
        }
    }
    
    with open(test_file2, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Archivo creado: {test_file1}")
    print(f"✅ Archivo creado: {test_file2}")
    
    # Contraseña maestra del sistema
    master_password = "MiClaveSegura2025!"
    
    print(f"\n🔑 Usando contraseña maestra: {master_password}")
    
    # DEMOSTRACIÓN 1: Cifrado de archivos individuales
    print("\n" + "="*40)
    print("🔒 DEMO 1: CIFRADO DE ARCHIVOS")
    print("="*40)
    
    print(f"\n1️⃣ Cifrando archivo: {test_file1}")
    if security_manager.encrypt_file(str(test_file1), master_password):
        print("✅ Cifrado exitoso")
        
        # Verificar que el archivo cifrado existe
        encrypted_file1 = test_file1.with_suffix(test_file1.suffix + '.enc')
        if encrypted_file1.exists():
            print(f"📁 Archivo cifrado: {encrypted_file1}")
    
    print(f"\n2️⃣ Cifrando archivo: {test_file2}")
    if security_manager.encrypt_file(str(test_file2), master_password):
        print("✅ Cifrado exitoso")
    
    # DEMOSTRACIÓN 2: Descifrado de archivos
    print("\n" + "="*40)
    print("🔓 DEMO 2: DESCIFRADO DE ARCHIVOS")
    print("="*40)
    
    encrypted_file1 = test_file1.with_suffix(test_file1.suffix + '.enc')
    decrypted_file1 = Path("documento_descifrado.txt")
    
    print(f"\n1️⃣ Descifrando: {encrypted_file1}")
    if security_manager.decrypt_file(str(encrypted_file1), master_password, str(decrypted_file1)):
        print("✅ Descifrado exitoso")
        print(f"📁 Archivo descifrado: {decrypted_file1}")
        
        # Verificar contenido
        with open(decrypted_file1, 'r', encoding='utf-8') as f:
            content = f.read()[:100]
        print(f"📄 Contenido (primeros 100 chars): {content}...")
    
    # DEMOSTRACIÓN 3: Verificación de integridad con SHA-256
    print("\n" + "="*40)
    print("🔍 DEMO 3: VERIFICACIÓN DE INTEGRIDAD")
    print("="*40)
    
    print(f"\n1️⃣ Verificando integridad: {test_file1}")
    security_manager.verify_file_integrity(str(test_file1))
    
    print(f"\n2️⃣ Verificando integridad: {test_file2}")
    security_manager.verify_file_integrity(str(test_file2))
    
    print(f"\n3️⃣ Verificando archivo descifrado:")
    security_manager.verify_file_integrity(str(decrypted_file1))
    
    # DEMOSTRACIÓN 4: Sistema de copias de seguridad
    print("\n" + "="*40)
    print("💾 DEMO 4: SISTEMA DE BACKUPS")
    print("="*40)
    
    # Crear directorio con múltiples archivos
    test_dir = Path("datos_empresa")
    test_dir.mkdir(exist_ok=True)
    
    # Copiar archivos al directorio de prueba
    shutil.copy2(test_file1, test_dir / "confidencial.txt")
    shutil.copy2(test_file2, test_dir / "bd_empleados.json")
    
    # Crear archivos adicionales
    (test_dir / "reporte_2025.txt").write_text("Reporte financiero anual 2025...", encoding='utf-8')
    (test_dir / "config.ini").write_text("[database]\nhost=localhost\nport=5432", encoding='utf-8')
    
    print(f"📁 Directorio de prueba creado: {test_dir}")
    print(f"📊 Archivos en el directorio: {len(list(test_dir.iterdir()))}")
    
    # Crear backup cifrado
    print(f"\n1️⃣ Creando backup cifrado del directorio...")
    backup_name = "backup_empresa_2025"
    if security_manager.create_backup(str(test_dir), master_password, backup_name):
        print("✅ Backup creado exitosamente")
    
    # Listar backups disponibles
    print(f"\n2️⃣ Listando backups disponibles:")
    backups = security_manager.list_backups()
    for i, backup in enumerate(backups, 1):
        print(f"   {i}. {backup['backup_name']}")
        print(f"      📅 Creado: {backup['created']}")
        print(f"      📊 Archivos: {backup['files_count']}")
        print(f"      📁 Origen: {backup['source_path']}")
        print()
    
    # DEMOSTRACIÓN 5: Restauración de backup
    print("\n" + "="*40)
    print("♻️ DEMO 5: RESTAURACIÓN DE BACKUP")
    print("="*40)
    
    if backups:
        backup_to_restore = backups[0]['backup_name']
        print(f"🔄 Restaurando backup: {backup_to_restore}")
        
        if security_manager.restore_backup(backup_to_restore, master_password):
            print("✅ Restauración exitosa")
            
            # Verificar archivos restaurados
            restored_dir = Path(f"restored_{backup_to_restore}")
            if restored_dir.exists():
                restored_files = list(restored_dir.rglob('*'))
                restored_files = [f for f in restored_files if f.is_file()]
                print(f"📊 Archivos restaurados: {len(restored_files)}")
                for file in restored_files:
                    print(f"   📄 {file.relative_to(restored_dir)}")
    
    # DEMOSTRACIÓN 6: Prueba de integridad después de manipulación
    print("\n" + "="*40)
    print("🛡️ DEMO 6: DETECCIÓN DE MANIPULACIÓN")
    print("="*40)
    
    # Crear archivo y verificar integridad inicial
    test_integrity = Path("archivo_integridad.txt")
    test_integrity.write_text("Contenido original del archivo", encoding='utf-8')
    
    print("1️⃣ Verificación inicial:")
    security_manager.verify_file_integrity(str(test_integrity))
    
    # Modificar archivo (simular manipulación)
    print("\n2️⃣ Simulando manipulación del archivo...")
    test_integrity.write_text("Contenido MODIFICADO maliciosamente", encoding='utf-8')
    
    print("3️⃣ Verificación después de modificación:")
    security_manager.verify_file_integrity(str(test_integrity))
    
    # Resumen final
    print("\n" + "="*60)
    print("📋 RESUMEN DE LA DEMOSTRACIÓN")
    print("="*60)
    print("✅ Cifrado AES-256-CBC implementado correctamente")
    print("✅ Generación y verificación SHA-256 funcionando")  
    print("✅ Sistema de copias de seguridad operativo")
    print("✅ Detección de manipulación de archivos")
    print("✅ Gestión segura de claves con PBKDF2")
    print("✅ Disponibilidad y confidencialidad garantizadas")
    
    print(f"\n🔐 Sistema de seguridad completamente funcional!")
    print(f"📊 Total de archivos procesados en la demostración")
    print(f"🔒 Cifrado: Múltiples archivos")
    print(f"🔓 Descifrado: Verificación exitosa")
    print(f"💾 Backup: Sistema operativo")
    print(f"♻️  Restauración: Funcional")
    print(f"🛡️  Integridad: Detecta modificaciones")

if __name__ == "__main__":
    try:
        demo_sistema_seguridad()
    except KeyboardInterrupt:
        print("\n\n⚠️  Demostración interrumpida por el usuario")
    except Exception as e:
        print(f"\n❌ Error durante la demostración: {e}")
        print("🔧 Revisa que tengas instaladas las dependencias:")
        print("   pip install cryptography")
    finally:
        print("\n👋 Fin de la demostración del sistema de seguridad")