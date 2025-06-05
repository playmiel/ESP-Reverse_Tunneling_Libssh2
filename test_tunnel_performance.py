#!/usr/bin/env python3
"""
Script de test pour valider les optimisations du tunnel SSH ESP32
Teste les transferts de données et mesure les performances
"""

import requests
import time
import threading
import os
import hashlib
from concurrent.futures import ThreadPoolExecutor

class TunnelPerformanceTest:
    def __init__(self, tunnel_url="http://localhost:8080"):
        self.tunnel_url = tunnel_url
        self.results = []
        
    def create_test_file(self, size_mb, filename):
        """Crée un fichier de test de taille spécifiée"""
        print(f"Création du fichier de test {filename} ({size_mb} MB)...")
        size_bytes = size_mb * 1024 * 1024
        
        with open(filename, 'wb') as f:
            # Données pseudo-aléatoires pour éviter la compression
            for i in range(0, size_bytes, 1024):
                chunk_size = min(1024, size_bytes - i)
                data = os.urandom(chunk_size)
                f.write(data)
        
        # Calculer le hash pour vérification d'intégrité
        with open(filename, 'rb') as f:
            file_hash = hashlib.md5(f.read()).hexdigest()
        
        return file_hash
    
    def test_upload(self, filename, size_mb):
        """Test d'upload d'un fichier"""
        print(f"Test upload: {filename} ({size_mb} MB)")
        start_time = time.time()
        
        try:
            with open(filename, 'rb') as f:
                response = requests.post(
                    f"{self.tunnel_url}/upload",
                    files={'file': f},
                    timeout=600  # 10 minutes timeout
                )
            
            end_time = time.time()
            duration = end_time - start_time
            throughput = size_mb / duration
            
            result = {
                'test_type': 'upload',
                'file_size_mb': size_mb,
                'duration_sec': duration,
                'throughput_mbps': throughput,
                'status_code': response.status_code,
                'success': response.status_code == 200
            }
            
            print(f"Upload terminé: {duration:.2f}s, {throughput:.2f} MB/s, Status: {response.status_code}")
            
        except Exception as e:
            result = {
                'test_type': 'upload',
                'file_size_mb': size_mb,
                'duration_sec': 0,
                'throughput_mbps': 0,
                'status_code': 0,
                'success': False,
                'error': str(e)
            }
            print(f"Erreur upload: {e}")
        
        self.results.append(result)
        return result
    
    def test_download(self, endpoint, size_mb):
        """Test de téléchargement"""
        print(f"Test download: {endpoint} ({size_mb} MB)")
        start_time = time.time()
        
        try:
            response = requests.get(
                f"{self.tunnel_url}{endpoint}",
                timeout=600,
                stream=True
            )
            
            # Télécharger et mesurer
            downloaded_bytes = 0
            for chunk in response.iter_content(chunk_size=8192):
                downloaded_bytes += len(chunk)
            
            end_time = time.time()
            duration = end_time - start_time
            actual_size_mb = downloaded_bytes / (1024 * 1024)
            throughput = actual_size_mb / duration
            
            result = {
                'test_type': 'download',
                'file_size_mb': actual_size_mb,
                'duration_sec': duration,
                'throughput_mbps': throughput,
                'status_code': response.status_code,
                'success': response.status_code == 200
            }
            
            print(f"Download terminé: {duration:.2f}s, {throughput:.2f} MB/s, Status: {response.status_code}")
            
        except Exception as e:
            result = {
                'test_type': 'download',
                'file_size_mb': size_mb,
                'duration_sec': 0,
                'throughput_mbps': 0,
                'status_code': 0,
                'success': False,
                'error': str(e)
            }
            print(f"Erreur download: {e}")
        
        self.results.append(result)
        return result
    
    def test_concurrent_transfers(self, num_concurrent=3):
        """Test de transferts simultanés"""
        print(f"Test de {num_concurrent} transferts simultanés...")
        
        def worker(thread_id):
            filename = f"test_concurrent_{thread_id}.dat"
            size_mb = 10
            
            # Créer le fichier de test
            self.create_test_file(size_mb, filename)
            
            # Test upload
            result = self.test_upload(filename, size_mb)
            result['thread_id'] = thread_id
            
            # Nettoyer
            os.remove(filename)
            
            return result
        
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=num_concurrent) as executor:
            futures = [executor.submit(worker, i) for i in range(num_concurrent)]
            concurrent_results = [f.result() for f in futures]
        
        end_time = time.time()
        total_duration = end_time - start_time
        
        successful_transfers = sum(1 for r in concurrent_results if r['success'])
        total_data_mb = sum(r['file_size_mb'] for r in concurrent_results if r['success'])
        overall_throughput = total_data_mb / total_duration
        
        print(f"Transferts simultanés terminés: {successful_transfers}/{num_concurrent} réussis")
        print(f"Débit global: {overall_throughput:.2f} MB/s")
        
        return concurrent_results
    
    def run_performance_tests(self):
        """Lance une suite complète de tests"""
        print("=== DÉBUT DES TESTS DE PERFORMANCE ===")
        print(f"URL du tunnel: {self.tunnel_url}")
        
        # Tests avec différentes tailles de fichiers
        test_sizes = [1, 5, 10, 50]  # MB
        
        for size_mb in test_sizes:
            filename = f"test_{size_mb}mb.dat"
            
            # Créer le fichier de test
            file_hash = self.create_test_file(size_mb, filename)
            
            # Test upload
            self.test_upload(filename, size_mb)
            
            # Nettoyer
            os.remove(filename)
            
            # Attendre un peu entre les tests
            time.sleep(2)
        
        # Test de transferts simultanés
        self.test_concurrent_transfers(3)
        
        # Rapport final
        self.generate_report()
    
    def generate_report(self):
        """Génère un rapport des résultats"""
        print("\n=== RAPPORT DE PERFORMANCE ===")
        
        successful_tests = [r for r in self.results if r['success']]
        failed_tests = [r for r in self.results if not r['success']]
        
        print(f"Tests réussis: {len(successful_tests)}")
        print(f"Tests échoués: {len(failed_tests)}")
        
        if successful_tests:
            avg_throughput = sum(r['throughput_mbps'] for r in successful_tests) / len(successful_tests)
            max_throughput = max(r['throughput_mbps'] for r in successful_tests)
            min_throughput = min(r['throughput_mbps'] for r in successful_tests)
            
            print(f"Débit moyen: {avg_throughput:.2f} MB/s")
            print(f"Débit maximum: {max_throughput:.2f} MB/s")
            print(f"Débit minimum: {min_throughput:.2f} MB/s")
        
        # Détails des tests échoués
        if failed_tests:
            print("\n=== TESTS ÉCHOUÉS ===")
            for test in failed_tests:
                print(f"- {test['test_type']} {test['file_size_mb']}MB: {test.get('error', 'Erreur inconnue')}")
        
        # Sauvegarder les résultats
        import json
        with open('tunnel_performance_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print("\nRésultats sauvegardés dans: tunnel_performance_results.json")

def main():
    # Vérifier que le tunnel est accessible
    tunnel_url = "http://localhost:8080"
    
    print("Vérification de la connectivité du tunnel...")
    try:
        response = requests.get(tunnel_url, timeout=10)
        print(f"Tunnel accessible, status: {response.status_code}")
    except Exception as e:
        print(f"Erreur de connexion au tunnel: {e}")
        print("Assurez-vous que:")
        print("1. L'ESP32 est connecté et le tunnel SSH est actif")
        print("2. nginx est configuré et en cours d'exécution")
        print("3. Le port 8080 est accessible")
        return
    
    # Lancer les tests
    tester = TunnelPerformanceTest(tunnel_url)
    tester.run_performance_tests()

if __name__ == "__main__":
    main()