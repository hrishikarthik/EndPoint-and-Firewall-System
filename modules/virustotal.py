"""
VirusTotal API Integration Module
File and URL scanning capabilities
"""

import requests
import hashlib
import time
import logging
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

class VirusTotalAPI:
    def __init__(self, api_key: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        # Get API key from environment variable only
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.session = requests.Session()
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 1  # 1 second between requests
        
        # Cache for results
        self.cache = {}
        self.cache_file = "virustotal_cache.json"
        self.load_cache()
    
    def set_api_key(self, api_key: str):
        """Set VirusTotal API key"""
        self.api_key = api_key
        self.logger.info("VirusTotal API key set")
    
    def load_cache(self):
        """Load cached results from file"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
                self.logger.info(f"Loaded {len(self.cache)} cached results")
        except Exception as e:
            self.logger.error(f"Error loading cache: {e}")
            self.cache = {}
    
    def save_cache(self):
        """Save cache to file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving cache: {e}")
    
    def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _make_request(self, endpoint: str, params: Optional[Dict] = None, files: Optional[Dict] = None) -> Optional[Dict]:
        """Make API request with error handling"""
        if not self.api_key:
            self.logger.error("VirusTotal API key not set")
            return None
        
        try:
            self._rate_limit()
            
            url = f"{self.base_url}/{endpoint}"
            params = params or {}
            params['apikey'] = self.api_key
            
            if files:
                response = self.session.post(url, params=params, files=files)
            else:
                response = self.session.get(url, params=params)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 204:
                self.logger.warning("API quota exceeded")
                return None
            else:
                self.logger.error(f"API request failed: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error making API request: {e}")
            return None
    
    def scan_file(self, file_path: str) -> Optional[Dict]:
        """Scan a file with VirusTotal"""
        try:
            if not os.path.exists(file_path):
                self.logger.error(f"File not found: {file_path}")
                return None
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Check cache first
            if file_hash in self.cache:
                self.logger.info(f"Using cached result for {file_path}")
                return self.cache[file_hash]
            
            # Check if file is too large (VirusTotal limit is 32MB)
            file_size = os.path.getsize(file_path)
            if file_size > 32 * 1024 * 1024:  # 32MB
                self.logger.warning(f"File too large for VirusTotal: {file_path}")
                return None
            
            # Upload file for scanning
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
                result = self._make_request('file/scan', files=files)
            
            if result:
                # Cache the result
                self.cache[file_hash] = result
                self.save_cache()
                
                self.logger.info(f"File scan initiated for {file_path}")
                return result
            
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")
        
        return None
    
    def get_file_report(self, file_hash: str) -> Optional[Dict]:
        """Get scan report for a file hash"""
        try:
            # Check cache first
            if file_hash in self.cache:
                return self.cache[file_hash]
            
            # Get report from VirusTotal
            params = {'resource': file_hash}
            result = self._make_request('file/report', params=params)
            
            if result:
                # Cache the result
                self.cache[file_hash] = result
                self.save_cache()
                
                return result
            
        except Exception as e:
            self.logger.error(f"Error getting file report for {file_hash}: {e}")
        
        return None
    
    def scan_url(self, url: str) -> Optional[Dict]:
        """Scan a URL with VirusTotal"""
        try:
            # Check cache first
            if url in self.cache:
                return self.cache[url]
            
            # Submit URL for scanning
            params = {'url': url}
            result = self._make_request('url/scan', params=params)
            
            if result:
                # Cache the result
                self.cache[url] = result
                self.save_cache()
                
                self.logger.info(f"URL scan initiated for {url}")
                return result
            
        except Exception as e:
            self.logger.error(f"Error scanning URL {url}: {e}")
        
        return None
    
    def get_url_report(self, url: str) -> Optional[Dict]:
        """Get scan report for a URL"""
        try:
            # Check cache first
            if url in self.cache:
                return self.cache[url]
            
            # Get report from VirusTotal
            params = {'resource': url}
            result = self._make_request('url/report', params=params)
            
            if result:
                # Cache the result
                self.cache[url] = result
                self.save_cache()
                
                return result
            
        except Exception as e:
            self.logger.error(f"Error getting URL report for {url}: {e}")
        
        return None
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def analyze_file(self, file_path: str) -> Dict:
        """Analyze a file and return comprehensive results"""
        try:
            file_hash = self._calculate_file_hash(file_path)
            
            # Get file report
            report = self.get_file_report(file_hash)
            
            if not report:
                return {
                    'file_path': file_path,
                    'hash': file_hash,
                    'status': 'not_found',
                    'message': 'File not found in VirusTotal database'
                }
            
            # Parse results
            positives = report.get('positives', 0)
            total = report.get('total', 0)
            scan_date = report.get('scan_date')
            
            # Determine threat level
            if positives == 0:
                threat_level = 'CLEAN'
            elif positives <= 5:
                threat_level = 'LOW'
            elif positives <= 20:
                threat_level = 'MEDIUM'
            else:
                threat_level = 'HIGH'
            
            # Get detailed scan results
            scans = report.get('scans', {})
            detected_by = []
            
            for antivirus, scan_result in scans.items():
                if scan_result.get('detected', False):
                    detected_by.append({
                        'antivirus': antivirus,
                        'result': scan_result.get('result', 'Unknown')
                    })
            
            return {
                'file_path': file_path,
                'hash': file_hash,
                'status': 'analyzed',
                'positives': positives,
                'total': total,
                'detection_rate': (positives / total * 100) if total > 0 else 0,
                'threat_level': threat_level,
                'scan_date': scan_date,
                'detected_by': detected_by,
                'permalink': report.get('permalink', ''),
                'timestamp': datetime.now()
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")
            return {
                'file_path': file_path,
                'status': 'error',
                'message': str(e)
            }
    
    def analyze_url(self, url: str) -> Dict:
        """Analyze a URL and return comprehensive results"""
        try:
            # Get URL report
            report = self.get_url_report(url)
            
            if not report:
                return {
                    'url': url,
                    'status': 'not_found',
                    'message': 'URL not found in VirusTotal database'
                }
            
            # Parse results
            positives = report.get('positives', 0)
            total = report.get('total', 0)
            scan_date = report.get('scan_date')
            
            # Determine threat level
            if positives == 0:
                threat_level = 'CLEAN'
            elif positives <= 5:
                threat_level = 'LOW'
            elif positives <= 20:
                threat_level = 'MEDIUM'
            else:
                threat_level = 'HIGH'
            
            # Get detailed scan results
            scans = report.get('scans', {})
            detected_by = []
            
            for antivirus, scan_result in scans.items():
                if scan_result.get('detected', False):
                    detected_by.append({
                        'antivirus': antivirus,
                        'result': scan_result.get('result', 'Unknown')
                    })
            
            return {
                'url': url,
                'status': 'analyzed',
                'positives': positives,
                'total': total,
                'detection_rate': (positives / total * 100) if total > 0 else 0,
                'threat_level': threat_level,
                'scan_date': scan_date,
                'detected_by': detected_by,
                'permalink': report.get('permalink', ''),
                'timestamp': datetime.now()
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing URL {url}: {e}")
            return {
                'url': url,
                'status': 'error',
                'message': str(e)
            }
    
    def bulk_scan_files(self, file_paths: List[str]) -> List[Dict]:
        """Scan multiple files"""
        results = []
        
        for file_path in file_paths:
            result = self.analyze_file(file_path)
            results.append(result)
            
            # Rate limiting between requests
            time.sleep(self.min_request_interval)
        
        return results
    
    def bulk_scan_urls(self, urls: List[str]) -> List[Dict]:
        """Scan multiple URLs"""
        results = []
        
        for url in urls:
            result = self.analyze_url(url)
            results.append(result)
            
            # Rate limiting between requests
            time.sleep(self.min_request_interval)
        
        return results
    
    def get_scan_statistics(self) -> Dict:
        """Get scanning statistics"""
        total_scans = len(self.cache)
        clean_results = 0
        malicious_results = 0
        
        for result in self.cache.values():
            if isinstance(result, dict):
                positives = result.get('positives', 0)
                if positives == 0:
                    clean_results += 1
                else:
                    malicious_results += 1
        
        return {
            'total_scans': total_scans,
            'clean_results': clean_results,
            'malicious_results': malicious_results,
            'cache_size': len(self.cache)
        }
    
    def clear_cache(self):
        """Clear the cache"""
        self.cache.clear()
        if os.path.exists(self.cache_file):
            os.remove(self.cache_file)
        self.logger.info("Cache cleared") 