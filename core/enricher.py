import sys
from pathlib import Path

# Ensure root workspace directory is in sys.path for direct script execution
_root_dir = str(Path(__file__).resolve().parent.parent)
if _root_dir not in sys.path:
    sys.path.insert(0, _root_dir)

import math
from typing import Dict, Tuple, Optional
from datetime import datetime
from core.models import ThreatIntel

# Known malicious threat intelligence dataset (simulating AbuseIPDB / Tor / Scanner feeds)
KNOWN_THREAT_DATABASE: Dict[str, Dict] = {
    # Tor Exit Nodes & Bulletproof hosters commonly seen in SSH/Web attacks
    "185.220.101.5": {
        "country": "Germany", "country_code": "DE", "city": "Frankfurt",
        "lat": 50.1109, "lon": 8.6821, "isp": "Tor Exit Node / Zwiebelfreunde",
        "threat_score": 98, "is_malicious": True, "category": "Tor Exit Relay"
    },
    "194.26.29.112": {
        "country": "Russia", "country_code": "RU", "city": "Moscow",
        "lat": 55.7558, "lon": 37.6173, "isp": "Megalink ASN48287",
        "threat_score": 94, "is_malicious": True, "category": "Known SSH Brute Force Botnet"
    },
    "45.148.10.88": {
        "country": "Netherlands", "country_code": "NL", "city": "Amsterdam",
        "lat": 52.3676, "lon": 4.9041, "isp": "HostPalace Web Services",
        "threat_score": 89, "is_malicious": True, "category": "Web Vulnerability Scanner"
    },
    "103.203.57.18": {
        "country": "Vietnam", "country_code": "VN", "city": "Hanoi",
        "lat": 21.0285, "lon": 105.8542, "isp": "VNPT Corp",
        "threat_score": 86, "is_malicious": True, "category": "Credential Stuffing Source"
    },
    "118.25.6.39": {
        "country": "China", "country_code": "CN", "city": "Shanghai",
        "lat": 31.2304, "lon": 121.4737, "isp": "Tencent Cloud Computing",
        "threat_score": 91, "is_malicious": True, "category": "Active Exploit Scanner"
    },
    "203.0.113.195": {
        "country": "Brazil", "country_code": "BR", "city": "São Paulo",
        "lat": -23.5505, "lon": -46.6333, "isp": "Claro Brasil",
        "threat_score": 82, "is_malicious": True, "category": "Distributed Brute Force"
    },
    "198.51.100.42": {
        "country": "United States", "country_code": "US", "city": "Ashburn, VA",
        "lat": 39.0438, "lon": -77.4874, "isp": "Amazon AWS Cloud",
        "threat_score": 75, "is_malicious": True, "category": "Compromised Cloud Instance"
    },
    "89.248.165.70": {
        "country": "Seychelles", "country_code": "SC", "city": "Victoria",
        "lat": -4.6191, "lon": 55.4513, "isp": "Recubed Network",
        "threat_score": 95, "is_malicious": True, "category": "Masscan Reconnaissance"
    },
    "142.250.190.46": {
        "country": "United States", "country_code": "US", "city": "Mountain View, CA",
        "lat": 37.422, "lon": -122.084, "isp": "Google LLC",
        "threat_score": 5, "is_malicious": False, "category": "Legitimate Search Engine / Cloud"
    },
    "127.0.0.1": {
        "country": "Localhost", "country_code": "LO", "city": "Internal Loopback",
        "lat": 38.8951, "lon": -77.0364, "isp": "Local System",
        "threat_score": 0, "is_malicious": False, "category": "Localhost"
    }
}

# Country geolocations for deterministic mock resolution
GEO_REGIONS = [
    {"country": "United States", "code": "US", "city": "New York", "lat": 40.7128, "lon": -74.0060, "isp": "DigitalOcean ASN14061"},
    {"country": "United Kingdom", "code": "GB", "city": "London", "lat": 51.5074, "lon": -0.1278, "isp": "British Telecom"},
    {"country": "Germany", "code": "DE", "city": "Berlin", "lat": 52.5200, "lon": 13.4050, "isp": "Hetzner Online GmbH"},
    {"country": "France", "code": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522, "isp": "OVH SAS"},
    {"country": "Canada", "code": "CA", "city": "Toronto", "lat": 43.6532, "lon": -79.3832, "isp": "Rogers Communications"},
    {"country": "Japan", "code": "JP", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503, "isp": "NTT Communications"},
    {"country": "Australia", "code": "AU", "city": "Sydney", "lat": -33.8688, "lon": 151.2093, "isp": "Telstra Corp"},
    {"country": "Singapore", "code": "SG", "city": "Singapore", "lat": 1.3521, "lon": 103.8198, "isp": "Singtel Global"},
    {"country": "India", "code": "IN", "city": "Bengaluru", "lat": 12.9716, "lon": 77.5946, "isp": "Reliance Jio"},
    {"country": "Brazil", "code": "BR", "city": "Rio de Janeiro", "lat": -22.9068, "lon": -43.1729, "isp": "Embratel"}
]


class GeoIPEnricher:
    """Enriches IP addresses with Geographic data and Threat Intelligence reputation."""

    def __init__(self):
        self._cache: Dict[str, ThreatIntel] = {}

    def enrich(self, ip: str) -> ThreatIntel:
        """Resolve IP to threat intelligence and geographic coordinates."""
        if ip in self._cache:
            return self._cache[ip]

        # Check explicit curated threat database first
        if ip in KNOWN_THREAT_DATABASE:
            data = KNOWN_THREAT_DATABASE[ip]
            intel = ThreatIntel(
                ip=ip,
                country=data["country"],
                country_code=data["country_code"],
                city=data["city"],
                lat=data["lat"],
                lon=data["lon"],
                isp=data["isp"],
                threat_score=data["threat_score"],
                is_malicious=data["is_malicious"],
                reputation_category=data["category"]
            )
            self._cache[ip] = intel
            return intel

        # Handle RFC1918 Private IP addresses
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip == "127.0.0.1" or ip == "localhost":
            intel = ThreatIntel(
                ip=ip,
                country="Internal Lab",
                country_code="INT",
                city="Local Subnet",
                lat=38.8951,
                lon=-77.0364,
                isp="Private Network / Intranet",
                threat_score=10,
                is_malicious=False,
                reputation_category="Internal RFC1918"
            )
            self._cache[ip] = intel
            return intel

        # Hash-based deterministic geo mapping for any random external test IPs
        ip_hash = sum(ord(c) for c in ip)
        region = GEO_REGIONS[ip_hash % len(GEO_REGIONS)]
        # Deterministic threat score from IP octets
        try:
            octets = [int(p) for p in ip.split(".") if p.isdigit()]
            last_octet = octets[-1] if octets else 20
        except Exception:
            last_octet = 20

        score = min(95, max(15, (last_octet * 37) % 100))
        is_mal = score > 60
        cat = "Suspicious Host" if is_mal else "Benign IP"

        intel = ThreatIntel(
            ip=ip,
            country=region["country"],
            country_code=region["code"],
            city=region["city"],
            lat=region["lat"] + ((ip_hash % 20) - 10) * 0.05,
            lon=region["lon"] + ((ip_hash % 30) - 15) * 0.05,
            isp=region["isp"],
            threat_score=score,
            is_malicious=is_mal,
            reputation_category=cat
        )
        self._cache[ip] = intel
        return intel

    @staticmethod
    def calculate_distance_km(coord1: Tuple[float, float], coord2: Tuple[float, float]) -> float:
        """
        Calculates Great-Circle distance in kilometers between two lat/lon coordinates
        using the Haversine formula.
        """
        lat1, lon1 = coord1
        lat2, lon2 = coord2

        R = 6371.0  # Earth radius in kilometers

        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)

        a = (math.sin(delta_phi / 2.0) ** 2 +
             math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2)
        c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))

        return R * c

    @staticmethod
    def calculate_velocity_kmh(coord1: Tuple[float, float], time1: datetime,
                               coord2: Tuple[float, float], time2: datetime) -> Tuple[float, float]:
        """
        Calculates distance (km) and speed (km/h) between two time-stamped coordinates.
        Returns (distance_km, speed_kmh).
        """
        distance = GeoIPEnricher.calculate_distance_km(coord1, coord2)
        time_diff = abs((time2 - time1).total_seconds())

        if time_diff <= 0:
            return distance, float('inf') if distance > 10 else 0.0

        hours = time_diff / 3600.0
        speed = distance / hours
        return distance, speed


if __name__ == "__main__":
    enricher = GeoIPEnricher()
    test_ips = ["185.220.101.5", "194.26.29.112", "45.148.10.88", "198.51.100.42", "8.8.8.8"]
    print("=" * 70)
    print("SOC Sentinel - GeoIP & Threat Intel Self-Test")
    print("=" * 70)
    for ip in test_ips:
        intel = enricher.enrich(ip)
        print(f"IP: {intel.ip:<16} | Location: {intel.city}, {intel.country} ({intel.lat:.4f}, {intel.lon:.4f}) | Threat: {intel.threat_score} ({intel.reputation_category})")
    print("=" * 70)
    print("GeoIP enricher self-test completed successfully.")

