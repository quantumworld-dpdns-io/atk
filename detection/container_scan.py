#!/usr/bin/env python3
import json
import subprocess
import sys


VULNERABLE_VERSIONS = {
    'nginx': (
        '0.6.27', '1.30.0'
    ),
}


def check_docker_image(image):
    try:
        result = subprocess.run(
            ['docker', 'inspect', image],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return None

        data = json.loads(result.stdout)
        if not data:
            return None

        env_vars = data[0].get('Config', {}).get('Env', [])
        for env in env_vars:
            if 'NGINX_VERSION=' in env:
                version = env.split('=', 1)[1]
                return version

        labels = data[0].get('Config', {}).get('Labels', {})
        for key, val in labels.items():
            if 'version' in key.lower() and 'nginx' in key.lower():
                return val

        return None

    except Exception:
        return None


def version_in_range(version, start, end):
    try:
        parts = tuple(int(x) for x in version.split('.')[:3])
        start_parts = tuple(int(x) for x in start.split('.')[:3])
        end_parts = tuple(int(x) for x in end.split('.')[:3])

        if len(parts) < 2:
            return False

        while len(parts) < 3:
            parts = parts + (0,)
        while len(start_parts) < 3:
            start_parts = start_parts + (0,)
        while len(end_parts) < 3:
            end_parts = end_parts + (0,)

        return start_parts <= parts <= end_parts

    except (ValueError, TypeError):
        return False


def scan_image(image):
    print(f"Scanning {image}...")
    version = check_docker_image(image)
    if version is None:
        print(f"  Could not determine NGINX version")
        return None

    start, end = VULNERABLE_VERSIONS['nginx']
    vulnerable = version_in_range(version, start, end)
    status = "VULNERABLE" if vulnerable else "SAFE"
    print(f"  NGINX {version} — {status}")

    return {
        'image': image,
        'version': version,
        'vulnerable': vulnerable,
    }


def main():
    images = sys.argv[1:] if len(sys.argv) > 1 else [
        'nginx:latest',
        'nginx:1.26-alpine',
        'nginx:1.22-alpine',
        'nginx:1.24-alpine',
    ]

    results = []
    for img in images:
        r = scan_image(img)
        if r:
            results.append(r)

    vulnerable = [r for r in results if r['vulnerable']]
    if vulnerable:
        print(f"\nVULNERABLE IMAGES: {len(vulnerable)}")
        for v in vulnerable:
            print(f"  {v['image']} (NGINX {v['version']})")
    else:
        print("\nNo vulnerable images found.")

    return len(vulnerable)


if __name__ == "__main__":
    sys.exit(main())
