import subprocess

def scan_target(target, ports=None):
    """
    Scan a target IP or subnet using nmap.
    :param target: IP address or subnet (e.g. 192.168.1.1 or 192.168.1.0/24)
    :param ports: Optional string like '22,80,443'
    :return: Scan result as text
    """

    command = ["nmap", "-sV"]

    if ports:
        command.extend(["-p", ports])

    command.append(target)

    try:
        result = subprocess.check_output(command, stderr=subprocess.STDOUT)
        return result.decode()
    except subprocess.CalledProcessError as e:
        return f"Scan failed:\n{e.output.decode()}"

