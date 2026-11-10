#!/usr/bin/env python3
"""Interfaz gráfica para generar peers WireGuard para MikroTik RouterOS."""

import base64
import binascii
import ipaddress
import os
import re
import threading
import tkinter as tk
import urllib.error
import urllib.request
import webbrowser
import zipfile
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


ZIP_FILENAME = "clientes_wireguard.zip"
RSC_FILENAME = "importar_peers_mikrotik.rsc"
CHANGELOG_URL = "https://mikrotik.com/download/changelogs"
WIREGUARD_DOCS_URL = "https://help.mikrotik.com/docs/display/ROS/WireGuard"
SCRIPTING_DOCS_URL = "https://help.mikrotik.com/docs/display/ROS/Scripting"
IP_CLOUD_DOCS_URL = "https://help.mikrotik.com/docs/display/ROS/Cloud"
ROUTERBOARD_DOCS_URL = "https://help.mikrotik.com/docs/display/ROS/RouterBOARD"
ROUTEROS_INFO_COMMANDS = """:local sn [/system routerboard get serial-number]; :put ("WGINFO|ENDPOINT_DDNS=" . $sn . ".sn.mynetname.net|PUBLIC_ADDRESS=")
:put ("ROS_VERSION|" . [/system resource get version])
:foreach w in=[/interface wireguard find] do={:put ("WG|NAME=" . [/interface wireguard get $w name] . "|PORT=" . [/interface wireguard get $w listen-port] . "|PUBLIC_KEY=" . [/interface wireguard get $w public-key])}
:foreach a in=[/ip address find where disabled=no] do={:put ("ADDR_CANDIDATE|ADDRESS=" . [/ip address get $a address] . "|INTERFACE=" . [/ip address get $a interface])}"""
READONLY_COMMAND_PROFILES = (
    ((7, 1, 0), (7, 16, 2), "RouterOS 7.1–7.16.2", ROUTEROS_INFO_COMMANDS),
)


def x25519(private_key: bytes, public_u: bytes) -> bytes:
    """Calcula X25519 según RFC 7748 usando solo la biblioteca estándar."""
    if len(private_key) != 32 or len(public_u) != 32:
        raise ValueError("Las claves X25519 deben tener exactamente 32 bytes.")

    scalar = bytearray(private_key)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    scalar_int = int.from_bytes(scalar, "little")

    prime = (1 << 255) - 19
    u = int.from_bytes(public_u, "little") & ((1 << 255) - 1)
    x_2, z_2 = 1, 0
    x_3, z_3 = u, 1
    swap = 0

    for bit_index in range(254, -1, -1):
        bit = (scalar_int >> bit_index) & 1
        swap ^= bit
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = bit

        a = (x_2 + z_2) % prime
        aa = (a * a) % prime
        b = (x_2 - z_2) % prime
        bb = (b * b) % prime
        e = (aa - bb) % prime
        c = (x_3 + z_3) % prime
        d = (x_3 - z_3) % prime
        da = (d * a) % prime
        cb = (c * b) % prime
        x_3 = ((da + cb) ** 2) % prime
        z_3 = (u * ((da - cb) ** 2)) % prime
        x_2 = (aa * bb) % prime
        z_2 = (e * (aa + 121665 * e)) % prime

    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2

    result = (x_2 * pow(z_2, prime - 2, prime)) % prime
    return result.to_bytes(32, "little")


def encode_key(raw_key: bytes) -> str:
    return base64.b64encode(raw_key).decode("ascii")


def decode_public_key(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("La clave debe estar codificada en Base64.") from error
    if len(decoded) != 32:
        raise ValueError("La clave pública debe representar exactamente 32 bytes.")
    return decoded


def validate_endpoint(value: str) -> str:
    host = value.strip()
    if not host or any(char.isspace() for char in host):
        raise ValueError("Introduce un dominio DDNS o una dirección IP.")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        labels = host.rstrip(".").split(".")
        valid_labels = all(
            len(label) <= 63
            and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
            for label in labels
        )
        if len(host) <= 253 and valid_labels:
            return host
        raise ValueError("El Endpoint/DDNS no parece un dominio o una dirección IP válida.")


def validate_vpn_prefix(value: str) -> str:
    parts = value.strip().split(".")
    try:
        if len(parts) != 3 or any(not part.isdecimal() for part in parts):
            raise ValueError
        octets = [int(part) for part in parts]
        if any(not 0 <= octet <= 255 for octet in octets):
            raise ValueError
    except ValueError as error:
        raise ValueError("Usa tres octetos, por ejemplo 192.168.100.") from error
    return ".".join(str(octet) for octet in octets)


def validate_dns_servers(value: str) -> list[str]:
    servers = [server.strip() for server in value.split(",") if server.strip()]
    try:
        if not servers:
            raise ValueError
        return [str(ipaddress.ip_address(server)) for server in servers]
    except ValueError as error:
        raise ValueError("Introduce direcciones DNS IPv4 o IPv6 válidas separadas por coma.") from error


def validate_lan_network(value: str, vpn_network: ipaddress.IPv4Network) -> str:
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
        if network.version != 4 or network.overlaps(vpn_network):
            raise ValueError
        return str(network)
    except ValueError as error:
        raise ValueError("La red LAN debe ser IPv4 válida y no solaparse con la red VPN.") from error


def validate_port(value: str) -> int:
    try:
        port = int(value.strip())
    except ValueError as error:
        raise ValueError("El puerto debe ser un número entero entre 1 y 65535.") from error
    if not 1 <= port <= 65535:
        raise ValueError("El puerto debe estar entre 1 y 65535.")
    return port


def validate_peer_count(value: str) -> int:
    try:
        count = int(value.strip())
    except ValueError as error:
        raise ValueError("La cantidad de peers debe ser un número entero.") from error
    if not 1 <= count <= 253:
        raise ValueError("La cantidad de peers debe estar entre 1 y 253.")
    return count


def validate_routeros_version(value: str) -> tuple[int, ...]:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+){1,2})(?:\s*\((?:stable|long-term|testing|development)\))?\s*", value, re.I)
    if not match:
        raise ValueError("Introduce una versión RouterOS, por ejemplo 7.16.2.")
    version = tuple(int(part) for part in match.group(1).split("."))
    if version[0] != 7 or version + (0,) * (3 - len(version)) < (7, 1, 0):
        raise ValueError("Este generador de peers WireGuard requiere RouterOS 7.1 o superior.")
    return version


def select_readonly_command_profile(version_text: str) -> tuple[str, str]:
    version = validate_routeros_version(version_text)
    normalized_version = version + (0,) * (3 - len(version))
    matching_profiles = [
        profile
        for profile in READONLY_COMMAND_PROFILES
        if profile[0] <= normalized_version <= profile[1]
    ]
    if not matching_profiles:
        raise ValueError(
            f"No hay comandos de solo lectura verificados para RouterOS {version_text}."
        )
    _, _, profile_name, commands = max(matching_profiles, key=lambda profile: profile[0])
    return profile_name, commands


def routeros_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    return f'"{escaped}"'


def peer_name(index: int) -> str:
    return "user" if index == 1 else f"user{index}"


def build_routeros_peer_commands(
    interface_name: str,
    peers: list[tuple[str, str]],
    routeros_version: str,
) -> list[str]:
    validate_routeros_version(routeros_version)
    lines = [
        f"# RouterOS objetivo: {routeros_version}",
        "# Sintaxis WireGuard de RouterOS 7; cada peer usa disabled=no.",
    ]
    for index, (client_ip, public_key) in enumerate(peers, start=1):
        lines.append(
            "/interface wireguard peers add "
            f"interface={routeros_quote(interface_name)} "
            f"public-key={routeros_quote(public_key)} "
            f"allowed-address={client_ip}/32 "
            f"comment={routeros_quote(peer_name(index))} "
            "disabled=no"
        )
    return lines


def generate_files(
    endpoint_host: str,
    port: int,
    vpn_prefix: str,
    dns_servers: list[str],
    lan_network: str,
    server_public_key: bytes,
    peer_count: int,
    interface_name: str,
    routeros_version: str,
    output_dir: Path,
) -> tuple[Path, Path]:
    validate_routeros_version(routeros_version)
    endpoint = f"[{endpoint_host}]:{port}" if ":" in endpoint_host else f"{endpoint_host}:{port}"
    vpn_network = ipaddress.ip_network(f"{vpn_prefix}.0/24")
    allowed_ips = ", ".join(dict.fromkeys((str(vpn_network), lan_network)))
    conf_files: list[tuple[str, str]] = []
    routeros_peers: list[tuple[str, str]] = []

    for index in range(peer_count):
        peer_number = index + 1
        client_ip = f"{vpn_prefix}.{index + 2}"
        private_key = os.urandom(32)
        public_key_text = encode_key(x25519(private_key, (9).to_bytes(32, "little")))
        conf_text = (
            "[Interface]\n"
            f"PrivateKey = {encode_key(private_key)}\n"
            f"Address = {client_ip}/32\n"
            f"DNS = {', '.join(dns_servers)}\n\n"
            "[Peer]\n"
            f"PublicKey = {encode_key(server_public_key)}\n"
            f"Endpoint = {endpoint}\n"
            f"AllowedIPs = {allowed_ips}\n"
            "PersistentKeepalive = 25\n"
        )
        conf_files.append((f"{peer_name(peer_number)}.conf", conf_text))
        routeros_peers.append((client_ip, public_key_text))

    rsc_lines = [
        "# Importar en el MikroTik que aloja el servidor WireGuard.",
        "# Verifique que la interfaz y las rutas/firewall de la LAN ya esten configurados.",
        *build_routeros_peer_commands(interface_name, routeros_peers, routeros_version),
    ]

    zip_path = output_dir / ZIP_FILENAME
    rsc_path = output_dir / RSC_FILENAME
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for filename, contents in conf_files:
            archive.writestr(filename, contents)
    rsc_path.write_text("\n".join(rsc_lines) + "\n", encoding="utf-8")
    return zip_path, rsc_path


def parse_wireguard_print_detail(text: str) -> dict[str, str]:
    """Extrae los datos marcados por ROUTEROS_INFO_COMMANDS o salidas print simples."""
    labelled = _parse_labelled_routeros_output(text)
    if labelled:
        return labelled

    field_pattern = re.compile(
        r'\b(name|listen-port|public-key)=(?:"((?:\\.|[^"])*)"|([^\s]+))'
    )
    interface_fields: dict[str, str] = {}
    routeros_version = ""
    for line in text.splitlines():
        version_match = re.match(
            r"\s*version\s*:\s*(\d+(?:\.\d+){1,2})(?:\s+\(([^)]+)\))?",
            line,
            re.I,
        )
        if version_match:
            routeros_version = version_match.group(1)
        line_fields: dict[str, str] = {}
        for match in field_pattern.finditer(line):
            raw_value = match.group(2) if match.group(2) is not None else match.group(3)
            line_fields.setdefault(
                match.group(1),
                raw_value.replace('\\"', '"').replace("\\\\", "\\"),
            )
        if line_fields and not interface_fields:
            interface_fields = line_fields
        elif line_fields.get("public-key") and (
            not interface_fields.get("name")
            or not line_fields.get("name")
            or interface_fields["name"] == line_fields["name"]
        ):
            interface_fields.update(line_fields)
    if interface_fields or routeros_version:
        result: dict[str, str] = {}
        if interface_fields.get("name"):
            result["interface"] = interface_fields["name"]
        if interface_fields.get("listen-port"):
            result["port"] = str(validate_port(interface_fields["listen-port"]))
        if interface_fields.get("public-key"):
            decode_public_key(interface_fields["public-key"])
            result["public_key"] = interface_fields["public-key"]
        if routeros_version:
            result["routeros_version"] = routeros_version
        if result:
            return result
    raise ValueError(
        "No encontré datos RouterOS reconocibles. Pega la salida de los comandos de la pestaña MikroTik."
    )


def _parse_labelled_routeros_output(text: str) -> dict[str, str]:
    cloud: dict[str, str] = {}
    wireguard_rows: list[dict[str, str]] = []
    address_rows: list[dict[str, str]] = []
    routeros_version = ""
    in_cloud_block = False

    for line in text.splitlines():
        normalized_line = line.strip()
        if "CLOUD_BEGIN" in normalized_line.upper():
            in_cloud_block = True
            continue
        if "CLOUD_END" in normalized_line.upper():
            in_cloud_block = False
            continue
        if in_cloud_block:
            cloud_match = re.match(
                r"(dns-name|public-address)\s*:\s*(.*?)\s*$",
                normalized_line,
                re.I,
            )
            if cloud_match:
                cloud_key = (
                    "ENDPOINT_DDNS"
                    if cloud_match.group(1).lower() == "dns-name"
                    else "PUBLIC_ADDRESS"
                )
                cloud[cloud_key] = cloud_match.group(2).strip().strip('"')

        parts = [part.strip() for part in line.strip().split("|")]
        if not parts:
            continue
        marker = parts[0].upper()
        values: dict[str, str] = {}
        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                values[key.strip().upper()] = value.strip().strip('"')
        if marker == "WGINFO":
            cloud.update({key: value for key, value in values.items() if value})
        elif marker == "CLOUD":
            if "DNS_NAME" in values:
                cloud["ENDPOINT_DDNS"] = values["DNS_NAME"]
            if "PUBLIC_ADDRESS" in values:
                cloud["PUBLIC_ADDRESS"] = values["PUBLIC_ADDRESS"]
        elif marker == "WG":
            wireguard_rows.append(values)
        elif marker in {"ADDR", "ADDR_CANDIDATE"}:
            address_rows.append(values)
        elif marker == "ROS_VERSION":
            routeros_version = parts[1] if len(parts) > 1 else ""

    if not (cloud or wireguard_rows or address_rows or routeros_version):
        return {}
    if len(wireguard_rows) > 1:
        names = ", ".join(row.get("NAME", "(sin nombre)") for row in wireguard_rows)
        raise ValueError(
            f"El router tiene varias interfaces WireGuard ({names}). "
            "Vuelve a pegar solo la línea WG correspondiente a la interfaz del servidor."
        )

    result: dict[str, str] = {}
    endpoint = _select_public_endpoint(cloud, address_rows, wireguard_rows)
    if endpoint:
        result["endpoint"] = endpoint

    wg_interface = ""
    vpn_network: ipaddress.IPv4Network | None = None
    if wireguard_rows:
        wg = wireguard_rows[0]
        wg_interface = wg.get("NAME", "")
        if wg_interface:
            result["interface"] = wg_interface
        if wg.get("PORT"):
            result["port"] = str(validate_port(wg["PORT"]))
        if wg.get("PUBLIC_KEY"):
            decode_public_key(wg["PUBLIC_KEY"])
            result["public_key"] = wg["PUBLIC_KEY"]

    if routeros_version:
        result["routeros_version"] = ".".join(
            str(part) for part in validate_routeros_version(routeros_version)
        )

    vpn_addresses: list[ipaddress.IPv4Network] = []
    lan_candidates: list[tuple[str, ipaddress.IPv4Network]] = []
    private_networks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    for row in address_rows:
        address_text = row.get("ADDRESS", "")
        interface = row.get("INTERFACE", "")
        try:
            address = ipaddress.ip_interface(address_text)
        except ValueError:
            continue
        if not isinstance(address, ipaddress.IPv4Interface):
            continue
        if interface == wg_interface:
            vpn_addresses.append(address.network)
        elif (
            address.network.prefixlen < 32
            and any(address.ip in network for network in private_networks)
        ):
            lan_candidates.append((interface, address.network))

    if vpn_addresses:
        vpn_network = vpn_addresses[0]
        if vpn_network.prefixlen != 24:
            raise ValueError(
                f"La interfaz VPN usa {vpn_network}; este generador necesita una red VPN /24 "
                "para asignar direcciones correlativas."
            )
        result["vpn_prefix"] = ".".join(str(vpn_network.network_address).split(".")[:3])

    if lan_candidates:
        unique_networks = list(dict.fromkeys(network for _, network in lan_candidates))
        bridge_candidates = list(
            dict.fromkeys(
                network for interface, network in lan_candidates
                if "bridge" in interface.lower()
            )
        )
        if len(bridge_candidates) == 1:
            chosen_lan = bridge_candidates[0]
        elif len(unique_networks) == 1:
            chosen_lan = unique_networks[0]
        else:
            choices = ", ".join(
                f"{interface} ({network})" for interface, network in lan_candidates
            )
            raise ValueError(
                "Hay varias redes IPv4 privadas y no se puede determinar la LAN automáticamente: "
                f"{choices}. Pega solo la línea ADD de la interfaz LAN que quieres usar."
            )
        result["lan_network"] = str(chosen_lan)

    if not result:
        raise ValueError(
            "La salida no contiene campos reconocibles. Ejecuta los comandos de lectura de la pestaña MikroTik."
        )
    return result


def _select_public_endpoint(
    cloud: dict[str, str],
    address_rows: list[dict[str, str]],
    wireguard_rows: list[dict[str, str]],
) -> str | None:
    ddns_name = cloud.get("ENDPOINT_DDNS", "").strip()
    if ddns_name and ddns_name.lower() != "none":
        endpoint = _validate_public_endpoint(ddns_name)
        if endpoint:
            return endpoint

    cloud_address = cloud.get("PUBLIC_ADDRESS", "").strip()
    if cloud_address and cloud_address.lower() != "none":
        endpoint = _validate_public_endpoint(cloud_address)
        if endpoint:
            return endpoint

    wg_names = {row.get("NAME", "") for row in wireguard_rows}
    for row in address_rows:
        if row.get("INTERFACE", "") in wg_names:
            continue
        try:
            address = ipaddress.ip_interface(row.get("ADDRESS", "")).ip
        except ValueError:
            continue
        if address.is_global:
            return str(address)
    return None


def _validate_public_endpoint(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        try:
            return validate_endpoint(value)
        except ValueError:
            return None
    return str(address) if address.is_global else None


def fetch_latest_release() -> str:
    request = urllib.request.Request(
        CHANGELOG_URL,
        headers={"User-Agent": "WireGuard-MikroTik-Generator/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            payload = response.read(1_000_000).decode("utf-8", errors="replace")
    except (OSError, urllib.error.URLError, TimeoutError) as error:
        raise RuntimeError(f"No se pudo consultar el servidor oficial: {error}") from error

    versions = list(
        dict.fromkeys(
            re.findall(
                r"""versionChangelog\(['"](7\.\d+(?:\.\d+)?)['"]\)""",
                payload,
            )
        )
    )
    if not versions:
        raise RuntimeError(
            "La página oficial respondió, pero no se pudo reconocer una versión de RouterOS 7."
        )
    return versions[0]


def check_readonly_command_docs() -> tuple[str, list[str]]:
    documentation = (
        (
            "IP Cloud",
            IP_CLOUD_DOCS_URL,
            ("dns-name", "public-address", "/ip cloud print"),
        ),
        (
            "RouterBOARD",
            ROUTERBOARD_DOCS_URL,
            ("serial-number",),
        ),
        (
            "WireGuard",
            WIREGUARD_DOCS_URL,
            ("listen-port", "public-key", "allowed-address"),
        ),
    )
    verified: list[str] = []
    for section, url, required_terms in documentation:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "WireGuard-MikroTik-Generator/1.0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                page = response.read(1_000_000).decode("utf-8", errors="replace").casefold()
        except (OSError, urllib.error.URLError, TimeoutError) as error:
            raise RuntimeError(f"No se pudo consultar la documentación de {section}: {error}") from error

        missing = [term for term in required_terms if term.casefold() not in page]
        if missing:
            raise RuntimeError(
                f"La página oficial de {section} no contiene los campos esperados: "
                f"{', '.join(missing)}."
            )
        verified.append(section)

    return fetch_latest_release(), verified


class WireGuardGeneratorApp:
    COLORS = {
        "background": "#eef3f9",
        "card": "#ffffff",
        "navy": "#14243a",
        "blue": "#2463eb",
        "blue_hover": "#174fc7",
        "text": "#243247",
        "muted": "#66758a",
        "border": "#d8e1ed",
        "success": "#16804a",
        "error": "#c2333d",
        "soft_blue": "#e8f0ff",
        "soft_orange": "#fff5e6",
    }

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("WireGuard Studio · MikroTik")
        self.root.geometry("1000x850")
        self.root.minsize(900, 700)
        self.root.configure(bg=self.COLORS["background"])

        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TFrame", background=self.COLORS["background"])
        style.configure("Card.TFrame", background=self.COLORS["card"])
        style.configure(
            "TLabel",
            background=self.COLORS["background"],
            foreground=self.COLORS["text"],
            font=("Segoe UI", 10),
        )
        style.configure(
            "Card.TLabel",
            background=self.COLORS["card"],
            foreground=self.COLORS["text"],
            font=("Segoe UI", 10),
        )
        style.configure(
            "Hint.Card.TLabel",
            background=self.COLORS["card"],
            foreground=self.COLORS["muted"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "Title.TLabel",
            background=self.COLORS["navy"],
            foreground="#ffffff",
            font=("Segoe UI", 21, "bold"),
        )
        style.configure(
            "Subtitle.TLabel",
            background=self.COLORS["navy"],
            foreground="#c9d6e8",
            font=("Segoe UI", 10),
        )
        style.configure(
            "TNotebook",
            background=self.COLORS["background"],
            borderwidth=0,
            tabmargins=(0, 0, 0, 0),
        )
        style.configure(
            "TNotebook.Tab",
            background="#e1e9f4",
            foreground=self.COLORS["muted"],
            padding=(18, 10),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.COLORS["card"])],
            foreground=[("selected", self.COLORS["blue"])],
        )
        style.configure(
            "Primary.TButton",
            background=self.COLORS["blue"],
            foreground="#ffffff",
            borderwidth=0,
            padding=(16, 11),
            font=("Segoe UI", 11, "bold"),
        )
        style.map("Primary.TButton", background=[("active", self.COLORS["blue_hover"])])
        style.configure(
            "Secondary.TButton",
            background="#e8eef7",
            foreground=self.COLORS["text"],
            borderwidth=0,
            padding=(11, 8),
            font=("Segoe UI", 9, "bold"),
        )
        style.map("Secondary.TButton", background=[("active", "#d9e4f2")])
        style.configure("TEntry", padding=(8, 7), font=("Segoe UI", 10))
        style.configure("Valid.TEntry", fieldbackground="#ffffff")
        style.configure("Invalid.TEntry", fieldbackground="#fff1f1")

        self._build_header()
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=24, pady=(0, 20))
        self.config_tab = ttk.Frame(self.notebook, padding=18)
        self.router_tab = ttk.Frame(self.notebook, padding=18)
        self.version_tab = ttk.Frame(self.notebook, padding=18)
        self.notebook.add(self.config_tab, text="  Generador  ")
        self.notebook.add(self.router_tab, text="  MikroTik  ")
        self.notebook.add(self.version_tab, text="  Versiones  ")

        self.fields: dict[str, tk.StringVar] = {}
        self.entries: dict[str, ttk.Entry] = {}
        self.field_errors: dict[str, tk.StringVar] = {}
        self.output_dir = tk.StringVar(value="")
        self.output_status = tk.StringVar(value="Elige la carpeta donde guardar los archivos.")
        self.routeros_version = tk.StringVar(value="7.16.2")
        self.latest_routeros_version: str | None = None
        self.custom_readonly_commands = False
        self._build_config_tab()
        self._build_router_tab()
        self._build_version_tab()

    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg=self.COLORS["navy"], padx=28, pady=18)
        header.pack(fill="x", padx=24, pady=(20, 14))
        ttk.Label(header, text="WireGuard Studio", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Genera clientes, prepara peers activos y revisa recursos oficiales de MikroTik.",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(3, 0))

    def _card(self, parent: ttk.Frame, padding: int = 16) -> ttk.Frame:
        card = ttk.Frame(parent, style="Card.TFrame", padding=padding)
        return card

    def _build_config_tab(self) -> None:
        tab = self.config_tab
        tab.columnconfigure(0, weight=1)
        card = self._card(tab, 18)
        card.grid(row=0, column=0, sticky="nsew")
        card.columnconfigure(0, weight=1)
        card.columnconfigure(1, weight=1)

        ttk.Label(card, text="Datos del servidor y los clientes", style="Card.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 12)
        )
        specs = [
            ("endpoint", "Endpoint / DDNS", "", 1, 0),
            ("port", "Puerto UDP", "13231", 1, 1),
            ("vpn_prefix", "Red VPN (tres octetos)", "192.168.100", 2, 0),
            ("peer_count", "Peers ACTIVOS (1-253)", "5", 2, 1),
            ("dns", "Servidores DNS", "8.8.8.8, 8.8.4.4", 3, 0),
            ("lan", "Red LAN local (CIDR)", "192.168.0.0/24", 3, 1),
            ("public_key", "Clave pública del servidor", "", 4, 0),
            ("interface", "Interfaz WireGuard en MikroTik", "wg0", 4, 1),
        ]
        for key, label, default, row, column in specs:
            self._add_field(card, key, label, default, row, column)

        folder_card = self._card(tab, 14)
        folder_card.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        folder_card.columnconfigure(0, weight=1)
        ttk.Label(folder_card, text="Carpeta de destino", style="Card.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            folder_card,
            textvariable=self.output_status,
            style="Hint.Card.TLabel",
            wraplength=570,
        ).grid(row=1, column=0, sticky="w", pady=(3, 0))
        ttk.Button(
            folder_card,
            text="Elegir carpeta…",
            style="Secondary.TButton",
            command=self.choose_output_dir,
        ).grid(row=0, column=1, rowspan=2, padx=(14, 0))

        ttk.Button(
            tab,
            text="✦   Generar Archivos",
            style="Primary.TButton",
            command=self.on_generate,
        ).grid(row=2, column=0, sticky="ew", pady=(14, 0))

    def _add_field(
        self,
        parent: ttk.Frame,
        key: str,
        label: str,
        default: str,
        row: int,
        column: int,
    ) -> None:
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.grid(row=row, column=column, sticky="ew", padx=(0, 14) if column == 0 else (14, 0), pady=6)
        frame.columnconfigure(0, weight=1)
        ttk.Label(frame, text=label, style="Card.TLabel").grid(row=0, column=0, sticky="w")
        variable = tk.StringVar(value=default)
        self.fields[key] = variable
        entry = ttk.Entry(frame, textvariable=variable, style="Valid.TEntry")
        entry.grid(row=1, column=0, sticky="ew", pady=(4, 0))
        self.entries[key] = entry
        error = tk.StringVar(value="")
        self.field_errors[key] = error
        ttk.Label(
            frame,
            textvariable=error,
            style="Hint.Card.TLabel",
            foreground=self.COLORS["error"],
            wraplength=360,
        ).grid(row=2, column=0, sticky="w", pady=(2, 0))
        variable.trace_add("write", lambda *_, field=key: self._validate_field(field))
        self._validate_field(key)

    def _field_value(self, key: str) -> str:
        return self.fields[key].get().strip()

    def _validate_one(self, key: str) -> None:
        value = self._field_value(key)
        if key == "endpoint":
            validate_endpoint(value)
        elif key == "port":
            validate_port(value)
        elif key == "vpn_prefix":
            validate_vpn_prefix(value)
        elif key == "peer_count":
            validate_peer_count(value)
        elif key == "dns":
            validate_dns_servers(value)
        elif key == "lan":
            prefix = validate_vpn_prefix(self._field_value("vpn_prefix"))
            validate_lan_network(value, ipaddress.ip_network(f"{prefix}.0/24"))
        elif key == "public_key":
            decode_public_key(value)
        elif key == "interface":
            if not value or len(value) > 64 or any(ord(char) < 32 for char in value):
                raise ValueError("Escribe un nombre de interfaz válido (máximo 64 caracteres).")

    def _validate_field(self, key: str) -> bool:
        try:
            self._validate_one(key)
        except ValueError as error:
            self.field_errors[key].set(str(error))
            self.entries[key].configure(style="Invalid.TEntry")
            return False
        self.field_errors[key].set("")
        self.entries[key].configure(style="Valid.TEntry")
        return True

    def _validate_all(self) -> bool:
        valid = True
        for key in self.fields:
            if not self._validate_field(key):
                valid = False
        return valid

    def choose_output_dir(self) -> None:
        selected = filedialog.askdirectory(
            parent=self.root,
            title="Selecciona dónde guardar ZIP y scripts RouterOS",
            mustexist=True,
        )
        if selected:
            self.output_dir.set(selected)
            self.output_status.set(selected)

    def on_generate(self) -> None:
        if not self._validate_all():
            self.notebook.select(self.config_tab)
            messagebox.showwarning(
                "Revisa los campos",
                "Corrige los campos marcados en rojo antes de generar los archivos.",
                parent=self.root,
            )
            return
        destination = self.output_dir.get()
        if not destination:
            destination = filedialog.askdirectory(
                parent=self.root,
                title="¿Dónde quieres guardar los archivos generados?",
                mustexist=True,
            )
            if not destination:
                self.output_status.set("Selecciona una carpeta para poder continuar.")
                return
            self.output_dir.set(destination)
            self.output_status.set(destination)

        try:
            version_parts = validate_routeros_version(self.routeros_version.get())
            endpoint = validate_endpoint(self._field_value("endpoint"))
            port = validate_port(self._field_value("port"))
            vpn_prefix = validate_vpn_prefix(self._field_value("vpn_prefix"))
            dns_servers = validate_dns_servers(self._field_value("dns"))
            vpn_network = ipaddress.ip_network(f"{vpn_prefix}.0/24")
            lan_network = validate_lan_network(self._field_value("lan"), vpn_network)
            server_key = decode_public_key(self._field_value("public_key"))
            peer_count = validate_peer_count(self._field_value("peer_count"))
            interface_name = self._field_value("interface")
            zip_path, rsc_path = generate_files(
                endpoint,
                port,
                vpn_prefix,
                dns_servers,
                lan_network,
                server_key,
                peer_count,
                interface_name,
                ".".join(str(part) for part in version_parts),
                Path(destination),
            )
        except (OSError, ValueError, zipfile.BadZipFile) as error:
            messagebox.showerror("Error al generar", str(error), parent=self.root)
            return

        messagebox.showinfo(
            "¡Listo!",
            f"Se generaron {peer_count} peers activos.\n\n"
            "Siguiente:\n"
            "1. Descomprime el ZIP y entrega a cada usuario su archivo user.conf, user2.conf, etc.\n"
            "2. Importa cada .conf en la aplicación WireGuard de ese dispositivo.\n"
            "3. Para añadir los peers al router, haz antes una copia de seguridad, sube el .rsc "
            "a Files y ejecuta /import file-name=importar_peers_mikrotik.rsc. Esto modifica el MikroTik.\n\n"
            f"ZIP: {zip_path}\nScript RouterOS: {rsc_path}",
            parent=self.root,
        )

    def _build_router_tab(self) -> None:
        tab = self.router_tab
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)

        command_card = self._card(tab, 14)
        command_card.grid(row=0, column=0, sticky="ew")
        command_card.columnconfigure(0, weight=1)
        ttk.Label(command_card, text="Comandos para consultar MikroTik", style="Card.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            command_card,
            text="El bloque original consulta IP Cloud, versión, datos WireGuard e IPs del router; "
            "no crea peers ni cambia la configuración. Si editas los comandos, la aplicación no puede "
            "garantizar que sigan siendo de solo lectura: revísalos antes de ejecutarlos.",
            style="Hint.Card.TLabel",
            wraplength=800,
        ).grid(row=1, column=0, sticky="w", pady=(4, 8))
        self.commands_view = tk.Text(
            command_card,
            height=4,
            wrap="none",
            font=("Consolas", 9),
            bg="#101c2d",
            fg="#dce8f8",
            relief="flat",
            padx=10,
            pady=8,
        )
        self.commands_view.insert("1.0", ROUTEROS_INFO_COMMANDS)
        self.commands_view.configure(state="disabled")
        self.commands_view.grid(row=2, column=0, sticky="ew")
        command_buttons = ttk.Frame(command_card, style="Card.TFrame")
        command_buttons.grid(row=3, column=0, sticky="e", pady=(8, 0))
        ttk.Button(
            command_buttons,
            text="Editar comandos…",
            style="Secondary.TButton",
            command=self.edit_routeros_info_commands,
        ).pack(side="left", padx=(0, 8))
        ttk.Button(
            command_buttons,
            text="Copiar comandos MikroTik",
            style="Secondary.TButton",
            command=self.copy_routeros_info_commands,
        ).pack(side="left")

        auto_card = self._card(tab, 14)
        auto_card.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        auto_card.columnconfigure(0, weight=1)
        auto_card.rowconfigure(2, weight=1)
        ttk.Label(auto_card, text="Autocompletar desde datos del MikroTik", style="Card.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            auto_card,
            text="Copia toda la salida producida por los comandos de arriba y pégala aquí. Se "
            "autocompletan DDNS/IP, puerto, red VPN, LAN, interfaz, clave pública y versión cuando "
            "están disponibles. Si hay varias redes o interfaces, el aviso indicará qué línea conservar.",
            style="Hint.Card.TLabel",
            wraplength=800,
        ).grid(row=1, column=0, sticky="w", pady=(4, 8))
        self.export_text = tk.Text(
            auto_card,
            height=8,
            wrap="word",
            font=("Consolas", 9),
            bg="#f8fafc",
            fg=self.COLORS["text"],
            relief="flat",
            padx=10,
            pady=8,
            insertbackground=self.COLORS["blue"],
        )
        self.export_text.grid(row=2, column=0, sticky="nsew")
        self.export_text.bind("<Return>", self._handle_export_enter)
        ttk.Button(
            auto_card,
            text="Leer datos y autocompletar",
            style="Secondary.TButton",
            command=self.import_routeros_output,
        ).grid(row=3, column=0, sticky="e", pady=(8, 0))

        import_card = self._card(tab, 14)
        import_card.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        import_card.columnconfigure(0, weight=1)
        ttk.Label(
            import_card,
            text="Importar los peers generados (esto modifica el MikroTik)",
            style="Card.TLabel",
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            import_card,
            text="Después de generar los archivos, sube importar_peers_mikrotik.rsc a Files en el router. "
            "Haz una copia de seguridad antes de ejecutarlo; el comando añade los peers del archivo.",
            style="Hint.Card.TLabel",
            wraplength=800,
        ).grid(row=1, column=0, sticky="w", pady=(4, 8))
        import_command = tk.Frame(import_card, bg="#101c2d", padx=12, pady=10)
        import_command.grid(row=2, column=0, sticky="ew")
        ttk.Label(
            import_command,
            text="/import file-name=importar_peers_mikrotik.rsc",
            foreground="#dce8f8",
            background="#101c2d",
            font=("Consolas", 10),
        ).pack(anchor="w")
        ttk.Button(
            import_card,
            text="Copiar comando de importación",
            style="Secondary.TButton",
            command=self.copy_peer_import_command,
        ).grid(row=3, column=0, sticky="w", pady=(8, 0))

    def _handle_export_enter(self, _event: tk.Event) -> str:
        self.import_routeros_output()
        return "break"

    def import_routeros_output(self) -> None:
        try:
            values = parse_wireguard_print_detail(self.export_text.get("1.0", "end").strip())
        except ValueError as error:
            messagebox.showerror("No se pudieron leer los datos", str(error), parent=self.root)
            return

        mapping = {
            "endpoint": "endpoint",
            "port": "port",
            "vpn_prefix": "vpn_prefix",
            "lan_network": "lan",
            "public_key": "public_key",
            "interface": "interface",
        }
        labels = {
            "endpoint": "Endpoint/DDNS",
            "port": "puerto",
            "vpn_prefix": "red VPN",
            "lan_network": "red LAN",
            "public_key": "clave pública",
            "interface": "interfaz",
            "routeros_version": "versión RouterOS",
        }
        filled = []
        for source_key, field_key in mapping.items():
            value = values.get(source_key, "").strip()
            if value:
                self.fields[field_key].set(value)
                filled.append(labels[source_key])
        endpoint_missing = not values.get("endpoint", "").strip()
        if "routeros_version" in values:
            self.routeros_version.set(values["routeros_version"])
            filled.append(labels["routeros_version"])
        self.notebook.select(self.config_tab)
        self._validate_all()
        if not filled:
            messagebox.showwarning(
                "No hay datos para autocompletar",
                "La salida no incluyó los datos necesarios. Ejecuta los comandos de la pestaña MikroTik "
                "y copia sus resultados completos.",
                parent=self.root,
            )
            return
        if endpoint_missing:
            if self._field_value("endpoint"):
                endpoint_notice = (
                    "No se encontró DDNS ni una IP pública global; se conserva el Endpoint que ya "
                    "estaba escrito."
                )
            else:
                endpoint_notice = (
                    "No se encontró DDNS ni una IP pública global; introduce el Endpoint manualmente "
                    "antes de generar los archivos."
                )
        else:
            endpoint_notice = "Endpoint obtenido de DDNS/IP Cloud o de una dirección pública de interfaz."
        messagebox.showinfo(
            "Autocompletado terminado",
            "Se completaron: " + ", ".join(filled) + ".\n"
            + endpoint_notice
            + "\nCompleta manualmente los DNS y la cantidad de peers.",
            parent=self.root,
        )

    def copy_routeros_info_commands(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(self.commands_view.get("1.0", "end-1c"))
        self.root.update()
        messagebox.showinfo(
            "Comandos copiados",
            "Pégalos en la terminal del MikroTik y copia toda la salida al cuadro de autocompletado.",
            parent=self.root,
        )

    def edit_routeros_info_commands(self) -> None:
        if not messagebox.askyesno(
            "Advertencia: comandos del router",
            "El programa no puede comprobar que los comandos que escribas sean solo de lectura. "
            "Un comando modificado podría cambiar o borrar la configuración del MikroTik si lo ejecutas.\n\n"
            "¿Quieres abrir el editor? Editar aquí no ejecuta nada en el router.",
            icon="warning",
            parent=self.root,
        ):
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Editar comandos de lectura")
        dialog.transient(self.root)
        dialog.geometry("760x440")
        dialog.minsize(580, 320)
        dialog.columnconfigure(0, weight=1)
        dialog.rowconfigure(1, weight=1)

        ttk.Label(
            dialog,
            text="Revisa cada línea antes de copiarla y ejecutarla en el MikroTik.",
            wraplength=720,
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(14, 8))
        editor = tk.Text(
            dialog,
            wrap="none",
            font=("Consolas", 10),
            undo=True,
            padx=10,
            pady=8,
        )
        editor.insert("1.0", self.commands_view.get("1.0", "end-1c"))
        editor.grid(row=1, column=0, sticky="nsew", padx=14)

        buttons = ttk.Frame(dialog)
        buttons.grid(row=2, column=0, sticky="e", padx=14, pady=14)

        def save_commands() -> None:
            commands = editor.get("1.0", "end-1c").strip()
            if not commands:
                messagebox.showwarning(
                    "Comandos vacíos",
                    "Escribe al menos un comando antes de guardar.",
                    parent=dialog,
                )
                return
            if not messagebox.askyesno(
                "Confirmar cambios",
                "¿Guardar este bloque para mostrarlo y copiarlo desde la aplicación?\n\n"
                "No se valida que sea de solo lectura y no se ejecutará automáticamente. "
                "Comprueba el contenido antes de pegarlo en el MikroTik.",
                icon="warning",
                parent=dialog,
            ):
                return

            self.commands_view.configure(state="normal")
            self.commands_view.delete("1.0", "end")
            self.commands_view.insert("1.0", commands)
            self.commands_view.configure(state="disabled")
            self.custom_readonly_commands = True
            self.compatibility_status.set(
                "Comandos personalizados guardados solo durante esta sesión. "
                "La aplicación no ha validado que sean de solo lectura."
            )
            dialog.destroy()

        ttk.Button(
            buttons,
            text="Cancelar",
            command=dialog.destroy,
        ).pack(side="right", padx=(8, 0))
        ttk.Button(
            buttons,
            text="Guardar cambios",
            style="Primary.TButton",
            command=save_commands,
        ).pack(side="right")
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.grab_set()
        editor.focus_set()

    def copy_peer_import_command(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append("/import file-name=importar_peers_mikrotik.rsc")
        self.root.update()
        messagebox.showwarning(
            "Comando de importación copiado",
            "Sube primero importar_peers_mikrotik.rsc a Files en el MikroTik y crea una copia de "
            "seguridad. Al ejecutar el comando, RouterOS añadirá los peers y modificará la configuración.",
            parent=self.root,
        )

    def _build_version_tab(self) -> None:
        tab = self.version_tab
        tab.columnconfigure(0, weight=1)
        card = self._card(tab, 20)
        card.grid(row=0, column=0, sticky="new")
        card.columnconfigure(0, weight=1)
        ttk.Label(card, text="Comprobación online de RouterOS", style="Card.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            card,
            text="Consulta la página oficial de changelogs y detecta la versión de RouterOS 7 que "
            "aparece primero. Introduce también la versión instalada (o aplícala desde la comprobación); "
            "esa versión se usa al generar el .rsc. La comprobación de comandos consulta documentación "
            "oficial actual; no puede certificar cada versión histórica o futura ni modifica código automáticamente.",
            style="Hint.Card.TLabel",
            wraplength=790,
        ).grid(row=1, column=0, sticky="w", pady=(6, 14))
        ttk.Label(card, text="Versión instalada en el MikroTik", style="Card.TLabel").grid(
            row=2, column=0, sticky="w"
        )
        version_row = ttk.Frame(card, style="Card.TFrame")
        version_row.grid(row=3, column=0, sticky="ew", pady=(4, 12))
        version_row.columnconfigure(0, weight=1)
        version_entry = ttk.Entry(version_row, textvariable=self.routeros_version)
        version_entry.grid(
            row=0, column=0, sticky="ew", padx=(0, 10)
        )
        self.routeros_version_error = tk.StringVar(value="")
        ttk.Label(
            card,
            textvariable=self.routeros_version_error,
            style="Hint.Card.TLabel",
            foreground=self.COLORS["error"],
        ).grid(row=4, column=0, sticky="w", pady=(0, 8))
        self.routeros_version.trace_add("write", self._validate_routeros_version_field)
        ttk.Button(
            version_row,
            text="Usar última detectada",
            style="Secondary.TButton",
            command=self.apply_latest_version,
        ).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(
            version_row,
            text="Comprobar última versión online",
            style="Primary.TButton",
            command=self.check_latest_version,
        ).grid(row=0, column=2)
        self.version_status = tk.StringVar(value="Aún no se ha consultado MikroTik.")
        self.version_result = ttk.Label(
            card,
            textvariable=self.version_status,
            style="Hint.Card.TLabel",
            wraplength=790,
        )
        self.version_result.grid(row=5, column=0, sticky="w", pady=(6, 10))

        compatibility_card = self._card(tab, 16)
        compatibility_card.grid(row=1, column=0, sticky="ew", pady=(14, 0))
        compatibility_card.columnconfigure(0, weight=1)
        ttk.Label(
            compatibility_card,
            text="Validez de los comandos de solo lectura",
            style="Card.TLabel",
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            compatibility_card,
            text="Contrasta los campos usados por los comandos con las páginas oficiales actuales "
            "de IP Cloud, RouterBOARD y WireGuard, y compara la versión instalada con la última publicada. "
            "Si la verificación pasa, actualiza en ejecución el bloque mostrado al perfil conocido de "
            "esa versión. Si falla o no hay perfil, conserva el bloque actual. No reescribe este archivo "
            "ni inventa sintaxis automáticamente.",
            style="Hint.Card.TLabel",
            wraplength=790,
        ).grid(row=1, column=0, sticky="w", pady=(4, 8))
        ttk.Button(
            compatibility_card,
            text="Comprobar comandos en documentación oficial",
            style="Secondary.TButton",
            command=self.check_readonly_compatibility,
        ).grid(row=2, column=0, sticky="w")
        self.compatibility_status = tk.StringVar(
            value="Perfil local RouterOS 7.1–7.16.2 cargado; falta comprobar la documentación online."
        )
        ttk.Label(
            compatibility_card,
            textvariable=self.compatibility_status,
            style="Hint.Card.TLabel",
            wraplength=790,
        ).grid(row=3, column=0, sticky="w", pady=(8, 0))

        links = ttk.Frame(card, style="Card.TFrame")
        links.grid(row=6, column=0, sticky="w")
        ttk.Button(
            links,
            text="Abrir changelog oficial",
            style="Secondary.TButton",
            command=lambda: webbrowser.open(CHANGELOG_URL),
        ).pack(side="left", padx=(0, 8))
        ttk.Button(
            links,
            text="Documentación WireGuard",
            style="Secondary.TButton",
            command=lambda: webbrowser.open(WIREGUARD_DOCS_URL),
        ).pack(side="left", padx=(0, 8))
        ttk.Button(
            links,
            text="Documentación de scripts",
            style="Secondary.TButton",
            command=lambda: webbrowser.open(SCRIPTING_DOCS_URL),
        ).pack(side="left")
        ttk.Button(
            links,
            text="Documentación IP Cloud",
            style="Secondary.TButton",
            command=lambda: webbrowser.open(IP_CLOUD_DOCS_URL),
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            links,
            text="Documentación RouterBOARD",
            style="Secondary.TButton",
            command=lambda: webbrowser.open(ROUTERBOARD_DOCS_URL),
        ).pack(side="left", padx=(8, 0))

    def _validate_routeros_version_field(self, *_: object) -> None:
        try:
            validate_routeros_version(self.routeros_version.get())
        except ValueError as error:
            self.routeros_version_error.set(str(error))
        else:
            self.routeros_version_error.set("")

    def check_latest_version(self) -> None:
        self.version_status.set("Conectando con el servidor oficial de MikroTik…")

        def worker() -> None:
            try:
                version = fetch_latest_release()
            except (RuntimeError, ValueError, OSError) as error:
                self.root.after(
                    0, lambda message=str(error): self.version_status.set(f"No se pudo verificar: {message}")
                )
                return
            self.root.after(0, lambda latest=version: self._show_latest_version(latest))

        threading.Thread(target=worker, daemon=True).start()

    def check_readonly_compatibility(self) -> None:
        self.compatibility_status.set(
            "Consultando changelog y documentación oficial de IP Cloud, RouterBOARD y WireGuard…"
        )
        installed_text = self.routeros_version.get().strip()

        def worker() -> None:
            try:
                latest, verified_sections = check_readonly_command_docs()
            except (RuntimeError, ValueError, OSError) as error:
                result = (
                    "NO CONFIRMADO: no fue posible validar todos los comandos contra la "
                    f"documentación oficial. {error} Se conservan sin cambios los comandos que ya "
                    "están en pantalla."
                )
                self.root.after(0, lambda text=result: self.compatibility_status.set(text))
            else:
                self.root.after(
                    0,
                    lambda: self._apply_verified_readonly_profile(
                        installed_text,
                        latest,
                        verified_sections,
                    ),
                )

        threading.Thread(target=worker, daemon=True).start()

    def _apply_verified_readonly_profile(
        self,
        installed_text: str,
        latest: str,
        verified_sections: list[str],
    ) -> None:
        if self.custom_readonly_commands:
            self.compatibility_status.set(
                f"Documentación actual verificada: {', '.join(verified_sections)}. "
                f"Última versión detectada: {latest}. Se mantienen tus comandos personalizados "
                "sin cambios; la aplicación no puede confirmar que sean de solo lectura."
            )
            return

        try:
            profile_name, commands = select_readonly_command_profile(installed_text)
            installed = validate_routeros_version(installed_text)
            latest_parts = validate_routeros_version(latest)
        except ValueError as error:
            self.compatibility_status.set(
                f"NO CONFIRMADO: {error} Se conservan sin cambios los comandos que ya están en pantalla."
            )
            return

        installed_compare = installed + (0,) * (3 - len(installed))
        latest_compare = latest_parts + (0,) * (3 - len(latest_parts))
        if installed_compare > latest_compare:
            self.compatibility_status.set(
                f"NO CONFIRMADO: RouterOS {installed_text} es superior a la última versión encontrada "
                f"({latest}); no existe un perfil futuro verificado. Se conservan los comandos actuales."
            )
            return

        self.commands_view.configure(state="normal")
        self.commands_view.delete("1.0", "end")
        self.commands_view.insert("1.0", commands)
        self.commands_view.configure(state="disabled")
        self.compatibility_status.set(
            f"Comandos actualizados en ejecución al perfil «{profile_name}» para RouterOS "
            f"{installed_text}. Documentación actual verificada: {', '.join(verified_sections)}. "
            "La documentación confirma los campos actuales, no la ejecución en cada versión histórica. "
            "Si MikroTik publica cambios incompatibles, se necesita añadir y verificar un perfil nuevo."
        )

    def _show_latest_version(self, latest: str) -> None:
        self.latest_routeros_version = latest
        try:
            installed = validate_routeros_version(self.routeros_version.get())
            latest_parts = validate_routeros_version(latest)
            installed_compare = installed + (0,) * (3 - len(installed))
            latest_compare = latest_parts + (0,) * (3 - len(latest_parts))
            if installed_compare < latest_compare:
                status = (
                    f"Última en el changelog oficial: {latest}. La versión indicada "
                    f"({self.routeros_version.get().strip()}) es anterior. Pulsa «Usar última "
                    "detectada» si ya actualizaste el router."
                )
            elif installed_compare == latest_compare:
                status = f"Última publicada: {latest}. Coincide con la versión indicada."
            else:
                status = (
                    f"Última en el changelog oficial: {latest}. La versión indicada es superior; "
                    "verifica la rama/canal del router en el changelog."
                )
        except ValueError:
            status = (
                f"Última en el changelog oficial: {latest}. La versión manual no es válida; "
                "escribe una versión RouterOS 7.x."
            )
        self.version_status.set(status)

    def apply_latest_version(self) -> None:
        if self.latest_routeros_version is None:
            messagebox.showwarning(
                "Primero comprueba la versión",
                "Consulta la última versión online antes de aplicarla.",
                parent=self.root,
            )
            return
        self.routeros_version.set(self.latest_routeros_version)
        self._show_latest_version(self.latest_routeros_version)


def main() -> None:
    root = tk.Tk()
    WireGuardGeneratorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
