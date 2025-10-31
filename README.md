Rust-Scanner (Raw Socket Scanner) - 2600 - THEO PAVLOVIC

Petit scanner réseau en Rust construisant manuellement les en-têtes Ethernet (L2), IPv4 (L3) et TCP/UDP (L4).
Mode silencieux par défaut (pas d’output terminal), exit 0 si succès, exit ≠ 0 en cas d’erreur.

Build (Linux)
cargo build --release --locked


Recommandé : Cargo.lock committé
Utilisation

Le binaire s’invoque avec cargo run -- <options> ou cargo run --release -- <options>.

Options (testées indépendamment) :

--src_ip=<IPv4>

--dst_ip=<IPv4>

--dest_port=<port>

--src_mac=<aa:bb:cc:dd:ee:ff>

--dst_mac=<aa:bb:cc:dd:ee:ff>

--l4_protocol=<udp|tcp>

--timeout_ms=<milliseconds>

--debug_file=<path>

--debug_format=<json|pcap>

--ip_bitfield=<hex> (ex. 0x00, 0x04)

--dry_run (ne pas envoyer sur le réseau ; écrire seulement dans --debug_file)

Comportement :

Pas de progression imprimée sur stdout/stderr lorsque les flags ci-dessus sont fournis.

Les erreurs sont imprimées sur stderr et renvoient un code de sortie non nul.

Exemples (appelés individuellement)
cargo run -- --src_ip=192.168.25.2
cargo run -- --dst_ip=192.168.1.25
cargo run -- --dest_port=8080
cargo run -- --src_mac=aa:bb:cc:dd:ee:ff
cargo run -- --dst_mac=11:22:33:44:55:66
cargo run -- --l4_protocol=udp
cargo run -- --l4_protocol=tcp
cargo run -- --timeout_ms=2000
cargo run -- --debug_file=./debug.pcap --debug_format=pcap --dry_run
cargo run -- --debug_file=./debug.json --debug_format=json --dry_run
cargo run -- --ip_bitfield=0x04 --dry_run

Sorties de debug

--debug_format=pcap → écrit un pcap lisible par Wireshark/tshark dans --debug_file.

--debug_format=json → écrit un JSON compact décrivant L2/L3/L4 (champs + checksums) et les octets du paquet.

En --dry_run, aucun envoi sur le réseau : tous les champs (dont checksums) doivent figurer dans le fichier debug.

Privilèges

Sans privilèges : utiliser --dry_run (recommandé pour l’évaluation) ou un mode connect() si implémenté.

Raw sockets : peuvent exiger CAP_NET_RAW (ou root). Exemple (si nécessaire) :

sudo setcap cap_net_raw+ep ./target/release/rust-scanner


Objectif final : exécuter sans sudo.

Aspects techniques

Construction d’headers Ethernet/IPv4/TCP-UDP selon les options fournies.

Checksums correctement calculés (ou documenter l’offload ; en --dry_run, afficher les valeurs prévues).

--ip_bitfield : valeur OR-ée dans l’octet “Flags+FragmentOffset (haut)” de l’entête IPv4.

--timeout_ms : délai inter-paquets / retry.

Reproductibilité

Dépendances pinnées dans Cargo.toml + Cargo.lock committé.

rust-toolchain.toml pour fixer la version de Rust.

Build testé avec --locked.
