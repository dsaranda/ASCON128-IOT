"""
Traza didáctica de Ascon-128 (v1.2): descifra paso a paso y guarda el estado interno
de cada fase para mostrarlo en la página /paso-a-paso.

Usa los bloques internos de ascon.py (implementación de referencia de los autores),
así que los valores son exactamente los del algoritmo real, no una simulación.
"""
import ascon as A

KEY_DEMO = bytes(range(16))
RATE = 8     # bytes por bloque en Ascon-128
ROUNDS_A = 12
ROUNDS_B = 6
ROT = [(19, 28), (61, 39), (1, 6), (10, 17), (7, 41)]
MASK = 0xFFFFFFFFFFFFFFFF


def w(x):
    return format(x, "016X")


def estado(S):
    return [w(x) for x in S]


# --- Una ronda de la permutación, capa por capa (idéntica a ascon.ascon_permutation) ---
def capa_constante(S, r):
    S[2] ^= (0xf0 - r * 0x10 + r * 0x1)


def capa_sbox(S):
    S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1]
    T = [(S[i] ^ MASK) & S[(i + 1) % 5] for i in range(5)]
    for i in range(5):
        S[i] ^= T[(i + 1) % 5]
    S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]; S[2] ^= MASK


def capa_lineal(S):
    for i, (r1, r2) in enumerate(ROT):
        S[i] ^= A.rotr(S[i], r1) ^ A.rotr(S[i], r2)


def ronda(S, r):
    capa_constante(S, r); capa_sbox(S); capa_lineal(S)


def trazar(payload_hex, key=KEY_DEMO):
    data = bytes.fromhex(payload_hex.strip())
    if len(data) < 16 + 16:
        raise ValueError("payload demasiado corto")
    nonce, ct_tag = data[:16], data[16:]
    ct, tag_rec = ct_tag[:-16], ct_tag[-16:]
    t = {
        "hex": payload_hex.strip().upper(),
        "nonce": nonce.hex().upper(), "ct": ct.hex().upper(), "tag": tag_rec.hex().upper(),
        "clave": key.hex().upper(), "largo": len(ct),
    }

    # 1) Inicialización: IV || K || N
    S = [0] * 5
    iv = A.to_bytes([len(key) * 8, RATE * 8, ROUNDS_A, ROUNDS_B]) + A.zero_bytes(4)
    S[0], S[1], S[2], S[3], S[4] = A.bytes_to_state(iv + key + nonce)
    t["iv"] = iv.hex().upper()
    t["estado_inicial"] = estado(S)

    # Primera ronda detallada (r = 0 durante la inicialización de 12 rondas)
    R = S[:]
    capas = {"entrada": estado(R)}
    capa_constante(R, 0); capas["constante"] = estado(R)
    capa_sbox(R);         capas["sbox"] = estado(R)
    capa_lineal(R);       capas["lineal"] = estado(R)
    t["ronda1"] = capas
    t["constante_r0"] = "F0"

    # Evolución ronda a ronda (efecto avalancha)
    E = S[:]
    evol = []
    for r in range(ROUNDS_A):
        ronda(E, r)
        evol.append(estado(E))
    t["evolucion"] = evol

    A.ascon_permutation(S, ROUNDS_A)
    assert estado(S) == evol[-1], "la ronda manual no coincide con la de referencia"
    t["tras_permutacion"] = estado(S)
    S[3] ^= A.bytes_to_int(key[0:8]); S[4] ^= A.bytes_to_int(key[8:16])
    t["tras_clave_init"] = estado(S)

    # 2) Datos asociados: no hay; solo separación de dominio
    S[4] ^= 1
    t["tras_ad"] = estado(S)

    # 3) Descifrado bloque a bloque (réplica de ascon_process_ciphertext, guardando cada paso)
    bloques = []
    lastlen = len(ct) % RATE
    padded = ct + A.zero_bytes(RATE - lastlen)
    plano = b""
    n = len(padded) // RATE
    for i in range(n):
        Ci = A.bytes_to_int(padded[i * RATE:(i + 1) * RATE])
        s0 = S[0]
        ultimo = (i == n - 1)
        largo = lastlen if ultimo else RATE
        Pi = A.int_to_bytes(s0 ^ Ci, 8)[:largo]
        plano += Pi
        bloques.append({
            "i": i + 1, "c": A.int_to_bytes(Ci, 8)[:largo].hex().upper(),
            "s0": A.int_to_bytes(s0, 8)[:largo].hex().upper(),
            "p": Pi.hex().upper(), "txt": Pi.decode("latin-1"), "largo": largo, "ultimo": ultimo,
        })
        if not ultimo:
            S[0] = Ci
            A.ascon_permutation(S, ROUNDS_B)
        else:
            pad = (0x80 << (RATE - lastlen - 1) * 8)
            maskc = (MASK >> (lastlen * 8))
            S[0] = Ci ^ (S[0] & maskc) ^ pad
    t["bloques"] = bloques
    t["tras_datos"] = estado(S)

    # 4) Finalización y tag
    S[1] ^= A.bytes_to_int(key[0:8]); S[2] ^= A.bytes_to_int(key[8:16])
    t["fin_clave"] = estado(S)
    A.ascon_permutation(S, ROUNDS_A)
    t["fin_perm"] = estado(S)
    S[3] ^= A.bytes_to_int(key[0:8]); S[4] ^= A.bytes_to_int(key[8:16])
    tag_calc = A.int_to_bytes(S[3], 8) + A.int_to_bytes(S[4], 8)
    t["tag_calc"] = tag_calc.hex().upper()
    t["ok"] = tag_calc == tag_rec
    t["bits_distintos_tag"] = bin(int.from_bytes(tag_calc, "big") ^ int.from_bytes(tag_rec, "big")).count("1")
    t["texto"] = plano.decode("latin-1")

    # Control: la traza debe coincidir con la función de referencia
    ref = A.ascon_decrypt(key, nonce, b"", ct_tag, "Ascon-128")
    assert (ref is not None) == t["ok"] and (ref is None or ref == plano)

    # 5) Verificación cruzada: Python vuelve a cifrar con el mismo nonce
    if t["ok"]:
        re = A.ascon_encrypt(key, nonce, b"", plano, "Ascon-128")
        t["recifrado"] = (nonce + re).hex().upper()
        t["recifrado_igual"] = (nonce + re) == data
    return t


def mensaje_demo(key=KEY_DEMO):
    """Genera un mensaje como el del Wemos, para probar la página sin hardware."""
    nonce = A.get_random_bytes(16)
    ct = A.ascon_encrypt(key, nonce, b"", b"ALERTA SE DETECTO MOVIMIENTO EN LA HABITACION", "Ascon-128")
    return (nonce + ct).hex().upper()
