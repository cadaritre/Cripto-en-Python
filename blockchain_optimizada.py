#!/usr/bin/python
# -*- coding: utf-8 -*-
# Nombre: "Lapis Mens Bitcoin-Style" - Blockchain con formato similar a Bitcoin
# Autor: Grok
# Descripción: Genera bloques continuamente en formato binario similar a Bitcoin (guardados en blocks.dat).
# Usa coinbase con mensaje personalizado. Mina hasta Ctrl+C. Dificultad baja fija para simulación rápida.

import os  # Para ruta del archivo
import struct  # Para packing binario
import hashlib  # Para SHA-256
import time  # Para timestamp y pausas

def double_sha256(data):
    """
    Calcula double SHA-256 como en Bitcoin.
    """
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def varint(n):
    """
    Serializa un entero variable (VarInt) como en Bitcoin.
    """
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)

def bits_to_target(bits):
    """
    Convierte bits (formato compacto) a target para PoW.
    """
    exponent = bits >> 24
    mantissa = bits & 0xffffff
    if mantissa == 0:
        return 0
    target = mantissa * (1 << (8 * (exponent - 3)))
    return target

def create_coinbase(height, message):
    """
    Crea una transacción coinbase simple con mensaje.
    """
    # ScriptSig: longitud + mensaje (simplificado)
    scriptSig = struct.pack('<B', height % 256) + message.encode()
    scriptSig_len = varint(len(scriptSig))
    
    tx = (
        struct.pack('<i', 1) +  # Version
        b'\x01' +  # Input count
        b'\x00' * 32 +  # Prev hash (zeros)
        struct.pack('<I', 0xFFFFFFFF) +  # Prev index
        scriptSig_len + scriptSig +  # ScriptSig
        struct.pack('<I', 0) +  # Sequence
        b'\x01' +  # Output count
        struct.pack('<q', 0) +  # Value (0 para simulación)
        varint(1) + b'\x6A' +  # ScriptPubKey: OP_RETURN (minimal)
        struct.pack('<i', 0)  # Locktime
    )
    return tx

class Block:
    """
    Clase que representa un bloque en formato similar a Bitcoin.
    """
    def __init__(self, number=0, previous_hash="0"*64):
        self.number = number
        self.version = 1  # Version del bloque
        self.previous_hash = previous_hash  # Hash anterior (hex string)
        self.timestamp = int(time.time())  # Timestamp actual
        self.bits = 0x1f007fff  # Bits fijos para dificultad baja
        self.nonce = 0  # Nonce inicial
        # Mensaje coinbase similar a Bitcoin
        message = f"Grok's Block {number} / {time.strftime('%d/%b/%Y', time.localtime(self.timestamp))}"
        self.transactions = [create_coinbase(number, message)]  # Solo coinbase
        self.merkle_root = self.calculate_merkle_root()  # Merkle root

    def calculate_merkle_root(self):
        """
        Calcula el Merkle root (para una tx, es su double hash).
        """
        return double_sha256(self.transactions[0])

    def get_header(self):
        """
        Serializa el header del bloque (80 bytes, little-endian).
        """
        prev_bytes = bytes.fromhex(self.previous_hash)[::-1]  # LE
        merkle_bytes = self.merkle_root[::-1]  # LE
        return struct.pack('<i32s32sIII', self.version, prev_bytes, merkle_bytes,
                           self.timestamp, self.bits, self.nonce)

    def hash(self):
        """
        Calcula el hash del bloque (double SHA-256, hex big-endian).
        """
        header = self.get_header()
        hash_bytes = double_sha256(header)
        return hash_bytes[::-1].hex()  # Big-endian hex para display

    def serialize(self):
        """
        Serializa el bloque completo en formato binario como Bitcoin.
        """
        header = self.get_header()
        tx_count = varint(len(self.transactions))
        txs = b''.join(self.transactions)
        block_data = header + tx_count + txs
        size = struct.pack('<I', len(block_data))
        magic = struct.pack('<I', 0xF9BEB4D9)  # Magic bytes mainnet
        return magic + size + block_data

    def __str__(self):
        """
        Representación en string del bloque (estilo Bitcoin).
        """
        return (f"Block#: {self.number}\n"
                f"Hash: {self.hash()}\n"
                f"Previous: {self.previous_hash}\n"
                f"Merkle Root: {self.merkle_root[::-1].hex()}\n"
                f"Timestamp: {self.timestamp} ({time.ctime(self.timestamp)})\n"
                f"Bits: {hex(self.bits)}\n"
                f"Nonce: {self.nonce}\n"
                f"Tx Count: {len(self.transactions)}\n")

class Blockchain:
    """
    Clase que maneja la cadena de bloques en formato Bitcoin.
    """
    def __init__(self):
        self.chain = []  # Lista de bloques
        self.blocks_path = self.get_blocks_path()  # Ruta al archivo binario

    def get_blocks_path(self):
        """
        Obtiene la ruta para blocks.dat.
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(script_dir, "blocks.dat")

    def add(self, block):
        """
        Añade un bloque a la cadena y lo appenda al archivo binario.
        """
        self.chain.append(block)
        with open(self.blocks_path, 'ab') as f:
            f.write(block.serialize())

    def mine(self, block):
        """
        Mina el bloque ajustando nonce hasta hash < target.
        """
        try:
            block.previous_hash = self.chain[-1].hash()
        except IndexError:
            pass  # Genesis block

        while True:
            header = block.get_header()
            hash_int = int.from_bytes(double_sha256(header), 'little')
            target = bits_to_target(block.bits)
            if hash_int < target:
                self.add(block)
                break
            block.nonce += 1
            if block.nonce % 100000 == 0:
                print(f"Nonce en {block.nonce}, continuando minería...")

    def isValid(self):
        """
        Valida la cadena: hashes coinciden y PoW válido.
        """
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i-1]
            if current.previous_hash != prev.hash():
                return False
            header = current.get_header()
            hash_int = int.from_bytes(double_sha256(header), 'little')
            target = bits_to_target(current.bits)
            if hash_int >= target:
                return False
        return True

def main():
    """
    Función principal: Genera bloques continuamente hasta Ctrl+C.
    """
    blockchain = Blockchain()
    num = 0

    try:
        while True:
            num += 1
            block = Block(number=num)
            print(f"Minando bloque {num}...")
            blockchain.mine(block)
            print(f"Bloque {num} minado. Hash: {block.hash()}")
            time.sleep(1)  # Pausa entre bloques (ajusta o quita)
    except KeyboardInterrupt:
        print("\nGeneración detenida por el usuario.")
        print("Cadena final:")
        for block in blockchain.chain:
            print(block)
        print(f"¿Es válida la cadena? {blockchain.isValid()}")
        print(f"Bloques guardados en formato binario: {blockchain.blocks_path}")

if __name__ == '__main__':
    main()